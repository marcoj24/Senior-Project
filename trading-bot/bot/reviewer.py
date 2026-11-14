"""Asks Claude to approve, reduce or veto a trade. Claude can only make the bot more cautious.

Every failure of the call or the parse is a veto, and nothing raised inside escapes the public methods.
"""

import hashlib
import json
import math
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Literal

from bot.config import Config
from bot.models import Regime
from bot.store import Store

# (model, system, user_json) -> (reply_text, cost_usd)
LLMClient = Callable[[str, str, str], tuple[str, float]]

_DECISIONS = ("approve", "reduce", "veto")
_CAUTION: dict[str, int] = {"risk_on": 0, "neutral": 1, "risk_off": 2}

# USD per million tokens (input, output). Unknown models are billed at the highest rate so the
# monthly budget errs on the side of stopping early.
_PRICES = {
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-sonnet-5-5": (2.00, 10.00),
}
_FALLBACK_PRICE = (10.00, 50.00)


@dataclass(frozen=True)
class EntryDecision:
    decision: Literal["approve", "reduce", "veto"]
    multiplier: float
    invalidation: str
    reason: str


@dataclass(frozen=True)
class RegimeDecision:
    label: Regime
    risk_multiplier: float
    notes: str


def anthropic_client() -> LLMClient:
    """Real client. The key comes from ANTHROPIC_API_KEY and is never logged or journaled."""
    import anthropic

    client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"), max_retries=1, timeout=60.0)

    def call(model: str, system: str, user_json: str) -> tuple[str, float]:
        resp = client.messages.create(
            model=model,
            max_tokens=2048,
            system=system,
            messages=[{"role": "user", "content": user_json}],
            output_config={"effort": "low"},
        )
        text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
        in_price, out_price = _PRICES.get(model, _FALLBACK_PRICE)
        usage = resp.usage
        cost = (usage.input_tokens * in_price + usage.output_tokens * out_price) / 1_000_000
        return text, cost

    return call


def _veto(reason: str) -> EntryDecision:
    return EntryDecision("veto", 0.0, "", reason)


def _clamp01(x: float) -> float:
    return min(1.0, max(0.0, x))


def _number(v) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise ValueError("not a number")
    f = float(v)
    if not math.isfinite(f):
        raise ValueError("not finite")
    return f


class Reviewer:
    def __init__(self, cfg: Config, store: Store, client: LLMClient, prompt_path: str):
        self.cfg = cfg
        self.store = store
        self.client = client
        with open(prompt_path, "rb") as f:
            raw = f.read()
        self.system = raw.decode("utf-8")
        self.prompt_version = hashlib.sha256(raw).hexdigest()[:12]

    # -- public -----------------------------------------------------------------------------

    def review_entry(self, packet: dict, equity: float, now_ts: int) -> EntryDecision:
        try:
            if not self.cfg.review_enabled:
                return EntryDecision("approve", 1.0, "", "review disabled")
            if self._over_budget(now_ts):
                return _veto("budget")
            reply = self._call("entry", packet, equity, now_ts)
            decision = self._parse_entry(reply)
        except Exception:
            return _veto("invalid reply")
        self._journal_review("entry", packet.get("product_id") if isinstance(packet, dict) else None, decision, now_ts)
        return decision

    def review_regime(self, packet: dict, equity: float, now_ts: int) -> RegimeDecision:
        fallback_label = self._system_label(packet)
        try:
            if not self.cfg.review_enabled:
                return RegimeDecision(fallback_label, 1.0, "review disabled")
            if self._over_budget(now_ts):
                return RegimeDecision(fallback_label, 1.0, "budget")
            reply = self._call("regime", packet, equity, now_ts)
            decision = self._parse_regime(reply, fallback_label)
        except Exception:
            return RegimeDecision(fallback_label, 1.0, "invalid reply")
        self._journal_review("regime", None, decision, now_ts)
        return decision

    # -- internals --------------------------------------------------------------------------

    @staticmethod
    def _system_label(packet) -> str:
        try:
            label = packet["regime"]
            return label if label in _CAUTION else "risk_off"
        except Exception:
            return "risk_off"

    def _over_budget(self, now_ts: int) -> bool:
        day_start = now_ts - now_ts % 86400
        d = datetime.fromtimestamp(now_ts, timezone.utc)
        month_start = int(d.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp())
        return (
            self.store.api_calls(day_start) >= self.cfg.max_calls_per_day
            or self.store.api_spend(month_start) >= self.cfg.monthly_budget_usd
        )

    def _call(self, kind: str, packet: dict, equity: float, now_ts: int) -> str:
        model = self.cfg.model_small if equity < self.cfg.model_switch_equity else self.cfg.model_large
        user_json = json.dumps(
            {"review": kind, "equity": equity, "packet": packet}, default=str, sort_keys=True
        )
        reply, cost = self.client(model, self.system, user_json)
        self.store.journal("api_cost", None, {"cost_usd": float(cost), "model": model}, now_ts)
        return reply

    def _journal_review(self, kind: str, product_id, decision, now_ts: int) -> None:
        try:
            data = {"review": kind, "prompt_version": self.prompt_version}
            data.update(decision.__dict__)
            self.store.journal("review", product_id, data, now_ts)
        except Exception:
            pass  # the decision stands even if the audit row cannot be written

    @staticmethod
    def _parse_entry(reply: str) -> EntryDecision:
        try:
            d = json.loads(reply)
            decision = d["decision"]
            if decision not in _DECISIONS:
                return _veto("invalid reply")
            mult = _number(d["multiplier"])
            invalidation, reason = str(d["invalidation"]), str(d["reason"])
        except Exception:
            return _veto("invalid reply")
        if decision == "approve":
            mult = 1.0
        elif decision == "reduce":
            mult = _clamp01(mult)
        else:
            mult = 0.0
        return EntryDecision(decision, mult, invalidation, reason)

    @staticmethod
    def _parse_regime(reply: str, system_label: str) -> RegimeDecision:
        try:
            d = json.loads(reply)
            label = d["label"]
            if label not in _CAUTION:
                raise ValueError("unknown label")
            mult = _clamp01(_number(d["risk_multiplier"]))
            notes = str(d["notes"])
        except Exception:
            return RegimeDecision(system_label, 1.0, "invalid reply")
        if _CAUTION[label] < _CAUTION[system_label]:
            label = system_label
        return RegimeDecision(label, mult, notes)
