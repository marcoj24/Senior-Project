"""The trading cycle: sync, reconcile, protect, trail, limits, regime, scan, gate/size/review, record.

Safety rules kept throughout:
- Positions exist only for coins bought by the bot's own entry orders (tracked in an order registry
  in the store's meta table); a balance the bot did not buy is never adopted or sold.
- Every protective sell is sized from the position (rounded down), never from the balance.
- Fills are accounted per order as cumulative totals, so re-reading a fill can never double count.
- Exchange failures end the cycle; protection of other positions runs first.
"""

import json
import math
import traceback
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Callable

from bot.alerts import Alerts
from bot.config import Config
from bot.costs import evaluate_costs
from bot.exchange.base import Exchange, ExchangeError
from bot.indicators import atr
from bot.models import Candidate, Leg, Position, Product
from bot.regime import breadth, confirmed_regime, raw_regime
from bot.reviewer import Reviewer
from bot.risk import (RiskState, apply_transfer, check_limits, correlation_ok, max_positions,
                      on_trade_closed, risk_multiplier, roll_day, round_down, size_position)
from bot.signals import D1, H4, closed, find_candidate
from bot.store import Store
from bot.universe import build_universe, prefilter

_EPS = 1e-9
BTC = "BTC-USD"
H4_LIMIT = 200
FORCED_EXIT_PRICE = 0.98  # IOC limit as a fraction of bid
TARGET_EXIT_PRICE = 0.995  # bot-managed target (venue without brackets): IOC limit as a fraction of bid
FAILED_CYCLES_ALERT = 3
SETUP_MEMORY_S = 7 * D1
FILL_LOOKBACK_S = 7 * D1  # fills window for an order whose exchange timestamp is unknown


@dataclass
class CycleResult:
    entered: list[str] = field(default_factory=list)
    exited: list[str] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    halted: str | None = None
    errors: list[str] = field(default_factory=list)


def _sub(a: float, b: float) -> float:
    return float(Decimal(str(a)) - Decimal(str(b)))


def _add(a: float, b: float) -> float:
    return float(Decimal(str(a)) + Decimal(str(b)))


def _held(balances: dict[str, float], p: Product) -> float:
    """The balance of the product's base coin in whole increments, ignoring float noise."""
    return round_down(balances.get(p.base, 0.0) + _EPS, p.base_increment)


class Engine:
    def __init__(self, cfg: Config, exchange: Exchange, store: Store, reviewer: Reviewer,
                 alerts: Alerts, now: Callable[[], int]):
        self.cfg, self.ex, self.store, self.reviewer, self.alerts, self.now = (
            cfg, exchange, store, reviewer, alerts, now)
        self.state: RiskState | None = None
        self._products: dict[str, Product] = {}
        self._daily_cache: dict[str, list] = {}
        self._grown: set[str] = set()
        self._target_missed: set[str] = set()
        self._exited: list[str] = []

    # ---------------------------------------------------------------- persistence helpers

    def _meta(self, key: str, default):
        raw = self.store.get_meta(key)
        return json.loads(raw) if raw is not None else default

    def _set_meta(self, key: str, value) -> None:
        self.store.set_meta(key, json.dumps(value))

    def _load(self) -> None:
        self.pos: dict[str, Position] = {p.product_id: p for p in self.store.positions()}
        self.orders: dict[str, dict] = self._meta("orders", {})
        self.trades: dict[str, dict] = self._meta("trades", {})
        self.setups: dict[str, dict] = self._meta("setups", {})
        self.pending: dict[str, dict] = self._meta("pending", {})  # exit/leg placements not yet registered
        self.state = self.store.load_risk_state()
        self._grown, self._target_missed, self._exited, self._daily_cache = set(), set(), [], {}

    def _save_orders(self) -> None:
        self._set_meta("orders", self.orders)

    def _save_trades(self) -> None:
        self._set_meta("trades", self.trades)

    def _save_setups(self) -> None:
        self._set_meta("setups", self.setups)

    def _save_pending(self) -> None:
        self._set_meta("pending", self.pending)

    def _log(self, _kind: str, _pid: str | None, /, **data) -> None:
        self.store.journal(_kind, _pid, data, self.now())

    def _alert(self, title: str, body: str) -> None:
        self._log("alert", None, title=title, body=body)
        self.alerts.send(title, body)

    def _today(self) -> str:
        return datetime.fromtimestamp(self.now(), timezone.utc).strftime("%Y-%m-%d")

    def _product(self, pid: str) -> Product:
        if pid not in self._products:
            self._products = {p.product_id: p for p in self.ex.products()}
        if pid not in self._products:
            raise ExchangeError(f"unknown product {pid}")
        return self._products[pid]

    def _cid(self, pid: str, kind: str) -> str:
        seq = self._meta("seq", 0) + 1
        self._set_meta("seq", seq)
        return f"{pid}-{kind}-{self.now()}-{seq}"

    def _entries(self) -> dict[str, dict]:
        return {oid: r for oid, r in self.orders.items() if r["kind"] == "entry"}

    # ---------------------------------------------------------------- public

    def equity(self) -> float:
        """USD cash plus the coins held by bot positions, valued at bid."""
        cash = self.ex.balances().get("USD", 0.0)
        return cash + sum(p.base_size * self.ex.bid_ask(pid)[0] for pid, p in self.pos.items())

    def needs_watch(self) -> bool:
        """True while an entry rests, an order placement is unresolved, or a position is not fully
        covered by its open sell legs: the main loop then calls watch_fills every few seconds."""
        try:
            self._load()
            if self._entries() or self.pending or any(s["status"] == "placing" for s in self.setups.values()):
                return True
            if not self.pos:
                return False
            open_ids = {o.order_id for o in self.ex.open_orders()}
            return any(self._uncovered(pos, open_ids) for pos in self.pos.values())
        except Exception as e:  # cannot tell: keep watching
            self._log("error", None, where="needs_watch", error=repr(e))
            return True

    def watch_fills(self) -> None:
        """Fill poll: resolve lost replies, account entry fills, then re-protect ANY position whose
        open legs do not cover it, so an uncovered position is retried on every poll."""
        self._load()
        self._resolve_all(None)

        def entry_fills():
            entries = self._entries()
            if entries and any(self._entry_changed(oid, rec) for oid, rec in entries.items()):
                self._sync_orders(None)

        if self._guard(None, None, "watch_fills", entry_fills):
            self._protect_grown(None)
            self._repair_coverage()

    def run_cycle(self) -> CycleResult:
        self._load()
        res = CycleResult()
        try:
            if self._step(res, "sync", self._sync):  # without a sync the bot's view is stale
                self._after_sync(res)
                self._step(res, "reconcile", self._reconcile)  # per-position steps from here:
                self._protect_all(res)                           # one broken position never blocks
                self._trail_all(res)                             # protecting the others
                entries_ok = not res.errors
                self._step(res, "limits", lambda r: self._limits_and_entries(r, entries_ok))
        finally:
            res.exited = list(self._exited)
            self._record(res)
        return res

    # ---------------------------------------------------------------- cycle plumbing

    def _step(self, res: CycleResult, name: str, fn) -> bool:
        return self._guard(res, None, name, lambda: fn(res))

    def _guard(self, res: CycleResult | None, pid: str | None, where: str, fn, alert: str | None = None) -> bool:
        """Run one unit of work. An ExchangeError, or any unexpected error, is journaled, recorded
        and (unexpected ones always) alerted; it never escapes, so the next unit still runs."""
        try:
            fn()
            return True
        except ExchangeError as e:
            self._log("error", pid, where=where, error=str(e))
            if alert:
                self._alert(alert, f"{pid or where}: {e}")
            msg = str(e)
        except Exception as e:
            self._log("error", pid, where=where, error=repr(e), traceback=traceback.format_exc())
            self._alert("engine error", f"{where} {pid or ''}: {e!r}")
            msg = repr(e)
        if res is not None:
            res.errors.append(f"{where} {pid}: {msg}" if pid else f"{where}: {msg}")
        return False

    def _record(self, res: CycleResult) -> None:
        if self.state is not None:
            self.store.save_risk_state(self.state)
        streak = self._meta("failed_cycles", 0) + 1 if res.errors else 0
        self._set_meta("failed_cycles", streak)
        if streak == FAILED_CYCLES_ALERT:
            self._alert("cycle failing", f"{streak} cycles in a row failed: {'; '.join(res.errors)}")
        self._log("cycle", None, **asdict(res))
        if not res.errors:
            self.alerts.heartbeat()

    # ---------------------------------------------------------------- 1. sync

    def _sync(self, res: CycleResult) -> None:
        self._products = {p.product_id: p for p in self.ex.products()}
        self._sync_transfers()
        self._resolve_all(res)
        self._sync_orders(None)

    def _after_sync(self, res: CycleResult) -> None:
        """Per position: protect new entry fills, re-cover missed targets, move to break-even."""
        self._protect_grown(res)
        self._cover_missed_targets(res)
        for pid in list(self.pos):
            pos = self.pos.get(pid)
            if pos and pos.half_taken and pos.stop_price < pos.entry_price:
                self._guard(res, pid, "break-even", lambda: self._replace_stop(pos, pos.entry_price, "break-even"),
                            alert="protection failed")

    def _sync_transfers(self) -> None:
        if self.state is None:
            return
        cur = self._meta("transfer_cursor", {"ts": self.now(), "seen": []})
        seen = Counter(cur["seen"])
        got = sorted(self.ex.transfers(cur["ts"]), key=lambda t: t.ts)
        for t in got:
            key = repr(t.amount_usd)
            if t.ts == cur["ts"] and seen[key] > 0:
                seen[key] -= 1
                continue
            apply_transfer(self.state, t.amount_usd)
            self._log("transfer", None, amount_usd=t.amount_usd, ts=t.ts)
        if got:
            last = max(cur["ts"], got[-1].ts)
            cur = {"ts": last, "seen": [repr(t.amount_usd) for t in got if t.ts == last]}
        self.store.save_risk_state(self.state)
        self._set_meta("transfer_cursor", cur)

    def _resolve_all(self, res: CycleResult | None) -> None:
        """Lost replies: look each unresolved placement up by client order id, one at a time.
        A failed lookup leaves that placement unresolved and never blocks fill accounting."""
        for key in [k for k, s in self.setups.items() if s["status"] == "placing"]:
            self._guard(res, self.setups[key]["candidate"].get("product_id"), "resolve entry",
                        lambda: self._resolve_entry(key))
        for cid in list(self.pending):
            self._guard(res, self.pending[cid]["product_id"], "resolve order", lambda: self._resolve_order(cid))

    def _resolve_entry(self, key: str) -> None:
        """An entry whose placement call raised may still exist: if so it is the bot's own order and
        is adopted (sync then protects any fill); if not, the setup may be placed again."""
        s = self.setups[key]
        o = self.ex.get_order_by_client_id(key)
        if o is None:
            s["status"] = "dropped"
            self._save_setups()
            self._log("entry_intent_dropped", s["candidate"].get("product_id"), client_order_id=key)
            return
        recovered = o.order_id not in self.orders
        if recovered:
            self._register(o.order_id, "entry", o.product_id, key, o.base_size,
                           candidate=s["candidate"], limit=o.limit_price, placed_ts=s["ts"])
        s["status"] = "placed"
        self._save_setups()
        self._log("entry_adopted", o.product_id, order_id=o.order_id, client_order_id=key,
                  status=o.status, filled_size=o.filled_size)
        if recovered:
            self._alert("recovered entry", f"{o.product_id}: entry {key} was placed although the call "
                                           f"failed; filled {o.filled_size} of {o.base_size}")

    def _resolve_order(self, cid: str) -> None:
        o = self.ex.get_order_by_client_id(cid)
        if o is not None:
            self._adopt_order(o, self.pending[cid])  # drop the intent only once the order is tracked
        self.pending.pop(cid)
        self._save_pending()

    def _adopt_order(self, o, rec: dict) -> None:
        """Track an exit or leg order the venue accepted although its placement call failed."""
        pid, kind = rec["product_id"], rec["kind"]
        if o.order_id in self.orders:
            return
        extra = {k: v for k, v in rec.items() if k not in ("kind", "product_id", "size")}
        pos = self.pos.get(pid)
        if kind in ("bracket", "stop") and pos is not None and o.status == "open" \
                and not any(lg.order_id == o.order_id for lg in pos.legs):
            pos.legs.append(Leg(o.order_id, o.base_size - o.filled_size, kind, o.stop_trigger))
            self.store.save_position(pos)
        self._register(o.order_id, kind, pid, o.client_order_id, rec["size"], **extra)
        self._log("order_recovered", pid, order_id=o.order_id, client_order_id=o.client_order_id,
                  kind=kind, status=o.status, filled_size=o.filled_size)
        self._alert("recovered order", f"{pid}: {kind} {o.client_order_id} was placed although the call failed")

    def _place_order(self, kind: str, pid: str, size: float, place, **extra) -> tuple[str, bool]:
        """Place an exit or leg order with a fresh client id, recording the intent first. If the call
        raises, the order is looked up by client id: found -> it is tracked as if placed; lookup also
        failing -> the intent stays pending and is resolved by the next sync or fill poll.
        Returns (order_id, recovered)."""
        if any(r["product_id"] == pid for r in self.pending.values()):
            raise ExchangeError(f"{pid}: an earlier order placement is unresolved")  # might hold the coins
        cid = self._cid(pid, kind)
        self.pending[cid] = {"kind": kind, "product_id": pid, "size": size, **extra}
        self._save_pending()
        try:
            oid = place(cid)
        except ExchangeError:
            o = self.ex.get_order_by_client_id(cid)  # raising here leaves the intent pending
            if o is None:
                self.pending.pop(cid)
                self._save_pending()
                raise
            self._adopt_order(o, self.pending[cid])
            self.pending.pop(cid)
            self._save_pending()
            return o.order_id, True
        self._register(oid, kind, pid, cid, size, **extra)
        self.pending.pop(cid, None)
        self._save_pending()
        return oid, False

    def _entry_changed(self, oid: str, rec: dict) -> bool:
        o = self.ex.get_order(oid)
        return o.filled_size > rec["acc_size"] + _EPS or o.status != "open"

    def _sync_orders(self, kinds: set[str] | None) -> None:
        """Account every new fill of the bot's own orders and drop orders that are finished."""
        recs = {oid: r for oid, r in self.orders.items() if kinds is None or r["kind"] in kinds}
        if not recs:
            return
        fills = self.ex.fills(min(r["created_ts"] for r in recs.values()))
        open_ids = {o.order_id for o in self.ex.open_orders()}
        for oid, rec in recs.items():
            mine = [f for f in fills if f.order_id == oid]
            size = sum(f.base_size for f in mine)
            if size > rec["acc_size"] + _EPS:
                value = sum(f.price * f.base_size for f in mine)
                fee = sum(f.fee for f in mine)
                delta = (_sub(size, rec["acc_size"]), value - rec["acc_value"], fee - rec["acc_fee"])
                rec.update(acc_size=size, acc_value=value, acc_fee=fee)
                if rec["kind"] == "entry":  # position first: an over-count is later fixed by reconcile
                    self._on_entry_fill(oid, rec, *delta)
                    self._save_orders()
                else:  # registry first: an under-reduced position is later fixed by reconcile
                    self._save_orders()
                    self._on_exit_fill(oid, rec, *delta, reason=mine[-1].reason)
            pos = self.pos.get(rec["product_id"])
            leg = next((lg for lg in pos.legs if lg.order_id == oid), None) if pos else None
            if oid in open_ids:
                continue
            o = self.ex.get_order(oid)
            if o.status != "open" and o.filled_size <= rec["acc_size"] + _EPS:
                del self.orders[oid]
                self._save_orders()
                if rec.get("purpose") == "target" and rec["acc_size"] < rec["size"] - _EPS:
                    self._target_missed.add(rec["product_id"])
                if leg is not None and rec["product_id"] in self.pos:
                    pos.legs.remove(leg)
                    self.store.save_position(pos)

    def _on_entry_fill(self, oid: str, rec: dict, size: float, value: float, fee: float) -> None:
        pid, c = rec["product_id"], rec["candidate"]
        t = self.trades.setdefault(pid, {
            "entry_order": oid, "setup_ts": c["setup_ts"], "initial_stop": c["stop"],
            "bought": 0.0, "buy_value": 0.0, "buy_fee": 0.0, "sold": 0.0, "proceeds": 0.0, "sell_fee": 0.0,
            "exits": []})
        t["bought"] = _add(t["bought"], size)
        t["buy_value"] += value
        t["buy_fee"] += fee
        vwap = t["buy_value"] / t["bought"]
        pos = self.pos.get(pid)
        if pos is None:
            pos = Position(pid, size, vwap, c["stop"], c["target"], c["atr"], self.now(), [], False, vwap)
            self.pos[pid] = pos
        else:
            pos.base_size = _add(pos.base_size, size)
            pos.entry_price = vwap
        self.store.save_position(pos)
        self._save_trades()
        self._grown.add(pid)
        self._log("entry_fill", pid, order_id=oid, size=size, price=value / size, fee=fee,
                  position_size=pos.base_size, entry_price=vwap)

    def _on_exit_fill(self, oid: str, rec: dict, size: float, value: float, fee: float, reason: str) -> None:
        pid = rec["product_id"]
        pos, t = self.pos.get(pid), self.trades.get(pid)
        self._log("exit_fill", pid, order_id=oid, kind=rec["kind"], reason=reason, size=size,
                  price=value / size, fee=fee)
        if pos is None or t is None:
            return
        t["sold"] = _add(t["sold"], size)
        t["proceeds"] += value
        t["sell_fee"] += fee
        t["exits"].append({"order_id": oid, "reason": reason, "size": size, "price": value / size})
        self._save_trades()
        pos.base_size = max(0.0, _sub(pos.base_size, size))
        for leg in pos.legs:
            if leg.order_id == oid:
                leg.base_size = max(0.0, _sub(leg.base_size, size))
        if reason == "target" or rec.get("purpose") == "target":
            pos.half_taken = True
        if pos.base_size <= _EPS:
            self._close_trade(pos, reason)
        else:
            self.store.save_position(pos)

    def _close_trade(self, pos: Position, reason: str) -> None:
        pid = pos.product_id
        for leg in pos.legs:
            try:
                self.ex.cancel(leg.order_id)
            except ExchangeError as e:
                self._log("error", pid, where="close_trade", error=str(e))
        t = self.trades.pop(pid, None) or {}
        bought = t.get("bought", 0.0)
        cost = (t.get("buy_value", 0.0) + t.get("buy_fee", 0.0)) * (t.get("sold", 0.0) / bought if bought else 0)
        pnl = t.get("proceeds", 0.0) - t.get("sell_fee", 0.0) - cost
        risk = bought * (pos.entry_price - t.get("initial_stop", pos.stop_price))
        self.store.delete_position(pid)
        del self.pos[pid]
        self._save_trades()
        self._log("trade_closed", pid, pnl_usd=pnl, r_multiple=pnl / risk if risk > 0 else None,
                  exit_reason=reason, entry_price=pos.entry_price, opened_ts=pos.opened_ts, **t)
        if self.state is not None:
            on_trade_closed(self.state, pnl, self.cfg)
            self.store.save_risk_state(self.state)
        self._exited.append(pid)

    # ---------------------------------------------------------------- 2. reconcile

    def _reconcile(self, res: CycleResult) -> None:
        bal = self.ex.balances()
        for pid in list(self.pos):
            if pid in self.pos:
                self._guard(res, pid, "reconcile", lambda: self._reconcile_one(self.pos[pid], bal))

    def _reconcile_one(self, pos: Position, bal: dict[str, float]) -> None:
        pid = pos.product_id
        p = self._product(pid)
        held = _held(bal, p)
        if held >= round_down(pos.base_size, p.base_increment) - _EPS:
            return  # extra coins the bot did not buy are never adopted
        self._cancel_legs(pos)
        if pid not in self.pos:
            return  # a leg had filled; the fill closed the position
        held = _held(self.ex.balances(), p)
        if held >= pos.base_size - _EPS:
            self._protect(pos)
            return
        self._log("reconcile", pid, position_size=pos.base_size, balance=held)
        if held >= p.min_base_size:
            pos.base_size = held
            self.store.save_position(pos)
            self._alert("position reconciled", f"{pid}: balance fell to {held}; position shrunk")
            self._protect(pos)
        else:
            self.store.delete_position(pid)
            del self.pos[pid]
            self.trades.pop(pid, None)
            self._save_trades()
            self._alert("position reconciled", f"{pid}: coins sold outside the bot; position removed")

    # ---------------------------------------------------------------- 3. protect

    def _protect_all(self, res: CycleResult) -> None:
        status_alerts = self._meta("status_alerts", {})
        def one(pid: str) -> None:
            p = self._product(pid)
            if p.status != "online" and status_alerts.get(pid) != p.status:
                self._alert(f"{pid} is {p.status}", f"{pid} holds a position; entries stop, exits still tried")
            status_alerts[pid] = p.status
            self._protect_position(self.pos[pid])

        for pid in list(self.pos):
            if pid in self.pos:
                self._guard(res, pid, "protect", lambda: one(pid), alert="protection failed")
        self._set_meta("status_alerts", {k: v for k, v in status_alerts.items() if k in self.pos})

    def _protect_position(self, pos: Position) -> None:
        pid = pos.product_id
        if self._ioc_in_flight(pid):
            return  # a forced or target exit is in flight
        bid, _ = self.ex.bid_ask(pid)
        if bid < pos.stop_price:
            self._forced_exit(pos, bid)
            return
        p = self._product(pid)
        open_ids = {o.order_id for o in self.ex.open_orders()}
        covered = sum(leg.base_size for leg in pos.legs if leg.order_id in open_ids)
        need = round_down(pos.base_size, p.base_increment)
        if any(leg.order_id not in open_ids for leg in pos.legs) or abs(covered - need) > _EPS:
            self._alert("missing stop", f"{pid}: legs cover {covered} of {need}; re-placing")
            self._protect(pos)

    def _forced_exit(self, pos: Position, bid: float) -> None:
        pid = pos.product_id
        self._cancel_legs(pos)
        if pid not in self.pos:
            return
        p = self._product(pid)
        size = round_down(min(pos.base_size, _held(self.ex.balances(), p)), p.base_increment)
        if size < p.min_base_size:
            self._alert("unprotected", f"{pid}: {size} is below the minimum order size")
            return
        limit = round_down(bid * FORCED_EXIT_PRICE, p.quote_increment)
        oid, _ = self._place_order("ioc", pid, size, lambda cid: self.ex.place_ioc_sell(pid, size, limit, cid))
        self._log("forced_exit", pid, order_id=oid, size=size, limit=limit, bid=bid, stop=pos.stop_price)
        self._alert("forced exit", f"{pid}: bid {bid} below stop {pos.stop_price}; IOC sell {size} at {limit}")

    def _protect_grown(self, res: CycleResult | None) -> None:
        for pid in sorted(self._grown):
            self._grown.discard(pid)
            if pid in self.pos:
                self._guard(res, pid, "protect fill", lambda: self._protect(self.pos[pid]), alert="unprotected")

    def _uncovered(self, pos: Position, open_ids: set[str]) -> bool:
        """Legs missing or not summing to the position, with no exit IOC in flight to explain it."""
        if self._ioc_in_flight(pos.product_id):
            return False
        need = round_down(pos.base_size, self._product(pos.product_id).base_increment)
        covered = sum(leg.base_size for leg in pos.legs if leg.order_id in open_ids)
        return any(leg.order_id not in open_ids for leg in pos.legs) or abs(covered - need) > _EPS

    def _repair_coverage(self) -> None:
        """Fill-poll repair of any uncovered position. Alerts once per uncovered episode."""
        alerted = self._meta("uncovered_alerted", {})
        open_ids: set[str] = set()
        if not self._guard(None, None, "watch open orders",
                           lambda: open_ids.update(o.order_id for o in self.ex.open_orders())):
            return
        for pid in list(self.pos):
            pos = self.pos.get(pid)
            ok = True
            try:
                bad = pos is not None and self._uncovered(pos, open_ids)
            except Exception:
                bad = True
            if bad:
                if pid not in alerted:
                    self._alert("missing stop", f"{pid}: legs do not cover the position; re-placing")
                    alerted[pid] = "missing stop"
                ok = self._guard(None, pid, "watch protect", lambda: self._repair(self.pos[pid]))
                if not ok and alerted.get(pid) != "unprotected":
                    self._alert("unprotected", f"{pid}: could not re-place stops; retrying every poll")
                    alerted[pid] = "unprotected"
            if ok and not bad:
                alerted.pop(pid, None)
        self._set_meta("uncovered_alerted", {k: v for k, v in alerted.items() if k in self.pos})

    def _repair(self, pos: Position) -> None:
        pid = pos.product_id
        self._sync_orders(None)  # an exit fill may explain the gap
        if pid not in self.pos:
            return
        open_ids = {o.order_id for o in self.ex.open_orders()}
        if not self._uncovered(pos, open_ids):
            return
        bid, _ = self.ex.bid_ask(pid)
        covered = sum(leg.base_size for leg in pos.legs)
        if bid < pos.stop_price:
            self._forced_exit(pos, bid)
        elif all(leg.order_id in open_ids for leg in pos.legs) and covered < pos.base_size:
            self._cover_gap(pos)  # live legs stay; only the uncovered part gets a stop
        else:
            self._protect(pos)

    def _protect(self, pos: Position) -> None:
        """Cancel the position's legs and place fresh ones covering its full size."""
        pid = pos.product_id
        if pos.legs:
            self._cancel_legs(pos)
            if pid not in self.pos:
                return
        p = self._product(pid)
        size = round_down(pos.base_size, p.base_increment)
        if size < p.min_base_size:
            self._alert("unprotected", f"{pid}: {pos.base_size} is below the minimum order size")
            return
        split = None if pos.half_taken else self._split(size, p)
        if split:  # leg a carries the target: a bracket, or a plain stop the bot sells itself at target
            self._place_leg(pos, "bracket" if self.ex.supports_bracket else "stop", split[0], pos.stop_price)
            self._place_leg(pos, "stop", split[1], pos.stop_price)
        else:
            self._place_leg(pos, "stop", size, pos.stop_price)
        self._log("protect", pid, size=size, legs=[asdict(leg) for leg in pos.legs])

    @staticmethod
    def _split(size: float, p: Product) -> tuple[float, float] | None:
        a = round_down(size / 2, p.base_increment)
        b = _sub(size, a)
        return (a, b) if a >= p.min_base_size and b >= p.min_base_size else None

    def _place_leg(self, pos: Position, kind: str, size: float, stop: float) -> None:
        pid = pos.product_id
        p = self._product(pid)
        trigger = round_down(stop, p.quote_increment)
        limit = round_down(trigger * (1 - self.cfg.stop_limit_offset), p.quote_increment)
        target = round_down(pos.target_price, p.quote_increment)

        def place(cid: str) -> str:
            if kind == "bracket":
                return self.ex.place_bracket(pid, size, trigger, limit, target, cid)
            return self.ex.place_stop(pid, size, trigger, limit, cid)

        oid, recovered = self._place_order(kind, pid, size, place)
        if not any(leg.order_id == oid for leg in pos.legs):
            pos.legs.append(Leg(oid, size, kind, trigger))
            self.store.save_position(pos)
        o = self.ex.get_order(oid)
        if o.status == "cancelled" or abs(o.base_size - size) > _EPS:
            raise ExchangeError(f"{kind} leg {oid} is not live")

    def _register(self, oid: str, kind: str, pid: str, cid: str, size: float, **extra):
        if oid in self.orders:  # already tracked: never reset its accounted fills
            return self.ex.get_order(oid)
        rec = {"kind": kind, "product_id": pid, "client_order_id": cid, "size": size,
               "created_ts": self.now() - FILL_LOOKBACK_S, "placed_ts": self.now(),
               "acc_size": 0.0, "acc_value": 0.0, "acc_fee": 0.0, **extra}
        self.orders[oid] = rec
        self._save_orders()
        o = self.ex.get_order(oid)  # verify, and learn the exchange's own timestamp for fills
        rec["created_ts"] = o.created_ts
        self._save_orders()
        return o

    def _cancel_legs(self, pos: Position) -> None:
        for leg in list(pos.legs):
            self.ex.cancel(leg.order_id)
        pos.legs = []
        self.store.save_position(pos)
        self._sync_orders(None)  # a leg may have filled before the cancel landed

    # ---------------------------------------------------------------- 4. trail

    def _trail_all(self, res: CycleResult) -> None:
        def one(pid: str) -> None:
            self._manage_target(self.pos[pid], res)
            if pid in self.pos:
                self._trail(self.pos[pid])

        for pid in list(self.pos):
            if pid in self.pos:
                self._guard(res, pid, "trail", lambda: one(pid), alert="protection failed")

    def _trail(self, pos: Position) -> None:
        pid, now = pos.product_id, self.now()
        c4h = closed(self.ex.candles(pid, H4, H4_LIMIT), H4, now)
        after = [c.close for c in c4h if c.ts + H4 > pos.opened_ts]
        if after and max(after) > pos.highest_close:
            pos.highest_close = max(after)
            self.store.save_position(pos)
        cur = atr(c4h, 14)[-1] if len(c4h) >= 14 else None
        a = cur if cur else pos.atr
        if self._ioc_in_flight(pid):
            return
        bid, _ = self.ex.bid_ask(pid)
        p = self._product(pid)
        too_small = self._split(round_down(pos.base_size, p.base_increment), p) is None
        if not (pos.half_taken or (too_small and max(pos.highest_close, bid) >= pos.target_price)):
            return
        new_stop = pos.highest_close - self.cfg.stop_atr_mult * a
        if new_stop - pos.stop_price >= self.cfg.trail_min_improve_atr * a - _EPS and new_stop < bid:
            self._replace_stop(pos, new_stop, "trail")

    def _manage_target(self, pos: Position, res: CycleResult) -> None:
        """Venue without brackets: at the target, sell leg a with an IOC; leg b moves to break-even
        once that fills (sync), and leg a's stop is re-placed at once if it does not."""
        pid = pos.product_id
        if self.ex.supports_bracket or pos.half_taken or self._ioc_in_flight(pid):
            return
        p = self._product(pid)
        split = self._split(round_down(pos.base_size, p.base_increment), p)
        bid, _ = self.ex.bid_ask(pid)
        if split is None or bid < pos.target_price:
            return
        leg = next((lg for lg in pos.legs if lg.kind == "stop" and abs(lg.base_size - split[0]) <= _EPS), None)
        if leg is None:
            return  # legs are not in their two-stop shape; protect restores it next cycle
        self.ex.cancel(leg.order_id)
        pos.legs.remove(leg)
        self.store.save_position(pos)
        self._sync_orders(None)  # leg a may have filled before the cancel landed
        if pid not in self.pos:
            return
        size = min(split[0], _sub(round_down(pos.base_size, p.base_increment),
                                  sum(lg.base_size for lg in pos.legs)))
        if size >= p.min_base_size:
            limit = round_down(bid * TARGET_EXIT_PRICE, p.quote_increment)
            try:
                oid, _ = self._place_order("ioc", pid, size,
                                           lambda cid: self.ex.place_ioc_sell(pid, size, limit, cid),
                                           purpose="target")
                self._log("target_exit", pid, order_id=oid, size=size, limit=limit, bid=bid,
                          target=pos.target_price)
            except ExchangeError as e:
                self._log("error", pid, where="target_exit", error=str(e))
                self._target_missed.add(pid)
            self._sync_orders(None)  # an IOC that is already done is accounted now
        self._cover_missed_targets(res)

    def _cover_missed_targets(self, res: CycleResult | None) -> None:
        """Re-place a stop at once for coins a target IOC did not sell."""
        for pid in sorted(self._target_missed):
            self._target_missed.discard(pid)
            pos = self.pos.get(pid)
            if pos is None or self._ioc_in_flight(pid):
                continue
            self._guard(res, pid, "cover target", lambda: self._cover_gap(pos), alert="unprotected")

    def _cover_gap(self, pos: Position) -> None:
        pid = pos.product_id
        p = self._product(pid)
        open_ids = {o.order_id for o in self.ex.open_orders()}
        covered = sum(lg.base_size for lg in pos.legs if lg.order_id in open_ids)
        gap = _sub(round_down(pos.base_size, p.base_increment), covered)
        if gap >= p.min_base_size:
            self._place_leg(pos, "stop", gap, pos.stop_price)
        elif gap > _EPS:
            self._alert("unprotected", f"{pid}: {gap} uncovered is below the minimum order size")

    def _ioc_in_flight(self, pid: str) -> bool:
        return any(r["kind"] == "ioc" and r["product_id"] == pid for r in self.orders.values())

    def _replace_stop(self, pos: Position, new_stop: float, why: str) -> None:
        """Verified cancel-and-replace of the stop legs at a higher stop. Stops never move down."""
        pid = pos.product_id
        if new_stop <= pos.stop_price:
            return
        old = pos.stop_price
        for leg in [lg for lg in pos.legs if lg.kind == "stop"]:
            self.ex.cancel(leg.order_id)
        pos.legs = [lg for lg in pos.legs if lg.kind != "stop"]
        pos.stop_price = new_stop  # a failed placement below is re-placed at this stop by protect
        self.store.save_position(pos)
        for attempt in range(2):
            try:
                self._sync_orders(None)  # a cancelled leg may have filled first
                if pid not in self.pos:
                    return
                if not any(lg.kind == "stop" for lg in pos.legs):
                    p = self._product(pid)
                    size = _sub(round_down(pos.base_size, p.base_increment),
                                sum(lg.base_size for lg in pos.legs))
                    if size >= p.min_base_size:
                        self._place_leg(pos, "stop", size, new_stop)
                self._log("stop_moved", pid, why=why, old_stop=old, new_stop=new_stop, size=pos.base_size)
                return
            except ExchangeError as e:
                self._log("error", pid, where="replace_stop", attempt=attempt + 1, error=str(e))
        self._alert("unprotected", f"{pid}: could not place the {why} stop at {new_stop}")

    # ---------------------------------------------------------------- 5-8. limits and entries

    def _limits_and_entries(self, res: CycleResult, entries_ok: bool = True) -> None:
        """Limits, kill-switch cancel and entry expiry always run after a good sync; regime, scan
        and new entries run only when no earlier step of this cycle failed."""
        equity = self.equity()
        if not math.isfinite(equity) or equity <= 0:
            res.errors.append("invalid equity")
            res.halted = "invalid equity"
            self._log("error", None, where="limits", error="invalid equity", equity=repr(equity))
            return
        today = self._today()
        if self.state is None:
            self.state = RiskState(equity, today, equity, False, 0, 0)
            self._set_meta("transfer_cursor", {"ts": self.now(), "seen": []})
        roll_day(self.state, equity, today)
        lim = check_limits(self.state, equity, self.cfg)
        self.store.save_risk_state(self.state)
        if lim.kill_triggered or self.state.kill_switch:
            res.halted = lim.reason
            if lim.kill_triggered:  # alert first: a failed cancel below must not swallow it
                self._alert("kill switch", f"equity {equity:.2f} is {self.cfg.kill_drawdown:.0%} below the "
                                           f"peak {self.state.peak_equity:.2f}; cancelling entries, stops kept")
            self._cancel_entries(res, "kill switch")
            return
        self._expire_entries(res)
        if not lim.can_enter:
            res.halted = lim.reason
            return
        if not entries_ok:
            self._log("scan_skipped", None, reason="earlier step failed")
            return
        regime, day_mult = self._regime(equity, today)
        if regime == "risk_off":
            self._log("scan_skipped", None, reason="risk_off")
            return
        self._scan_and_enter(res, equity, regime, day_mult)

    def _cancel_entries(self, res: CycleResult, why: str, only: set[str] | None = None) -> None:
        for oid, rec in self._entries().items():
            if only is None or oid in only:
                self.ex.cancel(oid)
                self._log("entry_cancelled", rec["product_id"], order_id=oid, why=why)
        self._sync_orders({"entry"})
        self._protect_grown(res)

    def _expire_entries(self, res: CycleResult) -> None:
        ttl = self.cfg.entry_ttl_hours * 3600
        old = {oid for oid, r in self._entries().items() if self.now() - r["placed_ts"] >= ttl}
        if old:
            self._cancel_entries(res, "expired", old)

    def _daily(self, pid: str) -> list:
        if pid not in self._daily_cache:
            limit = max(300, self.cfg.min_history_days)
            self._daily_cache[pid] = self.ex.candles(pid, D1, limit)
        return self._daily_cache[pid]

    def _universe(self, today: str) -> list[str]:
        cached = self._meta("universe", None)
        if cached and cached["day"] == today:
            return cached["ids"]
        products = list(self._products.values())
        history, spreads = {}, {}
        for p in prefilter(products, self.cfg):
            history[p.product_id] = len(self._daily(p.product_id))
            bid, ask = self.ex.bid_ask(p.product_id)
            spreads[p.product_id] = (ask - bid) / ((ask + bid) / 2)
        ids = build_universe(products, history, spreads, self.cfg)
        self._set_meta("universe", {"day": today, "ids": ids})
        self._log("universe", None, ids=ids, history=history, spreads=spreads)
        return ids

    def _regime(self, equity: float, today: str) -> tuple[str, float]:
        if self._meta("regime_day", None) != today:
            ids = self._universe(today)
            now = self.now()
            btc = closed(self._daily(BTC), D1, now)
            b = breadth({pid: closed(self._daily(pid), D1, now) for pid in ids})
            raw = raw_regime(btc, b)
            confirmed = confirmed_regime(self._meta("regime_confirmed", "neutral"), raw,
                                         self._meta("regime_raw", None))
            if confirmed == "risk_off" and not self.pos and not self._entries():
                label, mult, notes = "risk_off", 1.0, "flat and risk-off: not reviewed"
            else:
                packet = {"regime": confirmed, "raw_regime": raw, "breadth": b,
                          "btc_close": btc[-1].close if btc else None, "portfolio": self._portfolio(equity)}
                d = self.reviewer.review_regime(packet, equity, now)
                label, mult, notes = d.label, d.risk_multiplier, d.notes
            for k, v in (("regime_day", today), ("regime_raw", raw), ("regime_confirmed", confirmed),
                         ("regime", label), ("day_multiplier", mult)):
                self._set_meta(k, v)
            self._log("regime", None, raw=raw, breadth=b, confirmed=confirmed, label=label,
                      day_multiplier=mult, notes=notes)
        return self._meta("regime", "neutral"), float(self._meta("day_multiplier", 1.0))

    def _book(self, fees) -> dict:
        """Open risk, exposure and free cash across positions and resting entries."""
        risk = exposure = reserved = 0.0
        for pid, p in self.pos.items():
            bid = self.ex.bid_ask(pid)[0]
            exit_cost = p.stop_price * (fees.taker + self.cfg.slippage)
            risk += p.base_size * (max(0.0, p.entry_price - p.stop_price) + exit_cost)
            exposure += p.base_size * bid
        for rec in self._entries().values():
            c, rem = rec["candidate"], max(0.0, rec["size"] - rec["acc_size"])
            loss = c["entry"] - c["stop"] + c["entry"] * fees.maker + c["stop"] * (fees.taker + self.cfg.slippage)
            risk += rem * loss
            exposure += rem * rec["limit"]
            reserved += rem * rec["limit"] * (1 + fees.maker)
        cash = self.ex.balances().get("USD", 0.0)
        return {"open_risk_usd": risk, "exposure_usd": exposure, "free_cash": cash - reserved, "cash": cash}

    def _portfolio(self, equity: float) -> dict:
        return {"equity": equity, "open_entries": len(self._entries()),
                "positions": [{"product_id": p.product_id, "base_size": p.base_size,
                               "entry_price": p.entry_price, "stop_price": p.stop_price,
                               "half_taken": p.half_taken} for p in self.pos.values()]}

    def _scan_and_enter(self, res: CycleResult, equity: float, regime: str, day_mult: float) -> None:
        now = self.now()
        self.setups = {k: s for k, s in self.setups.items() if now - s["ts"] < SETUP_MEMORY_S}
        ids = self._universe(self._today())
        busy = {o.product_id for o in self.ex.open_orders()}
        entry_pids = {r["product_id"] for r in self._entries().values()}
        bal = self.ex.balances()
        btc = self._daily(BTC)
        cands: list[Candidate] = []
        for pid in ids:
            p = self._products.get(pid)
            if pid in self.pos:
                res.skipped[pid] = "held"
            elif pid in entry_pids:
                res.skipped[pid] = "open entry"
            elif pid in busy:
                res.skipped[pid] = "open order on exchange"
            elif p is not None and bal.get(p.base, 0.0) >= p.min_base_size:
                res.skipped[pid] = "balance held outside the bot"
            else:
                c = find_candidate(pid, self.ex.candles(pid, H4, H4_LIMIT), self._daily(pid), btc, now, self.cfg)
                if c is not None:
                    cands.append(c)
        cands.sort(key=lambda c: c.rs_score, reverse=True)
        fees = self.ex.fees()
        for cand in cands:
            reason = self._try_entry(res, cand, equity, regime, day_mult, fees)
            if reason:
                res.skipped[cand.product_id] = reason
                self._log("skip", cand.product_id, reason=reason, setup_ts=cand.setup_ts)

    def _try_entry(self, res: CycleResult, cand: Candidate, equity: float, regime: str,
                   day_mult: float, fees) -> str | None:
        """Gate, size, review and place one candidate. Returns a skip reason, or None if placed."""
        pid, now = cand.product_id, self.now()
        held = list(self.pos) + [r["product_id"] for r in self._entries().values()]
        if len(held) >= max_positions(equity, self.cfg):
            return "max positions"
        p = self._product(pid)
        if p.status != "online":
            return f"status {p.status}"
        key = f"{pid}-{cand.setup_ts}"
        if key in self.setups and self.setups[key]["status"] != "dropped":
            return f"setup already {self.setups[key]['status']}"
        if not correlation_ok(pid, held, regime):
            return "correlation"
        bid, ask = self.ex.bid_ask(pid)
        spread = (ask - bid) / ((ask + bid) / 2)
        cc = evaluate_costs(cand.entry, cand.stop, cand.target, fees, spread, self.cfg)
        if not cc.passed:
            return f"cost gate: {cc.reason}"
        book = self._book(fees)
        mult = day_mult * risk_multiplier(self.state, self.cfg)

        def size(m: float):
            return size_position(equity, book["free_cash"], book["open_risk_usd"], book["exposure_usd"],
                                 cand, cc.loss_cost, p, m, self.cfg)

        first = size(mult)
        costs = {"win_cost": cc.win_cost, "loss_cost": cc.loss_cost, "net_rr": cc.net_rr, "spread": spread}
        proposed = {"base_size": first.base_size, "quote_value": first.quote_value, "risk_usd": first.risk_usd,
                    "entry": cand.entry, "stop": cand.stop, "target": cand.target, "multiplier": mult}
        self._log("candidate", pid, candidate=asdict(cand), costs=costs, proposed=proposed,
                  skipped=first.skipped, regime=regime, day_multiplier=day_mult)
        if first.skipped:
            return first.skipped
        packet = {"product_id": pid, "regime": regime, "candidate": asdict(cand), "costs": costs,
                  "proposed": proposed, "portfolio": {**self._portfolio(equity), **book},
                  "recent_trades": [r["data"] for r in self.store.journal_rows("trade_closed")[-30:]]}
        d = self.reviewer.review_entry(packet, equity, now)
        if d.decision in ("veto", "reduce"):
            self.store.add_shadow(cand, d.decision, d.multiplier, now)
        if d.decision == "veto":
            self._remember(key, "vetoed", cand)
            return f"vetoed: {d.reason}"
        final_mult = mult * min(1.0, max(0.0, d.multiplier))
        final = size(final_mult)
        if final.skipped:
            self._remember(key, "skipped", cand)
            return final.skipped
        base = min(final.base_size, first.base_size)
        limit = round_down(cand.entry, p.quote_increment)
        self._remember(key, "placing", cand)  # intent first: a lost reply is resolved by client id
        self._log("entry_intent", pid, client_order_id=key, base_size=base, limit=limit,
                  stop=cand.stop, target=cand.target, atr=cand.atr)
        try:
            oid = self.ex.place_entry(pid, base, limit, key)
        except ExchangeError as e:
            self._log("entry_place_failed", pid, client_order_id=key, error=str(e))
            raise
        self._register(oid, "entry", pid, key, base, candidate=asdict(cand), limit=limit)
        self._remember(key, "placed", cand)
        self._log("entry_placed", pid, order_id=oid, client_order_id=key, base_size=base, limit=limit,
                  decision=d.decision, review_multiplier=d.multiplier, final_multiplier=final_mult,
                  risk_usd=final.risk_usd)
        res.entered.append(pid)
        return None

    def _remember(self, key: str, status: str, cand: Candidate) -> None:
        self.setups[key] = {"status": status, "ts": self.now(), "candidate": asdict(cand)}
        self._save_setups()
