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
        self.state = self.store.load_risk_state()
        self._grown, self._exited, self._daily_cache = set(), [], {}

    def _save_orders(self) -> None:
        self._set_meta("orders", self.orders)

    def _save_trades(self) -> None:
        self._set_meta("trades", self.trades)

    def _save_setups(self) -> None:
        self._set_meta("setups", self.setups)

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

    def watch_fills(self) -> None:
        self._load()
        try:
            entries = self._entries()
            if not entries:
                return
            if any(self._entry_changed(oid, rec) for oid, rec in entries.items()):
                self._sync_orders({"entry"})
                self._protect_grown(None)
        except ExchangeError as e:
            self._log("error", None, where="watch_fills", error=str(e))

    def run_cycle(self) -> CycleResult:
        self._load()
        res = CycleResult()
        try:
            self._step(res, "sync", self._sync)
            if not res.errors:  # per-position steps: one broken position never blocks the others
                self._step(res, "reconcile", self._reconcile)
                self._protect_all(res)
                self._trail_all(res)
            if not res.errors:
                self._step(res, "entries", self._limits_and_entries)
        finally:
            res.exited = list(self._exited)
            self._record(res)
        return res

    # ---------------------------------------------------------------- cycle plumbing

    def _step(self, res: CycleResult, name: str, fn) -> None:
        if res.errors:
            return
        try:
            fn(res)
        except ExchangeError as e:
            res.errors.append(f"{name}: {e}")
            self._log("error", None, where=name, error=str(e))

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
        self._adopt_pending_entries()
        self._sync_orders(None)
        self._protect_grown(res)
        for pid in list(self.pos):
            pos = self.pos[pid]
            if pos.half_taken and pos.stop_price < pos.entry_price:
                self._replace_stop(pos, pos.entry_price, "break-even")

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

    def _adopt_pending_entries(self) -> None:
        """An entry whose placement call failed may still exist: adopt it by its client order id."""
        pending = {k: s for k, s in self.setups.items() if s["status"] == "placing"}
        if not pending:
            return
        by_cid = {o.client_order_id: o for o in self.ex.open_orders()}
        for key, s in pending.items():
            o = by_cid.get(key)
            if o is not None:
                if o.order_id not in self.orders:
                    self._register(o.order_id, "entry", o.product_id, key, o.base_size,
                                   candidate=s["candidate"], limit=o.limit_price, placed_ts=s["ts"])
                    self._log("entry_adopted", o.product_id, order_id=o.order_id, client_order_id=key)
                s["status"] = "placed"
            else:
                del self.setups[key]  # never reached the exchange; the setup may be retried
        self._save_setups()

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
        if reason == "target":
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
            try:
                self._reconcile_one(self.pos[pid], bal)
            except ExchangeError as e:  # one bad position must not stop the others being protected
                res.errors.append(f"reconcile {pid}: {e}")
                self._log("error", pid, where="reconcile", error=str(e))

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
        for pid in list(self.pos):
            try:
                p = self._product(pid)
                if p.status != "online" and status_alerts.get(pid) != p.status:
                    self._alert(f"{pid} is {p.status}", f"{pid} holds a position; entries stop, exits still tried")
                status_alerts[pid] = p.status
                self._protect_position(self.pos[pid])
            except ExchangeError as e:
                res.errors.append(f"protect {pid}: {e}")
                self._alert("protection failed", f"{pid}: {e}")
        self._set_meta("status_alerts", {k: v for k, v in status_alerts.items() if k in self.pos})

    def _protect_position(self, pos: Position) -> None:
        pid = pos.product_id
        if any(r["kind"] == "ioc" and r["product_id"] == pid for r in self.orders.values()):
            return  # a forced exit is in flight
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
        cid = self._cid(pid, "ioc")
        oid = self.ex.place_ioc_sell(pid, size, limit, cid)
        self._register(oid, "ioc", pid, cid, size)
        self._log("forced_exit", pid, order_id=oid, size=size, limit=limit, bid=bid, stop=pos.stop_price)
        self._alert("forced exit", f"{pid}: bid {bid} below stop {pos.stop_price}; IOC sell {size} at {limit}")

    def _protect_grown(self, res: CycleResult | None) -> None:
        for pid in sorted(self._grown):
            self._grown.discard(pid)
            if pid in self.pos:
                try:
                    self._protect(self.pos[pid])
                except ExchangeError as e:
                    self._alert("unprotected", f"{pid}: entry filled but protection failed: {e}")
                    if res is not None:
                        res.errors.append(f"protect {pid}: {e}")

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
        a = round_down(size / 2, p.base_increment)
        b = _sub(size, a)
        if (not pos.half_taken and self.ex.supports_bracket
                and a >= p.min_base_size and b >= p.min_base_size):
            self._place_leg(pos, "bracket", a, pos.stop_price)
            self._place_leg(pos, "stop", b, pos.stop_price)
        else:
            self._place_leg(pos, "stop", size, pos.stop_price)
        self._log("protect", pid, size=size, legs=[asdict(leg) for leg in pos.legs])

    def _place_leg(self, pos: Position, kind: str, size: float, stop: float) -> None:
        pid = pos.product_id
        p = self._product(pid)
        trigger = round_down(stop, p.quote_increment)
        limit = round_down(trigger * (1 - self.cfg.stop_limit_offset), p.quote_increment)
        cid = self._cid(pid, kind)
        if kind == "bracket":
            target = round_down(pos.target_price, p.quote_increment)
            oid = self.ex.place_bracket(pid, size, trigger, limit, target, cid)
        else:
            oid = self.ex.place_stop(pid, size, trigger, limit, cid)
        pos.legs.append(Leg(oid, size, kind, trigger))
        self.store.save_position(pos)
        o = self._register(oid, kind, pid, cid, size)
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
        for pid in list(self.pos):
            try:
                self._trail(self.pos[pid])
            except ExchangeError as e:
                res.errors.append(f"trail {pid}: {e}")

    def _trail(self, pos: Position) -> None:
        pid, now = pos.product_id, self.now()
        c4h = closed(self.ex.candles(pid, H4, H4_LIMIT), H4, now)
        after = [c.close for c in c4h if c.ts + H4 > pos.opened_ts]
        if after and max(after) > pos.highest_close:
            pos.highest_close = max(after)
            self.store.save_position(pos)
        cur = atr(c4h, 14)[-1] if len(c4h) >= 14 else None
        a = cur if cur else pos.atr
        if any(r["kind"] == "ioc" and r["product_id"] == pid for r in self.orders.values()):
            return
        bid, _ = self.ex.bid_ask(pid)
        no_bracket = not any(leg.kind == "bracket" for leg in pos.legs)
        if not (pos.half_taken or (no_bracket and max(pos.highest_close, bid) >= pos.target_price)):
            return
        new_stop = pos.highest_close - self.cfg.stop_atr_mult * a
        if new_stop - pos.stop_price >= self.cfg.trail_min_improve_atr * a - _EPS and new_stop < bid:
            self._replace_stop(pos, new_stop, "trail")

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

    def _limits_and_entries(self, res: CycleResult) -> None:
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
        if key in self.setups:
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
        self._remember(key, "placing", cand)  # intent first: a lost reply is adopted next cycle
        oid = self.ex.place_entry(pid, base, limit, key)
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
