"""The trading cycle: sync, reconcile, protect, trail, limits, regime, scan, gate/size/review, record.

Safety rules kept throughout:
- Positions exist only for coins bought by the bot's own entry orders (tracked in an order registry
  in the store's meta table); a balance the bot did not buy is never adopted or sold.
- QUANTITY has one authority: the venue's order status (bot/orders.py). A position is what its
  entry orders filled minus what its exit orders filled. fills() supplies prices and fees only;
  its lag, loss or rounding can never change a size, refuse a sell or close a trade twice.
- Every sell is sized from the position net of its other open sells, never from the balance
  (the balance may only make a sell smaller).
- A trade is flat the moment order status says so; its trade_closed row is written exactly once,
  when its fill prices arrive or after cfg.fill_wait_cycles cycles on estimated prices.
- Exchange failures end the cycle; protection of other positions runs first.
"""

import json
import math
import traceback
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable

from bot.alerts import Alerts
from bot.config import Config
from bot.costs import evaluate_costs
from bot.exchange.base import Exchange, ExchangeError
from bot.indicators import atr
from bot import orders as ledger
from bot.models import Candidate, Leg, Position, Product
from bot.orders import EPS as _EPS, add as _add, sub as _sub
from bot.regime import breadth, confirmed_regime, raw_regime
from bot.reviewer import Reviewer
from bot.risk import (RiskState, apply_transfer, check_limits, correlation_ok, max_positions,
                      on_trade_closed, risk_multiplier, roll_day, round_down, size_position)
from bot.signals import D1, H4, closed, find_candidate
from bot.store import Store
from bot.universe import build_universe, prefilter

BTC = "BTC-USD"
H4_LIMIT = 200
FORCED_EXIT_PRICE = 0.98  # IOC limit as a fraction of bid
TARGET_EXIT_PRICE = 0.995  # bot-managed target (venue without brackets): IOC limit as a fraction of bid
FAILED_CYCLES_ALERT = 3
SETUP_MEMORY_S = 7 * D1
FILL_LOOKBACK_S = 7 * D1  # fills window for an order whose exchange timestamp is unknown
LEG_KINDS = ("stop", "bracket")  # resting protective orders
FORCED_EXIT_BLOCKED = ("disabled", "cancel_only")  # statuses in which no new sell order is accepted


@dataclass
class CycleResult:
    entered: list[str] = field(default_factory=list)
    exited: list[str] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    halted: str | None = None
    errors: list[str] = field(default_factory=list)


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
        self.trades: dict[str, dict] = self._meta("trades", {})  # open trades, by product id
        self.closing: dict[str, dict] = self._meta("closing", {})  # flat trades awaiting prices, by trade id
        for pid in [pid for pid, t in self.trades.items() if t["id"] in self.closing]:
            del self.trades[pid]  # interrupted between the two saves: it is closing
        self.cycle_no: int = self._meta("cycle_no", 0)
        self._qty_events = 0  # counts quantity changes seen in order status (reconcile's snapshot check)
        self.setups: dict[str, dict] = self._meta("setups", {})
        self.pending: dict[str, dict] = self._meta("pending", {})  # exit/leg placements not yet registered
        self.episodes: dict[str, dict] = self._meta("episodes", {})  # alert-once state, by episode key
        self.last_bid: dict[str, float] = self._meta("last_bid", {})
        self.state = self.store.load_risk_state()
        self._grown, self._target_missed, self._exited, self._daily_cache = set(), set(), [], {}

    def _save_orders(self) -> None:
        self._set_meta("orders", self.orders)

    def _save_trades(self) -> None:
        self._set_meta("closing", self.closing)  # first: a trade in both places counts as closing
        self._set_meta("trades", self.trades)

    def _save_setups(self) -> None:
        self._set_meta("setups", self.setups)

    def _save_pending(self) -> None:
        self._set_meta("pending", self.pending)

    def _log(self, _kind: str, _pid: str | None, /, **data) -> None:
        self.store.journal(_kind, _pid, data, self.now())

    def _alert(self, title: str, body: str) -> None:
        """Never raises: a broken alert transport must not stop protection."""
        try:
            self._log("alert", None, title=title, body=body)
            self.alerts.send(title, body)
        except Exception as e:
            try:
                self._log("alert_failed", None, title=title, error=repr(e))
            except Exception:
                pass

    def _episode(self, key: str, value=True) -> bool:
        """Start (or keep) an alert episode. True only when it is new or its value changed."""
        if self.episodes.get(key) == value:
            return False
        self.episodes[key] = value
        self._set_meta("episodes", self.episodes)
        return True

    def _end_episode(self, key: str) -> None:
        if key in self.episodes:
            del self.episodes[key]
            self._set_meta("episodes", self.episodes)

    def _clear_episodes(self, pid: str) -> None:
        """A deleted position ends every alert episode of its product."""
        keys = [k for k in self.episodes if k.split("|")[-1] == pid]
        for k in keys:
            del self.episodes[k]
        if keys:
            self._set_meta("episodes", self.episodes)

    def _dust(self, pos: Position, why: str) -> None:
        """A position too small to carry a sell order: alert and journal once per size."""
        if self._episode(f"dust|{pos.product_id}", pos.base_size):
            self._log("dust", pos.product_id, size=pos.base_size, why=why)
            self._alert("unprotected", f"{pos.product_id}: {pos.base_size} is below the minimum order size ({why})")

    def _is_dust(self, pos: Position) -> bool:
        p = self._product(pos.product_id)
        return round_down(pos.base_size, p.base_increment) < p.min_base_size

    def _bid(self, pid: str) -> float:
        bid = self.ex.bid_ask(pid)[0]
        if self.last_bid.get(pid) != bid:
            self.last_bid[pid] = bid
            self._set_meta("last_bid", self.last_bid)
        self._end_episode(f"stale|{pid}")
        return bid

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
        """Entry orders still working."""
        return {oid: r for oid, r in self.orders.items() if r["kind"] == "entry" and not r["final"]}

    # ---------------------------------------------------------------- public

    def equity(self) -> float:
        """USD cash plus the coins held by bot positions, valued at bid."""
        if not hasattr(self, "pos"):
            self._load()
        cash = self.ex.balances().get("USD", 0.0)
        total = cash
        for pid, p in self.pos.items():
            try:
                bid = self._bid(pid)
            except ExchangeError as e:  # value it at the last known bid so limits still run
                bid = self.last_bid.get(pid, p.entry_price)
                if self._episode(f"stale|{pid}"):
                    self._alert("stale price", f"{pid}: no bid ({e}); valued at the last known {bid}")
            total += p.base_size * bid
        return total

    def needs_watch(self) -> bool:
        """True while an entry rests, an order placement is unresolved, or a position is not fully
        covered by its open sell legs: the main loop then calls watch_fills every few seconds."""
        try:
            self._load()
            if self._entries() or self.pending or any(s["status"] == "placing" for s in self.setups.values()):
                return True
            exits = [oid for oid, r in self.orders.items() if ledger.is_exit(r) and not r["final"]]
            if not self.pos and not exits:
                return False
            open_ids = {o.order_id for o in self.ex.open_orders()}
            if any(oid not in open_ids for oid in exits):
                return True  # an exit order has finished: its status is still to be applied
            return any(self._uncovered(pos, open_ids) for pos in self.pos.values())
        except Exception as e:  # cannot tell: keep watching
            self._log("error", None, where="needs_watch", error=repr(e))
            return True

    def watch_fills(self) -> None:
        """Fill poll: resolve lost replies, apply order status, then re-protect ANY position whose
        open legs do not cover it, so an uncovered position is retried on every poll."""
        if not self._guard(None, None, "load", self._load):
            return
        self._resolve_all(None)
        if self._guard(None, None, "watch_fills", self._sync_orders):
            self._protect_grown(None)
            self._repair_coverage()

    def run_cycle(self) -> CycleResult:
        res = CycleResult()
        if not self._guard(res, None, "load", self._load):
            return res
        try:
            if self._step(res, "sync", self._sync):  # without a sync the bot's view is stale
                self._after_sync(res)
                self._step(res, "reconcile", self._reconcile)  # per-position steps from here:
                self._protect_all(res)                           # one broken position never blocks
                self._trail_all(res)                             # protecting the others
                entries_ok = not res.errors
                self._step(res, "limits", lambda r: self._limits_and_entries(r, entries_ok))
                self._repair_coverage()  # a last pass: nothing a step left uncovered waits for the poll
        finally:
            res.exited = list(self._exited)
            self._guard(None, None, "record", lambda: self._record(res))
        return res

    # ---------------------------------------------------------------- cycle plumbing

    def _step(self, res: CycleResult, name: str, fn) -> bool:
        return self._guard(res, None, name, lambda: fn(res))

    def _guard(self, res: CycleResult | None, pid: str | None, where: str, fn, alert: str | None = None) -> bool:
        """Run one unit of work. An ExchangeError, or any unexpected error, is journaled, recorded
        and (unexpected ones always) alerted; it never escapes, so the next unit still runs."""
        key, xkey = f"engine|{where}|{pid}", f"exchange|{where}|{pid}"
        try:
            fn()
            for k in (key, xkey):
                if k in getattr(self, "episodes", {}):
                    self._end_episode(k)
            return True
        except ExchangeError as e:
            msg = str(e)
            try:
                self._log("error", pid, where=where, error=msg)
                if alert and (not hasattr(self, "episodes") or self._episode(xkey)):
                    self._alert(alert, f"{pid or where}: {e}")
            except Exception:
                pass  # the store itself is failing; nothing more can be recorded
        except Exception as e:
            msg = repr(e)
            try:
                period = self.now() // (self.cfg.cycle_minutes * 60)
                seen = getattr(self, "episodes", {}).get(key)
                if seen is None or seen != period:
                    self._log("error", pid, where=where, error=msg, traceback=traceback.format_exc())
                if seen is None:
                    self._alert("engine error", f"{where} {pid or ''}: {msg}")
                if hasattr(self, "episodes"):
                    self._episode(key, period)
            except Exception:
                pass  # the store itself is failing; nothing more can be recorded
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
            try:
                self.alerts.heartbeat()
            except Exception as e:
                self._log("alert_failed", None, title="heartbeat", error=repr(e))

    # ---------------------------------------------------------------- 1. sync

    def _sync(self, res: CycleResult) -> None:
        self.cycle_no += 1
        self._set_meta("cycle_no", self.cycle_no)
        self._products = {p.product_id: p for p in self.ex.products()}
        self._sync_transfers()
        self._resolve_all(res)
        self._sync_orders(res)

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
            self._register(o.order_id, "entry", o.product_id, key, o.base_size, candidate=s["candidate"],
                           limit=o.limit_price, ref_price=o.limit_price, placed_ts=s["ts"])
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
        self._register(o.order_id, kind, pid, o.client_order_id, rec["size"], **extra)
        pos = self.pos.get(pid)
        if kind in ("bracket", "stop") and pos is not None and self._live(o.order_id) \
                and not any(lg.order_id == o.order_id for lg in pos.legs):
            pos.legs.append(Leg(o.order_id, ledger.remaining(self.orders[o.order_id]), kind, o.stop_trigger))
            self.store.save_position(pos)
        self._log("order_recovered", pid, order_id=o.order_id, client_order_id=o.client_order_id,
                  kind=kind, status=o.status, filled_size=o.filled_size)
        self._alert("recovered order", f"{pid}: {kind} {o.client_order_id} was placed although the call failed")

    def _place_order(self, kind: str, pid: str, size: float, place, **extra) -> tuple[str, bool]:
        """Place an exit or leg order with a fresh client id, recording the intent first. If the call
        raises, the order is looked up by client id: found -> it is tracked as if placed; lookup also
        failing -> the intent stays pending and is resolved by the next sync or fill poll.
        Returns (order_id, recovered)."""
        self._check_no_pending(pid)
        self._check_sell_room(pid, size)
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

    def _room(self, pos: Position) -> float:
        """What may still be sold: the position net of its resting and unresolved sells, by order
        status. The account balance plays no part."""
        size = round_down(pos.base_size, self._product(pos.product_id).base_increment)
        return ledger.sell_room(self.orders, self.pending, pos.product_id, size)

    def _check_sell_room(self, pid: str, size: float) -> None:
        """No sell may exceed the bot's own position net of its other open sells. Both sides are
        read from order status just before placing; nothing here waits on fills()."""
        if pid not in self.pos:
            raise ExchangeError(f"{pid}: no position to sell")
        self._refresh(pid)
        pos = self.pos.get(pid)
        if pos is None:
            raise ExchangeError(f"{pid}: the position closed before the sell was placed")
        room = self._room(pos)
        if size > room + _EPS:
            raise ExchangeError(f"{pid}: sell {size} would exceed the {room} free of the position "
                                f"{pos.base_size}")

    def _check_no_pending(self, pid: str) -> None:
        if any(r["product_id"] == pid for r in self.pending.values()):
            raise ExchangeError(f"{pid}: an earlier order placement is unresolved")  # might hold the coins

    # ---------------------------------------------------------------- order status -> quantity

    def _sync_orders(self, res: CycleResult | None = None) -> None:
        """Quantity from order status first; then prices and fees from fills(), whose failure or
        lag is recorded but never stops or undoes anything."""
        self._sync_status()
        self._guard(res, None, "fills", self._sync_fills)

    def _sync_status(self) -> None:
        """Order status is the authority for quantity: read it for every order still working and
        apply what it says to the positions at once."""
        live = [oid for oid, r in self.orders.items() if not r["final"]]
        if live:
            open_ = {o.order_id: o for o in self.ex.open_orders()}
            for oid in live:
                rec = self.orders.get(oid)
                if rec is not None and not rec["final"]:
                    self._apply_status(oid, rec, open_.get(oid) or self.ex.get_order(oid))
        for pid in list(self.trades):
            self._derive(pid)
        for pid, t in list(self.trades.items()):  # a flat trade's orders still resting: cancel them
            if pid in self.pos:
                continue
            for oid, rec in ledger.of_trade(self.orders, t["id"]).items():
                if not rec["final"]:
                    try:
                        self.ex.cancel(oid)
                        self._apply_status(oid, rec, self.ex.get_order(oid))
                    except ExchangeError as e:
                        self._log("error", pid, where="cancel leftover", order_id=oid, error=str(e))

    def _refresh(self, pid: str) -> None:
        """Fresh status of the product's resting sell orders."""
        for oid, rec in list(self.orders.items()):
            if rec["product_id"] == pid and ledger.is_exit(rec) and not rec["final"]:
                self._apply_status(oid, rec, self.ex.get_order(oid))

    def _live(self, oid: str) -> bool:
        rec = self.orders.get(oid)
        return rec is not None and not rec["final"]

    def _trade_of(self, rec: dict) -> dict | None:
        t = self.trades.get(rec["product_id"])
        if t is not None and t["id"] == rec.get("trade"):
            return t
        return self.closing.get(rec.get("trade") or "")

    def _apply_status(self, oid: str, rec: dict, o) -> None:
        """Apply one order's status: the registry is saved first (it is the authority), then the
        position is derived from it."""
        was_final = rec["final"]
        delta = ledger.apply_status(rec, o)
        if not delta and rec["final"] == was_final:
            return
        pid = rec["product_id"]
        if rec["final"] and not was_final:
            rec["final_cycle"] = self.cycle_no
        if delta:
            self._qty_events += 1
            if rec["kind"] == "entry":
                self._link_entry(oid, rec)
        t = self._trade_of(rec)
        if rec["final"] and (rec["filled"] <= _EPS or t is None):
            del self.orders[oid]  # nothing to price; a filled order stays until its trade is closed
        self._save_orders()
        if delta:
            price, _ = ledger.price_of(rec)
            self._log("entry_fill" if rec["kind"] == "entry" else "exit_fill", pid, order_id=oid,
                      kind=rec["kind"], size=delta, filled=rec["filled"], price=price,
                      trade_id=rec.get("trade"), untracked=t is None)
            if rec["kind"] == "entry":
                self._grown.add(pid)
            elif t is not None:
                self._record_exit(oid, rec, t, last=True)
        pos = self.pos.get(pid)
        leg = next((lg for lg in pos.legs if lg.order_id == oid), None) if pos else None
        if leg is not None:
            if rec["final"]:
                pos.legs.remove(leg)
            else:
                leg.base_size = ledger.remaining(rec)
            self.store.save_position(pos)
        if rec["final"] and rec.get("purpose") == "target" and rec["filled"] < rec["size"] - _EPS:
            self._target_missed.add(pid)
        self._derive(pid)

    def _link_entry(self, oid: str, rec: dict) -> None:
        """An entry fill belongs to the product's open trade, or opens one."""
        pid, c = rec["product_id"], rec["candidate"]
        t = self.trades.get(pid)
        if t is None:
            t = {"id": self._cid(pid, "trade"), "product_id": pid, "entry_order": oid,
                 "setup_ts": c["setup_ts"], "initial_stop": c["stop"], "target": c["target"], "atr": c["atr"],
                 "opened_ts": self.now(), "written_off": 0.0, "half_taken": False, "exits": [],
                 "last_exit": None}
            self.trades[pid] = t
            self._save_trades()
        rec["trade"] = t["id"]

    def _exit_reason(self, rec: dict) -> str:
        if rec["kind"] != "bracket":
            return "ioc" if rec["kind"] == "ioc" else "stop"
        if rec.get("fill_reason"):
            return rec["fill_reason"]
        avg, target = rec.get("avg_price"), rec.get("target")
        if avg and target:
            return "target" if avg >= target * (1 - 1e-9) else "stop"
        return "bracket"  # which side filled is not known until a price arrives

    def _record_exit(self, oid: str, rec: dict, t: dict, last: bool) -> None:
        reason = self._exit_reason(rec)
        row = next((x for x in t["exits"] if x["order_id"] == oid), None)
        if row is None:
            row = {"order_id": oid}
            t["exits"].append(row)
        row.update(reason=reason, size=rec["filled"], price=ledger.price_of(rec)[0])
        if last:
            t["last_exit"] = oid
        if reason == "target" or rec.get("purpose") == "target":
            t["half_taken"] = True
            pos = self.pos.get(rec["product_id"])
            if pos is not None and not pos.half_taken and self.trades.get(pos.product_id) is t:
                pos.half_taken = True
                self.store.save_position(pos)
        self._save_trades()

    def _derive(self, pid: str) -> None:
        """The position of the product's open trade, derived from the order registry."""
        t = self.trades.get(pid)
        if t is None:
            return
        qty = ledger.position_size(self.orders, t)
        pos = self.pos.get(pid)
        if qty <= _EPS:
            if pos is not None:
                self._flat(pos, t)
            self._settle(pid, t)
            return
        price = ledger.entry_price(self.orders, t["id"]) or (pos.entry_price if pos else 0.0)
        if pos is None:
            pos = Position(pid, qty, price, t["initial_stop"], t["target"], t["atr"], t["opened_ts"], [],
                           bool(t.get("half_taken")), price)
            self.pos[pid] = pos
        elif pos.base_size == qty and pos.entry_price == price:
            return
        else:
            pos.base_size, pos.entry_price = qty, price
        self.store.save_position(pos)

    def _flat(self, pos: Position, t: dict) -> None:
        """Order status says everything bought has been sold: the position is gone now, whether or
        not the fills that price it have arrived."""
        pid = pos.product_id
        self.store.delete_position(pid)
        del self.pos[pid]
        self._exited.append(pid)
        last = self.orders.get(t.get("last_exit") or "")
        reason = self._exit_reason(last) if last else "unknown"
        self._end_forced_exit(pid, f"position closed ({reason})")
        self._clear_episodes(pid)
        self._log("position_flat", pid, trade_id=t["id"], exit_reason=reason)

    def _settle(self, pid: str, t: dict) -> None:
        """A flat trade whose orders are all finished waits only for its prices."""
        if any(not r["final"] for r in ledger.of_trade(self.orders, t["id"]).values()):
            return  # an order still rests (it is being cancelled) and could fill
        self.closing[t["id"]] = t
        del self.trades[pid]
        self._save_trades()

    # ---------------------------------------------------------------- fills -> prices and fees

    def _sync_fills(self) -> None:
        """Prices and fees for what order status says has filled. Never changes a quantity."""
        need = {oid: r for oid, r in self.orders.items() if ledger.needs_fills(r)}
        err = None
        if need:
            try:
                fills = self.ex.fills(min(r["created_ts"] for r in need.values()))
            except ExchangeError as e:
                err, fills = e, []
            changed = set()
            for oid, rec in need.items():
                if ledger.apply_fills(rec, [f for f in fills if f.order_id == oid]):
                    changed.add(rec["product_id"])
                    self._log("fill_prices", rec["product_id"], order_id=oid, kind=rec["kind"],
                              size=rec["acc_size"], filled=rec["filled"], fee=rec["acc_fee"],
                              price=rec["acc_value"] / rec["acc_size"])
                    t = self._trade_of(rec)
                    if ledger.is_exit(rec) and t is not None:
                        self._record_exit(oid, rec, t, last=False)
            if changed:
                self._save_orders()
                for pid in changed:
                    self._derive(pid)  # the entry price
        self._give_up()
        self._finalise()
        if err is not None:
            raise err

    def _give_up(self) -> None:
        """Bounded wait: a finished order whose fills have not arrived after fill_wait_cycles cycles
        is priced by estimate."""
        changed = False
        for oid, rec in self.orders.items():
            if rec["final"] and ledger.needs_fills(rec) \
                    and self.cycle_no - rec.get("final_cycle", self.cycle_no) >= self.cfg.fill_wait_cycles:
                rec["given_up"] = changed = True
                self._log("fills_missing", rec["product_id"], order_id=oid, kind=rec["kind"],
                          filled=rec["filled"], fills_size=rec["acc_size"], price=ledger.price_of(rec)[0])
        if changed:
            self._save_orders()

    def _finalise(self) -> None:
        """One trade_closed row and one on_trade_closed call per flat trade, once every order of the
        trade has its prices (or has been given up on)."""
        for tid, t in list(self.closing.items()):
            recs = ledger.of_trade(self.orders, tid)
            if any(not r["final"] or ledger.needs_fills(r) for r in recs.values()):
                continue
            pid = t["product_id"]
            maker = taker = 0.0
            fees_unknown = False
            if any(r["acc_size"] <= _EPS for r in recs.values()):  # no fill at all: estimate the fee
                try:
                    f = self.ex.fees()
                    maker, taker = f.maker, f.taker
                except ExchangeError:
                    fees_unknown = True
            r = ledger.trade_result(recs, t, maker, taker)
            last = recs.get(t.get("last_exit") or "")
            reason = self._exit_reason(last) if last else "unknown"
            pnl, entry = r.pop("pnl_usd"), r.pop("entry_price") or 0.0
            risk = r["bought"] * (entry - t["initial_stop"])
            if not any(row["data"].get("trade_id") == tid for row in self.store.journal_rows("trade_closed")):
                self._log("trade_closed", pid, trade_id=tid, pnl_usd=pnl,
                          r_multiple=pnl / risk if risk > 0 else None, exit_reason=reason, entry_price=entry,
                          opened_ts=t["opened_ts"], entry_order=t["entry_order"], setup_ts=t["setup_ts"],
                          initial_stop=t["initial_stop"], written_off=t.get("written_off", 0.0),
                          exits=t["exits"], fees_unknown=fees_unknown, **r)
                if self.state is not None:
                    on_trade_closed(self.state, pnl, self.cfg)
                    self.store.save_risk_state(self.state)
            for oid in recs:
                del self.orders[oid]
            self._save_orders()
            del self.closing[tid]
            self._save_trades()
            if r["estimated"]:
                self._alert("trade closed on estimated prices",
                            f"{pid}: the fills of trade {tid} did not arrive within "
                            f"{self.cfg.fill_wait_cycles} cycles; P&L {pnl:.2f} uses the orders' average "
                            f"or limit prices")

    # ---------------------------------------------------------------- 2. reconcile

    def _stable_balances(self) -> dict[str, float] | None:
        """Balances read between two order-status reads that agree, so a fill landing in between
        cannot be mistaken for coins sold by hand. None if the orders kept filling."""
        for _ in range(2):
            self._sync_orders()
            seen = self._qty_events
            bal = self.ex.balances()
            self._sync_status()
            if seen == self._qty_events:
                return bal
        return None

    def _reconcile(self, res: CycleResult) -> None:
        bal = self._stable_balances()
        if bal is None:
            self._log("reconcile_skipped", None, reason="orders were filling")
            return
        for pid in list(self.pos):
            if pid in self.pos:
                self._guard(res, pid, "reconcile", lambda: self._reconcile_one(self.pos[pid], bal))

    def _reconcile_one(self, pos: Position, bal: dict[str, float]) -> None:
        """The position is what the bot's orders bought and sold. A balance below it means the owner
        sold coins by hand: the position shrinks. A balance above it is never adopted."""
        pid = pos.product_id
        p = self._product(pid)
        if _held(bal, p) >= round_down(pos.base_size, p.base_increment) - _EPS:
            return
        self._cancel_legs(pos)
        if self.pos.get(pid) is not pos:
            return  # a leg had filled; order status closed the position
        bal = self._stable_balances()
        if bal is None:
            raise ExchangeError(f"{pid}: orders kept filling; reconcile is retried next cycle")
        held = _held(bal, p)
        if held >= round_down(pos.base_size, p.base_increment) - _EPS:
            self._protect(pos)
            return
        self._log("reconcile", pid, position_size=pos.base_size, balance=held)
        t = self.trades.get(pid)
        if held >= p.min_base_size:
            if t is not None:
                t["written_off"] = _add(t.get("written_off", 0.0), _sub(pos.base_size, held))
                self._save_trades()
            pos.base_size = held
            self.store.save_position(pos)
            self._alert("position reconciled", f"{pid}: balance fell to {held}; position shrunk")
            self._protect(pos)
        else:  # sold by hand: the proceeds are unknown, so no trade_closed is written
            self.store.delete_position(pid)
            del self.pos[pid]
            if t is not None:
                del self.trades[pid]
                for oid, r in ledger.of_trade(self.orders, t["id"]).items():
                    if r["final"]:
                        del self.orders[oid]
                    else:
                        r["trade"] = None
                self._save_orders()
                self._save_trades()
            self._clear_episodes(pid)
            self._alert("position reconciled", f"{pid}: coins sold outside the bot; position removed")

    # ---------------------------------------------------------------- 3. protect

    def _protect_all(self, res: CycleResult) -> None:
        status_alerts = self._meta("status_alerts", {})
        def one(pid: str) -> None:
            p = self._product(pid)
            if p.status != "online" and status_alerts.get(pid) != p.status:
                what = ("the venue may reject new orders: resting stops stay and re-placing them is still "
                        "tried, but a forced exit is not sent" if p.status in FORCED_EXIT_BLOCKED
                        else "no new entries; stops and forced exits are still placed")
                self._alert(f"{pid} is {p.status}", f"{pid} holds a position; {what}")
            status_alerts[pid] = p.status
            self._protect_position(self.pos[pid])

        for pid in list(self.pos):
            if pid in self.pos:
                self._guard(res, pid, "protect", lambda: one(pid), alert="protection failed")
        self._set_meta("status_alerts", {k: v for k, v in status_alerts.items() if k in self.pos})

    def _protect_position(self, pos: Position) -> None:
        pid = pos.product_id
        self._sync_orders()
        self._protect_grown(None)
        if self.pos.get(pid) is not pos:
            return
        if self._ioc_in_flight(pid) and not self._uncovered(pos):
            return  # a forced or target exit is in flight and, with the legs, covers the position
        bid = self._bid(pid)
        if bid < pos.stop_price:
            self._forced_exit(pos, bid)
            return
        self._bid_recovered(pid)
        if self._is_dust(pos):
            self._dust(pos, "cannot be protected")
            return
        if self._uncovered(pos):
            p = self._product(pid)
            covered = ledger.open_sells(self.orders, pid)
            self._alert("missing stop", f"{pid}: open sells cover {covered} of "
                                        f"{round_down(pos.base_size, p.base_increment)}; re-placing")
            self._restore(pos)

    def _bid_recovered(self, pid: str) -> None:
        """The bid is back at or above the stop: a forced-exit episode ends here, so its attempt
        count never carries into the next gap."""
        self._end_forced_exit(pid, "the bid is back above the stop")
        self._end_episode(f"blocked|{pid}")

    def _forced_exit(self, pos: Position, bid: float) -> None:
        """Bid below the stop: cancel the stops and sell with an IOC. Everything that can refuse the
        IOC is checked before a stop is cancelled; every attempt, placed or not, is journaled as
        forced_exit and starts or extends the backoff."""
        pid = pos.product_id
        if self._is_dust(pos):
            self._dust(pos, "too small to sell")
            return
        p = self._product(pid)
        if p.status in FORCED_EXIT_BLOCKED:  # the IOC would be rejected: keep whatever rests
            if self._episode(f"blocked|{pid}", p.status):
                resting = ledger.open_sells(self.orders, pid)
                self._log("forced_exit_blocked", pid, status=p.status, bid=bid, stop=pos.stop_price,
                          resting=resting)
                self._alert("forced exit blocked",
                            f"{pid} is {p.status}: bid {bid} is below the stop {pos.stop_price} and no exit "
                            f"can be sent; resting sell orders cover {resting} of {pos.base_size}")
            return
        ep = self.episodes.get(f"forced|{pid}")
        if ep and self.now() < ep["next_ts"]:
            return  # backing off after an attempt that sold nothing
        try:
            self._check_no_pending(pid)  # before cancelling anything
            free = ledger.sell_room(self.orders, self.pending, pid, pos.base_size, cancelling=LEG_KINDS)
            if round_down(free, p.base_increment) < p.min_base_size:
                return  # an IOC in flight already carries all but a sliver: nothing to cancel or place
            self._cancel_legs(pos)
            if self.pos.get(pid) is not pos:
                return  # a stop filled before its cancel landed and closed the position
            if self._is_dust(pos):
                self._dust(pos, "too small to sell")
                return
            # sized from order status; the balance can only make the sell smaller
            size = round_down(min(self._room(pos), _held(self.ex.balances(), p)), p.base_increment)
            if size < p.min_base_size:
                raise ExchangeError(f"{pid}: only {size} can be sold after cancelling the stops")
            limit = round_down(bid * FORCED_EXIT_PRICE, p.quote_increment)
            oid, _ = self._place_order("ioc", pid, size, lambda cid: self.ex.place_ioc_sell(pid, size, limit, cid),
                                       ref_price=limit)
        except ExchangeError as e:
            self._forced_attempt(pos, ep, bid, f"the exit could not be placed ({e}); retrying", error=str(e))
            raise
        self._forced_attempt(pos, ep, bid, f"IOC sell {size} at {limit}", order_id=oid, size=size, limit=limit)

    def _forced_attempt(self, pos: Position, ep: dict | None, bid: float, what: str, **row) -> None:
        pid = pos.product_id
        attempts = (ep or {}).get("attempts", 0) + 1
        wait = min(self.cfg.fill_poll_seconds * 2 ** min(attempts - 1, 30), self.cfg.cycle_minutes * 60)
        self.episodes[f"forced|{pid}"] = {"attempts": attempts, "next_ts": self.now() + wait}
        self._set_meta("episodes", self.episodes)
        self._log("forced_exit", pid, bid=bid, stop=pos.stop_price, attempt=attempts, **row)
        if ep is None:
            self._alert("forced exit", f"{pid}: bid {bid} below stop {pos.stop_price}; {what}")
        if self.pos.get(pid) is not pos:  # the IOC filled as it was placed: the episode is over
            self._end_forced_exit(pid, "position closed (ioc)")

    def _end_forced_exit(self, pid: str, how: str) -> None:
        if f"forced|{pid}" in self.episodes:
            self._end_episode(f"forced|{pid}")
            self._alert("forced exit ended", f"{pid}: {how}")

    def _protect_grown(self, res: CycleResult | None) -> None:
        for pid in sorted(self._grown):
            self._grown.discard(pid)
            if pid in self.pos:
                self._guard(res, pid, "protect fill", lambda: self._protect(self.pos[pid]), alert="unprotected")

    def _uncovered(self, pos: Position, open_ids: set[str] | None = None) -> bool:
        """A leg is missing, or the live legs plus any exit IOC in flight do not sum to the position.
        A dust position (below the minimum order size) cannot be covered and does not count.
        Orders are judged by the registry's order status (and by `open_ids` too, when given)."""
        pid = pos.product_id
        if self._is_dust(pos):
            return False
        need = round_down(pos.base_size, self._product(pid).base_increment)
        live = [lg for lg in pos.legs if self._live(lg.order_id) and (open_ids is None or lg.order_id in open_ids)]
        covered = sum(lg.base_size for lg in live) + sum(
            ledger.remaining(r) for oid, r in self.orders.items()
            if r["kind"] == "ioc" and r["product_id"] == pid and (open_ids is None or oid in open_ids))
        return len(live) != len(pos.legs) or abs(covered - need) > _EPS

    def _repair_coverage(self) -> None:
        """Repair of any uncovered position (every fill poll, and once more at the end of a cycle).
        Alerts once per uncovered episode."""
        self._guard(None, None, "watch repair", self._repair_coverage_inner)

    def _repair_coverage_inner(self) -> None:
        alerted = self._meta("uncovered_alerted", {})
        for attempt in range(2):  # a second pass at once: one lost reply or rejected call is retried now
            if not self._guard(None, None, "watch sync", self._sync_orders):
                break
            self._protect_grown(None)
            failed = False
            for pid in list(self.pos):
                pos = self.pos.get(pid)
                try:
                    bad = pos is not None and self._uncovered(pos)
                except Exception:
                    bad = True
                if not bad:
                    alerted.pop(pid, None)
                    continue
                if pid not in alerted:
                    self._alert("missing stop", f"{pid}: legs do not cover the position; re-placing")
                    alerted[pid] = "missing stop"
                if not self._guard(None, pid, "watch protect", lambda: self._repair(self.pos[pid])):
                    failed = True
                    if attempt and alerted.get(pid) != "unprotected":
                        self._alert("unprotected", f"{pid}: could not re-place stops; retrying every poll")
                        alerted[pid] = "unprotected"
            if not failed:
                break
        self._set_meta("uncovered_alerted", {k: v for k, v in alerted.items() if k in self.pos})

    def _repair(self, pos: Position) -> None:
        pid = pos.product_id
        if not self._uncovered(pos):
            return
        bid = self._bid(pid)
        if bid < pos.stop_price:
            self._forced_exit(pos, bid)
            return
        self._bid_recovered(pid)
        if all(self._live(leg.order_id) for leg in pos.legs):
            self._cover_gap(pos)  # live legs stay; only the uncovered part gets a stop (if it can)
        else:
            self._protect(pos)

    def _restore(self, pos: Position) -> None:
        """Cycle-time repair: full re-protection (which restores the two-leg shape), except while an
        exit IOC is in flight, when only the part nothing covers gets a stop."""
        if self._ioc_in_flight(pos.product_id) and all(self._live(leg.order_id) for leg in pos.legs):
            self._cover_gap(pos)
        else:
            self._protect(pos)

    def _protect(self, pos: Position) -> None:
        """Cancel the position's stops and place fresh ones covering what is not already committed
        to an exit in flight."""
        pid = pos.product_id
        if pos.legs or ledger.open_sells(self.orders, pid, LEG_KINDS) > _EPS:
            self._cancel_legs(pos)
            if self.pos.get(pid) is not pos:
                return
            if ledger.open_sells(self.orders, pid, LEG_KINDS) > _EPS:
                raise ExchangeError(f"{pid}: the old stops are still cancelling")
        p = self._product(pid)
        if self._is_dust(pos):
            self._dust(pos, "cannot be protected")
            return
        size = round_down(self._room(pos), p.base_increment)
        if size < p.min_base_size:
            return  # the rest is committed to an exit in flight
        self._end_episode(f"dust|{pid}")
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

        extra = {"target": target} if kind == "bracket" else {}
        oid, _ = self._place_order(kind, pid, size, place, ref_price=limit, trigger=trigger, **extra)
        if self.pos.get(pid) is not pos:
            return
        rec = self.orders.get(oid)  # its status was read when it was registered
        if self._live(oid) and not any(leg.order_id == oid for leg in pos.legs):
            pos.legs.append(Leg(oid, ledger.remaining(rec), kind, trigger))
            self.store.save_position(pos)
        if not self._live(oid) or abs(rec["size"] - size) > _EPS:
            if self._live(oid):  # wrong size but live: it must not keep holding coins
                self.ex.cancel(oid)
                self._apply_status(oid, rec, self.ex.get_order(oid))
                if self._live(oid):
                    raise ExchangeError(f"{kind} leg {oid} has the wrong size and did not cancel")
            raise ExchangeError(f"{kind} leg {oid} is not live")
        self._end_forced_exit(pid, "stops restored")  # a live protective leg ends a forced-exit episode
        self._end_episode(f"blocked|{pid}")

    def _register(self, oid: str, kind: str, pid: str, cid: str, size: float, **extra) -> None:
        """Track an order, then read its status at once (an IOC may already be done)."""
        if oid in self.orders:  # already tracked: never reset what it has filled
            return
        rec = ledger.new_record(kind, pid, cid, size, self.now(), self.now() - FILL_LOOKBACK_S, **extra)
        if kind != "entry":
            rec["trade"] = (self.trades.get(pid) or {}).get("id")
        self.orders[oid] = rec
        self._save_orders()
        o = self.ex.get_order(oid)  # verify, and learn the exchange's own timestamp for fills
        rec["created_ts"] = o.created_ts
        self._save_orders()
        self._apply_status(oid, rec, o)

    def _cancel_legs(self, pos: Position) -> None:
        """Cancel every resting stop of the product (legs, and any the position lost track of), then
        take order status: a leg may have filled before its cancel landed."""
        pid = pos.product_id
        ids = {leg.order_id for leg in pos.legs}
        ids |= {oid for oid, r in self.orders.items()
                if r["product_id"] == pid and r["kind"] in LEG_KINDS and not r["final"]}
        for oid in sorted(ids):
            self.ex.cancel(oid)
        self._sync_orders()
        if self.pos.get(pid) is pos and any(not self._live(leg.order_id) for leg in pos.legs):
            pos.legs = [leg for leg in pos.legs if self._live(leg.order_id)]
            self.store.save_position(pos)

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
        bid = self._bid(pid)
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
        bid = self._bid(pid)
        if split is None or bid < pos.target_price:
            return
        leg = next((lg for lg in pos.legs if lg.kind == "stop" and abs(lg.base_size - split[0]) <= _EPS), None)
        if leg is None:
            return  # legs are not in their two-stop shape; protect restores it next cycle
        self.ex.cancel(leg.order_id)
        self._sync_orders()  # leg a may have filled before the cancel landed
        if self.pos.get(pid) is not pos:
            return
        if self._live(leg.order_id):
            return  # the cancel has not landed: its coins are not free yet; tried again next cycle
        size = min(split[0], round_down(self._room(pos), p.base_increment))
        self._target_missed.add(pid)  # unless the IOC is placed, leg a's coins need their stop back
        if size >= p.min_base_size:
            limit = round_down(bid * TARGET_EXIT_PRICE, p.quote_increment)
            try:
                oid, _ = self._place_order("ioc", pid, size,
                                           lambda cid: self.ex.place_ioc_sell(pid, size, limit, cid),
                                           purpose="target", ref_price=limit)
                self._log("target_exit", pid, order_id=oid, size=size, limit=limit, bid=bid,
                          target=pos.target_price)
            except ExchangeError as e:
                self._log("error", pid, where="target_exit", error=str(e))
            self._sync_orders()  # an IOC that is already done is applied now
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
        self._refresh(pid)
        if self.pos.get(pid) is not pos:
            return
        gap = round_down(self._room(pos), p.base_increment)
        if gap >= p.min_base_size:
            self._place_leg(pos, "stop", gap, pos.stop_price)
        elif gap > _EPS:
            self._protect(pos)  # the gap alone is below the minimum: re-place merged legs

    def _ioc_in_flight(self, pid: str) -> bool:
        """An exit IOC of the product is still working, by order status. One that has finished,
        filled or not, is never in flight, whatever fills() has reported."""
        return any(r["kind"] == "ioc" and r["product_id"] == pid and not r["final"]
                   for r in self.orders.values())

    def _replace_stop(self, pos: Position, new_stop: float, why: str) -> None:
        """Verified cancel-and-replace of the stop legs at a higher stop. Stops never move down."""
        pid = pos.product_id
        if new_stop <= pos.stop_price:
            return
        old = pos.stop_price
        p = self._product(pid)
        trigger = round_down(new_stop, p.quote_increment)

        def stale() -> list[str]:  # resting stops that are not at the new trigger
            return [oid for oid, r in self.orders.items()
                    if r["product_id"] == pid and r["kind"] == "stop" and not r["final"]
                    and abs((r.get("trigger") or 0.0) - trigger) > _EPS]

        freed = sum(ledger.remaining(self.orders[oid]) for oid in stale())
        if freed > _EPS and round_down(self._room(pos) + freed, p.base_increment) < p.min_base_size:
            return  # what the old stop covers is too small to place again (an IOC holds the rest): keep it
        for oid in stale():
            self.ex.cancel(oid)
        pos.stop_price = new_stop  # a failed placement below is re-placed at this stop by protect
        self.store.save_position(pos)
        for attempt in range(2):
            try:
                self._sync_orders()  # a cancelled leg may have filled first; dead legs drop out
                if self.pos.get(pid) is not pos:
                    return
                if stale():  # a cancel has not landed: the old stop must be gone before this is logged
                    for oid in stale():
                        self.ex.cancel(oid)
                    raise ExchangeError(f"{pid}: the old stop is still open")
                if not any(lg.kind == "stop" for lg in pos.legs):
                    size = round_down(self._room(pos), p.base_increment)
                    if size < p.min_base_size:
                        if self._is_dust(pos):
                            self._dust(pos, "stop remainder")
                        return  # otherwise an exit in flight holds the rest
                    self._place_leg(pos, "stop", size, new_stop)  # raises unless confirmed live
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
        if self.closing:  # its result (loss streak) is not known yet; bounded by fill_wait_cycles
            self._log("scan_skipped", None, reason="a closed trade awaits its fill prices")
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
        self._sync_orders()
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
            bid = self._bid(pid)
            exit_cost = p.stop_price * (fees.taker + self.cfg.slippage)
            risk += p.base_size * (max(0.0, p.entry_price - p.stop_price) + exit_cost)
            exposure += p.base_size * bid
        for rec in self._entries().values():
            c, rem = rec["candidate"], ledger.remaining(rec)
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
        self._register(oid, "entry", pid, key, base, candidate=asdict(cand), limit=limit, ref_price=limit)
        self._remember(key, "placed", cand)
        self._log("entry_placed", pid, order_id=oid, client_order_id=key, base_size=base, limit=limit,
                  decision=d.decision, review_multiplier=d.multiplier, final_multiplier=final_mult,
                  risk_usd=final.risk_usd)
        res.entered.append(pid)
        return None

    def _remember(self, key: str, status: str, cand: Candidate) -> None:
        self.setups[key] = {"status": status, "ts": self.now(), "candidate": asdict(cand)}
        self._save_setups()
