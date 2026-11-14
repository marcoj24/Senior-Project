import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from bot.alerts import Alerts
from bot.config import Config
from bot.exchange.base import ExchangeError
from bot.engine import Engine
from bot.exchange.paper import PaperExchange
from bot.models import Candle, Fees, Product
from bot.reviewer import Reviewer
from bot.risk import RiskState, round_down
from bot.store import Store

PROMPT = str(Path(__file__).resolve().parent.parent / "prompts" / "trader_system.md")
H4 = 14_400
D1 = 86_400
T0 = 20_000 * D1  # a UTC day boundary; the setup is complete at this moment
DAY0 = datetime.fromtimestamp(T0, timezone.utc).strftime("%Y-%m-%d")
S = 4.5  # half range of each 4h candle: ATR(14) ~ 9.5 on a ~120 price, so 2 x ATR clamps to a 15% stop
FEES = Fees(0.005, 0.009)  # the owner's spot fees; the 15% stop passes the cost gate with them


def product(pid: str, status: str = "online") -> Product:
    return Product(pid, pid.split("-")[0], "USD", 0.001, 0.01, 0.01, status, 1e9)


def series(closes, interval, last_ts, volumes=None, spread=S):
    """Contiguous candles, each opening at the previous close, the last starting at `last_ts`."""
    first = last_ts - (len(closes) - 1) * interval
    out = []
    for i, c in enumerate(closes):
        o = closes[i - 1] if i else c
        v = volumes[i] if volumes else 1000.0
        out.append(Candle(first + i * interval, o, max(o, c) + spread, min(o, c) - spread, c, v))
    return out


def setup_4h():
    """Rising 4h trend; three candles before T0 a close jumps through the 20-candle high on 3x volume.
    find_candidate gives entry 119.70 (the breakout level), stop 101.745 (15%), target 155.61."""
    n, b = 80, 77
    closes = [100 + 0.2 * i + (6.0 if i >= b else 0.0) for i in range(n)]
    volumes = [1000.0] * n
    volumes[b] = 3000.0
    return series(closes, H4, T0 - H4, volumes)


def daily(start, step, n=260):
    return series([start + step * i for i in range(n)], D1, T0 - D1, spread=0.5)


ENTRY, STOP, TARGET = 119.70, 101.745, 155.61


class Clock:
    def __init__(self, t: int):
        self.t = t

    def __call__(self) -> int:
        return self.t


class FakeLLM:
    """Answers entry and regime reviews from settable replies (the real Reviewer parses them)."""

    def __init__(self, entry=("approve", 1.0), regime_mult=1.0):
        self.entry, self.regime_mult = entry, regime_mult
        self.calls: list[str] = []

    def __call__(self, model, system, user_json):
        kind = json.loads(user_json)["review"]
        self.calls.append(kind)
        if kind == "entry":
            d, m = self.entry
            return json.dumps({"decision": d, "multiplier": m, "invalidation": "x", "reason": "test"}), 0.0
        return json.dumps({"label": "risk_on", "risk_multiplier": self.regime_mult, "notes": "test"}), 0.0


class World:
    """SOL-USD and BTC-USD on a paper venue, an engine wired to it, and a clock at T0."""

    def __init__(self, entry=("approve", 1.0), regime_mult=1.0, btc_step=1.0, cfg=None, brackets=True,
                 also=()):
        self.cfg = cfg or Config()
        self.alts = ["SOL-USD", *also]  # alts all share SOL's history
        self.ex = PaperExchange(1000.0, FEES, [product(p) for p in self.alts] + [product("BTC-USD")], brackets)
        for pid in self.alts:
            for c in daily(50.0, 0.3):
                self.ex.feed(pid, D1, c, fills=False)
        for c in daily(1000.0, btc_step):
            self.ex.feed("BTC-USD", D1, c, fills=False)
        self.c4h = setup_4h()
        for pid in self.alts:
            for c in self.c4h:
                self.ex.feed(pid, H4, c)
        self.clock = Clock(T0)
        self.llm = FakeLLM(entry, regime_mult)
        self.alerts = Alerts()
        self.store = Store(":memory:")
        self.engine = self.make_engine(self.store)

    def make_engine(self, store: Store) -> Engine:
        reviewer = Reviewer(self.cfg, store, self.llm, PROMPT)
        return Engine(self.cfg, self.ex, store, reviewer, self.alerts, self.clock)

    def bar(self, close, low=None, high=None, open_=None):
        """Feed the next 4h candle to every alt (fills on) and move the clock to its close."""
        o = self.c4h[-1].close if open_ is None else open_
        ts = self.c4h[-1].ts + H4
        c = Candle(ts, o, high if high is not None else max(o, close) + S,
                   low if low is not None else min(o, close) - S, close, 1000.0)
        self.c4h.append(c)
        for pid in self.alts:
            self.ex.feed(pid, H4, c)
        self.clock.t = ts + H4

    def cycle(self):
        r = self.engine.run_cycle()
        self.check_covered()
        return r

    def watch(self):
        self.engine.watch_fills()
        self.check_covered()

    def check_covered(self):
        """Whenever the bot holds coins, open sell orders cover exactly the bot's position."""
        for pid in self.alts:
            held = sum(p.base_size for p in self.store.positions() if p.product_id == pid)
            coins = self.ex.balances().get(pid.split("-")[0], 0.0)
            assert held == pytest.approx(coins, abs=1e-9)
            assert self.sells(pid) == pytest.approx(coins, abs=1e-9)

    def sells(self, pid="SOL-USD"):
        return sum(o.base_size - o.filled_size for o in self.ex.open_orders()
                   if o.product_id == pid and o.kind != "entry")

    def entries(self):
        return [o for o in self.ex.open_orders() if o.kind == "entry"]

    def position(self, pid="SOL-USD"):
        return next((p for p in self.store.positions() if p.product_id == pid), None)

    def titles(self):
        return [t for t, _ in self.alerts.sent]

    def enter(self):
        """Cycle (entry placed), pull back through the entry, watch_fills (protected)."""
        r = self.cycle()
        assert r.entered == ["SOL-USD"], r
        self.bar(121.0)  # low 116.5 < 119.70: the entry fills
        self.watch()
        return self.position()

    def set_status(self, pid, status):
        self.ex._products[pid] = replace(self.ex._products[pid], status=status)

    def edit_state(self, **changes):
        st = self.store.load_risk_state()
        for k, v in changes.items():
            setattr(st, k, v)
        self.store.save_risk_state(st)


def test_full_trade_lifecycle():
    w = World()
    r = w.cycle()
    assert r.entered == ["SOL-USD"] and r.errors == [] and r.halted is None
    [order] = w.entries()
    assert order.limit_price == pytest.approx(ENTRY)
    assert order.client_order_id == f"SOL-USD-{w.c4h[-3].ts}"
    size = order.base_size

    w.bar(121.0)  # pullback through the entry
    w.watch()
    pos = w.position()
    assert pos.base_size == pytest.approx(size) and pos.entry_price == pytest.approx(ENTRY)
    assert pos.highest_close == pytest.approx(ENTRY)
    kinds = sorted(o.kind for o in w.ex.open_orders())
    assert kinds == ["bracket", "stop"]
    [br] = [o for o in w.ex.open_orders() if o.kind == "bracket"]
    assert br.target == pytest.approx(TARGET, abs=0.01) and br.stop_trigger == pytest.approx(STOP, abs=0.01)
    assert br.limit_price == pytest.approx(STOP * 0.95, abs=0.02)

    w.cycle()
    for close in (130.0, 140.0, 150.0, 158.0):  # the last candle's high crosses the 2R target
        w.bar(close)
        w.cycle()
    pos = w.position()
    assert pos.half_taken
    assert pos.base_size == pytest.approx(size - round_down(size / 2, 0.001))  # the bracket half sold
    assert pos.stop_price >= ENTRY  # break-even, then trailed
    moves = [r["data"] for r in w.store.journal_rows("stop_moved")]
    assert moves[0]["why"] == "break-even" and moves[0]["new_stop"] == pytest.approx(ENTRY)
    for close in (168.0, 178.0, 188.0):
        w.bar(close)
        w.cycle()
    pos = w.position()
    assert pos.highest_close == pytest.approx(188.0)
    assert pos.stop_price > ENTRY + 20  # trailed well above break-even
    [stop] = [o for o in w.ex.open_orders() if o.kind == "stop"]
    assert stop.stop_trigger == pytest.approx(pos.stop_price, abs=0.01)
    assert stop.base_size == pytest.approx(pos.base_size)

    w.bar(150.0)  # falls through the trailed stop
    r = w.cycle()
    assert r.exited == ["SOL-USD"] and w.position() is None
    [closed] = w.store.journal_rows("trade_closed")
    assert closed["data"]["pnl_usd"] > 0
    assert w.ex.balances()["SOL"] == pytest.approx(0.0)
    assert w.store.load_risk_state().consecutive_losses == 0
    assert w.ex.open_orders() == []


def test_entry_fill_is_protected_before_next_cycle():
    w = World()
    w.cycle()
    w.bar(121.0)
    assert w.ex.balances()["SOL"] > 0 and w.sells() == 0  # filled, not yet seen
    w.engine.watch_fills()
    pos = w.position()
    assert pos is not None and w.sells() == pytest.approx(pos.base_size)
    assert sorted(leg.kind for leg in pos.legs) == ["bracket", "stop"]


def test_veto_places_nothing_and_records_shadow():
    w = World(entry=("veto", 0.0))
    r = w.cycle()
    assert r.entered == [] and w.entries() == []
    assert r.skipped["SOL-USD"].startswith("vetoed")
    [shadow] = w.store.open_shadows()
    assert shadow["decision"] == "veto" and shadow["product_id"] == "SOL-USD"
    w.cycle()  # the same setup is not sent for review again
    assert w.llm.calls.count("entry") == 1 and len(w.store.open_shadows()) == 1


def _entry_size(entry):
    w = World(entry=entry)
    w.cycle()
    [o] = w.entries()
    return o.base_size, w


def test_reduce_shrinks_order():
    full, _ = _entry_size(("approve", 1.0))
    half, w = _entry_size(("reduce", 0.5))
    assert half < full and abs(half - full / 2) <= 0.001
    [shadow] = w.store.open_shadows()
    assert shadow["decision"] == "reduce" and shadow["multiplier"] == 0.5


def test_reviewer_cannot_enlarge():
    full, _ = _entry_size(("approve", 1.0))
    assert _entry_size(("approve", 5.0))[0] == full
    assert _entry_size(("reduce", 5.0))[0] == full


def test_kill_switch_cancels_entries_keeps_stops():
    w = World()
    w.cycle()
    [order] = w.entries()
    w.ex.partial_fill(order.order_id, 0.6, ENTRY, T0)
    w.watch()
    legs = [o.order_id for o in w.ex.open_orders() if o.kind != "entry"]
    assert legs
    w.edit_state(peak_equity=2000.0)  # equity ~1000 is 50% below the peak
    r = w.cycle()
    assert r.halted == "kill switch triggered"
    assert w.ex.get_order(order.order_id).status == "cancelled"
    assert all(w.ex.get_order(i).status == "open" for i in legs)
    assert any("kill switch" in t for t in w.titles())
    r = w.cycle()
    assert r.halted == "kill switch latched" and r.entered == [] and w.entries() == []


def test_daily_halt_blocks_entries_only():
    w = World()
    w.store.save_risk_state(RiskState(1100.0, DAY0, 1100.0, False, 0, 0))  # ~1000 is 9% down today
    r = w.cycle()
    assert r.halted == "daily loss halt" and r.entered == [] and w.entries() == []

    w = World()
    w.enter()
    w.edit_state(day_start_equity=1100.0)
    stop_leg = next(leg for leg in w.position().legs if leg.kind == "stop")
    w.ex.cancel(stop_leg.order_id)
    r = w.cycle()  # protection still runs during the halt
    assert r.halted == "daily loss halt"
    assert w.sells() == pytest.approx(w.position().base_size)
    assert "missing stop" in w.titles()


def test_gap_through_stop_forces_exit_and_alerts():
    w = World()
    pos = w.enter()
    w.cycle()
    w.bar(90.0, low=88.0, high=92.0, open_=90.0)  # opens below the stop's limit: stop left unfilled
    assert w.ex.balances()["SOL"] == pytest.approx(pos.base_size)
    w.cycle()
    assert "forced exit" in w.titles()
    [ioc] = [o for o in w.ex.open_orders() if o.kind == "ioc"]
    assert ioc.base_size == pytest.approx(pos.base_size)
    assert ioc.limit_price == pytest.approx(90.0 * (1 - 0.0005) * 0.98, abs=0.01)
    assert not [o for o in w.ex.open_orders() if o.kind in ("stop", "bracket")]
    w.bar(89.0, low=87.0, high=91.0, open_=90.0)
    r = w.cycle()
    assert r.exited == ["SOL-USD"] and w.position() is None
    [closed] = w.store.journal_rows("trade_closed")
    assert closed["data"]["pnl_usd"] < 0
    assert w.store.load_risk_state().consecutive_losses == 1


def test_missing_stop_is_replaced_and_alerted():
    w = World()
    pos = w.enter()
    bracket = next(leg for leg in pos.legs if leg.kind == "bracket")
    w.ex.cancel(bracket.order_id)  # behind the bot's back
    assert w.sells() < pos.base_size
    w.cycle()
    assert "missing stop" in w.titles()
    pos = w.position()
    assert w.sells() == pytest.approx(pos.base_size)
    assert sorted(leg.kind for leg in pos.legs) == ["bracket", "stop"]


def test_owner_sold_by_hand_is_reconciled():
    w = World()
    pos = w.enter()
    old_legs = [leg.order_id for leg in pos.legs]
    half = round(pos.base_size / 2, 3)
    w.ex._coins["SOL"] = half  # the owner sold half on the website
    w.cycle()
    assert w.position().base_size == pytest.approx(half)
    assert all(w.ex.get_order(i).status == "cancelled" for i in old_legs)
    assert w.sells() == pytest.approx(half)  # the rest is re-protected

    w.ex._coins["SOL"] = 0.0  # and then the rest
    w.cycle()
    assert w.position() is None
    assert [o for o in w.ex.open_orders() if o.product_id == "SOL-USD"] == []
    assert not any(o.kind == "ioc" for o in w.ex._orders.values())  # nothing was sold by the bot
    assert any("reconcil" in t for t in w.titles())


def test_exchange_error_mid_cycle_is_safe():
    w = World()
    w.ex.fail_next = "place_entry"
    r = w.cycle()
    assert r.errors and r.entered == [] and w.entries() == [] and w.position() is None
    [intent] = w.store.journal_rows("entry_intent")  # journaled before the call
    assert intent["data"]["client_order_id"] == f"SOL-USD-{w.c4h[-3].ts}"
    assert intent["data"]["stop"] == pytest.approx(STOP) and intent["data"]["limit"] == pytest.approx(ENTRY)
    r = w.cycle()  # no such order on the exchange: the intent is dropped and the setup placed normally
    assert [row["data"]["client_order_id"] for row in w.store.journal_rows("entry_intent_dropped")] == [
        intent["data"]["client_order_id"]]
    assert r.entered == ["SOL-USD"] and len(w.entries()) == 1
    r = w.cycle()
    assert r.entered == [] and len(w.entries()) == 1  # no duplicate

    # positions keep their stops when protection itself fails, and repeated failures alert
    w.bar(121.0)
    w.watch()
    for i in range(3):
        w.ex.fail_next = "products"
        assert w.engine.run_cycle().errors
        assert ("cycle failing" in w.titles()) == (i == 2)
        assert w.sells() == pytest.approx(w.position().base_size)
    assert not w.cycle().errors


def test_lost_reply_after_entry_is_adopted_once():
    w = World()
    w.ex.fail_next = "get_order"  # the entry reached the exchange but its verification failed
    assert w.cycle().errors
    [order] = w.entries()
    r = w.cycle()
    assert r.entered == [] and len(w.entries()) == 1
    w.bar(121.0)
    w.watch()
    assert w.position().base_size == pytest.approx(order.base_size)  # counted once
    w.cycle()
    assert w.position().base_size == pytest.approx(order.base_size)


def test_one_broken_position_does_not_block_protecting_the_others():
    w = World(also=["AVAX-USD"])
    assert sorted(w.cycle().entered) == ["AVAX-USD", "SOL-USD"]
    w.bar(121.0)
    w.watch()
    avax = w.position("AVAX-USD")
    del w.ex._products["SOL-USD"]  # SOL vanishes from the product list
    w.ex.cancel(next(leg.order_id for leg in avax.legs if leg.kind == "bracket"))
    r = w.engine.run_cycle()
    assert any("SOL-USD" in e for e in r.errors)
    assert w.sells("AVAX-USD") == pytest.approx(avax.base_size)  # AVAX was still repaired
    assert r.entered == []


def test_lost_reply_entry_fills_and_is_recovered():
    w = World()
    w.ex.fail_after_next = "place_entry"  # the venue creates the order, the reply is lost
    r = w.cycle()
    assert r.errors and r.entered == []
    [order] = w.entries()
    w.bar(121.0)  # it fills before the bot has ever seen it
    assert w.ex.get_order(order.order_id).status == "filled"
    w.watch()  # resolves the intent, adopts the fill and protects it at once
    pos = w.position()
    assert pos.base_size == pytest.approx(order.base_size) and pos.entry_price == pytest.approx(ENTRY)
    assert w.sells() == pytest.approx(order.base_size)
    assert "recovered entry" in w.titles()
    r = w.cycle()
    assert r.entered == [] and len(w.ex._orders) == 3  # entry + two legs: no second order for the setup


def test_unresolved_intent_blocks_a_second_order():
    w = World()
    w.ex.fail_after_next = "place_entry"
    w.cycle()
    w.ex.fail_next = "get_order_by_client_id"  # the intent cannot be resolved this cycle
    r = w.cycle()
    assert r.errors and len(w.ex._orders) == 1
    r = w.cycle()
    assert r.entered == [] and len(w.ex._orders) == 1 and len(w.entries()) == 1


def test_partial_fill_then_expiry_is_protected():
    w = World()
    w.cycle()
    [order] = w.entries()
    part = round(order.base_size * 0.4, 3)
    w.ex.partial_fill(order.order_id, part, ENTRY, T0)
    w.watch()
    assert w.position().base_size == pytest.approx(part)
    assert w.sells() == pytest.approx(part)
    w.clock.t = T0 + 25 * 3600  # past the 24h entry lifetime
    w.cycle()
    assert w.ex.get_order(order.order_id).status == "cancelled"
    assert w.entries() == []
    assert w.position().base_size == pytest.approx(part) and w.sells() == pytest.approx(part)


def test_cancel_only_product_exits_still_work():
    w = World(entry=("veto", 0.0))
    w.cycle()  # universe built while online; this setup is vetoed
    w.set_status("SOL-USD", "cancel_only")
    w.llm.entry = ("approve", 1.0)
    r = w.cycle()
    assert r.skipped["SOL-USD"] == "status cancel_only" and w.entries() == []

    w = World()
    pos = w.enter()
    w.set_status("SOL-USD", "cancel_only")
    w.cycle()
    assert any("cancel_only" in t for t in w.titles())
    bracket = next(leg for leg in pos.legs if leg.kind == "bracket")
    w.ex.cancel(bracket.order_id)
    w.cycle()  # protection is still attempted
    assert w.sells() == pytest.approx(pos.base_size)
    w.bar(90.0, low=88.0, high=92.0, open_=90.0)
    w.cycle()  # a forced exit would be rejected: the resting stops are kept and the owner alerted
    w.cycle()
    assert w.titles().count("forced exit blocked") == 1
    assert sorted(o.kind for o in w.ex.open_orders()) == ["bracket", "stop"]
    assert not any(o.kind == "ioc" for o in w.ex._orders.values())


def test_risk_off_scans_nothing():
    w = World(btc_step=-1.0)  # BTC falling: raw regime risk_off too
    w.store.set_meta("regime", json.dumps("risk_off"))
    w.store.set_meta("regime_confirmed", json.dumps("risk_off"))
    calls = []
    real = w.ex.candles

    def spy(pid, granularity, limit):
        calls.append(granularity)
        return real(pid, granularity, limit)

    w.ex.candles = spy
    r = w.cycle()
    assert r.entered == [] and w.entries() == [] and r.errors == []
    assert H4 not in calls
    assert w.llm.calls == []  # flat and risk-off: no regime review either


def test_stacked_reductions_skip_with_reason():
    w = World(entry=("reduce", 0.5), regime_mult=0.5)
    w.store.save_risk_state(RiskState(1000.0, DAY0, 1000.0, False, 3, 0))  # streak brake: x0.5
    r = w.cycle()
    assert r.skipped["SOL-USD"] == "multiplier below floor"
    assert w.entries() == [] and w.llm.calls == ["regime", "entry"]


def test_restart_rebuilds_from_exchange():
    w = World()
    pos = w.enter()
    orders_before = len(w.ex._orders)
    open_before = {o.order_id for o in w.ex.open_orders()}

    fresh = Store(":memory:")
    r = w.make_engine(fresh).run_cycle()
    assert fresh.positions() == [] and r.entered == []
    assert len(w.ex._orders) == orders_before  # placed nothing, sold nothing
    assert {o.order_id for o in w.ex.open_orders()} == open_before
    assert r.skipped["SOL-USD"] == "open order on exchange"

    w.engine = w.make_engine(w.store)  # same store: resumes
    w.cycle()
    resumed = w.position()
    assert resumed.base_size == pytest.approx(pos.base_size)
    assert {leg.order_id for leg in resumed.legs} == {leg.order_id for leg in pos.legs}
    for close in (130.0, 140.0, 150.0, 158.0):
        w.bar(close)
        w.cycle()
    assert w.position().half_taken and w.position().stop_price >= ENTRY


def test_too_small_to_split_trails_whole_after_target():
    w = World(cfg=Config(risk_per_trade=0.0003))  # ~0.015 SOL: halves would be below the 0.01 minimum
    pos = w.enter()
    assert pos.base_size < 0.02
    assert [leg.kind for leg in pos.legs] == ["stop"] and pos.legs[0].base_size == pos.base_size
    for close in (130.0, 140.0, 150.0):
        w.bar(close)
        w.cycle()
    assert w.position().stop_price == pytest.approx(STOP)  # below target: no trailing yet
    w.bar(160.0)
    w.cycle()
    pos = w.position()
    assert not pos.half_taken and pos.stop_price > ENTRY  # whole position trails once 2R is reached
    assert w.sells() == pytest.approx(pos.base_size)


def test_without_brackets_bot_sells_half_at_target_lifecycle():
    w = World(brackets=False)
    pos = w.enter()
    size = pos.base_size
    a = round_down(size / 2, 0.001)
    assert sorted(leg.base_size for leg in pos.legs) == pytest.approx(sorted([a, size - a]))
    assert [leg.kind for leg in pos.legs] == ["stop", "stop"]
    for close in (130.0, 140.0, 150.0):
        w.bar(close)
        w.cycle()
    assert [o.kind for o in w.ex.open_orders()] == ["stop", "stop"]  # below target: nothing sold
    w.bar(160.0)
    w.cycle()  # bid >= target: leg a's stop becomes an IOC sell
    [ioc] = [o for o in w.ex.open_orders() if o.kind == "ioc"]
    assert ioc.base_size == pytest.approx(a)
    assert ioc.limit_price == pytest.approx(160.0 * (1 - 0.0005) * 0.995, abs=0.01)
    w.bar(161.0)  # the IOC fills
    w.cycle()
    pos = w.position()
    assert pos.half_taken and pos.base_size == pytest.approx(size - a) and pos.stop_price >= ENTRY
    moves = [r["data"] for r in w.store.journal_rows("stop_moved")]
    assert moves[0]["why"] == "break-even" and moves[0]["new_stop"] == pytest.approx(ENTRY)
    for close in (170.0, 180.0):
        w.bar(close)
        w.cycle()
    assert w.position().stop_price > ENTRY + 20  # trailing applies as usual
    w.bar(140.0)
    r = w.cycle()
    assert r.exited == ["SOL-USD"] and w.position() is None
    [closed] = w.store.journal_rows("trade_closed")
    assert closed["data"]["pnl_usd"] > 0
    first = closed["data"]["exits"][0]
    assert first["reason"] == "ioc" and first["size"] == pytest.approx(a) and first["price"] >= TARGET * 0.995


def test_without_brackets_unfilled_target_ioc_restores_the_stop():
    w = World(brackets=False)
    pos = w.enter()
    for close in (130.0, 140.0, 150.0, 160.0):
        w.bar(close)
        w.cycle()
    assert any(o.kind == "ioc" for o in w.ex.open_orders())
    w.bar(150.0)  # closes below the IOC limit: it cancels unfilled
    w.cycle()
    pos = w.position()
    assert not pos.half_taken and w.sells() == pytest.approx(pos.base_size)
    assert [o.kind for o in w.ex.open_orders()] == ["stop", "stop"]
    assert "missing stop" not in w.titles()  # re-placed at once, not by the repair path


def test_without_brackets_failed_target_ioc_recovers_stop_in_same_cycle():
    w = World(brackets=False)
    w.enter()
    for close in (130.0, 140.0, 150.0):
        w.bar(close)
        w.cycle()
    w.bar(160.0)
    w.ex.fail_next = "place_ioc_sell"
    w.cycle()  # check_covered: leg a's stop is back before the cycle ends
    assert [o.kind for o in w.ex.open_orders()] == ["stop", "stop"] and not w.position().half_taken


def test_withdrawal_is_not_counted_as_a_loss():
    w = World()
    w.cycle()
    [order] = w.entries()
    w.ex.cancel(order.order_id)
    w.ex.deposit(-300.0, T0 + 60)
    w.clock.t = T0 + 120
    r = w.cycle()
    assert r.halted is None
    st = w.store.load_risk_state()
    assert st.day_start_equity == pytest.approx(700.0) and st.peak_equity == pytest.approx(700.0)
    w.cycle()  # applied once only
    assert w.store.load_risk_state().day_start_equity == pytest.approx(700.0)


def fail_times(ex, method: str, n: int):
    """Make `ex.<method>` raise ExchangeError on its next `n` calls (without performing them)."""
    real = getattr(ex, method)
    left = [n]

    def wrapper(*args, **kwargs):
        if left[0] > 0:
            left[0] -= 1
            raise ExchangeError(f"injected failure in {method}")
        return real(*args, **kwargs)

    setattr(ex, method, wrapper)


def two_positions():
    """SOL and AVAX entries both filled and protected."""
    w = World(also=["AVAX-USD"])
    assert sorted(w.cycle().entered) == ["AVAX-USD", "SOL-USD"]
    w.bar(121.0)
    w.watch()
    return w


def test_kill_switch_runs_despite_a_broken_position():
    w = World(also=["AVAX-USD"])
    w.cycle()
    avax_entry = next(o for o in w.entries() if o.product_id == "AVAX-USD")
    sol_entry = next(o for o in w.entries() if o.product_id == "SOL-USD")
    w.ex.partial_fill(avax_entry.order_id, avax_entry.base_size, ENTRY, T0)
    w.watch()
    del w.ex._products["AVAX-USD"]  # every per-position step now fails for AVAX
    w.edit_state(peak_equity=2000.0)
    r = w.engine.run_cycle()
    assert any("AVAX-USD" in e for e in r.errors)
    assert r.halted == "kill switch triggered"
    assert w.ex.get_order(sol_entry.order_id).status == "cancelled"


def test_watch_retries_protection_after_a_failed_protect():
    w = World()
    w.cycle()
    w.bar(121.0)
    fail_times(w.ex, "place_stop", 3)  # bracket placed; the stop leg fails, and so do both in-poll retries
    w.engine.watch_fills()
    assert "unprotected" in w.titles()
    assert w.sells() < w.position().base_size and w.engine.needs_watch()
    w.watch()  # the next poll retries even though no entry changed
    assert sorted(leg.kind for leg in w.position().legs) == ["bracket", "stop"]
    assert not w.engine.needs_watch()


def test_protect_failure_in_sync_does_not_block_other_positions():
    w = World(also=["AVAX-USD"])
    w.cycle()
    entries = {o.product_id: o for o in w.entries()}
    w.ex.partial_fill(entries["AVAX-USD"].order_id, entries["AVAX-USD"].base_size, ENTRY, T0)
    w.watch()
    avax = w.position("AVAX-USD")
    w.ex.partial_fill(entries["SOL-USD"].order_id, entries["SOL-USD"].base_size, ENTRY, T0)  # not watched
    w.ex.cancel(next(leg.order_id for leg in avax.legs if leg.kind == "bracket"))
    w.ex.fail_next = "place_bracket"  # protecting SOL's new fill fails inside sync
    r = w.engine.run_cycle()
    assert any("SOL-USD" in e for e in r.errors)
    assert w.sells("AVAX-USD") == pytest.approx(avax.base_size)  # AVAX still repaired this cycle
    assert w.sells("SOL-USD") == pytest.approx(w.position("SOL-USD").base_size)  # and SOL retried


def test_failed_trail_replacement_is_retried_by_watch():
    w = World()
    w.enter()
    for close in (130.0, 140.0, 150.0, 158.0):
        w.bar(close)
        w.cycle()
    assert w.position().half_taken
    w.bar(175.0)
    fail_times(w.ex, "place_stop", 4)  # both attempts of the trailed stop fail after the cancel,
    w.engine.run_cycle()                 # and so do the two repair passes at the end of the cycle
    pos = w.position()
    assert "unprotected" in w.titles() and w.sells() == 0 and w.engine.needs_watch()
    w.watch()
    assert w.sells() == pytest.approx(pos.base_size) and w.position().stop_price == pytest.approx(pos.stop_price)


def test_unresolvable_intent_does_not_block_fill_protection():
    w = World()
    w.cycle()
    setups = json.loads(w.store.get_meta("setups"))
    setups["ETH-USD-1"] = {"status": "placing", "ts": T0, "candidate": {"product_id": "ETH-USD"}}
    w.store.set_meta("setups", json.dumps(setups))
    fail_times(w.ex, "get_order_by_client_id", 1000)
    w.bar(121.0)
    w.watch()  # the SOL fill is still accounted and protected
    assert w.position() is not None
    r = w.cycle()
    assert r.errors and r.entered == []
    assert json.loads(w.store.get_meta("setups"))["ETH-USD-1"]["status"] == "placing"


def gap_below_stop(w):
    w.cycle()
    w.bar(90.0, low=88.0, high=92.0, open_=90.0)


def test_lost_reply_forced_exit_is_recorded():
    w = World()
    w.enter()
    gap_below_stop(w)
    w.ex.fail_after_next = "place_ioc_sell"
    w.cycle()
    [ioc] = [o for o in w.ex.open_orders() if o.kind == "ioc"]
    assert len([o for o in w.ex._orders.values() if o.kind == "ioc"]) == 1
    w.bar(89.0, low=87.0, high=91.0, open_=90.0)
    r = w.cycle()
    assert r.exited == ["SOL-USD"]
    [closed] = w.store.journal_rows("trade_closed")
    assert closed["data"]["pnl_usd"] < 0 and w.store.load_risk_state().consecutive_losses == 1


def test_lost_reply_target_ioc_is_recorded():
    w = World(brackets=False)
    pos = w.enter()
    for close in (130.0, 140.0, 150.0):
        w.bar(close)
        w.cycle()
    w.bar(160.0)
    w.ex.fail_after_next = "place_ioc_sell"
    w.cycle()
    assert len([o for o in w.ex._orders.values() if o.kind == "ioc"]) == 1
    w.bar(161.0)
    w.cycle()
    after = w.position()
    a = round_down(pos.base_size / 2, 0.001)
    assert after.half_taken and after.base_size == pytest.approx(pos.base_size - a)
    trades = json.loads(w.store.get_meta("trades"))
    assert trades["SOL-USD"]["exits"][0]["size"] == pytest.approx(a)


def test_lost_reply_on_leg_placement_makes_no_duplicate():
    w = World()
    w.cycle()
    w.bar(121.0)
    w.ex.fail_after_next = "place_stop"  # found again by client id at once
    w.watch()
    assert sorted(leg.kind for leg in w.position().legs) == ["bracket", "stop"]
    assert len([o for o in w.ex._orders.values() if o.kind != "entry"]) == 2

    w = World()
    w.cycle()
    w.bar(121.0)
    w.ex.fail_after_next = "place_bracket"
    fail_times(w.ex, "get_order_by_client_id", 1)  # and the lookup fails too: resolved on the next poll
    w.engine.watch_fills()
    assert w.engine.needs_watch()
    w.watch()
    assert sorted(leg.kind for leg in w.position().legs) == ["bracket", "stop"]
    assert len([o for o in w.ex._orders.values() if o.kind != "entry"]) == 2


def test_needs_watch():
    w = World()
    assert not w.engine.needs_watch()
    w.cycle()
    assert w.engine.needs_watch()  # an entry rests
    w.bar(121.0)
    w.watch()
    assert not w.engine.needs_watch()  # filled and covered
    w.ex.cancel(w.position().legs[0].order_id)
    assert w.engine.needs_watch()  # uncovered
    w2 = World()
    w2.ex.fail_after_next = "place_entry"
    w2.cycle()
    fail_times(w2.ex, "get_order_by_client_id", 1)
    w2.engine.watch_fills()
    assert w2.engine.needs_watch()  # an intent is unresolved


def test_malformed_position_does_not_escape():
    w = two_positions()
    row = w.store._db.execute("SELECT data FROM positions WHERE product_id = 'AVAX-USD'").fetchone()
    d = json.loads(row[0])
    d["stop_price"] = "oops"  # (the size is derived from the order registry, so a bad one is just repaired)
    with w.store._db:
        w.store._db.execute("UPDATE positions SET data = ? WHERE product_id = 'AVAX-USD'", (json.dumps(d),))
    sol = w.position("SOL-USD")
    w.ex.cancel(next(leg.order_id for leg in sol.legs if leg.kind == "bracket"))
    r = w.engine.run_cycle()  # does not raise
    assert r.errors and "engine error" in w.titles()
    assert w.sells("SOL-USD") == pytest.approx(sol.base_size)  # SOL still repaired
    w.engine.watch_fills()  # does not raise
    assert w.engine.needs_watch() in (True, False)


class RaisingAlerts(Alerts):
    def send(self, title, body):
        super().send(title, body)
        raise RuntimeError("alert transport down")


def test_dead_forced_exit_ioc_is_retried_by_watch():
    w = World()
    pos = w.enter()
    gap_below_stop(w)
    w.cycle()  # forced exit: legs cancelled, IOC placed
    w.bar(80.0, low=78.0, high=82.0, open_=80.0)  # closes below the IOC limit: it dies unfilled
    assert w.sells() == 0
    assert w.engine.needs_watch()
    w.watch()  # bid still below the stop: the exit is retried at once
    [ioc] = [o for o in w.ex.open_orders() if o.kind == "ioc"]
    assert ioc.base_size == pytest.approx(pos.base_size)


def test_position_below_minimum_alerts_once_then_protects_when_it_grows():
    w = World()
    w.cycle()
    [order] = w.entries()
    w.ex.partial_fill(order.order_id, 0.005, ENTRY, T0)  # below the 0.01 minimum order size
    for _ in range(10):
        w.engine.watch_fills()
    assert sum("minimum order size" in b for _, b in w.alerts.sent) == 1
    w.ex.partial_fill(order.order_id, 0.5, ENTRY, T0)
    w.watch()
    assert w.sells() == pytest.approx(0.505)


def test_dust_position_does_not_keep_watch_on():
    w = World()
    w.cycle()
    [order] = w.entries()
    w.ex.partial_fill(order.order_id, 0.005, ENTRY, T0)
    w.engine.watch_fills()
    w.ex.cancel(order.order_id)
    w.engine.watch_fills()
    assert w.position().base_size == pytest.approx(0.005) and w.entries() == []
    assert not w.engine.needs_watch()
    for _ in range(5):
        w.engine.watch_fills()
        w.engine.run_cycle()
    assert sum("minimum order size" in b for _, b in w.alerts.sent) == 1
    assert "missing stop" not in w.titles()


def test_forced_exit_waits_for_unresolved_placement_before_cancelling():
    w = World()
    pos = w.enter()
    pending = {"SOL-USD-stop-x": {"kind": "stop", "product_id": "SOL-USD", "size": 0.1}}
    w.store.set_meta("pending", json.dumps(pending))
    fail_times(w.ex, "get_order_by_client_id", 1000)
    gap_below_stop(w)
    w.engine.run_cycle()
    assert all(w.ex.get_order(leg.order_id).status == "open" for leg in pos.legs)  # stops kept
    assert not any(o.kind == "ioc" for o in w.ex._orders.values())


def test_raising_alert_transport_never_escapes():
    w = World()
    w.alerts = RaisingAlerts()
    w.engine = w.make_engine(w.store)
    pos = w.enter()
    w.ex.cancel(pos.legs[0].order_id)
    w.engine.run_cycle()  # alerts "missing stop": the transport raises, the cycle does not
    assert "missing stop" in w.titles() and w.sells() == pytest.approx(pos.base_size)
    w.ex.cancel(w.position().legs[0].order_id)
    w.engine.watch_fills()
    assert w.sells() == pytest.approx(pos.base_size)
    assert w.store.journal_rows("alert_failed")


def test_engine_error_alerts_once_per_episode():
    w = two_positions()
    row = w.store._db.execute("SELECT data FROM positions WHERE product_id = 'AVAX-USD'").fetchone()
    d = json.loads(row[0])
    d["stop_price"] = "oops"  # (the size is derived from the order registry, so a bad one is just repaired)
    with w.store._db:
        w.store._db.execute("UPDATE positions SET data = ? WHERE product_id = 'AVAX-USD'", (json.dumps(d),))
    w.engine.run_cycle()
    w.engine.watch_fills()
    alerts = w.titles().count("engine error")
    errors = len(w.store.journal_rows("error"))
    assert alerts >= 1
    for _ in range(5):
        w.engine.watch_fills()
    assert w.titles().count("engine error") == alerts
    assert len(w.store.journal_rows("error")) == errors  # same cycle period: not journaled again
    w.clock.t += 15 * 60
    w.engine.run_cycle()
    assert w.titles().count("engine error") == alerts


def test_equity_uses_last_bid_when_a_price_fails():
    w = World(also=["AVAX-USD"])
    w.cycle()
    avax = next(o for o in w.entries() if o.product_id == "AVAX-USD")
    sol = next(o for o in w.entries() if o.product_id == "SOL-USD")
    w.ex.partial_fill(avax.order_id, avax.base_size, ENTRY, T0)
    w.watch()
    w.cycle()  # reads AVAX's bid
    real = w.ex.bid_ask

    def bid_ask(pid):
        if pid == "AVAX-USD":
            raise ExchangeError("no price")
        return real(pid)

    w.ex.bid_ask = bid_ask
    w.edit_state(peak_equity=2000.0)
    r = w.engine.run_cycle()
    assert r.halted == "kill switch triggered"
    assert w.ex.get_order(sol.order_id).status == "cancelled"
    assert w.titles().count("stale price") == 1
    w.engine.run_cycle()
    assert w.titles().count("stale price") == 1
    assert w.engine.equity() > 0


def test_stop_moved_only_when_the_new_stop_is_live():
    w = World()
    w.enter()
    for close in (130.0, 140.0, 150.0, 158.0):
        w.bar(close)
        w.cycle()
    moved = len(w.store.journal_rows("stop_moved"))
    real = w.ex.place_stop
    calls = [0]

    def dies_once(*args):
        oid = real(*args)
        calls[0] += 1
        if calls[0] == 1:
            w.ex.cancel(oid)  # accepted, then cancelled by the venue
        return oid

    w.ex.place_stop = dies_once
    w.bar(175.0)
    w.cycle()  # first attempt dead, second attempt live: coverage holds
    rows = w.store.journal_rows("stop_moved")
    assert len(rows) == moved + 1 and calls[0] == 2
    assert w.sells() == pytest.approx(w.position().base_size)


def test_filled_ioc_with_lagging_fills_is_not_sold_twice():
    w = World()
    pos = w.enter()
    gap_below_stop(w)
    w.cycle()
    [ioc] = [o for o in w.ex.open_orders() if o.kind == "ioc"]
    w.ex._coins["SOL"] += 10.0  # the owner's own SOL, not the bot's
    w.ex.hold_fills = True
    w.bar(89.0, low=87.0, high=91.0, open_=90.0)  # the IOC fills; its fills are not visible yet
    assert w.ex.get_order(ioc.order_id).filled_size == pytest.approx(pos.base_size)
    w.engine.watch_fills()  # order status says flat: the position is gone at once, without the fills
    assert w.position() is None and w.store.journal_rows("trade_closed") == []
    for _ in range(2):
        w.engine.watch_fills()
        w.engine.run_cycle()
    assert len([o for o in w.ex._orders.values() if o.kind == "ioc"]) == 1  # no second IOC
    assert not [o for o in w.ex.open_orders() if o.kind != "entry"]
    assert w.store.journal_rows("trade_closed") == []  # still inside the bounded wait
    w.ex.release_fills()
    w.engine.run_cycle()
    [closed] = w.store.journal_rows("trade_closed")
    assert closed["data"]["pnl_usd"] < 0 and not closed["data"]["estimated"]
    assert w.store.load_risk_state().consecutive_losses == 1
    w.engine.run_cycle()
    w.engine.watch_fills()
    assert len(w.store.journal_rows("trade_closed")) == 1
    assert w.ex.balances()["SOL"] == pytest.approx(10.0)  # the owner's coins untouched


def test_no_sell_exceeds_position_when_a_fill_is_invisible():
    w = World()
    pos = w.enter()
    w.ex._coins["SOL"] += 10.0  # the owner's own SOL: the balance would allow selling far more
    stop_leg = next(leg for leg in pos.legs if leg.kind == "stop")
    w.ex.hold_fills = True
    w.ex.partial_fill(stop_leg.order_id, stop_leg.base_size, STOP, T0 + H4)  # filled; fills() never shows it
    w.ex.cancel(next(leg.order_id for leg in pos.legs if leg.kind == "bracket"))  # and a leg goes missing
    w.engine.watch_fills()
    left = pos.base_size - stop_leg.base_size
    assert w.position().base_size == pytest.approx(left)  # sized by order status
    assert w.sells() == pytest.approx(left)  # the rest is protected, not refused, and not a coin more
    w.engine.run_cycle()
    assert w.sells() == pytest.approx(left) and w.ex.balances()["SOL"] == pytest.approx(10.0 + left)


def test_forced_exit_retries_back_off_and_alert_once():
    w = World()
    w.enter()
    real = w.ex.place_ioc_sell

    def dead_on_arrival(*args):
        oid = real(*args)
        w.ex._orders[oid].status = "cancelled"  # accepted, then dies unfilled at once
        return oid

    w.ex.place_ioc_sell = dead_on_arrival
    gap_below_stop(w)
    t0 = w.clock.t
    w.engine.run_cycle()  # attempt 1
    for i in range(1, 13):  # 60 seconds of 5 s polls
        w.clock.t = t0 + 5 * i
        w.engine.watch_fills()
    iocs = [o for o in w.ex._orders.values() if o.kind == "ioc"]
    assert len(iocs) == 4  # at 0, 5, 15, 35 s
    assert len(w.store.journal_rows("forced_exit")) == 4
    assert w.titles().count("forced exit") == 1
    w.ex.place_ioc_sell = real
    w.bar(110.0, low=108.0, high=112.0, open_=110.0)  # recovers above the stop
    w.watch()  # stops restored: the episode ends with one follow-up alert
    assert "forced exit ended" in w.titles()
    assert w.titles().count("forced exit") == 1


def test_mismatched_leg_is_cancelled_before_it_is_dropped():
    w = World()
    w.cycle()
    w.bar(121.0)
    real, calls = w.ex.place_stop, []

    def short_once(pid, size, trig, lim, cid):
        calls.append(cid)
        return real(pid, round(size - 0.001, 3) if len(calls) == 1 else size, trig, lim, cid)

    w.ex.place_stop = short_once
    w.watch()
    bad = w.ex._orders[w.ex._by_client_id[calls[0]]]
    assert bad.status == "cancelled"
    assert w.sells() == pytest.approx(w.position().base_size)


def test_episodes_cleared_when_a_position_is_deleted():
    w = World()
    w.cycle()
    [order] = w.entries()
    w.ex.partial_fill(order.order_id, 0.005, ENTRY, T0)
    w.engine.watch_fills()
    assert any(k.endswith("|SOL-USD") for k in json.loads(w.store.get_meta("episodes")))
    w.ex.cancel(order.order_id)
    w.ex._coins["SOL"] = 0.0  # the owner sold the dust
    w.engine.run_cycle()
    assert w.position() is None
    assert not any(k.endswith("|SOL-USD") for k in json.loads(w.store.get_meta("episodes")))


def test_exchange_error_alerts_once_per_episode():
    w = two_positions()
    del w.ex._products["AVAX-USD"]
    w.engine.run_cycle()
    first = w.titles().count("protection failed")
    assert 1 <= first <= 2  # once per failing unit (protect, trail) for AVAX
    for _ in range(3):
        w.engine.run_cycle()
    assert w.titles().count("protection failed") == first


# ------------------------------------------------------------------ quantity comes from order status

def forced_ioc(w):
    """Enter, gap below the stop, and let the cycle place the forced-exit IOC."""
    pos = w.enter()
    gap_below_stop(w)
    w.cycle()
    [ioc] = [o for o in w.ex.open_orders() if o.kind == "ioc"]
    return pos, ioc


def count_closes(monkeypatch):
    """Count on_trade_closed calls made by the engine."""
    import bot.engine as engine_module
    calls, real = [], engine_module.on_trade_closed

    def counted(state, pnl, cfg):
        calls.append(pnl)
        real(state, pnl, cfg)

    monkeypatch.setattr(engine_module, "on_trade_closed", counted)
    return calls


def test_half_filled_stop_with_hidden_fills_then_gap_is_force_sold():
    """The reviewer's probe: half the stop leg fills, fills() never shows it, then the price gaps
    below the stop. The exit must be sized by order status and placed, not refused."""
    w = World()
    pos = w.enter()
    stop_leg = next(leg for leg in pos.legs if leg.kind == "stop")
    half = round_down(stop_leg.base_size / 2, 0.001)
    w.ex._coins["SOL"] += 10.0  # the owner's own SOL: the exit must not be sized from the balance
    w.ex.hold_fills = True
    w.ex.partial_fill(stop_leg.order_id, half, STOP, T0 + H4)
    w.bar(90.0, low=88.0, high=92.0, open_=90.0)  # gap below the stop's limit: the stops cannot fill
    left = pos.base_size - half
    w.engine.run_cycle()
    for _ in range(3):
        w.engine.watch_fills()
    assert w.position().base_size == pytest.approx(left)
    [ioc] = [o for o in w.ex.open_orders() if o.kind != "entry"]
    assert ioc.kind == "ioc" and ioc.base_size == pytest.approx(left)
    assert len([o for o in w.ex._orders.values() if o.kind == "ioc"]) == 1
    assert not any("not accounted" in r["data"].get("error", "") for r in w.store.journal_rows("error"))
    w.bar(89.0, low=87.0, high=91.0, open_=90.0)  # the IOC fills; still no fills() for anything
    w.engine.watch_fills()
    assert w.position() is None and w.ex.balances()["SOL"] == pytest.approx(10.0)
    assert not w.engine.needs_watch()  # nothing is stuck "in flight"


def test_fills_that_never_arrive_close_the_trade_once_on_estimates(monkeypatch):
    calls = count_closes(monkeypatch)
    w = World()
    pos, ioc = forced_ioc(w)
    w.ex.hold_fills = True
    w.bar(89.0, low=87.0, high=91.0, open_=90.0)  # the IOC fills at the bid (89.0 less half the spread); its fills never arrive
    r = w.engine.run_cycle()
    assert r.exited == ["SOL-USD"] and w.position() is None  # flat by order status, at once
    for _ in range(w.cfg.fill_wait_cycles - 1):
        w.engine.watch_fills()
        r = w.engine.run_cycle()
        assert w.store.journal_rows("trade_closed") == [] and calls == []
        assert "scan_skipped" in [row["kind"] for row in w.store.journal_rows()]  # no new entry meanwhile
    w.engine.run_cycle()  # the bounded wait is over
    [closed] = w.store.journal_rows("trade_closed")
    d = closed["data"]
    assert d["estimated"] and d["exit_reason"] == "ioc"
    assert d["sold"] == pytest.approx(pos.base_size) and d["bought"] == pytest.approx(pos.base_size)
    assert d["proceeds"] == pytest.approx(pos.base_size * 89.0 * (1 - 0.0005))  # the IOC fills at the bid, 89 * (1 - spread/2)
    assert d["sell_fee"] == pytest.approx(d["proceeds"] * FEES.taker)  # no fill: fee at the venue's rate
    assert d["pnl_usd"] < 0 and calls == [d["pnl_usd"]]
    assert w.titles().count("trade closed on estimated prices") == 1
    w.ex.release_fills()  # fills turning up afterwards change nothing
    for _ in range(3):
        w.engine.run_cycle()
        w.engine.watch_fills()
    assert len(w.store.journal_rows("trade_closed")) == 1 and len(calls) == 1
    assert w.titles().count("trade closed on estimated prices") == 1
    assert json.loads(w.store.get_meta("closing")) == {}
    assert not [r for r in json.loads(w.store.get_meta("orders")).values() if r["product_id"] == "SOL-USD"]


def test_estimate_uses_the_limit_price_when_the_venue_reports_no_average(monkeypatch):
    calls = count_closes(monkeypatch)
    w = World(cfg=Config(fill_wait_cycles=1))
    pos, ioc = forced_ioc(w)
    w.ex.hold_fills = True
    w.ex.report_avg_price = False
    w.bar(89.0, low=87.0, high=91.0, open_=90.0)
    w.engine.run_cycle()
    assert w.store.journal_rows("trade_closed") == []
    w.engine.run_cycle()
    [closed] = w.store.journal_rows("trade_closed")
    assert closed["data"]["estimated"]
    assert closed["data"]["proceeds"] == pytest.approx(pos.base_size * ioc.limit_price)  # the IOC's floor
    assert len(calls) == 1


def lifecycle(factor):
    """A whole winning trade with fills() reporting every size times `factor`."""
    w = World()
    w.ex.fill_size_factor = factor
    w.enter()
    w.cycle()
    for close in (130.0, 140.0, 150.0, 158.0, 168.0, 178.0, 188.0, 150.0):
        w.bar(close)
        w.cycle()
    return w


def test_fills_not_summing_to_filled_size_change_no_quantity():
    exact = lifecycle(1.0).store.journal_rows("trade_closed")[0]["data"]
    w = lifecycle(0.9996)  # rounding: within tolerance, priced from the fills, scaled to the order's size
    [closed] = w.store.journal_rows("trade_closed")
    assert not closed["data"]["estimated"]
    for k in ("bought", "sold", "proceeds"):
        assert closed["data"][k] == pytest.approx(exact[k])  # quantities and prices are exact
    for k in ("pnl_usd", "buy_fee", "sell_fee"):
        assert closed["data"][k] == pytest.approx(exact[k], rel=1e-3)  # fees are scaled to the order's size
    assert w.ex.balances()["SOL"] == pytest.approx(0.0) and w.ex.open_orders() == []

    w = lifecycle(0.9)  # fills that never add up: every sell was still placed (check_covered ran throughout)
    assert w.position() is None and w.ex.balances()["SOL"] == pytest.approx(0.0)
    assert w.store.journal_rows("trade_closed") == []
    for _ in range(w.cfg.fill_wait_cycles):
        w.cycle()
    [closed] = w.store.journal_rows("trade_closed")
    assert closed["data"]["estimated"] and closed["data"]["sold"] == pytest.approx(exact["sold"])
    assert closed["data"]["pnl_usd"] == pytest.approx(exact["pnl_usd"], rel=0.01)  # the venue's averages


def test_reconcile_does_not_delete_a_position_whose_exit_fills_lag(monkeypatch):
    calls = count_closes(monkeypatch)
    w = World()
    pos, ioc = forced_ioc(w)
    w.ex.hold_fills = True
    w.bar(89.0, low=87.0, high=91.0, open_=90.0)  # the IOC fills: the balance is 0, fills() shows nothing
    w.engine.run_cycle()
    assert w.position() is None
    assert not any("reconcil" in t for t in w.titles()) and w.store.journal_rows("reconcile") == []
    w.ex.release_fills()
    w.engine.run_cycle()
    [closed] = w.store.journal_rows("trade_closed")
    assert closed["data"]["pnl_usd"] < 0 and not closed["data"]["estimated"] and len(calls) == 1


def test_partly_filled_ioc_with_lagging_fills_reduces_the_position_once():
    w = World()
    pos, ioc = forced_ioc(w)
    w.ex.hold_fills = True
    part = round_down(pos.base_size / 3, 0.001)
    w.ex.partial_fill(ioc.order_id, part, 88.0, w.clock.t)
    w.ex.cancel(ioc.order_id)  # the rest of the IOC is cancelled by the venue
    w.bar(110.0, low=108.0, high=112.0, open_=110.0)  # the bid is back above the stop
    w.cycle()  # check_covered: position == balance == open sells
    left = pos.base_size - part
    assert w.position().base_size == pytest.approx(left)
    assert not any("reconcil" in t for t in w.titles())
    w.ex.release_fills()  # the late fill must not reduce the position a second time
    w.cycle()
    w.watch()
    assert w.position().base_size == pytest.approx(left) and w.sells() == pytest.approx(left)
    trades = json.loads(w.store.get_meta("trades"))
    assert [(x["reason"], x["size"], x["price"]) for x in trades["SOL-USD"]["exits"]] == [("ioc", part, 88.0)]


def test_rejected_forced_exit_backs_off_and_is_journaled_as_forced_exit():
    w = World()
    pos = w.enter()
    gap_below_stop(w)
    fail_times(w.ex, "place_ioc_sell", 1000)  # the venue rejects every IOC
    t0 = w.clock.t
    w.engine.run_cycle()  # attempt 1: stops cancelled, IOC rejected
    assert w.sells() == 0 and w.engine.needs_watch()
    for i in range(1, 13):  # 60 seconds of 5 s polls
        w.clock.t = t0 + 5 * i
        w.engine.watch_fills()
    rows = [r["data"] for r in w.store.journal_rows("forced_exit")]
    assert [r["attempt"] for r in rows] == [1, 2, 3, 4]  # at 0, 5, 15, 35 s
    assert all("injected failure" in r["error"] for r in rows)
    assert w.titles().count("forced exit") == 1
    assert w.position().base_size == pytest.approx(pos.base_size)
    episodes = json.loads(w.store.get_meta("episodes"))
    assert episodes["forced|SOL-USD"]["next_ts"] > w.clock.t  # what covers it: the scheduled retry


def test_forced_exit_episode_ends_when_the_bid_recovers():
    w = World()
    pos = w.enter()
    gap_below_stop(w)
    fail_times(w.ex, "place_ioc_sell", 1)
    w.engine.run_cycle()  # attempt 1 rejected: an episode is open and the stops are gone
    assert "forced|SOL-USD" in json.loads(w.store.get_meta("episodes"))
    w.bar(110.0, low=108.0, high=112.0, open_=110.0)
    w.watch()  # bid back above the stop: stops restored, episode ended
    assert "forced|SOL-USD" not in json.loads(w.store.get_meta("episodes"))
    assert w.titles().count("forced exit ended") == 1
    w.bar(90.0, low=88.0, high=92.0, open_=90.0)  # a second gap starts a new episode at attempt 1
    w.cycle()
    assert [r["data"]["attempt"] for r in w.store.journal_rows("forced_exit")] == [1, 1]
    assert w.titles().count("forced exit") == 2


def test_forced_exit_episode_ends_even_when_only_dust_is_left():
    w = World()
    pos, ioc = forced_ioc(w)
    w.ex.partial_fill(ioc.order_id, round(pos.base_size - 0.005, 3), 88.0, w.clock.t)
    w.ex.cancel(ioc.order_id)  # 0.005 is left: too small for any order
    w.engine.watch_fills()
    assert w.position().base_size == pytest.approx(0.005)
    w.bar(110.0, low=108.0, high=112.0, open_=110.0)
    w.engine.run_cycle()
    assert "forced|SOL-USD" not in json.loads(w.store.get_meta("episodes"))


def test_limit_only_product_still_gets_a_forced_exit():
    w = World()
    pos = w.enter()
    w.set_status("SOL-USD", "limit_only")
    gap_below_stop(w)
    w.cycle()
    [ioc] = [o for o in w.ex.open_orders() if o.kind == "ioc"]
    assert ioc.base_size == pytest.approx(pos.base_size) and "forced exit blocked" not in w.titles()
    [body] = [b for t, b in w.alerts.sent if t == "SOL-USD is limit_only"]
    assert "forced exits are still placed" in body


def test_blocked_forced_exit_alert_says_what_actually_rests():
    w = World()
    pos = w.enter()
    w.set_status("SOL-USD", "disabled")
    w.cycle()
    [body] = [b for t, b in w.alerts.sent if t == "SOL-USD is disabled"]
    assert "a forced exit is not sent" in body
    bracket = next(leg for leg in pos.legs if leg.kind == "bracket")
    w.bar(90.0, low=88.0, high=92.0, open_=90.0)
    w.ex.cancel(bracket.order_id)  # a leg is missing when the gap comes
    w.engine.run_cycle()
    [body] = [b for t, b in w.alerts.sent if t == "forced exit blocked"]
    rest = round(pos.base_size - bracket.base_size, 3)
    assert f"resting sell orders cover {rest} of {pos.base_size}" in body
    assert not any(o.kind == "ioc" for o in w.ex._orders.values())


def test_flat_trade_cancels_its_resting_entry_and_closes_once(monkeypatch):
    calls = count_closes(monkeypatch)
    w = World()
    w.cycle()
    [order] = w.entries()
    w.ex.partial_fill(order.order_id, 0.6, ENTRY, T0)
    w.watch()
    for leg in w.position().legs:  # both stops fill while the rest of the entry still rests
        w.ex.partial_fill(leg.order_id, leg.base_size, STOP, T0 + 60)
    w.watch()
    assert w.position() is None and w.ex.get_order(order.order_id).status == "cancelled"
    [closed] = w.store.journal_rows("trade_closed")
    assert closed["data"]["bought"] == pytest.approx(0.6) and closed["data"]["sold"] == pytest.approx(0.6)
    assert closed["data"]["exit_reason"] == "stop" and len(calls) == 1
    w.cycle()
    assert len(w.store.journal_rows("trade_closed")) == 1 and w.entries() == []


def test_position_is_rederived_from_the_order_registry():
    w = World()
    pos = w.enter()
    w.store.delete_position("SOL-USD")  # as if the process died between saving the registry and the position
    assert w.position() is None
    w.watch()
    again = w.position()
    assert again.base_size == pytest.approx(pos.base_size) and again.entry_price == pytest.approx(ENTRY)
    assert again.stop_price == pytest.approx(pos.stop_price)


def instant_ioc(w, fraction=1.0):
    """IOC sells behave as on a real venue: done (filled `fraction`, rest cancelled) before the call returns."""
    real = w.ex.place_ioc_sell

    def place(pid, size, limit, cid):
        oid = real(pid, size, limit, cid)
        part = round_down(size * fraction, 0.001)
        if part > 0:
            w.ex.partial_fill(oid, part, limit, w.clock.t)
        w.ex.cancel(oid)
        return oid

    w.ex.place_ioc_sell = place


# ------------------------------------------------------------------ randomized invariants

OWNER_SOL = 10.0  # coins of the same asset that are the owner's, not the bot's
FAIL_BEFORE = ["place_stop", "place_bracket", "place_ioc_sell", "cancel", "get_order", "open_orders", "fills",
               "balances", "bid_ask", "get_order_by_client_id", "products"]
FAIL_AFTER = ["place_stop", "place_bracket", "place_ioc_sell"]  # the order is created, the reply is lost
STATUS_READS = {"open_orders", "get_order", "products"}  # without these the bot cannot see the venue at all
SEEDS = [10, 15, 1114]  # 10 and 15 fail if coverage ignores gaps beside an IOC, or sizes keep float noise


def truth(w, pid="SOL-USD"):
    """What the venue's own order book says the bot holds and has resting (every order is the bot's)."""
    orders = [o for o in w.ex._orders.values() if o.product_id == pid]
    qty = sum(o.filled_size for o in orders if o.kind == "entry") \
        - sum(o.filled_size for o in orders if o.kind != "entry")
    sells = sum(o.remaining for o in orders if o.kind != "entry" and o.status == "open")
    return round(qty, 9), round(sells, 9)


def check_invariants(w, closes, synced, pid="SOL-USD"):
    qty, sells = truth(w, pid)
    pos = w.position(pid)
    where = f"qty {qty} sells {sells} pos {pos}"
    # 2. open sells never exceed the bot's position, although the account holds far more coins
    assert sells <= qty + 1e-9, where
    assert w.ex.balances().get("SOL", 0.0) == pytest.approx(OWNER_SOL + qty, abs=1e-9), where  # owner's untouched
    # the stored position is the order-status quantity, whatever fills() has or has not reported
    if synced:
        assert (pos.base_size if pos else 0.0) == pytest.approx(qty, abs=1e-9), where
    # 1. the coins are covered, or dust, or a forced exit is retrying with the bid below the stop
    need = round_down(qty + 1e-9, 0.001)
    if need >= 0.01 and abs(sells - need) > 1e-9:
        episodes = json.loads(w.store.get_meta("episodes") or "{}")
        assert pos is not None and w.ex.bid_ask(pid)[0] < pos.stop_price and f"forced|{pid}" in episodes, where
    # 3. one trade_closed row and one on_trade_closed call per closed trade
    ids = [r["data"]["trade_id"] for r in w.store.journal_rows("trade_closed")]
    assert len(ids) == len(set(ids)) == len(closes), where
    return need >= 0.01 and abs(sells - need) > 1e-9


def random_bar(w, rng):
    last = w.c4h[-1].close
    kind = rng.choices(["up", "flat", "down", "gap", "recover"], [4, 3, 3, 2, 2])[0]
    if kind == "gap":  # opens far below: stop-limits cannot fill
        c = round(last * rng.uniform(0.70, 0.80), 2)
        w.bar(c, low=c - 2, high=c + 2, open_=c)
    elif kind == "recover":
        c = round(last * rng.uniform(1.15, 1.35), 2)
        w.bar(c, low=c - 2, high=c + 2, open_=c)
    else:
        lo, hi = {"up": (1.02, 1.09), "flat": (0.98, 1.02), "down": (0.91, 0.98)}[kind]
        w.bar(round(last * rng.uniform(lo, hi), 2))


def random_venue_event(w, rng):
    r = rng.random()
    open_ = [o for o in w.ex._orders.values() if o.status == "open"]
    if r < 0.35:
        random_bar(w, rng)
    elif r < 0.55 and open_:  # a partial (or complete) fill of any resting order
        o = rng.choice(open_)
        size = round_down(o.remaining * rng.choice([0.25, 0.5, 1.0]), 0.001)
        if size > 0:
            w.ex.partial_fill(o.order_id, size, o.limit_price, w.clock.t)
    elif r < 0.62 and open_:  # an order cancelled behind the bot's back (IOC remainder, stop, entry)
        w.ex.cancel(rng.choice(open_).order_id)
    elif r < 0.75:  # fills() starts lagging, or catches up
        if w.ex.hold_fills and rng.random() < 0.5:
            w.ex.release_fills()
        w.ex.hold_fills = not w.ex.hold_fills
    elif r < 0.80:  # fills() sizes stop summing to filled_size (or sum again)
        w.ex.fill_size_factor = rng.choice([1.0, 0.9997, 0.8])
    elif r < 0.84:
        w.ex.report_avg_price = not w.ex.report_avg_price


def random_run(seed, closes, episodes=12, steps_each=40):
    """Episodes of one entry each, driven by random venue events, failures and engine calls, with
    the invariants asserted after every step. Returns counters describing what the run exercised."""
    import random
    rng = random.Random(seed)
    stats = {"steps": 0, "backoff": 0, "lagged": 0, "closed": 0, "fired": 0}
    for _ in range(episodes):
        del closes[:]
        w = World(brackets=rng.random() < 0.5, cfg=Config(fill_wait_cycles=rng.choice([1, 3])))
        assert w.engine.run_cycle().entered == ["SOL-USD"]
        w.ex._coins["SOL"] = OWNER_SOL
        if rng.random() < 0.4:  # IOCs as on a real venue: done, wholly or partly filled, as they are placed
            instant_ioc(w, rng.choice([1.0, 0.5, 0.0]))
        for _ in range(steps_each):
            random_venue_event(w, rng)
            armed = method = None
            if rng.random() < 0.3:
                armed = "fail_next" if rng.random() < 0.6 else "fail_after_next"
                method = rng.choice(FAIL_BEFORE if armed == "fail_next" else FAIL_AFTER)
                setattr(w.ex, armed, method)
            w.clock.t += 5
            (w.engine.run_cycle if rng.random() < 0.4 else w.engine.watch_fills)()
            fired = armed is not None and getattr(w.ex, armed) is None
            w.ex.fail_next = w.ex.fail_after_next = None
            if fired and method in STATUS_READS:
                # the bot could not read order status this time: its view is one poll old, so the
                # invariants are asserted after its next 5 s poll (they hold for what it last saw)
                w.clock.t += 5
                w.engine.watch_fills()
            # every other failure or lost reply (placements, cancels, balances, prices, fills,
            # lookups) is repaired inside the same call
            stats["backoff"] += check_invariants(w, closes, synced=True)
            stats["lagged"] += w.ex.hold_fills
            stats["fired"] += fired
            stats["steps"] += 1
        # settle: fills catch up (or the bounded wait runs out) and every flat trade has closed once
        w.ex.release_fills()
        w.ex.hold_fills = False
        for _ in range(4):
            w.clock.t += 5
            w.engine.run_cycle()
            check_invariants(w, closes, synced=True)
        opened = {r["data"]["trade_id"] for r in w.store.journal_rows("entry_fill")}
        still_open = {t["id"] for t in json.loads(w.store.get_meta("trades") or "{}").values()}
        closed = {r["data"]["trade_id"] for r in w.store.journal_rows("trade_closed")}
        assert json.loads(w.store.get_meta("closing") or "{}") == {}
        assert closed == opened - still_open
        assert not [r for r in w.store.journal_rows("error") if "traceback" in r["data"]]  # no engine bug
        stats["closed"] += len(closed)
    return stats


@pytest.mark.parametrize("seed", SEEDS)
def test_random_fill_lag_lost_replies_gaps_keep_the_invariants(monkeypatch, seed):
    stats = random_run(seed, count_closes(monkeypatch))
    # the run really exercised it, and "in backoff" stayed the rare exception, not the way to pass
    assert stats["steps"] == 480 and stats["closed"] >= 5 and stats["lagged"] > 100 and stats["fired"] >= 8
    assert stats["backoff"] < stats["steps"] // 4


def test_ioc_that_is_done_as_it_is_placed_closes_the_trade_in_the_same_cycle(monkeypatch):
    calls = count_closes(monkeypatch)
    w = World()
    w.enter()
    instant_ioc(w)
    gap_below_stop(w)
    r = w.cycle()
    assert r.exited == ["SOL-USD"] and w.position() is None and w.ex.open_orders() == []
    assert len(w.store.journal_rows("trade_closed")) == 1 and len(calls) == 1
    assert "forced|SOL-USD" not in json.loads(w.store.get_meta("episodes"))  # no episode outlives the position
    assert w.titles().count("forced exit") == 1 and w.titles().count("forced exit ended") == 1
    assert not w.engine.needs_watch()


def test_partly_filled_instant_ioc_is_retried_for_the_rest_only():
    w = World()
    pos = w.enter()
    instant_ioc(w, fraction=0.5)
    gap_below_stop(w)
    t0 = w.clock.t
    w.engine.run_cycle()
    sold = round_down(pos.base_size * 0.5, 0.001)
    assert w.position().base_size == pytest.approx(pos.base_size - sold) and w.engine.needs_watch()
    w.clock.t = t0 + 5
    w.engine.watch_fills()  # the backoff has passed: a second IOC, for what is left
    iocs = [o for o in w.ex._orders.values() if o.kind == "ioc"]
    assert [o.base_size for o in iocs] == pytest.approx([pos.base_size, pos.base_size - sold])
    assert w.ex.balances()["SOL"] == pytest.approx(w.position().base_size)


def test_instant_target_ioc_takes_half_and_moves_the_rest_to_break_even():
    w = World(brackets=False)
    pos = w.enter()
    instant_ioc(w)
    for close in (130.0, 140.0, 150.0, 160.0):
        w.bar(close)
        w.cycle()  # check_covered each time
    after = w.position()
    a = round_down(pos.base_size / 2, 0.001)
    assert after.half_taken and after.base_size == pytest.approx(pos.base_size - a)
    w.cycle()
    assert w.position().stop_price >= ENTRY and w.sells() == pytest.approx(after.base_size)


@pytest.fixture(autouse=True)
def _reports_in_tmp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # the daily report is written under the working directory


def test_first_cycle_of_a_day_writes_report_and_alerts_once():
    w = World()
    w.cycle()
    report = Path("reports") / f"{DAY0}.txt"
    assert "Daily report" in report.read_text()
    assert w.titles().count(f"daily report {DAY0}") == 1
    w.clock.t += 900
    w.cycle()
    assert w.titles().count(f"daily report {DAY0}") == 1
    w.clock.t += D1
    w.cycle()
    assert len(w.titles()) and sum(t.startswith("daily report") for t in w.titles()) == 2


def test_open_shadow_is_resolved_by_later_hourly_candles():
    w = World(entry=("veto", 0.0))
    w.cycle()
    [shadow] = w.store.open_shadows()
    t = shadow["ts"]
    w.ex.feed("SOL-USD", 3600, Candle(t, 125, 126, 119.0, 120, 1))  # trades through the entry
    w.ex.feed("SOL-USD", 3600, Candle(t + 3600, 120, 130, 101.0, 105, 1))  # then through the stop
    w.cycle()
    assert w.store.open_shadows() == []
    assert w.store.closed_shadows()[0]["r_multiple"] == -1.0
