import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from bot.alerts import Alerts
from bot.config import Config
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

    def __init__(self, entry=("approve", 1.0), regime_mult=1.0, btc_step=1.0, cfg=None):
        self.cfg = cfg or Config()
        self.ex = PaperExchange(1000.0, FEES, [product("SOL-USD"), product("BTC-USD")])
        for c in daily(50.0, 0.3):
            self.ex.feed("SOL-USD", D1, c, fills=False)
        for c in daily(1000.0, btc_step):
            self.ex.feed("BTC-USD", D1, c, fills=False)
        self.c4h = setup_4h()
        for c in self.c4h:
            self.ex.feed("SOL-USD", H4, c)
        self.clock = Clock(T0)
        self.llm = FakeLLM(entry, regime_mult)
        self.alerts = Alerts()
        self.store = Store(":memory:")
        self.engine = self.make_engine(self.store)

    def make_engine(self, store: Store) -> Engine:
        reviewer = Reviewer(self.cfg, store, self.llm, PROMPT)
        return Engine(self.cfg, self.ex, store, reviewer, self.alerts, self.clock)

    def bar(self, close, low=None, high=None, open_=None):
        """Feed the next 4h SOL candle (fills on) and move the clock to its close."""
        o = self.c4h[-1].close if open_ is None else open_
        ts = self.c4h[-1].ts + H4
        c = Candle(ts, o, high if high is not None else max(o, close) + S,
                   low if low is not None else min(o, close) - S, close, 1000.0)
        self.c4h.append(c)
        self.ex.feed("SOL-USD", H4, c)
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
        held = sum(p.base_size for p in self.store.positions())
        coins = self.ex.balances().get("SOL", 0.0)
        assert held == pytest.approx(coins, abs=1e-9)
        assert self.sells() == pytest.approx(coins, abs=1e-9)

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
    r = w.cycle()
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
    w.cycle()  # and so is the forced exit
    assert "forced exit" in w.titles()
    assert [o.kind for o in w.ex.open_orders()] == ["ioc"]


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
