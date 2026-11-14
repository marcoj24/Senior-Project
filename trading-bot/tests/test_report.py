from datetime import datetime, timezone

from bot.config import Config
from bot.models import Candidate, Candle
from bot.report import daily_summary, resolve_shadow, scorecard
from bot.store import Store

CFG = Config()
T = 1_000_000 * 3600
SHADOW = {"ts": T, "entry": 100.0, "stop": 90.0, "target": 120.0}


def c(i, low, high):
    return Candle(T + i * 3600, 100, high, low, 100, 1)


def test_resolve_shadow_four_outcomes():
    assert resolve_shadow(SHADOW, [c(0, 99, 105), c(1, 100, 121)], CFG) == 2.0
    assert resolve_shadow(SHADOW, [c(0, 99, 105), c(1, 89, 110)], CFG) == -1.0
    assert resolve_shadow(SHADOW, [c(0, 89, 121)], CFG) == -1.0  # stop wins a tie
    assert resolve_shadow(SHADOW, [c(i, 100, 110) for i in range(0, 25)], CFG) == 0.0  # never traded through
    assert resolve_shadow(SHADOW, [c(0, 99, 105), c(1, 98, 110)], CFG) is None  # still open


def add_closed(store, n, decision, r):
    cand = Candidate("SOL-USD", 100, 90, 120, 5, 99, 1.0, T)
    for _ in range(n):
        sid = store.add_shadow(cand, decision, 0.0, T)
        store.close_shadow(sid, r)


def add_trades(store, n, r, pnl=1.0, ts=T):
    for i in range(n):
        store.journal("trade_closed", "SOL-USD", {"trade_id": f"{r}-{i}-{ts}", "pnl_usd": pnl, "r_multiple": r}, ts)


def test_scorecard_insufficient_below_minimum():
    s = Store(":memory:")
    add_closed(s, 20, "veto", -0.5)
    add_trades(s, 19, 0.3)
    assert scorecard(s, CFG)["verdict"] == "insufficient"


def test_scorecard_helping_and_not_helping():
    s = Store(":memory:")
    add_closed(s, 20, "veto", -0.5)
    add_trades(s, 20, 0.3)
    sc = scorecard(s, CFG)
    assert sc["reviewed"] == 40 and sc["verdict"] == "helping"
    assert sc["vetoed_avg_r"] == -0.5 and abs(sc["taken_avg_r"] - 0.3) < 1e-9
    assert "recommend switching review off" not in daily_summary(s, 25.0, T, CFG)
    s2 = Store(":memory:")
    add_closed(s2, 20, "veto", 0.5)
    add_trades(s2, 20, -0.3)
    assert scorecard(s2, CFG)["verdict"] == "not helping"
    assert "recommend switching review off" in daily_summary(s2, 25.0, T, CFG)


def test_daily_summary_true_pnl():
    s = Store(":memory:")
    now = int(datetime(2026, 3, 15, 12, tzinfo=timezone.utc).timestamp())
    add_trades(s, 1, 1.0, pnl=5.00, ts=now - 3600)
    s.journal("api_cost", None, {"cost_usd": 1.20}, now - 7200)
    text = daily_summary(s, 30.0, now, CFG)
    assert "true P&L $+3.80" in text and "Equity: $30.00" in text
