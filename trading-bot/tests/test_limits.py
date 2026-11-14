from bot.config import Config
from bot.risk import (
    RiskState,
    apply_transfer,
    check_limits,
    correlation_ok,
    max_positions,
    on_trade_closed,
    reset_kill_switch,
    risk_multiplier,
    roll_day,
)


def test_daily_halt_at_six_percent():
    s = RiskState(100, "2026-01-01", 100, False, 0, 0)
    assert check_limits(s, 94.1, Config()).can_enter
    st = check_limits(s, 94.0, Config())
    assert not st.can_enter and "daily" in st.reason


def test_kill_switch_latches_until_reset():
    s = RiskState(100, "2026-01-01", 80, False, 0, 0)
    assert check_limits(s, 75.0, Config()).kill_triggered and s.kill_switch
    assert not check_limits(s, 99.0, Config()).can_enter  # still latched after recovery
    reset_kill_switch(s, 76.0, Config())
    assert (s.kill_switch, s.peak_equity, s.post_reset_remaining) == (False, 76.0, 10)
    assert risk_multiplier(s, Config()) == 0.5


def test_peak_ratchets_up_and_kill_is_measured_from_it():
    s = RiskState(100, "2026-01-01", 100, False, 0, 0)
    assert check_limits(s, 120.0, Config()).can_enter and s.peak_equity == 120.0
    s.day_start_equity = 0.0  # isolate the drawdown rule from the daily halt
    assert not check_limits(s, 90.1, Config()).kill_triggered  # 90.1 > 120 * 0.75
    assert check_limits(s, 90.0, Config()).kill_triggered


def test_roll_day_resets_day_start_only_on_new_day():
    s = RiskState(100, "2026-01-01", 100, False, 0, 0)
    roll_day(s, 90.0, "2026-01-01")
    assert (s.day, s.day_start_equity) == ("2026-01-01", 100)
    roll_day(s, 90.0, "2026-01-02")
    assert (s.day, s.day_start_equity) == ("2026-01-02", 90.0)


def test_post_reset_counter_counts_down_to_zero():
    s = RiskState(100, "d", 100, False, 0, 10)
    for _ in range(10):
        on_trade_closed(s, +1, Config())
    assert s.post_reset_remaining == 0 and risk_multiplier(s, Config()) == 1.0
    on_trade_closed(s, +1, Config())
    assert s.post_reset_remaining == 0


def test_streak_and_post_reset_factors_multiply():
    s = RiskState(100, "d", 100, False, 3, 5)
    assert risk_multiplier(s, Config()) == 0.25


def test_streak_brake():
    s = RiskState(100, "d", 100, False, 0, 0)
    for _ in range(3):
        on_trade_closed(s, -1, Config())
    assert risk_multiplier(s, Config()) == 0.5
    on_trade_closed(s, +1, Config())
    assert risk_multiplier(s, Config()) == 1.0


def test_deposit_is_not_a_gain():
    s = RiskState(100, "d", 100, False, 0, 0)
    apply_transfer(s, 50)
    assert (s.peak_equity, s.day_start_equity) == (150, 150)


def test_tiers():
    assert [max_positions(e, Config()) for e in (25, 100, 999, 1000, 10000)] == [2, 3, 3, 5, 6]


def test_alts_are_one_group_outside_risk_on():
    assert not correlation_ok("SOL-USD", ["AVAX-USD", "LINK-USD"], "neutral")
    assert correlation_ok("BTC-USD", ["AVAX-USD", "LINK-USD"], "neutral")


def test_risk_on_allows_two_per_group():
    held = ["AVAX-USD", "LINK-USD"]
    assert not correlation_ok("SOL-USD", held, "risk_on")
    assert correlation_ok("SOL-USD", ["AVAX-USD"], "risk_on")
    assert correlation_ok("BTC-USD", held, "risk_on")
    assert correlation_ok("ETH-USD", ["BTC-USD"], "risk_on")
