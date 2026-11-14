import pytest

from bot.config import Config
from bot.models import Candidate, Product
from bot.risk import round_down, size_position

CAND = Candidate("SOL-USD", 100.0, 90.0, 120.0, 4.0, 98.0, 1.0, 0)
PROD = Product("SOL-USD", "SOL", "USD", 0.001, 0.01, 0.01, "online", 1e9)


def test_round_down_is_decimal_exact():
    assert round_down(0.0625, 0.001) == 0.062
    assert round_down(0.3, 0.1) == 0.3  # float 0.3 // 0.1 would give 2 steps
    assert round_down(1.999, 0.01) == 1.99


def test_twenty_five_dollar_account():
    r = size_position(25, 25, 0, 0, CAND, 0.02, PROD, 1.0, Config())
    assert r.base_size == 0.062 and r.quote_value == pytest.approx(6.2)  # 0.75 / 0.12 = 6.25 -> rounded down
    assert r.risk_usd == pytest.approx(0.744) and r.skipped is None


def test_risk_includes_costs():
    # loss_cost 0 -> 0.75 / 0.10 = 7.5 (under the 12.5 cap), larger than with costs
    r = size_position(25, 25, 0, 0, CAND, 0.0, PROD, 1.0, Config())
    assert r.base_size == 0.075 and r.quote_value == pytest.approx(7.5)


def test_heat_cap_shrinks_then_skips():
    assert size_position(1000, 1000, 70, 0, CAND, 0.02, PROD, 1.0, Config()).risk_usd <= 10.0
    assert size_position(1000, 1000, 80, 0, CAND, 0.02, PROD, 1.0, Config()).skipped == "heat cap"


def test_position_cap_small_account():
    cand = Candidate("SOL-USD", 100.0, 95.0, 110.0, 4.0, 98.0, 1.0, 0)
    # risk 1.5 / 0.05 = 30, capped at 50% of 50 = 25
    r = size_position(50, 50, 0, 0, cand, 0.0, PROD, 1.0, Config())
    assert r.base_size == 0.25 and r.quote_value == pytest.approx(25.0)
    assert r.risk_usd == pytest.approx(1.25)


def test_cash_cap():
    r = size_position(1000, 10, 0, 0, CAND, 0.02, PROD, 1.0, Config())
    assert r.base_size == 0.099 and r.quote_value == pytest.approx(9.9)


def test_multiplier_floor_skips():
    assert size_position(25, 25, 0, 0, CAND, 0.02, PROD, 0.2, Config()).skipped == "multiplier below floor"


def test_below_minimum_skips():
    r = size_position(1.0, 1.0, 0, 0, CAND, 0.02, PROD, 1.0, Config())
    assert r.skipped == "below minimum" and r.base_size == 0.0


def test_invalid_stop_skips():
    cand = Candidate("SOL-USD", 100.0, 100.0, 120.0, 4.0, 98.0, 1.0, 0)
    assert size_position(25, 25, 0, 0, cand, 0.0, PROD, 1.0, Config()).skipped == "invalid stop"
