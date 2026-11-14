import pytest

from bot.config import Config
from bot.costs import evaluate_costs
from bot.models import Fees

FEES = Fees(0.006, 0.012)


def test_ten_percent_stop_passes():
    r = evaluate_costs(100, 90, 120, FEES, 0.001, Config())
    assert r.win_cost == pytest.approx(0.013) and r.loss_cost == pytest.approx(0.020)
    assert r.net_rr == pytest.approx(0.187 / 0.120) and r.passed


def test_eight_percent_stop_fails_on_cost_share():
    r = evaluate_costs(100, 92, 116, FEES, 0.001, Config())
    assert not r.passed and "cost" in r.reason


def test_lower_fees_let_tighter_stops_pass():
    assert evaluate_costs(100, 94, 112, Fees(0.0025, 0.004), 0.001, Config()).passed


def test_wide_spread_fails():
    assert not evaluate_costs(100, 90, 120, FEES, 0.01, Config()).passed
