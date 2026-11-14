from bot.models import Candle
from bot.regime import breadth, confirmed_regime, raw_regime


def _series(closes):
    return [Candle(i, c, c, c, c, 1) for i, c in enumerate(closes)]


UP = _series([float(100 + i) for i in range(260)])
DOWN = _series([float(360 - i) for i in range(260)])


def test_uptrend_with_breadth_is_risk_on():
    assert raw_regime(UP, 0.6) == "risk_on"


def test_downtrend_with_weak_breadth_is_risk_off():
    assert raw_regime(DOWN, 0.2) == "risk_off"


def test_fewer_than_200_candles_is_neutral():
    assert raw_regime(UP[:150], 0.9) == "neutral"


def test_uptrend_with_low_breadth_is_neutral():
    assert raw_regime(UP, 0.4) == "neutral"


def test_breadth_share_above_ema50():
    assert breadth({"A": UP, "B": DOWN}) == 0.5
    assert breadth({}) == 0.0


def test_confirmation_needs_two_matching_closes():
    assert confirmed_regime("risk_on", "risk_off", "risk_on") == "risk_on"
    assert confirmed_regime("risk_on", "risk_off", "risk_off") == "risk_off"
    assert confirmed_regime("neutral", "neutral", "neutral") == "neutral"
