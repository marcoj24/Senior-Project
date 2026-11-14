import pytest

from bot.indicators import atr, donchian_high, ema, sma
from bot.models import Candle


def test_ema_seed_and_step():
    out = ema([1, 2, 3, 4, 5], 3)
    assert out[:2] == [None, None] and out[2] == 2.0
    assert out[3] == pytest.approx(3.0) and out[4] == pytest.approx(4.0)


def test_donchian_excludes_current():
    cs = [Candle(i, 1, h, 1, 1, 1) for i, h in enumerate([5, 6, 7, 99])]
    assert donchian_high(cs, 3)[3] == 7


def test_atr_constant_range():
    cs = [Candle(i, 10, 11, 9, 10, 1) for i in range(20)]
    assert atr(cs, 14)[-1] == pytest.approx(2.0)


def test_short_series_is_all_none():
    assert ema([1, 2], 3) == [None, None]


def test_sma():
    assert sma([1, 2, 3, 4], 2) == [None, 1.5, 2.5, 3.5]
