from dataclasses import replace

import pytest

from bot.config import Config
from bot.indicators import atr, donchian_high, ema
from bot.models import Candle
from bot.signals import find_candidate, relative_strength

H4 = 14_400
D1 = 86_400
NOW = 20_000 * D1  # a daily and 4h boundary
SPREAD = 1.5  # high = close + SPREAD, low = close - SPREAD -> ATR(14) ~ 3
JUMP = 3.0  # breakout candle closes this much above the trend line
BASE_VOL = 1_000.0


def trend(n: int, start: float, step: float) -> list[float]:
    return [start + i * step for i in range(n)]


def candles(closes, interval, last_ts, volumes=None, spread=SPREAD):
    """Contiguous candles ending with a candle that starts at `last_ts`."""
    first_ts = last_ts - (len(closes) - 1) * interval
    out = []
    for i, c in enumerate(closes):
        o = closes[i - 1] if i else c
        v = volumes[i] if volumes else BASE_VOL
        out.append(Candle(first_ts + i * interval, o, max(o, c) + spread, min(o, c) - spread, c, v))
    return out


def setup_4h(n=80, breakout_at=-3, vol_mult=3.0, last_ts=NOW - H4):
    """Rising 4h series; the candle at `breakout_at` jumps above the Donchian high on `vol_mult` volume."""
    closes = trend(n, 100.0, 0.2)
    b = n + breakout_at
    closes = [c + JUMP if i >= b else c for i, c in enumerate(closes)]
    volumes = [BASE_VOL] * n
    volumes[b] = BASE_VOL * vol_mult
    return candles(closes, H4, last_ts, volumes)


def daily(start=50.0, step=0.3, n=260):
    return candles(trend(n, start, step), D1, NOW - D1, spread=0.5)


C4H = setup_4h()
C1D = daily()
BTC = daily(start=1_000.0, step=1.0)


def test_breakout_then_candidate_at_retest_level():
    closes = [c.close for c in C4H]
    c = find_candidate("SOL-USD", C4H, C1D, BTC, NOW, Config())
    assert c is not None
    assert c.product_id == "SOL-USD"
    assert c.setup_ts == C4H[-3].ts
    assert c.breakout_level == pytest.approx(donchian_high(C4H, 20)[-3])
    assert c.atr == pytest.approx(atr(C4H, 14)[-1])
    assert c.rs_score == pytest.approx(relative_strength(C1D, BTC))
    assert c.entry == pytest.approx(max(c.breakout_level, ema(closes, 20)[-1]))
    assert c.entry < C4H[-1].close
    assert c.target - c.entry == pytest.approx(2 * (c.entry - c.stop))
    assert 0.05 <= (c.entry - c.stop) / c.entry <= 0.15
    # 2 x ATR is inside the 5-15% band here, so the stop is not clamped
    assert c.entry - c.stop == pytest.approx(2 * c.atr)


def test_no_candidate_without_volume():
    flat = setup_4h(vol_mult=1.0)
    assert [c.close for c in flat] == [c.close for c in C4H]
    assert find_candidate("SOL-USD", flat, C1D, BTC, NOW, Config()) is None


def test_no_candidate_below_daily_ema200():
    below = C1D[:-1] + [replace(C1D[-1], close=C1D[0].close, low=C1D[0].close - 0.5)]
    assert below[-1].close < ema([c.close for c in below], 200)[-1]
    assert find_candidate("SOL-USD", C4H, below, BTC, NOW, Config()) is None


def test_unclosed_candle_ignored():
    # Breakout is the newest candle, which started 2h before NOW and is still open.
    series = setup_4h(breakout_at=-1, last_ts=NOW - H4 // 2)
    assert find_candidate("SOL-USD", series, C1D, BTC, NOW + H4 // 2, Config()) is not None  # once it closes
    assert find_candidate("SOL-USD", series, C1D, BTC, NOW, Config()) is None


def test_gap_in_series_gives_none():
    gappy = C4H[:-10] + C4H[-9:]
    assert find_candidate("SOL-USD", gappy, C1D, BTC, NOW, Config()) is None


def test_stale_series_gives_none():
    last_close = C4H[-1].ts + H4
    assert find_candidate("SOL-USD", C4H, C1D, BTC, last_close + 3 * H4, Config()) is None


def test_no_candidate_when_last_close_is_not_above_entry():
    level = donchian_high(C4H, 20)[-3]
    under = C4H[:-1] + [replace(C4H[-1], close=level - 0.5, low=level - 0.5 - SPREAD)]
    assert under[-1].close > level - atr(under, 14)[-1]  # setup has not failed
    assert under[-1].close < max(level, ema([c.close for c in under], 20)[-1])
    assert find_candidate("SOL-USD", under, C1D, BTC, NOW, Config()) is None


def test_failed_setup_gives_none():
    level = donchian_high(C4H, 20)[-3]
    failed = list(C4H)
    drop = level - 3 * atr(C4H, 14)[-1]
    failed[-2] = replace(C4H[-2], close=drop, low=drop - SPREAD)
    failed[-1] = replace(C4H[-1], open=drop, low=drop - SPREAD)
    assert failed[-2].close < level - atr(failed, 14)[-1]
    assert failed[-1].close == C4H[-1].close
    assert find_candidate("SOL-USD", failed, C1D, BTC, NOW, Config()) is None
