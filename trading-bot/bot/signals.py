from bot.config import Config
from bot.indicators import atr, donchian_high, ema, sma
from bot.models import Candidate, Candle

H4 = 14_400
D1 = 86_400
LOOKBACK_4H = 60
LOOKBACK_1D = 210
RS_LOOKBACK = 31  # a 30-day return needs 31 daily closes


def closed(candles: list[Candle], interval_s: int, now_ts: int) -> list[Candle]:
    """Candles whose interval has ended by `now_ts` (`ts` is the candle start)."""
    return [c for c in candles if c.ts + interval_s <= now_ts]


def series_is_fresh(candles: list[Candle], interval_s: int, now_ts: int, lookback: int) -> bool:
    """False if the last candle closed more than one interval ago, or any gap exists in the last
    `lookback` candles. A series shorter than `lookback` cannot be checked and is not fresh."""
    if lookback < 1 or len(candles) < lookback:
        return False
    if now_ts - (candles[-1].ts + interval_s) > interval_s:
        return False
    window = candles[-lookback:]
    return all(b.ts - a.ts == interval_s for a, b in zip(window, window[1:]))


def _ret(closes: list[float], days: int) -> float:
    return closes[-1] / closes[-1 - days] - 1


def relative_strength(c1d: list[Candle], btc_1d: list[Candle]) -> float:
    """Mean of (7-day return - BTC 7-day return) and (30-day return - BTC 30-day return)."""
    if len(c1d) < RS_LOOKBACK or len(btc_1d) < RS_LOOKBACK:
        raise ValueError(f"relative_strength needs {RS_LOOKBACK} daily candles")
    a = [c.close for c in c1d]
    b = [c.close for c in btc_1d]
    return ((_ret(a, 7) - _ret(b, 7)) + (_ret(a, 30) - _ret(b, 30))) / 2


def find_candidate(product_id: str, c4h: list[Candle], c1d: list[Candle], btc_1d: list[Candle],
                   now_ts: int, cfg: Config) -> Candidate | None:
    c4h = closed(c4h, H4, now_ts)
    c1d = closed(c1d, D1, now_ts)
    btc_1d = closed(btc_1d, D1, now_ts)

    # 1. Fresh, gap-free data (BTC too: a stale BTC series would skew relative strength).
    if not (series_is_fresh(c4h, H4, now_ts, LOOKBACK_4H)
            and series_is_fresh(c1d, D1, now_ts, LOOKBACK_1D)
            and series_is_fresh(btc_1d, D1, now_ts, RS_LOOKBACK)):
        return None

    # 2. Trend.
    closes = [c.close for c in c4h]
    ema20 = ema(closes, 20)
    ema50 = ema(closes, 50)
    d_closes = [c.close for c in c1d]
    if not (ema20[-1] > ema50[-1] and d_closes[-1] > ema(d_closes, 200)[-1]):
        return None

    # 3. Most recent breakout within the setup window.
    donch = donchian_high(c4h, 20)
    vol_sma = sma([c.volume for c in c4h], 20)
    first = max(len(c4h) - cfg.setup_valid_candles, 0)
    b = next((i for i in range(len(c4h) - 1, first - 1, -1)
              if donch[i] is not None and vol_sma[i] is not None
              and c4h[i].close > donch[i] and c4h[i].volume > vol_sma[i]), None)
    if b is None:
        return None
    level = donch[b]

    # 4. Setup failed if any later close fell below level - 1 ATR.
    cur_atr = atr(c4h, 14)[-1]
    if any(c.close < level - cur_atr for c in c4h[b + 1:]):
        return None

    # 5. Retest entry, never a chase.
    entry = max(level, ema20[-1])
    if not entry < closes[-1]:
        return None

    # 6. Stop and target.
    distance = min(max(cfg.stop_atr_mult * cur_atr, cfg.stop_min * entry), cfg.stop_max * entry)
    return Candidate(
        product_id=product_id,
        entry=entry,
        stop=entry - distance,
        target=entry + cfg.target_r * distance,
        atr=cur_atr,
        breakout_level=level,
        rs_score=relative_strength(c1d, btc_1d),
        setup_ts=c4h[b].ts,
    )
