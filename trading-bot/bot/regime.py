from bot.indicators import ema
from bot.models import Candle, Regime


def raw_regime(btc_daily: list[Candle], breadth: float) -> Regime:
    if len(btc_daily) < 200:
        return "neutral"
    closes = [c.close for c in btc_daily]
    ema50 = ema(closes, 50)[-1]
    ema200 = ema(closes, 200)[-1]
    close = closes[-1]
    if close > ema200 and ema50 > ema200 and breadth >= 0.5:
        return "risk_on"
    if close < ema200 and (ema50 < ema200 or breadth < 0.3):
        return "risk_off"
    return "neutral"


def breadth(daily_by_product: dict[str, list[Candle]]) -> float:
    """Share of products whose last close is above their EMA50 (products with <50 candles are not counted)."""
    above = total = 0
    for candles in daily_by_product.values():
        e = ema([c.close for c in candles], 50)[-1] if candles else None
        if e is None:
            continue
        total += 1
        above += candles[-1].close > e
    return above / total if total else 0.0


def confirmed_regime(previous: Regime, raw_today: Regime, raw_yesterday: Regime) -> Regime:
    if raw_today == raw_yesterday and raw_today != previous:
        return raw_today
    return previous
