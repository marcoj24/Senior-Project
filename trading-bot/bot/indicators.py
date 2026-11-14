from bot.models import Candle


def sma(values: list[float], period: int) -> list[float | None]:
    out: list[float | None] = [None] * len(values)
    for i in range(period - 1, len(values)):
        out[i] = sum(values[i - period + 1 : i + 1]) / period
    return out


def ema(values: list[float], period: int) -> list[float | None]:
    out: list[float | None] = [None] * len(values)
    if len(values) < period:
        return out
    prev = sum(values[:period]) / period
    out[period - 1] = prev
    k = 2 / (period + 1)
    for i in range(period, len(values)):
        prev = values[i] * k + prev * (1 - k)
        out[i] = prev
    return out


def atr(candles: list[Candle], period: int = 14) -> list[float | None]:
    """Average true range with Wilder smoothing, seeded with the SMA of the first `period` true ranges."""
    out: list[float | None] = [None] * len(candles)
    if len(candles) < period:
        return out
    trs = [candles[0].high - candles[0].low]
    for i in range(1, len(candles)):
        c, pc = candles[i], candles[i - 1].close
        trs.append(max(c.high - c.low, abs(c.high - pc), abs(c.low - pc)))
    prev = sum(trs[:period]) / period
    out[period - 1] = prev
    for i in range(period, len(candles)):
        prev = (prev * (period - 1) + trs[i]) / period
        out[i] = prev
    return out


def donchian_high(candles: list[Candle], period: int = 20) -> list[float | None]:
    """Max high of the previous `period` candles, excluding the current one."""
    out: list[float | None] = [None] * len(candles)
    for i in range(period, len(candles)):
        out[i] = max(c.high for c in candles[i - period : i])
    return out
