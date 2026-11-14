from dataclasses import dataclass
from decimal import ROUND_FLOOR, Decimal

from bot.config import Config
from bot.models import Candidate, Product


@dataclass(frozen=True)
class SizeResult:
    base_size: float
    quote_value: float
    risk_usd: float
    skipped: str | None


def round_down(value: float, increment: float) -> float:
    inc = Decimal(str(increment))
    steps = (Decimal(str(value)) / inc).to_integral_value(rounding=ROUND_FLOOR)
    return float(steps * inc)


def _skip(reason: str) -> SizeResult:
    return SizeResult(0.0, 0.0, 0.0, reason)


def size_position(
    equity: float,
    cash: float,
    open_risk_usd: float,
    open_exposure_usd: float,
    cand: Candidate,
    loss_cost: float,
    product: Product,
    multiplier: float,
    cfg: Config,
) -> SizeResult:
    if multiplier < cfg.min_size_mult:
        return _skip("multiplier below floor")
    heat_room = equity * cfg.max_open_risk - open_risk_usd
    if heat_room <= 0:
        return _skip("heat cap")
    risk_usd = min(equity * cfg.risk_per_trade * multiplier, heat_room)
    loss_per_usd = (cand.entry - cand.stop) / cand.entry + loss_cost
    value = risk_usd / loss_per_usd
    position_cap = cfg.max_position_small if equity < cfg.small_equity else cfg.max_position
    value = min(
        value,
        position_cap * equity,
        equity * cfg.max_exposure - open_exposure_usd,
        cash * 0.99,
    )
    if value <= 0:
        return _skip("below minimum")
    base_size = round_down(value / cand.entry, product.base_increment)
    if base_size < product.min_base_size:
        return _skip("below minimum")
    return SizeResult(
        base_size=base_size,
        quote_value=base_size * cand.entry,
        risk_usd=base_size * cand.entry * loss_per_usd,
        skipped=None,
    )
