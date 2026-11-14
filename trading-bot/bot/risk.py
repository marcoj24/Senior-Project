from dataclasses import dataclass
from decimal import ROUND_FLOOR, Decimal

from bot.config import Config
from bot.models import Candidate, Product, Regime

_EPS = 1e-9  # guards exact-boundary float comparisons (e.g. 100 * (1 - 0.06) vs 94.0)


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


@dataclass
class RiskState:
    peak_equity: float
    day: str  # UTC "YYYY-MM-DD"
    day_start_equity: float
    kill_switch: bool
    consecutive_losses: int
    post_reset_remaining: int


@dataclass(frozen=True)
class LimitStatus:
    can_enter: bool
    reason: str | None
    kill_triggered: bool


def roll_day(state: RiskState, equity: float, today: str) -> None:
    if today != state.day:
        state.day = today
        state.day_start_equity = equity


def check_limits(state: RiskState, equity: float, cfg: Config) -> LimitStatus:
    state.peak_equity = max(state.peak_equity, equity)
    if state.kill_switch:
        return LimitStatus(False, "kill switch latched", False)
    if equity <= state.peak_equity * (1 - cfg.kill_drawdown) + _EPS:
        state.kill_switch = True
        return LimitStatus(False, "kill switch triggered", True)
    if equity <= state.day_start_equity * (1 - cfg.daily_loss_halt) + _EPS:
        return LimitStatus(False, "daily loss halt", False)
    return LimitStatus(True, None, False)


def on_trade_closed(state: RiskState, pnl_usd: float, cfg: Config) -> None:
    if pnl_usd < 0:
        state.consecutive_losses += 1
    else:
        state.consecutive_losses = 0
    if state.post_reset_remaining > 0:
        state.post_reset_remaining -= 1


def risk_multiplier(state: RiskState, cfg: Config) -> float:
    mult = 1.0
    if state.consecutive_losses >= cfg.streak_losses:
        mult *= cfg.streak_factor
    if state.post_reset_remaining > 0:
        mult *= cfg.post_reset_factor
    return mult


def reset_kill_switch(state: RiskState, equity: float, cfg: Config) -> None:
    state.kill_switch = False
    state.peak_equity = equity
    state.post_reset_remaining = cfg.post_reset_trades


def apply_transfer(state: RiskState, amount_usd: float) -> None:
    state.peak_equity += amount_usd
    state.day_start_equity += amount_usd


def max_positions(equity: float, cfg: Config) -> int:
    for limit, count in cfg.tiers:
        if equity < limit:
            return count
    return cfg.tiers[-1][1]


_MAJORS = {"BTC-USD", "ETH-USD"}


def correlation_ok(candidate_id: str, held_ids: list[str], regime: Regime) -> bool:
    is_major = candidate_id in _MAJORS
    if regime == "risk_on":
        same_group = sum((h in _MAJORS) == is_major for h in held_ids)
        return same_group < 2
    if is_major:
        return True
    return sum(h not in _MAJORS for h in held_ids) < 2
