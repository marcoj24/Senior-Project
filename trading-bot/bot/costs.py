from dataclasses import dataclass

from bot.config import Config
from bot.models import Fees

_EPS = 1e-9  # guards exact-boundary float comparisons (e.g. 0.020 vs 0.2 * 0.1)


@dataclass(frozen=True)
class CostCheck:
    win_cost: float  # fraction of entry
    loss_cost: float  # fraction of entry
    net_rr: float
    passed: bool
    reason: str


def evaluate_costs(
    entry: float, stop: float, target: float, fees: Fees, spread: float, cfg: Config
) -> CostCheck:
    stop_frac = (entry - stop) / entry
    target_frac = (target - entry) / entry
    win_cost = 2 * fees.maker + spread
    loss_cost = fees.maker + fees.taker + spread + cfg.slippage
    net_rr = (target_frac - win_cost) / (stop_frac + loss_cost)

    reasons = []
    if loss_cost > cfg.cost_max_frac_of_stop * stop_frac + _EPS:
        reasons.append(
            f"cost share too high: loss cost {loss_cost:.4f} > "
            f"{cfg.cost_max_frac_of_stop:.0%} of stop {stop_frac:.4f}"
        )
    if net_rr < cfg.min_net_rr - _EPS:
        reasons.append(f"net reward-to-risk {net_rr:.2f} < {cfg.min_net_rr}")
    return CostCheck(win_cost, loss_cost, net_rr, not reasons, "; ".join(reasons))
