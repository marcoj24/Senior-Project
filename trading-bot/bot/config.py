from dataclasses import dataclass, field, fields

import yaml


def _default_tiers() -> list[tuple[float, int]]:
    return [(100, 2), (1000, 3), (10000, 5), (float("inf"), 6)]


@dataclass
class Config:
    mode: str = "paper"  # paper | live (live also needs --i-understand-live)
    cycle_minutes: int = 15
    fill_poll_seconds: int = 5
    risk_per_trade: float = 0.03
    max_open_risk: float = 0.08
    stop_atr_mult: float = 2.0
    stop_min: float = 0.05
    stop_max: float = 0.15
    max_position_small: float = 0.50
    max_position: float = 0.35
    small_equity: float = 100
    max_exposure: float = 1.0
    daily_loss_halt: float = 0.06
    kill_drawdown: float = 0.25
    streak_losses: int = 3
    streak_factor: float = 0.5
    post_reset_trades: int = 10
    post_reset_factor: float = 0.5
    min_size_mult: float = 0.25
    cost_max_frac_of_stop: float = 0.20
    min_net_rr: float = 1.5
    target_r: float = 2.0
    slippage: float = 0.001
    stop_limit_offset: float = 0.05
    trail_min_improve_atr: float = 0.5
    entry_ttl_hours: int = 24
    fill_wait_cycles: int = 3  # cycles a finished order waits for its fills before it is priced by estimate
    setup_valid_candles: int = 12
    min_volume_24h_usd: float = 5_000_000
    max_spread: float = 0.002
    min_history_days: int = 250
    always_include: list[str] = field(default_factory=lambda: ["BTC-USD", "ETH-USD", "SOL-USD"])
    tiers: list[tuple[float, int]] = field(default_factory=_default_tiers)
    review_enabled: bool = True
    model_small: str = "claude-haiku-5-5"
    model_large: str = "claude-sonnet-5-5"
    model_switch_equity: float = 1000
    max_calls_per_day: int = 6
    monthly_budget_usd: float = 3.0
    scorecard_min: int = 40
    alert_url: str | None = None
    heartbeat_url: str | None = None
    db_path: str = "bot.db"


def load_config(path: str) -> Config:
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError("config must be a YAML mapping")
    unknown = set(data) - {f.name for f in fields(Config)}
    if unknown:
        raise ValueError(f"unknown config keys: {sorted(unknown)}")
    if "tiers" in data:
        data["tiers"] = [(limit, int(count)) for limit, count in data["tiers"]]
    return Config(**data)
