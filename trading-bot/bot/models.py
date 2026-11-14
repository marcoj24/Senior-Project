from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True)
class Candle:
    ts: int  # candle start, epoch seconds
    open: float
    high: float
    low: float
    close: float
    volume: float


@dataclass(frozen=True)
class Product:
    product_id: str
    base: str
    quote: str
    base_increment: float
    quote_increment: float
    min_base_size: float
    status: str  # online|disabled|cancel_only|limit_only
    volume_24h_usd: float


@dataclass(frozen=True)
class Fees:
    maker: float
    taker: float


Regime = Literal["risk_on", "neutral", "risk_off"]


@dataclass(frozen=True)
class Candidate:
    product_id: str
    entry: float
    stop: float
    target: float
    atr: float
    breakout_level: float
    rs_score: float
    setup_ts: int


@dataclass
class Leg:
    order_id: str
    base_size: float
    kind: Literal["bracket", "stop"]
    stop_price: float


@dataclass
class Position:
    product_id: str
    base_size: float
    entry_price: float
    stop_price: float
    target_price: float
    atr: float
    opened_ts: int
    legs: list[Leg] = field(default_factory=list)
    half_taken: bool = False
    highest_close: float = 0.0


@dataclass(frozen=True)
class Order:
    order_id: str
    client_order_id: str
    product_id: str
    kind: Literal["entry", "bracket", "stop", "ioc"]
    base_size: float
    filled_size: float
    status: Literal["open", "filled", "cancelled"]
    limit_price: float | None
    stop_trigger: float | None
    target: float | None
    created_ts: int
    avg_fill_price: float | None = None  # the venue's own average price of what has filled, if it reports one


@dataclass(frozen=True)
class Fill:
    order_id: str
    product_id: str
    side: Literal["buy", "sell"]
    price: float
    base_size: float
    fee: float
    ts: int
    reason: Literal["entry", "stop", "target", "ioc"]


@dataclass(frozen=True)
class Transfer:
    ts: int
    amount_usd: float  # + deposit, - withdrawal
