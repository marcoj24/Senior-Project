from dataclasses import dataclass

from bot.exchange.base import ExchangeError
from bot.models import Candle, Fees, Fill, Order, Product, Transfer

_EPS = 1e-9  # float tolerance for size and cash comparisons


@dataclass
class _Order:
    order_id: str
    client_order_id: str
    product_id: str
    kind: str  # entry | bracket | stop | ioc
    base_size: float
    limit_price: float | None  # entry/ioc limit, or the stop leg's limit for stop/bracket
    stop_trigger: float | None
    target: float | None
    created_ts: int
    filled_size: float = 0.0
    status: str = "open"
    stop_triggered: bool = False  # bracket: a triggered stop leg has cancelled the target leg

    @property
    def remaining(self) -> float:
        return self.base_size - self.filled_size

    def snapshot(self) -> Order:
        return Order(
            self.order_id, self.client_order_id, self.product_id, self.kind, self.base_size,
            self.filled_size, self.status, self.limit_price, self.stop_trigger, self.target,
            self.created_ts,
        )


class PaperExchange:
    """Simulated venue driven by fed candles. Also the backtest venue and the engine's test fake.

    Fill rules, applied per open order (oldest first) to each candle fed with fills=True:
    - entry: fills at its limit only if candle.low < limit (strictly through); maker fee.
    - stop / bracket stop: triggers if candle.low <= trigger; price = min(trigger, candle.open);
      if that price < stop limit the order stays open (gap) and is retried on later candles
      under the same rule; taker fee. A triggered bracket stop cancels the target leg.
    - bracket target: fills at target if candle.high > target and the stop did not trigger; maker fee.
    - ioc sell: fills at max(limit, close) if close >= limit, else cancels; taker fee.
    """

    def __init__(self, cash: float, fees: Fees, products: list[Product], supports_bracket: bool = True,
                 spread: float = 0.001):
        self.supports_bracket = supports_bracket
        self.fail_next: str | None = None
        self._cash = cash
        self._coins: dict[str, float] = {}
        self._fees = fees
        self._products = {p.product_id: p for p in products}
        self._spread = spread
        self._candles: dict[tuple[str, int], list[Candle]] = {}
        self._last_close: dict[str, float] = {}
        self._orders: dict[str, _Order] = {}
        self._by_client_id: dict[str, str] = {}
        self._fills: list[Fill] = []
        self._transfers: list[Transfer] = []
        self._now = 0

    # --- test and simulation controls -------------------------------------------------------

    def feed(self, product_id: str, granularity_s: int, candle: Candle, fills: bool = True) -> None:
        self._candles.setdefault((product_id, granularity_s), []).append(candle)
        self._last_close[product_id] = candle.close
        self._now = max(self._now, candle.ts)
        if fills:
            for o in list(self._orders.values()):
                if o.status == "open" and o.product_id == product_id:
                    self._process(o, candle)

    def deposit(self, amount: float, ts: int) -> None:
        self._cash += amount
        self._transfers.append(Transfer(ts, amount))

    def partial_fill(self, order_id: str, base_size: float, price: float, ts: int) -> None:
        o = self._orders.get(order_id)
        if o is None or o.kind != "entry" or o.status != "open":
            raise ExchangeError(f"no open entry order {order_id}")
        if base_size <= 0 or base_size > o.remaining + _EPS:
            raise ExchangeError("partial fill size out of range")
        self._fill(o, min(base_size, o.remaining), price, ts, "entry")

    # --- Exchange ---------------------------------------------------------------------------

    def _maybe_fail(self, method: str) -> None:
        if self.fail_next == method:
            self.fail_next = None
            raise ExchangeError(f"injected failure in {method}")

    def products(self) -> list[Product]:
        self._maybe_fail("products")
        return list(self._products.values())

    def candles(self, product_id: str, granularity_s: int, limit: int) -> list[Candle]:
        self._maybe_fail("candles")
        series = self._candles.get((product_id, granularity_s), [])
        return series[-limit:] if limit > 0 else []

    def fees(self) -> Fees:
        self._maybe_fail("fees")
        return self._fees

    def bid_ask(self, product_id: str) -> tuple[float, float]:
        self._maybe_fail("bid_ask")
        if product_id not in self._last_close:
            raise ExchangeError(f"no price for {product_id}")
        close = self._last_close[product_id]
        return close * (1 - self._spread / 2), close * (1 + self._spread / 2)

    def balances(self) -> dict[str, float]:
        self._maybe_fail("balances")
        return {"USD": self._cash, **self._coins}

    def place_entry(self, product_id: str, base_size: float, limit_price: float, client_order_id: str) -> str:
        self._maybe_fail("place_entry")
        if client_order_id in self._by_client_id:
            return self._by_client_id[client_order_id]
        self._check_order(product_id, base_size, limit_price)
        reserved = sum(
            o.remaining * o.limit_price * (1 + self._fees.maker)
            for o in self._orders.values() if o.kind == "entry" and o.status == "open"
        )
        if self._cash - reserved + _EPS < base_size * limit_price * (1 + self._fees.maker):
            raise ExchangeError("insufficient free cash")
        return self._add(client_order_id, product_id, "entry", base_size, limit_price, None, None)

    def place_bracket(self, product_id: str, base_size: float, stop_trigger: float, stop_limit: float,
                      target: float, client_order_id: str) -> str:
        self._maybe_fail("place_bracket")
        if client_order_id in self._by_client_id:
            return self._by_client_id[client_order_id]
        if not self.supports_bracket:
            raise ExchangeError("bracket orders not supported")
        self._check_order(product_id, base_size, stop_limit, stop_trigger, target)
        if not stop_limit <= stop_trigger < target:
            raise ExchangeError("bracket needs stop_limit <= stop_trigger < target")
        self._check_sell_hold(product_id, base_size)
        return self._add(client_order_id, product_id, "bracket", base_size, stop_limit, stop_trigger, target)

    def place_stop(self, product_id: str, base_size: float, stop_trigger: float, stop_limit: float,
                   client_order_id: str) -> str:
        self._maybe_fail("place_stop")
        if client_order_id in self._by_client_id:
            return self._by_client_id[client_order_id]
        self._check_order(product_id, base_size, stop_limit, stop_trigger)
        if stop_limit > stop_trigger:
            raise ExchangeError("stop needs stop_limit <= stop_trigger")
        self._check_sell_hold(product_id, base_size)
        return self._add(client_order_id, product_id, "stop", base_size, stop_limit, stop_trigger, None)

    def place_ioc_sell(self, product_id: str, base_size: float, limit_price: float, client_order_id: str) -> str:
        self._maybe_fail("place_ioc_sell")
        if client_order_id in self._by_client_id:
            return self._by_client_id[client_order_id]
        self._check_order(product_id, base_size, limit_price)
        self._check_sell_hold(product_id, base_size)
        return self._add(client_order_id, product_id, "ioc", base_size, limit_price, None, None)

    def cancel(self, order_id: str) -> None:
        """Cancels an open order; cancelling an order that is already filled or cancelled does nothing."""
        self._maybe_fail("cancel")
        o = self._get(order_id)
        if o.status == "open":
            o.status = "cancelled"

    def open_orders(self) -> list[Order]:
        self._maybe_fail("open_orders")
        return [o.snapshot() for o in self._orders.values() if o.status == "open"]

    def get_order(self, order_id: str) -> Order:
        self._maybe_fail("get_order")
        return self._get(order_id).snapshot()

    def fills(self, since_ts: int) -> list[Fill]:
        self._maybe_fail("fills")
        return [f for f in self._fills if f.ts >= since_ts]

    def transfers(self, since_ts: int) -> list[Transfer]:
        self._maybe_fail("transfers")
        return [t for t in self._transfers if t.ts >= since_ts]

    def can_transfer(self) -> bool:
        self._maybe_fail("can_transfer")
        return False

    # --- internals --------------------------------------------------------------------------

    def _get(self, order_id: str) -> _Order:
        if order_id not in self._orders:
            raise ExchangeError(f"unknown order {order_id}")
        return self._orders[order_id]

    def _check_order(self, product_id: str, base_size: float, *prices: float) -> None:
        if product_id not in self._products:
            raise ExchangeError(f"unknown product {product_id}")
        if base_size <= 0 or any(p <= 0 for p in prices):
            raise ExchangeError("size and prices must be positive")

    def _check_sell_hold(self, product_id: str, base_size: float) -> None:
        held = sum(
            o.remaining for o in self._orders.values()
            if o.status == "open" and o.product_id == product_id and o.kind != "entry"
        )
        balance = self._coins.get(self._products[product_id].base, 0.0)
        if held + base_size > balance + _EPS:
            raise ExchangeError("sell size exceeds unheld balance")

    def _add(self, client_order_id: str, product_id: str, kind: str, base_size: float,
             limit_price: float | None, stop_trigger: float | None, target: float | None) -> str:
        order_id = f"paper-{len(self._orders) + 1}"
        self._orders[order_id] = _Order(order_id, client_order_id, product_id, kind, base_size,
                                        limit_price, stop_trigger, target, self._now)
        self._by_client_id[client_order_id] = order_id
        return order_id

    def _process(self, o: _Order, c: Candle) -> None:
        if o.kind == "entry":
            if c.low < o.limit_price:
                self._fill(o, o.remaining, o.limit_price, c.ts, "entry")
        elif o.kind in ("stop", "bracket"):
            if c.low <= o.stop_trigger:
                o.stop_triggered = True
                price = min(o.stop_trigger, c.open)
                if price >= o.limit_price:
                    self._fill(o, o.remaining, price, c.ts, "stop")
            elif o.kind == "bracket" and not o.stop_triggered and c.high > o.target:
                self._fill(o, o.remaining, o.target, c.ts, "target")
        elif o.kind == "ioc":
            if c.close >= o.limit_price:
                self._fill(o, o.remaining, max(o.limit_price, c.close), c.ts, "ioc")
            else:
                o.status = "cancelled"

    def _fill(self, o: _Order, size: float, price: float, ts: int, reason: str) -> None:
        base = self._products[o.product_id].base
        rate = self._fees.taker if reason in ("stop", "ioc") else self._fees.maker
        fee = price * size * rate
        if o.kind == "entry":
            side = "buy"
            self._cash -= price * size + fee
            self._coins[base] = self._coins.get(base, 0.0) + size
        else:
            side = "sell"
            self._cash += price * size - fee
            left = self._coins.get(base, 0.0) - size
            self._coins[base] = 0.0 if abs(left) < _EPS else left
        o.filled_size += size
        if o.remaining <= _EPS:
            o.filled_size = o.base_size
            o.status = "filled"
        self._fills.append(Fill(o.order_id, o.product_id, side, price, size, fee, ts, reason))
