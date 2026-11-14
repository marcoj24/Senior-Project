"""Coinbase Advanced Trade adapter over the official SDK (coinbase-advanced-py, pinned in pyproject).

Every SDK method, parameter and response field used here is recorded, with its source, in
docs/coinbase-api-notes.md. Fields marked unverified there are read strictly: a missing field
raises ExchangeError, never a silent default.

Behaviour the engine relies on, matched to PaperExchange:
- Entries are post-only limit GTC buys. There is no market order anywhere in this module.
- Sizes and prices are sent as strings rounded down to the product increments with Decimal.
- supports_bracket is False: the SDK's trigger-bracket order takes no stop-leg limit price, so the
  protocol's place_bracket cannot be expressed; the engine uses two stops and a bot-managed target.
- Cancelling an order that is already finished does nothing.
- transfers() is inferred from USD balance changes that fills do not explain (no deposit or
  withdrawal endpoint exists in the SDK); see the notes file for its limits.
- Public market data (products, candles, best bid/ask) works without API keys.
Secrets are never logged or put in an exception message.
"""

import csv
import os
import re
import time
from datetime import datetime, timezone
from decimal import ROUND_FLOOR, Decimal, InvalidOperation
from typing import Any, Callable, Iterator

from bot.exchange.base import ExchangeError
from bot.models import Candle, Fees, Fill, Order, Product, Transfer

# Native candle granularities used (seconds -> SDK enum). Others are aggregated from the largest divisor.
_NATIVE = {300: "FIVE_MINUTE", 3600: "ONE_HOUR", 86400: "ONE_DAY"}
MAX_CANDLES_PER_REQUEST = 300  # conservative; the API maximum is unverified
MAX_PAGES = 200  # paging guard for accounts, orders and fills
STOP_DOWN = "STOP_DIRECTION_STOP_DOWN"  # unverified value: the SDK only shows STOP_DIRECTION_STOP_UP
SETTLE_S = 60  # transfers: a fill this recent may not be in the balance yet; try again next call
TRANSFER_TOLERANCE_USD = 0.01
MAX_FEE_RATE = 0.05  # a rate above this is taken as a unit error (percent instead of fraction)

_ORDER_KIND = {
    "limit_limit_gtc": "entry", "limit_limit_gtd": "entry",
    "stop_limit_stop_limit_gtc": "stop", "stop_limit_stop_limit_gtd": "stop",
    "trigger_bracket_gtc": "bracket", "trigger_bracket_gtd": "bracket",
    "sor_limit_ioc": "ioc", "limit_limit_fok": "ioc", "market_market_ioc": "ioc",
}
_ORDER_STATUS = {
    "OPEN": "open", "PENDING": "open", "QUEUED": "open", "CANCEL_QUEUED": "open",
    "FILLED": "filled", "CANCELLED": "cancelled", "EXPIRED": "cancelled", "FAILED": "cancelled",
}
_TIME = re.compile(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)")


# ------------------------------------------------------------------------------- parsing helpers

def _plain(resp: Any) -> dict:
    """SDK responses are BaseResponse objects; fakes may return dicts. Either becomes a plain dict."""
    if hasattr(resp, "to_dict"):
        resp = resp.to_dict()
    if not isinstance(resp, dict):
        raise ExchangeError(f"unexpected response type {type(resp).__name__}")
    return resp


def _req(d: Any, key: str, what: str) -> Any:
    if not isinstance(d, dict) or d.get(key) is None:
        raise ExchangeError(f"{what}: response has no '{key}'")
    return d[key]


def _dec(d: dict, key: str, what: str) -> Decimal:
    v = _req(d, key, what)
    try:
        out = Decimal(str(v))
    except InvalidOperation:
        raise ExchangeError(f"{what}: '{key}' is not a number: {v!r}") from None
    if not out.is_finite():
        raise ExchangeError(f"{what}: '{key}' is not finite: {v!r}")
    return out


def _num(d: dict, key: str, what: str) -> float:
    return float(_dec(d, key, what))


def _ts(s: Any, what: str) -> int:
    m = _TIME.fullmatch(str(s))
    if not m:
        raise ExchangeError(f"{what}: unreadable time {s!r}")
    zone = "+00:00" if m[3] == "Z" else m[3]
    return int(datetime.fromisoformat(m[1] + zone).timestamp())


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _floor(value: float, increment: float) -> Decimal:
    inc = Decimal(str(increment)).normalize()
    steps = (Decimal(str(value)) / inc).to_integral_value(rounding=ROUND_FLOOR)
    return (steps * inc).quantize(inc)


def _text(d: Decimal) -> str:
    return format(d, "f")


def _aggregate(native: list[Candle], granularity_s: int, now: int) -> list[Candle]:
    """Buckets aligned to multiples of granularity_s that the data covers from their start and that
    have ended by `now`."""
    if not native:
        return []
    groups: dict[int, list[Candle]] = {}
    for c in native:
        groups.setdefault(c.ts - c.ts % granularity_s, []).append(c)
    out = []
    for b in sorted(groups):
        if b < native[0].ts or b + granularity_s > now:
            continue
        cs = groups[b]
        out.append(Candle(b, cs[0].open, max(c.high for c in cs), min(c.low for c in cs), cs[-1].close,
                          sum(c.volume for c in cs)))
    return out


# ------------------------------------------------------------------------------- adapter

class CoinbaseExchange:
    supports_bracket = False

    def __init__(self, api_key: str, api_secret: str, portfolio_id: str | None, client: Any = None,
                 now: Callable[[], int] | None = None, timeout_s: int = 10):
        """Empty key and secret give a public client: market data only. No network call is made here;
        the SDK client constructor only stores the key and opens a requests.Session."""
        self._authenticated = bool(api_key and api_secret)
        secrets = [s for s in (api_secret, api_key) if s]
        lines = [ln.strip() for s in secrets for ln in s.splitlines() if len(ln.strip()) >= 8]
        self._scrub_list = sorted(set(secrets + lines), key=len, reverse=True)
        if client is None:
            from coinbase.rest import RESTClient
            client = RESTClient(api_key=api_key or None, api_secret=api_secret or None, timeout=timeout_s)
        self._client = client
        self._portfolio = portfolio_id
        self._now = now or (lambda: int(time.time()))
        self._products: dict[str, Product] = {}
        self._exit_kinds: dict[str, tuple[str, float | None]] = {}
        self._usd_base: tuple[int, float] | None = None
        self._transfers: list[Transfer] = []
        self._pending_transfer: float | None = None  # unexplained amount seen once, awaiting confirmation
        self._qty_recent = False

    def hint_quantity_change(self, recent: bool) -> None:
        """The engine says an order-status quantity change happened this cycle or the one before; fills may
        lag it, so transfer inference pauses."""
        self._qty_recent = recent

    def __repr__(self) -> str:
        return f"CoinbaseExchange(portfolio_id={self._portfolio!r}, authenticated={self._authenticated})"

    # --- calls --------------------------------------------------------------------------------

    def _scrub(self, msg: str) -> str:
        for s in self._scrub_list:
            msg = msg.replace(s, "[redacted]")
        return msg

    def _call(self, name: str, **kwargs) -> dict:
        try:
            return _plain(getattr(self._client, name)(**kwargs))
        except ExchangeError:
            raise
        except Exception as e:  # the SDK raises requests HTTPError, AuthenticationError, plain Exception
            raise ExchangeError(self._scrub(f"{name} failed: {type(e).__name__}: {e}")) from None

    def _private(self, name: str, **kwargs) -> dict:
        if not self._authenticated:
            raise ExchangeError(f"{name} needs an API key and secret")
        return self._call(name, **kwargs)

    def _pages(self, name: str, key: str, **kwargs) -> Iterator[dict]:
        cursor, seen = None, set()
        for _ in range(MAX_PAGES):
            r = self._private(name, cursor=cursor, **kwargs)
            items = r.get(key)
            if items is None:
                raise ExchangeError(f"{name}: response has no '{key}'")
            yield from items
            nxt = r.get("cursor")
            if r.get("has_next") is False or ("has_next" not in r and (not items or not nxt)):
                return
            if not nxt:
                raise ExchangeError(f"{name}: has_next without a cursor")
            if nxt in seen:
                raise ExchangeError(f"{name}: paging cursor repeated")
            seen.add(nxt)
            cursor = nxt
        raise ExchangeError(f"{name}: more than {MAX_PAGES} pages")

    # --- market data (public) -----------------------------------------------------------------

    def products(self) -> list[Product]:
        r = self._call("get_public_products", product_type="SPOT")
        items = _req(r, "products", "get_public_products")
        n = r.get("num_products")
        if n is not None and int(n) > len(items):
            raise ExchangeError(f"product list truncated: {len(items)} of {n}")
        out = [self._product_from(p) for p in items]
        self._products = {p.product_id: p for p in out}
        return out

    @staticmethod
    def _product_from(p: dict) -> Product:
        pid = _req(p, "product_id", "product")
        what = f"product {pid}"
        if p.get("trading_disabled") or p.get("is_disabled"):
            status = "disabled"
        elif p.get("cancel_only"):
            status = "cancel_only"
        elif p.get("limit_only") or p.get("post_only"):
            status = "limit_only"
        elif str(_req(p, "status", what)).lower() == "online":
            status = "online"
        else:  # any other status fails closed
            status = "disabled"
        if p.get("approximate_quote_24h_volume") not in (None, ""):
            volume = _num(p, "approximate_quote_24h_volume", what)
        elif p.get("volume_24h") not in (None, "") and p.get("price") not in (None, ""):
            volume = _num(p, "volume_24h", what) * _num(p, "price", what)
        else:
            raise ExchangeError(f"{what}: response has no 24h volume")
        return Product(pid, str(_req(p, "base_currency_id", what)), str(_req(p, "quote_currency_id", what)),
                       _num(p, "base_increment", what), _num(p, "quote_increment", what),
                       _num(p, "base_min_size", what), status, volume)

    def _product(self, pid: str) -> Product:
        if pid not in self._products:
            self.products()
        if pid not in self._products:
            raise ExchangeError(f"unknown product {pid}")
        return self._products[pid]

    def candles(self, product_id: str, granularity_s: int, limit: int) -> list[Candle]:
        if limit <= 0:
            return []
        divisors = [g for g in _NATIVE if granularity_s % g == 0]
        if not divisors:
            raise ExchangeError(f"unsupported granularity {granularity_s}s")
        native = max(divisors)
        k = granularity_s // native
        now = self._now()
        raw = self._fetch_back(product_id, native, now, limit if k == 1 else (limit + 1) * k)
        return (raw if k == 1 else _aggregate(raw, granularity_s, now))[-limit:]

    def _fetch_back(self, product_id: str, native: int, end: int, need: int, pause_s: float = 0) -> list[Candle]:
        """Up to `need` native candles ending at `end`, oldest first, paging backwards."""
        got: dict[int, Candle] = {}
        cur_end = end
        while len(got) < need:
            n = min(MAX_CANDLES_PER_REQUEST, need - len(got))
            r = self._call("get_public_candles", product_id=product_id, start=str(cur_end - n * native),
                           end=str(cur_end), granularity=_NATIVE[native], limit=n)
            page = [self._candle_from(c, product_id) for c in _req(r, "candles", "get_public_candles")]
            page = [c for c in page if c.ts <= cur_end]
            before = len(got)
            got.update((c.ts, c) for c in page)
            if not page or len(got) == before:
                break
            cur_end = min(c.ts for c in page) - 1
            if pause_s:
                time.sleep(pause_s)
        return sorted(got.values(), key=lambda c: c.ts)

    @staticmethod
    def _candle_from(c: dict, product_id: str) -> Candle:
        what = f"candle {product_id}"
        return Candle(int(_dec(c, "start", what)), _num(c, "open", what), _num(c, "high", what),
                      _num(c, "low", what), _num(c, "close", what), _num(c, "volume", what))

    def bid_ask(self, product_id: str) -> tuple[float, float]:
        r = self._call("get_public_product_book", product_id=product_id, limit=1)
        book = _req(r, "pricebook", f"book {product_id}")
        bids, asks = book.get("bids") or [], book.get("asks") or []
        if not bids or not asks:
            raise ExchangeError(f"no bid/ask for {product_id}")
        bid, ask = _num(bids[0], "price", f"bid {product_id}"), _num(asks[0], "price", f"ask {product_id}")
        if bid <= 0 or ask < bid:
            raise ExchangeError(f"bad bid/ask for {product_id}: {bid}/{ask}")
        return bid, ask

    # --- account ------------------------------------------------------------------------------

    def fees(self) -> Fees:
        r = self._private("get_transaction_summary", product_type="SPOT")
        tier = _req(r, "fee_tier", "get_transaction_summary")
        maker = _num(tier, "maker_fee_rate", "fee tier")
        taker = _num(tier, "taker_fee_rate", "fee tier")
        for rate in (maker, taker):
            if not 0 <= rate < MAX_FEE_RATE:
                raise ExchangeError(f"implausible fee rate {rate}")
        return Fees(maker, taker)

    def balances(self) -> dict[str, float]:
        out: dict[str, Decimal] = {}
        for a in self._pages("get_accounts", "accounts", retail_portfolio_id=self._portfolio):
            cur = str(_req(a, "currency", "account"))
            what = f"account {cur}"
            total = _dec(_req(a, "available_balance", what), "value", what) + \
                _dec(_req(a, "hold", what), "value", what)
            out[cur] = out.get(cur, Decimal(0)) + total
        return {k: float(v) for k, v in out.items()}

    def can_transfer(self) -> bool:
        try:
            r = self._private("get_api_key_permissions")
        except ExchangeError as e:
            raise ExchangeError(f"cannot verify key permissions: {e}") from None
        flags = [r.get(k) for k in ("can_transfer", "can_withdraw")]
        flags = [f for f in flags if isinstance(f, bool)]
        if not flags:
            raise ExchangeError("cannot verify key permissions")
        return any(flags)

    def key_permissions(self) -> dict[str, bool]:
        """The flags the venue reports for the key (can_view, can_trade, can_transfer), as given."""
        r = self._private("get_api_key_permissions")
        return {k: r[k] for k in ("can_view", "can_trade", "can_transfer") if isinstance(r.get(k), bool)}

    # --- orders -------------------------------------------------------------------------------

    def _size(self, p: Product, base_size: float) -> str:
        s = _floor(base_size, p.base_increment)
        if s <= 0 or s < Decimal(str(p.min_base_size)):
            raise ExchangeError(f"size {base_size} is below the minimum {p.min_base_size} for {p.product_id}")
        return _text(s)

    def _price(self, p: Product, price: float) -> str:
        v = _floor(price, p.quote_increment)
        if v <= 0:
            raise ExchangeError(f"price {price} is not positive at increment {p.quote_increment}")
        return _text(v)

    def _create(self, method: str, client_order_id: str, product_id: str, **fields) -> str:
        r = self._private(method, client_order_id=client_order_id, product_id=product_id,
                          retail_portfolio_id=self._portfolio, **fields)
        if r.get("success") is not True:
            raise ExchangeError(self._scrub(f"{method} {product_id} rejected: {self._failure(r)}"))
        oid = (r.get("success_response") or {}).get("order_id") or r.get("order_id")
        if not oid:
            raise ExchangeError(f"{method} {product_id}: response has no order_id")
        return str(oid)

    @staticmethod
    def _failure(r: dict) -> str:
        err = r.get("error_response") or {}
        parts = [str(err[k]) for k in ("error", "message", "error_details", "preview_failure_reason",
                                       "new_order_failure_reason") if err.get(k)]
        if r.get("failure_reason"):
            parts.append(str(r["failure_reason"]))
        return "; ".join(parts) or "no reason given"

    def place_entry(self, product_id: str, base_size: float, limit_price: float, client_order_id: str) -> str:
        p = self._product(product_id)
        return self._create("limit_order_gtc_buy", client_order_id, product_id, base_size=self._size(p, base_size),
                            limit_price=self._price(p, limit_price), post_only=True)

    def place_bracket(self, product_id: str, base_size: float, stop_trigger: float, stop_limit: float,
                      target: float, client_order_id: str) -> str:
        raise ExchangeError("bracket orders not supported")

    def place_stop(self, product_id: str, base_size: float, stop_trigger: float, stop_limit: float,
                   client_order_id: str) -> str:
        if stop_limit > stop_trigger:
            raise ExchangeError("stop needs stop_limit <= stop_trigger")
        p = self._product(product_id)
        return self._create("stop_limit_order_gtc_sell", client_order_id, product_id,
                            base_size=self._size(p, base_size), limit_price=self._price(p, stop_limit),
                            stop_price=self._price(p, stop_trigger), stop_direction=STOP_DOWN)

    def preview_stop(self, product_id: str, base_size: float, stop_trigger: float, stop_limit: float) -> None:
        """Asks the venue to check the exact stop-limit sell place_stop would send, without placing it.
        Raises ExchangeError with the venue's message if it is rejected."""
        if stop_limit > stop_trigger:
            raise ExchangeError("stop needs stop_limit <= stop_trigger")
        p = self._product(product_id)
        r = self._private("preview_stop_limit_order_gtc_sell", product_id=product_id,
                          base_size=self._size(p, base_size), limit_price=self._price(p, stop_limit),
                          stop_price=self._price(p, stop_trigger), stop_direction=STOP_DOWN,
                          retail_portfolio_id=self._portfolio)
        errs = r.get("errs")
        if errs:
            raise ExchangeError(self._scrub(f"stop preview {product_id} rejected: {errs}"))

    def place_ioc_sell(self, product_id: str, base_size: float, limit_price: float, client_order_id: str) -> str:
        p = self._product(product_id)
        return self._create("limit_order_ioc_sell", client_order_id, product_id,
                            base_size=self._size(p, base_size), limit_price=self._price(p, limit_price))

    def cancel(self, order_id: str) -> None:
        """Cancels an open order; cancelling an order that is already filled or cancelled does nothing."""
        r = self._private("cancel_orders", order_ids=[order_id])
        results = _req(r, "results", "cancel_orders")
        res = next((x for x in results if x.get("order_id") == order_id), None)
        if res is None:
            raise ExchangeError(f"cancel_orders: no result for {order_id}")
        if res.get("success") is True:
            return
        if self.get_order(order_id).status != "open":
            return
        raise ExchangeError(f"cancel {order_id} failed: {res.get('failure_reason') or 'no reason given'}")

    def _order_from(self, o: dict) -> Order:
        oid = str(_req(o, "order_id", "order"))
        what = f"order {oid}"
        cfg = {k: v for k, v in _req(o, "order_configuration", what).items() if v}
        if len(cfg) != 1:
            raise ExchangeError(f"{what}: expected one order configuration, got {sorted(cfg)}")
        (ck, c), = cfg.items()
        if ck not in _ORDER_KIND:
            raise ExchangeError(f"{what}: unsupported order type {ck}")
        kind = _ORDER_KIND[ck]
        raw_status = str(_req(o, "status", what)).upper()
        if raw_status not in _ORDER_STATUS:
            raise ExchangeError(f"{what}: unknown status {raw_status}")
        limit = _num(c, "limit_price", what) if c.get("limit_price") is not None else None
        trigger_key = "stop_price" if "stop_price" in c else "stop_trigger_price"
        trigger = _num(c, trigger_key, what) if c.get(trigger_key) is not None else None
        target = None
        if kind == "bracket":  # the SDK's limit_price is the take-profit; the stop leg's limit is not exposed
            limit, target = None, limit
        filled = _num(o, "filled_size", what)
        avg = None  # optional: only an estimate for when fills() never arrive, so a bad value is dropped
        if filled > 0 and o.get("average_filled_price") not in (None, ""):
            try:
                avg = _num(o, "average_filled_price", what)
            except ExchangeError:
                avg = None
            avg = avg if avg and avg > 0 else None
        return Order(oid, str(o.get("client_order_id") or ""), str(_req(o, "product_id", what)), kind,
                     _num(c, "base_size", what), filled, _ORDER_STATUS[raw_status],
                     limit, trigger, target, _ts(_req(o, "created_time", what), what), avg)

    def open_orders(self) -> list[Order]:
        orders = self._pages("list_orders", "orders", order_status=["OPEN"], retail_portfolio_id=self._portfolio)
        return [o for o in map(self._order_from, orders) if o.status == "open"]

    def get_order(self, order_id: str) -> Order:
        r = self._private("get_order", order_id=order_id)
        return self._order_from(_req(r, "order", f"get_order {order_id}"))

    def get_order_by_client_id(self, client_order_id: str) -> Order | None:
        """Searches every order (all statuses); None only after the whole list was read."""
        for o in self._pages("list_orders", "orders", retail_portfolio_id=self._portfolio):
            if o.get("client_order_id") == client_order_id:
                return self._order_from(o)
        return None

    # --- fills and transfers ------------------------------------------------------------------

    def fills(self, since_ts: int) -> list[Fill]:
        out = []
        for f in self._pages("get_fills", "fills", start_sequence_timestamp=_iso(since_ts),
                             retail_portfolio_id=self._portfolio):
            oid = str(_req(f, "order_id", "fill"))
            what = f"fill of {oid}"
            ts = _ts(_req(f, "trade_time", what), what)
            if ts < since_ts:
                continue
            price, size = _num(f, "price", what), _num(f, "size", what)
            in_quote = _req(f, "size_in_quote", what)
            if in_quote is True or str(in_quote).lower() == "true":
                size = size / price
            side = str(_req(f, "side", what)).lower()
            if side not in ("buy", "sell"):
                raise ExchangeError(f"{what}: unknown side {side}")
            reason = "entry" if side == "buy" else self._exit_reason(oid, price)
            out.append(Fill(oid, str(_req(f, "product_id", what)), side, price, size,
                            _num(f, "commission", what), ts, reason))
        return sorted(out, key=lambda x: x.ts)

    def _exit_reason(self, order_id: str, price: float) -> str:
        if order_id not in self._exit_kinds:
            o = self.get_order(order_id)
            self._exit_kinds[order_id] = (o.kind, o.target)
        kind, target = self._exit_kinds[order_id]
        if kind == "bracket":
            return "target" if target is not None and price >= target else "stop"
        return {"stop": "stop", "ioc": "ioc"}.get(kind, "target")

    def transfers(self, since_ts: int) -> list[Transfer]:
        """Deposits (+) and withdrawals (-) inferred from USD balance changes that USD-quoted fills
        do not explain. The first call only records a baseline, so a transfer made while the bot was
        not running is not seen."""
        now = self._now()
        usd = self.balances().get("USD", 0.0)
        if self._usd_base is None:
            self._usd_base = (now, usd)
        elif self._qty_recent:
            self._pending_transfer = None  # fills may lag order status: infer nothing, keep the base
        else:
            base_ts, base_usd = self._usd_base
            new = [f for f in self.fills(base_ts) if f.ts > base_ts]
            if not any(f.ts > now - SETTLE_S for f in new):
                flow = 0.0
                for f in new:
                    if self._product(f.product_id).quote == "USD":
                        value = f.price * f.base_size
                        flow += (value if f.side == "sell" else -value) - f.fee
                unexplained = (usd - base_usd) - flow
                if abs(unexplained) < TRANSFER_TOLERANCE_USD:
                    self._pending_transfer = None
                    self._usd_base = (now, usd)
                elif self._pending_transfer is not None and abs(unexplained - self._pending_transfer) <= 0.01:
                    # the same amount on two consecutive quiet calls: a real deposit or withdrawal
                    self._transfers.append(Transfer(now, round(unexplained, 8)))
                    self._pending_transfer = None
                    self._usd_base = (now, usd)
                else:
                    self._pending_transfer = unexplained  # first sighting; the base stays put
        return [t for t in self._transfers if t.ts >= since_ts]


# ------------------------------------------------------------------------------- history download

def download_history(product_ids: list[str], days: int, out_dir: str, *, client: Any = None,
                     now: Callable[[], int] | None = None, pause_s: float = 0.2) -> None:
    """Writes out_dir/<PRODUCT>.csv (ts,open,high,low,close,volume) of closed 1-hour candles covering
    the last `days` days, oldest first, from the public candles endpoint (no API keys)."""
    ex = CoinbaseExchange("", "", None, client=client, now=now)
    end = ex._now()
    start = end - days * 86400
    os.makedirs(out_dir, exist_ok=True)
    for pid in product_ids:
        rows = [c for c in ex._fetch_back(pid, 3600, end, days * 24 + 1, pause_s)
                if c.ts >= start and c.ts + 3600 <= end]
        path = os.path.join(out_dir, f"{pid}.csv")
        tmp = path + ".tmp"
        with open(tmp, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ts", "open", "high", "low", "close", "volume"])
            for c in rows:
                w.writerow([c.ts, c.open, c.high, c.low, c.close, c.volume])
        os.replace(tmp, path)
