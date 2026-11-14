# Coinbase Advanced Trade API notes (Task 14)

Written 2026-11-14 while building `bot/exchange/coinbase.py`. Read this before changing the adapter.

## Sources and how far they go

| Source | Status |
|---|---|
| Installed SDK `coinbase-advanced-py==1.8.4` (pinned in `pyproject.toml`), `.venv/lib/python3.13/site-packages/coinbase/` | **Read in full for the parts used. This is the primary record.** |
| The same version's sdist from PyPI, `https://files.pythonhosted.org/packages/f6/57/58635185acc4d59fda732a528d8583c60c662b809d691febce4486c5514a/coinbase_advanced_py-1.8.4.tar.gz` (sha256 `33fd2c2d9fea18ca22a977506b64bdf746d3b35172bf0b3ce9805e2f95058f67`) | Downloaded. Its `coinbase/` tree is identical to the installed one (`diff -r`). The sdist also contains the SDK's own unit tests (`tests/rest/*.py`). They show request shapes and some enum values. Their mocked responses are placeholders, not recorded API output. |
| SDK README (in the installed `METADATA`, same text as `https://github.com/coinbase/coinbase-advanced-py`) | Read from the installed copy. |
| Official docs `https://docs.cdp.coinbase.com/...` | **Blocked.** The session's network policy does not resolve `docs.cdp.coinbase.com` (WebFetch: ENOTFOUND). `github.com` returns 403 from the proxy. Nothing below comes from the online documentation. The doc URLs listed are the ones the SDK docstrings cite. I could not read them. |

Legend used below:
- **SDK**: verified from the SDK source (file:line under `site-packages/coinbase/`).
- **SDK-test**: verified from the SDK's unit tests in the 1.8.4 sdist (request shape and argument values only).
- **unverified, not confirmed**: assumed, and the adapter treats it strictly. A missing field raises `ExchangeError`. An unknown value fails closed.

Before going live, the owner should check every *unverified* item against the docs or a read-only call (Task 15 `check`). The stop direction matters most (see "Create order").

## Client, authentication, public access

- `from coinbase.rest import RESTClient`; `RESTClient(api_key=..., api_secret=..., timeout=...)`. **SDK** `rest/__init__.py:4`, `rest/rest_base.py:55`, `api_base.py:24`.
  - The constructor makes no network call. It stores the key and creates a `requests.Session`. **SDK** `rest_base.py:74`, `api_base.py:50-67`.
  - With `api_key=None, api_secret=None` the client is unauthenticated (`is_authenticated = False`). A call to a private endpoint then raises `multiprocessing.AuthenticationError` before any request. **SDK** `rest_base.py:194-196`.
  - The defaults for `api_key`/`api_secret` are `os.getenv("COINBASE_API_KEY"/"COINBASE_API_SECRET")`, evaluated at import time. The adapter always passes them explicitly. **SDK** `rest_base.py:57-58`, `constants.py:3-4`.
  - Auth is a JWT built per request from the key and secret (Ed25519 or ECDSA). **SDK** `rest_base.py:244-260`, `jwt_generator.py`.
  - HTTP 4xx/5xx raise `requests.HTTPError` with the response body in the message. The SDK also logs it with `logger.error` on logger `coinbase.RESTClient`. The message holds the status and body, not the key or secret. **SDK** `rest_base.py:22-47`. JWT key-loading errors do not quote the secret either (`jwt_generator.py:13-52`). The adapter still removes the key and secret from every message, and raises `ExchangeError(...) from None`.
  - The SDK has no retry or backoff for REST calls. `backoff` is only used by the WebSocket client.
- **Endpoints usable without keys** (the SDK sends them with `public=True`). **SDK** `rest/public.py`:
  `get_public_products` (`/market/products`, l.78), `get_public_product` (l.129), `get_public_product_book` (`/market/product_book`, l.36), `get_public_candles` (`/market/products/{id}/candles`, l.158), `get_public_market_trades` (`/market/products/{id}/ticker`, l.199), `get_unix_time` (l.14). Their docstrings say: "This endpoint is public and does not need authentication."
  `get_best_bid_ask` (`/best_bid_ask`, `rest/products.py:121`) is **not** public, because it is sent without `public=True`. The adapter takes bid and ask from the public product book instead. Paper mode therefore needs no keys for products, candles or prices.

## Endpoints used by the adapter

Paths are relative to `https://api.coinbase.com/api/v3/brokerage` (`constants.py:6-7`).

### Products: `get_public_products(product_type="SPOT")`
- **SDK** `rest/public.py:78`, `GET /market/products`. Parameters: `limit, offset, product_type, product_ids, contract_expiry_type, expiring_contract_status, get_all_products`. The value `"SPOT"` comes from **SDK-test** `tests/rest/test_public.py:98`.
- Response `ListProductsResponse`: `products[]`, `num_products`. **SDK** `types/product_types.py:33`.
- Product fields declared (**SDK** `types/product_types.py:189-277`): `product_id, price, volume_24h, base_increment, quote_increment, base_min_size, base_max_size, quote_min_size, status, is_disabled, cancel_only, limit_only, post_only, trading_disabled, auction_mode, product_type, base_currency_id, quote_currency_id, approximate_quote_24h_volume, price_increment, product_venue, future_product_details, ...`. All numbers are strings.
- How the adapter maps them. The *meaning* of these fields is **unverified, not confirmed**:
  - `trading_disabled` or `is_disabled` → `disabled`; `cancel_only` → `cancel_only`; `limit_only` or `post_only` → `limit_only`; `status == "online"` (case-insensitive) → `online`; any other status → `disabled` (fail closed). The status value `"online"` is unverified.
  - `volume_24h_usd` = `approximate_quote_24h_volume`, or else `volume_24h * price`. This is in the *quote* currency, so it is USD only for `-USD` products.
  - `base`/`quote` = `base_currency_id`/`quote_currency_id`.
  - If `num_products` exceeds the number of products returned, the list was truncated and the adapter raises. Whether the API pages by default is **unverified**. The SDK exposes `limit`/`offset`.

### Candles: `get_public_candles(product_id, start, end, granularity, limit)`
- **SDK** `rest/public.py:158`, `GET /market/products/{product_id}/candles`. `start` and `end` are strings of unix seconds, `granularity` is an enum string, e.g. `"FIVE_MINUTE"`. **SDK-test** `tests/rest/test_public.py:138`.
- Response `candles[]` with `start, low, high, open, close, volume` (strings). **SDK** `types/product_types.py:137, 280`.
- **unverified, not confirmed**:
  - The other granularity values. The adapter uses only `FIVE_MINUTE` (**SDK-test**), `ONE_HOUR` and `ONE_DAY` (both unverified). Four-hour candles are built from `ONE_HOUR`, aligned to UTC multiples of 4 h. Only buckets the data covers from their start and that have ended are kept.
  - The maximum number of candles per request. The adapter asks for at most **300** per request and pages backwards.
  - The order candles come back in. The adapter sorts oldest first and removes duplicates.
  - Whether `start` and `end` are inclusive. Windows overlap and duplicates are removed.
  - That `start` is the bucket start in unix seconds.
- Doc cited by SDK: https://docs.cdp.coinbase.com/api-reference/advanced-trade-api/rest-api/public/get-public-product-candles

### Best bid/ask: `get_public_product_book(product_id, limit=1)`
- **SDK** `rest/public.py:36`, `GET /market/product_book`. The query `product_id=...&limit=...` is shown in **SDK-test** `tests/rest/test_public.py:84`.
- Response `pricebook{product_id, bids[{price,size}], asks[{price,size}], time}`, plus `last, mid_market, spread_bps, spread_absolute`. **SDK** `types/product_types.py:17, 163, 172`.
- **unverified, not confirmed**: that `bids[0]` and `asks[0]` are the best levels. An empty side raises.
- The authenticated alternative `get_best_bid_ask(product_ids)` returns `pricebooks[]` (**SDK** `products.py:121`, `types/product_types.py:7`). It is not used.

### Accounts (balances): `get_accounts(limit, cursor, retail_portfolio_id)`
- **SDK** `rest/accounts.py:7`, `GET /accounts`. Response: `accounts[], has_next, cursor, size`. **SDK** `types/accounts_types.py:16`.
- Account fields: `uuid, name, currency, available_balance, default, active, type, ready, hold, retail_portfolio_id, platform`. **SDK** `types/accounts_types.py:34`. `available_balance` and `hold` are untyped dicts. The README shows `available_balance['value']` (installed `METADATA`, "Custom Response Objects").
- **unverified, not confirmed**: that `hold` is `{value, currency}` like `available_balance`, and that available + hold is the total. The adapter reports total = `available_balance.value + hold.value` and raises if either is missing.

### Transaction summary (fee tier): `get_transaction_summary(product_type="SPOT")`
- **SDK** `rest/fees.py:7`, `GET /transaction_summary`. Parameters: `product_type, contract_expiry_type, product_venue`.
- Response: `total_volume, total_fees, fee_tier, margin_rate, goods_and_services_tax, advanced_trade_only_volumes, advanced_trade_only_fees, total_balance, has_promo_fee`. **SDK** `types/fees_types.py:7`. `fee_tier` is kept as a raw dict. Its keys come from the `FeeTier` class: `pricing_tier, usd_from, usd_to, taker_fee_rate, maker_fee_rate, aop_from, aop_to` (**SDK** `types/fees_types.py:45`).
- **unverified, not confirmed**: that the rates are fractions, e.g. `"0.005"`, not percentages. The adapter rejects any rate ≥ 0.05 as a unit error. The `product_type` value `"SPOT"` is reused from the products test.
- Fees the owner pays today (from the owner, for reference only; the adapter reads the live tier): spot **0.50 % maker / 0.90 % taker**; futures **0.095 % / 0.10 %**.

### Key permissions: `get_api_key_permissions()`
- **The endpoint exists.** **SDK** `rest/data_api.py:7`, `GET /key_permissions`. The design's claim is confirmed.
- Response fields declared: `can_view, can_trade, can_transfer, portfolio_uuid, portfolio_type`. **SDK** `types/data_api_types.py:7`.
- The SDK's own test mocks `can_withdraw` instead of `can_transfer` (**SDK-test** `tests/rest/test_data_api.py:17`), so the exact field name is in doubt.
- The adapter returns True if either `can_transfer` or `can_withdraw` is a true bool. It returns False if the ones present are all false. If neither is present, or the call fails, it raises `ExchangeError("cannot verify key permissions")`.
- **unverified, not confirmed**: what `portfolio_uuid` holds for a portfolio-scoped key.

### Create order
All placement helpers call `create_order(client_order_id, product_id, side, order_configuration, self_trade_prevention_id, leverage, margin_type, retail_portfolio_id)`, `POST /orders`. **SDK** `rest/orders.py:25`. An empty `client_order_id` is replaced by a random one (l.56-57). The adapter always sends its own id. A repeated id is sent unchanged.
Response `CreateOrderResponse`: `success, failure_reason, order_id, success_response{order_id, product_id, side, client_order_id, attached_order_id}, error_response{error, message, error_details, preview_failure_reason, new_order_failure_reason}, order_configuration`. **SDK** `types/orders_types.py:7, 498, 513`. The adapter requires `success is True` and takes the order id from `success_response.order_id` or else `order_id`.

| Use | SDK helper | `order_configuration` | Source |
|---|---|---|---|
| Entry: post-only limit GTC buy | `limit_order_gtc_buy(client_order_id, product_id, base_size, limit_price, post_only=True, ...)` | `{"limit_limit_gtc": {base_size, limit_price, post_only}}` | **SDK** `orders.py:357, 411` |
| Stop-loss: stop-limit GTC sell | `stop_limit_order_gtc_sell(client_order_id, product_id, base_size, limit_price, stop_price, stop_direction, ...)` | `{"stop_limit_stop_limit_gtc": {base_size, limit_price, stop_price, stop_direction}}` | **SDK** `orders.py:804, 909` |
| Exit: IOC limit sell | `limit_order_ioc_sell(client_order_id, product_id, base_size, limit_price, ...)` | `{"sor_limit_ioc": {base_size, limit_price}}` | **SDK** `orders.py:214, 310` |
| Bracket (not used) | `trigger_bracket_order_gtc_sell(client_order_id, product_id, base_size, limit_price, stop_trigger_price, ...)` | `{"trigger_bracket_gtc": {base_size, limit_price, stop_trigger_price}}` | **SDK** `orders.py:1120, 1221`; **SDK-test** `tests/rest/test_orders.py:909-943` |

- **Stop direction.** The only value in the SDK is `STOP_DIRECTION_STOP_UP` (**SDK-test** `tests/rest/test_orders.py:590`). A sell stop-loss needs the falling direction. The adapter sends **`STOP_DIRECTION_STOP_DOWN`**, which is **unverified, not confirmed**. If it is wrong, the API rejects every stop, the engine alerts, and positions stay unprotected. Verify it before going live. `preview_stop_limit_order_gtc_sell` (**SDK** `orders.py:2433`, `POST /orders/preview`) simulates the order without placing it.
- **Bracket orders.** The SDK has a spot `trigger_bracket_gtc` order, so the design was half right. But the order has only `limit_price` and `stop_trigger_price`, with **no stop-leg limit price**. The protocol's `place_bracket(stop_trigger, stop_limit, target)` cannot be expressed, and what `limit_price` means (take-profit, presumably) is **unverified**. So `supports_bracket = False` and `place_bracket` raises without sending. The engine uses its tested fallback: two stop legs and a bot-managed target sold by IOC.
- Market orders exist (`market_order_buy`, `orders.py:127`). The adapter never calls them.
- Sizes and prices are sent as strings, rounded down to `base_increment` and `quote_increment` with `Decimal`. A size below `base_min_size`, or a price that rounds to 0, raises before sending.
- **unverified, not confirmed**: the maximum length of `client_order_id` (the engine's ids are about 40 characters), and what the API does with a repeated `client_order_id` (reject, or return the original). The adapter passes it through and leaves the outcome to the API.

### Cancel: `cancel_orders(order_ids=[id])`
- **SDK** `rest/orders.py:1620`, `POST /orders/batch_cancel`. Response `results[{success, failure_reason, order_id}]`. **SDK** `types/orders_types.py:33, 487`.
- **unverified, not confirmed**: the failure reason for an order that is already finished. To match the paper venue, after a failed cancel the adapter reads the order. If it is no longer open, the cancel is a no-op. Otherwise it raises with the reason.

### Get order: `get_order(order_id)`
- **SDK** `rest/orders.py:1423`, `GET /orders/historical/{order_id}`. Response `order{...}`. **SDK** `types/orders_types.py:117`.
- Order fields: `order_id, product_id, user_id, order_configuration, side, client_order_id, status, time_in_force, created_time, completion_percentage, filled_size, average_filled_price, fee, number_of_fills, filled_value, pending_cancel, total_fees, trigger_status, order_type, reject_reason, cancel_message, outstanding_hold_amount, last_fill_time, retail_portfolio_id, originating_order_id, attached_order_id, ...`. **SDK** `types/orders_types.py:343-434`.
- `average_filled_price` (string; SDK `types/orders_types.py:369-370`) is read into `Order.avg_fill_price` when `filled_size > 0` and the value is a positive number; missing, empty, zero or unreadable gives `None`. The engine uses it only to price an order whose `get_fills` rows never arrive (bounded wait, `fill_wait_cycles`); quantity never depends on it. **Unverified live:** that it is populated for partially filled open orders.
- How the adapter maps them:
  - kind comes from the configuration key: `limit_limit_*` → entry, `stop_limit_stop_limit_*` → stop, `trigger_bracket_*` → bracket, `sor_limit_ioc`/`limit_limit_fok`/`market_market_ioc` → ioc. Any other key raises.
  - status: `OPEN` (**SDK-test** `test_orders.py:1103`) → open; `PENDING`, `QUEUED`, `CANCEL_QUEUED` → open; `FILLED` → filled; `CANCELLED`, `EXPIRED`, `FAILED` → cancelled. Any other value raises. Every status except `OPEN` is **unverified, not confirmed**.
  - `created_time` is read as RFC 3339 with `Z` or an offset, and a fraction of any length. The format is **unverified**.

### List orders: `list_orders(order_ids, product_ids, order_status, limit, start_date, end_date, ..., cursor, retail_portfolio_id, ...)`
- **SDK** `rest/orders.py:1446`, `GET /orders/historical/batch`. Response `orders[], sequence, has_next, cursor`. **SDK** `types/orders_types.py:89`.
- `open_orders()` uses `order_status=["OPEN"]`.
- `get_order_by_client_id()` pages through **all** orders, with no status filter, and matches `client_order_id`, because the SDK has no client-id filter. It returns None only after the last page. A repeated cursor or more than 200 pages raises.
- **unverified, not confirmed**: that `list_orders` without `order_status` returns orders of every status. If it returned only open orders, a filled entry whose placement reply was lost would not be found.

### List fills: `get_fills(order_ids, trade_ids, product_ids, start_sequence_timestamp, end_sequence_timestamp, retail_portfolio_id, limit, cursor, sort_by)`
- **SDK** `rest/orders.py:1506`, `GET /orders/historical/fills`. Response `fills[], cursor`. **SDK** `types/orders_types.py:105`.
- Fill fields: `entry_id, trade_id, order_id, trade_time, trade_type, price, size, commission, product_id, sequence_timestamp, liquidity_indicator, size_in_quote, user_id, side, retail_portfolio_id`. **SDK** `types/orders_types.py:437`.
- **unverified, not confirmed**:
  - The RFC 3339 format of `start_sequence_timestamp`. The adapter also filters on `trade_time` locally.
  - That `commission` is in the quote currency.
  - The type of `size_in_quote`, which the SDK annotates as `str`. The adapter accepts a bool or `"true"`, and converts the size to base when it is set.
  - That an empty `cursor` ends the list.
- The fill's reason comes from its order's kind (read once per order): buy → entry, stop → stop, ioc → ioc, bracket → target or stop by price.

## Portfolios

- `retail_portfolio_id` is accepted by `get_accounts`, `list_orders`, `get_fills` and `create_order` (**SDK** signatures above). The adapter passes the configured `portfolio_id`, or `None`, which the SDK drops (`rest_base.py:202-205`).
- **How a portfolio-scoped key behaves is unverified, not confirmed.** Presumably it sees and trades only its own portfolio, and `get_api_key_permissions().portfolio_uuid` names that portfolio. Task 15's `check` should print `portfolio_uuid` so the owner can compare.
- Portfolio management (`get_portfolios`, `move_portfolio_funds`, ...) exists (**SDK** `rest/portfolios.py`). It is not used.

## Deposits and withdrawals

- The SDK has **no endpoint for deposits, withdrawals or transfer history**. `payments.py` only lists payment methods (`allow_deposit` and `allow_withdraw` flags, `types/payments_types.py:46-49`). So whether a trade-only key could see them does not matter: the SDK cannot read them.
- So `transfers()` **infers** them: change in total USD balance minus the cash effect of USD-quoted fills since the previous call. A gap of at least $0.01 is reported as one `Transfer` at the time of the call.
- Limits of this inference:
  - The first call after start-up only records a baseline. A transfer made while the bot was stopped is never seen.
  - The calculation is skipped for one call while any fill is less than 60 s old, because the balance may lag.
  - Any USD change from a source other than USD-quoted fills is treated as a transfer: USD↔USDC conversion, staking rewards, or a manual trade on a non-USD pair.

## Futures (phase 2, recorded only, not built)

- Products: `product_type` and `contract_expiry_type` filters on `get_products` and `get_public_products`. A product carries `product_venue`, `fcm_trading_session_details` and `future_product_details` (an **untyped dict**). The SDK declares **no contract-size field**, so contract size has to be read from `future_product_details`; its keys are unverified. **SDK** `rest/public.py:78-122`, `types/product_types.py:245-277`.
- US futures (FCM), `rest/futures.py`: `get_futures_balance_summary` (`/cfm/balance_summary`), `list_futures_positions` / `get_futures_position` (`/cfm/positions`), sweeps (`/cfm/sweeps`), intraday margin settings (`/cfm/intraday/...`).
  - Position fields: `product_id, expiration_time, side, number_of_contracts, current_price, avg_entry_price, unrealized_pnl, daily_realized_pnl`. **SDK** `types/futures_types.py:143`.
  - Balance fields include `futures_buying_power, initial_margin, available_margin, liquidation_threshold, liquidation_buffer_amount`. **SDK** `types/futures_types.py:96`.
- Perpetuals (INTX), `rest/perpetuals.py`: `/intx/portfolio/{uuid}`, `/intx/positions/...`, `/intx/allocate`, multi-asset collateral.
- Every create-order helper takes `leverage` and `margin_type`. `close_position` exists (`POST /orders/close_position`, `orders.py:2897`).
- `get_transaction_summary` takes `product_type`, `contract_expiry_type` and `product_venue`, so a futures fee tier can be read the same way.

## Doc URLs cited by the SDK (not reachable from this session)

- Create order: https://docs.cdp.coinbase.com/api-reference/advanced-trade-api/rest-api/orders/create-order
- Cancel orders: https://docs.cdp.coinbase.com/api-reference/advanced-trade-api/rest-api/orders/cancel-order
- Get order: https://docs.cdp.coinbase.com/api-reference/advanced-trade-api/rest-api/orders/get-order
- List orders: https://docs.cdp.coinbase.com/api-reference/advanced-trade-api/rest-api/orders/list-orders
- List fills: https://docs.cdp.coinbase.com/api-reference/advanced-trade-api/rest-api/orders/list-fills
- List accounts: https://docs.cdp.coinbase.com/api-reference/advanced-trade-api/rest-api/accounts/list-accounts
- Transaction summary: https://docs.cdp.coinbase.com/api-reference/advanced-trade-api/rest-api/fees/get-transaction-summary
- Key permissions: https://docs.cdp.coinbase.com/api-reference/advanced-trade-api/rest-api/data-api/get-api-key-permissions
- Public products: https://docs.cdp.coinbase.com/api-reference/advanced-trade-api/rest-api/public/list-public-products
- Public candles: https://docs.cdp.coinbase.com/api-reference/advanced-trade-api/rest-api/public/get-public-product-candles
- Public product book: https://docs.cdp.coinbase.com/api-reference/advanced-trade-api/rest-api/public/get-public-product-book
- Rate limits (README): https://docs.cdp.coinbase.com/advanced-trade/docs/rest-api-rate-limits
