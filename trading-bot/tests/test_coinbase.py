"""CoinbaseExchange against a fake SDK client. No test reaches the network.

The fake returns the SDK's own response classes (coinbase.rest.types.*) built from dicts shaped as
recorded in docs/coinbase-api-notes.md, so the adapter is exercised on what RESTClient returns."""

import csv
import inspect
import os

import pytest
import requests
from coinbase.rest import RESTClient
from coinbase.rest.types.accounts_types import ListAccountsResponse
from coinbase.rest.types.data_api_types import GetAPIKeyPermissionsResponse
from coinbase.rest.types.fees_types import GetTransactionSummaryResponse
from coinbase.rest.types.orders_types import (CancelOrdersResponse, CreateOrderResponse, GetOrderResponse,
                                              ListFillsResponse, ListOrdersResponse)
from coinbase.rest.types.product_types import (GetProductBookResponse, GetProductCandlesResponse,
                                               ListProductsResponse)

from bot.exchange.base import ExchangeError
from bot.exchange.coinbase import CoinbaseExchange, download_history
from bot.models import Candle, Fees

NOW = 1_700_006_400  # a multiple of 4h and of 1d
SECRET = "-----BEGIN EC PRIVATE KEY-----\nTOPSECRET\n-----END EC PRIVATE KEY-----\n"
KEY = "organizations/org/apiKeys/key"


class FakeClient:
    """Records every call; each SDK method answers from `responses[name]`: a value, a callable taking
    the call's kwargs, or a list consumed one item per call. An Exception value is raised.
    Every call is bound against the real RESTClient method's signature, so a method or parameter
    name the SDK does not have fails the test."""

    def __init__(self, **responses):
        self.responses = responses
        self.calls: list[tuple[str, dict]] = []

    def __getattr__(self, name):
        if name.startswith("_") or name not in self.responses:
            raise AttributeError(name)

        def method(*args, **kwargs):
            assert not args, f"{name} called positionally"
            sig = inspect.signature(getattr(RESTClient, name))
            named = {n for n, prm in sig.parameters.items() if prm.kind is prm.POSITIONAL_OR_KEYWORD}
            assert set(kwargs) <= named, f"{name}: not SDK parameters: {set(kwargs) - named}"
            sig.bind(None, **kwargs)
            self.calls.append((name, kwargs))
            r = self.responses[name]
            if isinstance(r, list):
                r = r.pop(0)
            if callable(r) and not isinstance(r, type):
                r = r(**kwargs)
            if isinstance(r, Exception):
                raise r
            return r
        return method

    def named(self, name):
        return [kw for n, kw in self.calls if n == name]


def product(pid="BTC-USD", **over):
    base, quote = pid.split("-")
    p = {"product_id": pid, "base_currency_id": base, "quote_currency_id": quote,
         "base_increment": "0.00000001", "quote_increment": "0.01", "base_min_size": "0.00001",
         "status": "online", "trading_disabled": False, "cancel_only": False, "limit_only": False,
         "post_only": False, "is_disabled": False, "approximate_quote_24h_volume": "123456789.5",
         "volume_24h": "1000", "price": "50000", "product_type": "SPOT"}
    p.update(over)
    return p


def products_resp(*ps):
    return ListProductsResponse({"products": [dict(p) for p in ps], "num_products": len(ps)})


def ok_order(oid="oid-1"):
    return CreateOrderResponse({"success": True, "success_response": {"order_id": oid, "product_id": "BTC-USD",
                                                                       "side": "BUY", "client_order_id": "c"}})


def order_dict(oid="oid-1", cid="cid-1", status="OPEN", config=None, side="BUY", filled="0",
               created="2023-11-15T00:00:00.123456789Z"):
    return {"order_id": oid, "client_order_id": cid, "product_id": "BTC-USD", "side": side, "status": status,
            "filled_size": filled, "created_time": created,
            "order_configuration": config or {"limit_limit_gtc": {"base_size": "0.5", "limit_price": "100.00",
                                                                  "post_only": True}}}


def make(client, key=KEY, secret=SECRET, portfolio="pf-1", now=NOW):
    return CoinbaseExchange(key, secret, portfolio, client=client, now=lambda: now)


def hourly(start_ts, n, base=100.0):
    return [{"start": str(start_ts + i * 3600), "low": str(base + i - 1), "high": str(base + i + 2),
             "open": str(base + i), "close": str(base + i + 1), "volume": "10"} for i in range(n)]


def candle_server(series):
    """Answers get_public_candles from `series` (list of candle dicts) like the API: newest first,
    candles whose start lies in [start, end], at most `limit`."""
    def answer(product_id, start, end, granularity, limit=None):
        assert isinstance(start, str) and isinstance(end, str)
        got = [c for c in series if int(start) <= int(c["start"]) <= int(end)]
        got.sort(key=lambda c: -int(c["start"]))
        return GetProductCandlesResponse({"candles": [dict(c) for c in got[:limit] if limit] if limit else got})
    return answer


# ---------------------------------------------------------------- construction and secrets

def test_construction_makes_no_network_call(monkeypatch):
    def no_network(*a, **k):
        raise AssertionError("network call during construction")
    monkeypatch.setattr(requests.Session, "request", no_network)
    ex = CoinbaseExchange(KEY, SECRET, None)
    assert ex.supports_bracket is False
    public = CoinbaseExchange("", "", None)
    assert public.supports_bracket is False


def test_repr_does_not_reveal_secret():
    ex = make(FakeClient())
    assert "TOPSECRET" not in repr(ex) and "TOPSECRET" not in str(vars(ex).get("_client", ""))


def test_sdk_exception_becomes_exchange_error_without_secret():
    c = FakeClient(get_transaction_summary=RuntimeError(f"401 Unauthorized for key {KEY} secret {SECRET}"))
    with pytest.raises(ExchangeError) as e:
        make(c).fees()
    msg = str(e.value)
    assert "TOPSECRET" not in msg and KEY not in msg and "get_transaction_summary" in msg
    assert e.value.__cause__ is None and e.value.__suppress_context__


def test_private_call_without_keys_raises_without_calling_sdk():
    c = FakeClient(get_accounts=ListAccountsResponse({"accounts": []}))
    with pytest.raises(ExchangeError, match="API key"):
        make(c, key="", secret="").balances()
    assert c.calls == []


# ---------------------------------------------------------------- products

def test_products_map_status_flags_and_fields():
    c = FakeClient(get_public_products=products_resp(
        product("BTC-USD"),
        product("ETH-USD", trading_disabled=True),
        product("SOL-USD", cancel_only=True),
        product("ADA-USD", limit_only=True),
        product("XRP-USD", status="delisted"),
        product("DOT-USD", is_disabled=True),
    ))
    ps = {p.product_id: p for p in make(c, key="", secret="").products()}
    assert c.named("get_public_products") == [{"product_type": "SPOT"}]
    btc = ps["BTC-USD"]
    assert (btc.base, btc.quote, btc.base_increment, btc.quote_increment, btc.min_base_size) == \
        ("BTC", "USD", 0.00000001, 0.01, 0.00001)
    assert btc.status == "online" and btc.volume_24h_usd == 123456789.5
    assert ps["ETH-USD"].status == "disabled"
    assert ps["SOL-USD"].status == "cancel_only"
    assert ps["ADA-USD"].status == "limit_only"
    assert ps["XRP-USD"].status == "disabled"  # unknown status fails closed
    assert ps["DOT-USD"].status == "disabled"


def test_products_volume_falls_back_to_base_volume_times_price():
    p = product()
    del p["approximate_quote_24h_volume"]
    c = FakeClient(get_public_products=products_resp(p))
    assert make(c).products()[0].volume_24h_usd == 1000 * 50000


def test_products_missing_field_raises():
    p = product()
    del p["base_increment"]
    with pytest.raises(ExchangeError, match="base_increment"):
        make(FakeClient(get_public_products=products_resp(p))).products()


def test_products_truncated_list_raises():
    r = ListProductsResponse({"products": [product()], "num_products": 5})
    with pytest.raises(ExchangeError, match="truncated"):
        make(FakeClient(get_public_products=r)).products()


# ---------------------------------------------------------------- candles and prices

def test_candles_oldest_first_and_limited():
    series = hourly(NOW - 10 * 3600, 10)
    c = FakeClient(get_public_candles=candle_server(series))
    got = make(c, key="", secret="").candles("BTC-USD", 3600, 3)
    assert [x.ts for x in got] == [NOW - 3 * 3600, NOW - 2 * 3600, NOW - 3600]
    assert got[-1] == Candle(NOW - 3600, 109.0, 111.0, 108.0, 110.0, 10.0)
    kw = c.named("get_public_candles")[0]
    assert kw["granularity"] == "ONE_HOUR" and kw["product_id"] == "BTC-USD" and kw["end"] == str(NOW)


def test_candles_page_backwards_in_requests_of_at_most_300():
    series = hourly(NOW - 700 * 3600, 700)
    c = FakeClient(get_public_candles=candle_server(series))
    got = make(c).candles("BTC-USD", 3600, 650)
    assert len(got) == 650 and got == sorted(got, key=lambda x: x.ts) and len({x.ts for x in got}) == 650
    calls = c.named("get_public_candles")
    assert len(calls) == 3 and all(kw["limit"] <= 300 for kw in calls)


def test_four_hour_candles_aggregate_complete_buckets_only():
    # 10 hourly candles from NOW-9h: the last hour of a 4h bucket (incomplete), two full 4h buckets,
    # then the first hour of the bucket in progress at NOW.
    first = NOW - 9 * 3600
    series = hourly(first, 10)
    c = FakeClient(get_public_candles=candle_server(series))
    got = make(c).candles("BTC-USD", 14400, 10)
    assert all(x.ts % 14400 == 0 for x in got)
    # buckets fully covered by the hourly data and finished by NOW
    expect = [b for b in range(first - first % 14400, NOW, 14400) if b >= first and b + 14400 <= NOW]
    assert [x.ts for x in got] == expect and len(expect) == 2
    b0 = [h for h in series if expect[0] <= int(h["start"]) < expect[0] + 14400]
    assert got[0] == Candle(expect[0], float(b0[0]["open"]), max(float(h["high"]) for h in b0),
                            min(float(h["low"]) for h in b0), float(b0[-1]["close"]), 40.0)
    assert c.named("get_public_candles")[0]["granularity"] == "ONE_HOUR"


def test_candle_missing_field_raises():
    bad = hourly(NOW - 3600, 1)
    del bad[0]["close"]
    with pytest.raises(ExchangeError, match="close"):
        make(FakeClient(get_public_candles=candle_server(bad))).candles("BTC-USD", 3600, 1)


def test_bid_ask_from_public_book_without_keys():
    book = GetProductBookResponse({"pricebook": {"product_id": "BTC-USD", "bids": [{"price": "99.5", "size": "1"}],
                                                 "asks": [{"price": "100.5", "size": "2"}], "time": "t"}})
    c = FakeClient(get_public_product_book=book)
    assert make(c, key="", secret="").bid_ask("BTC-USD") == (99.5, 100.5)
    assert c.named("get_public_product_book") == [{"product_id": "BTC-USD", "limit": 1}]


def test_bid_ask_empty_book_raises():
    book = GetProductBookResponse({"pricebook": {"product_id": "BTC-USD", "bids": [], "asks": []}})
    with pytest.raises(ExchangeError, match="BTC-USD"):
        make(FakeClient(get_public_product_book=book)).bid_ask("BTC-USD")


# ---------------------------------------------------------------- account

def test_fee_tier_maps_to_fees():
    r = GetTransactionSummaryResponse({"total_volume": 0, "total_fees": 0, "fee_tier": {
        "pricing_tier": "Intro 1", "maker_fee_rate": "0.005", "taker_fee_rate": "0.009"}})
    c = FakeClient(get_transaction_summary=r)
    assert make(c).fees() == Fees(0.005, 0.009)
    assert c.named("get_transaction_summary") == [{"product_type": "SPOT"}]


@pytest.mark.parametrize("tier", [{"maker_fee_rate": "0.005"}, {"maker_fee_rate": "0.5", "taker_fee_rate": "0.9"}])
def test_fee_tier_missing_or_implausible_raises(tier):
    r = GetTransactionSummaryResponse({"fee_tier": tier})
    with pytest.raises(ExchangeError):
        make(FakeClient(get_transaction_summary=r)).fees()


def test_balances_sum_available_and_hold_across_pages():
    page1 = ListAccountsResponse({"accounts": [
        {"currency": "USD", "available_balance": {"value": "20.5", "currency": "USD"},
         "hold": {"value": "4.5", "currency": "USD"}}], "has_next": True, "cursor": "c2"})
    page2 = ListAccountsResponse({"accounts": [
        {"currency": "BTC", "available_balance": {"value": "0.001", "currency": "BTC"},
         "hold": {"value": "0", "currency": "BTC"}}], "has_next": False, "cursor": ""})
    c = FakeClient(get_accounts=[page1, page2])
    assert make(c).balances() == {"USD": 25.0, "BTC": 0.001}
    calls = c.named("get_accounts")
    assert calls[0]["retail_portfolio_id"] == "pf-1" and calls[1]["cursor"] == "c2"


def test_balances_missing_hold_raises():
    r = ListAccountsResponse({"accounts": [{"currency": "USD", "available_balance": {"value": "1"}}],
                              "has_next": False})
    with pytest.raises(ExchangeError, match="hold"):
        make(FakeClient(get_accounts=r)).balances()


@pytest.mark.parametrize("resp,expected", [
    ({"can_view": True, "can_trade": True, "can_transfer": True}, True),
    ({"can_view": True, "can_trade": True, "can_transfer": False}, False),
    ({"can_view": True, "can_trade": False, "can_withdraw": True}, True),
])
def test_can_transfer_reads_key_permissions(resp, expected):
    c = FakeClient(get_api_key_permissions=GetAPIKeyPermissionsResponse(dict(resp)))
    assert make(c).can_transfer() is expected


def test_can_transfer_unreadable_raises():
    c = FakeClient(get_api_key_permissions=GetAPIKeyPermissionsResponse({"can_view": True}))
    with pytest.raises(ExchangeError, match="cannot verify key permissions"):
        make(c).can_transfer()
    c = FakeClient(get_api_key_permissions=RuntimeError("403"))
    with pytest.raises(ExchangeError, match="cannot verify key permissions"):
        make(c).can_transfer()


# ---------------------------------------------------------------- order placement

def placing_client(**extra):
    return FakeClient(get_public_products=products_resp(product()), limit_order_gtc_buy=ok_order("e-1"),
                      stop_limit_order_gtc_sell=ok_order("s-1"), limit_order_ioc_sell=ok_order("i-1"), **extra)


def test_place_entry_is_post_only_gtc_with_sizes_rounded_down_as_strings():
    c = placing_client()
    oid = make(c).place_entry("BTC-USD", 0.123456789, 100.129, "BTC-USD-entry-1-1")
    assert oid == "e-1"
    assert c.named("limit_order_gtc_buy") == [{
        "client_order_id": "BTC-USD-entry-1-1", "product_id": "BTC-USD", "base_size": "0.12345678",
        "limit_price": "100.12", "post_only": True, "retail_portfolio_id": "pf-1"}]
    assert not any("market" in n for n, _ in c.calls)


def test_repeated_client_order_id_is_passed_through_unchanged():
    c = placing_client()
    c.responses["limit_order_gtc_buy"] = [ok_order("e-1"), ok_order("e-1")]
    ex = make(c)
    ex.place_entry("BTC-USD", 0.5, 100, "same-id")
    ex.place_entry("BTC-USD", 0.5, 100, "same-id")
    assert [kw["client_order_id"] for kw in c.named("limit_order_gtc_buy")] == ["same-id", "same-id"]


def test_place_entry_no_portfolio_sends_none():
    c = placing_client()
    make(c, portfolio=None).place_entry("BTC-USD", 0.5, 100, "x")
    assert c.named("limit_order_gtc_buy")[0]["retail_portfolio_id"] is None


def test_place_entry_rejected_raises_with_reason():
    c = placing_client()
    c.responses["limit_order_gtc_buy"] = CreateOrderResponse({
        "success": False, "error_response": {"error": "INSUFFICIENT_FUND", "message": "Insufficient balance"}})
    with pytest.raises(ExchangeError, match="INSUFFICIENT_FUND"):
        make(c).place_entry("BTC-USD", 0.5, 100, "x")


def test_place_entry_without_order_id_raises():
    c = placing_client()
    c.responses["limit_order_gtc_buy"] = CreateOrderResponse({"success": True, "success_response": {}})
    with pytest.raises(ExchangeError, match="order_id"):
        make(c).place_entry("BTC-USD", 0.5, 100, "x")


@pytest.mark.parametrize("size,price", [(0.000001, 100.0), (0.5, 0.001), (0.5, -1.0)])
def test_place_entry_below_minimum_or_bad_price_raises_before_sending(size, price):
    c = placing_client()
    with pytest.raises(ExchangeError):
        make(c).place_entry("BTC-USD", size, price, "x")
    assert c.named("limit_order_gtc_buy") == []


def test_place_entry_unknown_product_raises():
    with pytest.raises(ExchangeError, match="unknown product"):
        make(placing_client()).place_entry("NOPE-USD", 1, 1, "x")


def test_place_stop_payload():
    c = placing_client()
    oid = make(c).place_stop("BTC-USD", 0.300000009, 95.019, 90.261, "BTC-USD-stop-1-2")
    assert oid == "s-1"
    assert c.named("stop_limit_order_gtc_sell") == [{
        "client_order_id": "BTC-USD-stop-1-2", "product_id": "BTC-USD", "base_size": "0.30000000",
        "limit_price": "90.26", "stop_price": "95.01", "stop_direction": "STOP_DIRECTION_STOP_DOWN",
        "retail_portfolio_id": "pf-1"}]


def test_place_stop_limit_above_trigger_raises():
    c = placing_client()
    with pytest.raises(ExchangeError, match="stop_limit"):
        make(c).place_stop("BTC-USD", 0.3, 95, 96, "x")
    assert c.named("stop_limit_order_gtc_sell") == []


def test_place_bracket_unsupported_and_sends_nothing():
    c = placing_client(trigger_bracket_order_gtc_sell=ok_order("b-1"))
    ex = make(c)
    assert ex.supports_bracket is False
    with pytest.raises(ExchangeError, match="bracket"):
        ex.place_bracket("BTC-USD", 0.3, 95, 90, 120, "x")
    assert c.named("trigger_bracket_order_gtc_sell") == []


def test_preview_stop_sends_what_place_stop_sends_and_places_nothing():
    from coinbase.rest.types.orders_types import PreviewOrderResponse
    c = placing_client(preview_stop_limit_order_gtc_sell=PreviewOrderResponse({"order_total": "1"}))
    ex = make(c)
    ex.preview_stop("BTC-USD", 0.25, 80.019, 76.0188)
    ex.place_stop("BTC-USD", 0.25, 80.019, 76.0188, "cid")
    [prev] = c.named("preview_stop_limit_order_gtc_sell")
    [real] = c.named("stop_limit_order_gtc_sell")
    assert prev == {k: v for k, v in real.items() if k != "client_order_id"}
    assert c.named("limit_order_gtc_buy") == []


def test_preview_stop_rejection_raises_with_the_venue_message():
    from coinbase.rest.types.orders_types import PreviewOrderResponse
    c = placing_client(preview_stop_limit_order_gtc_sell=PreviewOrderResponse(
        {"errs": [{"preview_failure_reason": "INVALID_STOP_DIRECTION"}]}))
    with pytest.raises(ExchangeError, match="INVALID_STOP_DIRECTION"):
        make(c).preview_stop("BTC-USD", 0.25, 80.0, 76.0)


def test_place_ioc_sell_payload():
    c = placing_client()
    assert make(c).place_ioc_sell("BTC-USD", 0.25, 98.0099, "BTC-USD-ioc-1-3") == "i-1"
    assert c.named("limit_order_ioc_sell") == [{
        "client_order_id": "BTC-USD-ioc-1-3", "product_id": "BTC-USD", "base_size": "0.25000000",
        "limit_price": "98.00", "retail_portfolio_id": "pf-1"}]


# ---------------------------------------------------------------- orders

def test_get_order_maps_fields():
    c = FakeClient(get_order=GetOrderResponse({"order": order_dict(status="OPEN", filled="0.1")}))
    o = make(c).get_order("oid-1")
    assert (o.order_id, o.client_order_id, o.product_id, o.kind, o.status) == \
        ("oid-1", "cid-1", "BTC-USD", "entry", "open")
    assert (o.base_size, o.filled_size, o.limit_price, o.stop_trigger, o.target) == (0.5, 0.1, 100.0, None, None)
    assert o.created_ts == 1_700_006_400
    assert c.named("get_order") == [{"order_id": "oid-1"}]


def test_order_carries_the_venues_average_fill_price_when_present():
    """SDK types/orders_types.py: Order.average_filled_price. Optional: absent, empty or zero -> None."""
    def avg(**fields):
        c = FakeClient(get_order=GetOrderResponse({"order": {**order_dict(status="FILLED", filled="0.5"), **fields}}))
        return make(c).get_order("oid-1").avg_fill_price

    assert avg(average_filled_price="99.5") == 99.5
    assert avg() is None and avg(average_filled_price="") is None and avg(average_filled_price="0") is None
    c = FakeClient(get_order=GetOrderResponse({"order": {**order_dict(filled="0"), "average_filled_price": "99.5"}}))
    assert make(c).get_order("oid-1").avg_fill_price is None  # nothing filled: no price
    assert avg(average_filled_price="x") is None  # unreadable: dropped, the order itself still reads


@pytest.mark.parametrize("status,mapped", [("FILLED", "filled"), ("CANCELLED", "cancelled"),
                                           ("EXPIRED", "cancelled"), ("FAILED", "cancelled"),
                                           ("PENDING", "open"), ("QUEUED", "open"), ("CANCEL_QUEUED", "open")])
def test_order_status_mapping(status, mapped):
    c = FakeClient(get_order=GetOrderResponse({"order": order_dict(status=status)}))
    assert make(c).get_order("oid-1").status == mapped


def test_unknown_order_status_raises():
    c = FakeClient(get_order=GetOrderResponse({"order": order_dict(status="WEIRD")}))
    with pytest.raises(ExchangeError, match="WEIRD"):
        make(c).get_order("oid-1")


def test_stop_and_ioc_orders_map_kind_and_prices():
    stop = order_dict(side="SELL", config={"stop_limit_stop_limit_gtc": {
        "base_size": "0.3", "limit_price": "90.26", "stop_price": "95.01",
        "stop_direction": "STOP_DIRECTION_STOP_DOWN"}})
    ioc = order_dict(oid="oid-2", side="SELL", config={"sor_limit_ioc": {"base_size": "0.2", "limit_price": "98"}})
    c = FakeClient(get_order=[GetOrderResponse({"order": stop}), GetOrderResponse({"order": ioc})])
    ex = make(c)
    s = ex.get_order("oid-1")
    assert (s.kind, s.base_size, s.limit_price, s.stop_trigger) == ("stop", 0.3, 90.26, 95.01)
    i = ex.get_order("oid-2")
    assert (i.kind, i.base_size, i.limit_price) == ("ioc", 0.2, 98.0)


def test_get_order_missing_order_raises():
    with pytest.raises(ExchangeError, match="order"):
        make(FakeClient(get_order=GetOrderResponse({}))).get_order("oid-1")


def test_open_orders_pages_and_filters_open():
    p1 = ListOrdersResponse({"orders": [order_dict("a")], "has_next": True, "cursor": "n"})
    p2 = ListOrdersResponse({"orders": [order_dict("b")], "has_next": False, "cursor": ""})
    c = FakeClient(list_orders=[p1, p2])
    assert [o.order_id for o in make(c).open_orders()] == ["a", "b"]
    calls = c.named("list_orders")
    assert calls[0]["order_status"] == ["OPEN"] and calls[0]["retail_portfolio_id"] == "pf-1"
    assert calls[1]["cursor"] == "n"


def test_get_order_by_client_id_searches_pages():
    p1 = ListOrdersResponse({"orders": [order_dict("a", cid="other")], "has_next": True, "cursor": "n"})
    p2 = ListOrdersResponse({"orders": [order_dict("b", cid="mine", status="FILLED", filled="0.5")],
                             "has_next": False})
    c = FakeClient(list_orders=[p1, p2])
    o = make(c).get_order_by_client_id("mine")
    assert o.order_id == "b" and o.status == "filled"
    assert "order_status" not in c.named("list_orders")[0]


def test_get_order_by_client_id_none_when_absent():
    c = FakeClient(list_orders=ListOrdersResponse({"orders": [order_dict("a", cid="other")], "has_next": False}))
    assert make(c).get_order_by_client_id("mine") is None


def test_get_order_by_client_id_empty_page_with_more_keeps_searching():
    p1 = ListOrdersResponse({"orders": [], "has_next": True, "cursor": "n"})
    p2 = ListOrdersResponse({"orders": [order_dict("b", cid="mine")], "has_next": False})
    assert make(FakeClient(list_orders=[p1, p2])).get_order_by_client_id("mine").order_id == "b"


def test_get_order_by_client_id_unfinished_search_raises():
    c = FakeClient(list_orders=lambda **kw: ListOrdersResponse(
        {"orders": [order_dict("a", cid="other")], "has_next": True, "cursor": "same"}))
    with pytest.raises(ExchangeError):
        make(c).get_order_by_client_id("mine")


def test_cancel_success():
    c = FakeClient(cancel_orders=CancelOrdersResponse({"results": [{"success": True, "order_id": "a"}]}))
    make(c).cancel("a")
    assert c.named("cancel_orders") == [{"order_ids": ["a"]}]


def test_cancel_of_finished_order_does_nothing():
    c = FakeClient(cancel_orders=CancelOrdersResponse({"results": [
        {"success": False, "failure_reason": "UNKNOWN_CANCEL_ORDER", "order_id": "a"}]}),
        get_order=GetOrderResponse({"order": order_dict("a", status="FILLED", filled="0.5")}))
    make(c).cancel("a")


def test_cancel_failure_on_open_order_raises():
    c = FakeClient(cancel_orders=CancelOrdersResponse({"results": [
        {"success": False, "failure_reason": "UNKNOWN_CANCEL_FAILURE_REASON", "order_id": "a"}]}),
        get_order=GetOrderResponse({"order": order_dict("a", status="OPEN")}))
    with pytest.raises(ExchangeError, match="UNKNOWN_CANCEL_FAILURE_REASON"):
        make(c).cancel("a")


# ---------------------------------------------------------------- fills and transfers

def fill(oid, side, price, size, commission, t, **over):
    f = {"entry_id": "e", "trade_id": "t", "order_id": oid, "trade_time": t, "trade_type": "FILL",
         "price": price, "size": size, "commission": commission, "product_id": "BTC-USD",
         "sequence_timestamp": t, "liquidity_indicator": "MAKER", "size_in_quote": False,
         "user_id": "u", "side": side}
    f.update(over)
    return f


def test_fills_map_side_reason_and_time():
    stop_order = order_dict("s", side="SELL", config={"stop_limit_stop_limit_gtc": {
        "base_size": "0.5", "limit_price": "90", "stop_price": "95", "stop_direction": "STOP_DIRECTION_STOP_DOWN"}})
    ioc_order = order_dict("i", side="SELL", config={"sor_limit_ioc": {"base_size": "0.1", "limit_price": "98"}})
    fills = ListFillsResponse({"fills": [
        fill("e", "BUY", "100", "0.5", "0.25", "2023-11-15T00:00:00Z"),
        fill("s", "SELL", "94", "0.5", "0.42", "2023-11-15T01:00:00.5Z"),
        fill("i", "SELL", "98", "9.8", "0.08", "2023-11-15T02:00:00Z", size_in_quote=True),
    ], "cursor": ""})
    orders = {"s": stop_order, "i": ioc_order}
    c = FakeClient(get_fills=fills, get_order=lambda order_id: GetOrderResponse({"order": orders[order_id]}))
    got = make(c).fills(1_700_006_400)
    assert [(f.order_id, f.side, f.reason) for f in got] == [("e", "buy", "entry"), ("s", "sell", "stop"),
                                                            ("i", "sell", "ioc")]
    assert got[0].price == 100.0 and got[0].base_size == 0.5 and got[0].fee == 0.25
    assert got[1].ts == 1_700_006_400 + 3600
    assert got[2].base_size == pytest.approx(0.1)
    kw = c.named("get_fills")[0]
    assert kw["start_sequence_timestamp"] == "2023-11-15T00:00:00Z" and kw["retail_portfolio_id"] == "pf-1"


def test_fills_before_since_are_dropped():
    fills = ListFillsResponse({"fills": [fill("e", "BUY", "100", "0.5", "0.25", "2023-11-14T23:59:59Z")],
                               "cursor": ""})
    assert make(FakeClient(get_fills=fills)).fills(1_700_006_400) == []


def test_transfers_inferred_from_unexplained_usd_change():
    usd = {"v": "25"}
    accounts = lambda **kw: ListAccountsResponse({"accounts": [  # noqa: E731
        {"currency": "USD", "available_balance": {"value": usd["v"]}, "hold": {"value": "0"}}], "has_next": False})
    fills = {"list": []}
    c = FakeClient(get_accounts=accounts, get_public_products=products_resp(product()),
                   get_fills=lambda **kw: ListFillsResponse({"fills": list(fills["list"]), "cursor": ""}))
    clock = {"t": NOW}
    ex = CoinbaseExchange(KEY, SECRET, "pf-1", client=c, now=lambda: clock["t"])
    assert ex.transfers(0) == []  # first call sets the baseline
    clock["t"] += 900
    usd["v"] = "35"  # +10 deposit
    assert ex.transfers(0) == []  # first sighting only
    clock["t"] += 900
    got = ex.transfers(0)  # the same amount on a second consecutive call: a real deposit
    assert [(t.ts, t.amount_usd) for t in got] == [(NOW + 1800, 10.0)]
    clock["t"] += 900
    usd["v"] = "24.75"  # bought 0.1 @ 100 + 0.25 fee: explained, not a transfer
    fills["list"] = [fill("e", "BUY", "100", "0.1", "0.25", "2023-11-15T00:40:00Z")]
    assert [(t.ts, t.amount_usd) for t in ex.transfers(0)] == [(NOW + 1800, 10.0)]
    assert ex.transfers(NOW + 1801) == []


def _transfer_exchange(usd, fills):
    accounts = lambda **kw: ListAccountsResponse({"accounts": [  # noqa: E731
        {"currency": "USD", "available_balance": {"value": usd["v"]}, "hold": {"value": "0"}}], "has_next": False})
    c = FakeClient(get_accounts=accounts, get_public_products=products_resp(product()),
                   get_fills=lambda **kw: ListFillsResponse({"fills": list(fills["list"]), "cursor": ""}))
    clock = {"t": NOW}
    return CoinbaseExchange(KEY, SECRET, "pf-1", client=c, now=lambda: clock["t"]), clock


def test_a_late_fill_is_never_booked_as_a_transfer():
    usd, fills = {"v": "100"}, {"list": []}
    ex, clock = _transfer_exchange(usd, fills)
    ex.transfers(0)
    clock["t"] += 900
    usd["v"] = "50"  # entry fill spent 50 but fills() has not listed it yet
    ex.hint_quantity_change(True)  # the engine saw the order status change
    assert ex.transfers(0) == []
    clock["t"] += 900
    assert ex.transfers(0) == []  # without the hint: first sighting only
    clock["t"] += 900
    fills["list"] = [fill("e", "BUY", "100", "0.5", "0", "2023-11-15T00:20:00Z")]  # the fill appears
    assert ex.transfers(0) == []
    clock["t"] += 900
    assert ex.transfers(0) == []


def test_a_deposit_seen_on_two_quiet_calls_is_emitted_once():
    usd, fills = {"v": "25"}, {"list": []}
    ex, clock = _transfer_exchange(usd, fills)
    ex.transfers(0)
    usd["v"] = "75"
    for _ in range(2):
        clock["t"] += 900
        ex.hint_quantity_change(False)
        got = ex.transfers(0)
    assert [t.amount_usd for t in got] == [50.0]
    clock["t"] += 900
    assert [t.amount_usd for t in ex.transfers(0)] == [50.0]


def test_transfers_wait_while_a_fill_is_settling():
    usd = {"v": "25"}
    accounts = lambda **kw: ListAccountsResponse({"accounts": [  # noqa: E731
        {"currency": "USD", "available_balance": {"value": usd["v"]}, "hold": {"value": "0"}}], "has_next": False})
    fills = {"list": []}
    c = FakeClient(get_accounts=accounts, get_public_products=products_resp(product()),
                   get_fills=lambda **kw: ListFillsResponse({"fills": list(fills["list"]), "cursor": ""}))
    clock = {"t": NOW}
    ex = CoinbaseExchange(KEY, SECRET, "pf-1", client=c, now=lambda: clock["t"])
    ex.transfers(0)
    clock["t"] += 900
    fills["list"] = [fill("e", "BUY", "100", "0.1", "0.25", "2023-11-15T00:14:50Z")]  # 10 s before now
    assert ex.transfers(0) == []  # balance may not reflect it yet: try again next cycle
    clock["t"] += 900
    usd["v"] = "14.75"
    assert ex.transfers(0) == []


# ---------------------------------------------------------------- history download

def test_download_history_writes_closed_hourly_candles_oldest_first(tmp_path):
    series = hourly(NOW - 2 * 86400, 48 + 1)  # includes the hour in progress at NOW
    c = FakeClient(get_public_candles=candle_server(series))
    download_history(["BTC-USD"], 2, str(tmp_path), client=c, now=lambda: NOW, pause_s=0)
    with open(os.path.join(tmp_path, "BTC-USD.csv")) as f:
        rows = list(csv.reader(f))
    assert rows[0] == ["ts", "open", "high", "low", "close", "volume"]
    ts = [int(r[0]) for r in rows[1:]]
    assert ts == list(range(NOW - 2 * 86400, NOW, 3600))
    assert rows[1][1:] == ["100.0", "102.0", "99.0", "101.0", "10.0"]
    assert all(kw["granularity"] == "ONE_HOUR" and kw["limit"] <= 300 for kw in c.named("get_public_candles"))
