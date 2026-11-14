import pytest

from bot.exchange import ExchangeError, PaperExchange
from bot.models import Candle, Fees, Product, Transfer

SOL = Product("SOL-USD", "SOL", "USD", 0.001, 0.01, 0.01, "online", 1e9)
FEES = Fees(0.006, 0.012)
H = 3600


@pytest.fixture
def px():
    return PaperExchange(1000.0, FEES, [SOL])


def hold_tenth(px):
    """Buy 0.1 SOL at 100 on candle ts 0: cash 1000 - 10 - 0.06 = 989.94."""
    px.place_entry("SOL-USD", 0.1, 100.0, "buy")
    px.feed("SOL-USD", H, Candle(0, 101, 102, 99.0, 101, 1))
    assert px.balances()["SOL"] == pytest.approx(0.1)


def test_entry_needs_trade_through(px):
    oid = px.place_entry("SOL-USD", 0.1, 100.0, "c1")
    px.feed("SOL-USD", H, Candle(0, 101, 102, 100.0, 101, 1)); assert px.get_order(oid).status == "open"
    px.feed("SOL-USD", H, Candle(H, 101, 102, 99.9, 101, 1)); assert px.get_order(oid).status == "filled"
    f = px.fills(0)[0]
    assert f.fee == pytest.approx(0.1 * 100 * 0.006)
    assert (f.price, f.side, f.reason, f.ts) == (100.0, "buy", "entry", H)
    assert px.balances()["USD"] == pytest.approx(989.94)
    assert px.get_order(oid).filled_size == pytest.approx(0.1)


def test_gap_through_stop_limit_leaves_stop_unfilled(px):
    hold_tenth(px)
    sid = px.place_stop("SOL-USD", 0.1, 90.0, 85.5, "s1")
    px.feed("SOL-USD", H, Candle(H, 80, 82, 78, 81, 1))  # trigger price min(90, 80) = 80 < 85.5
    assert px.get_order(sid).status == "open" and px.balances()["SOL"] == 0.1
    assert len(px.fills(0)) == 1  # only the entry


def test_gapped_stop_rests_as_limit_sell(px):
    hold_tenth(px)
    sid = px.place_stop("SOL-USD", 0.1, 90.0, 85.5, "s1")
    px.feed("SOL-USD", H, Candle(H, 80, 82, 78, 81, 1))  # gap: triggered, unfilled
    px.feed("SOL-USD", H, Candle(2 * H, 83, 85.0, 82, 84, 1))  # high 85.0 < 85.5
    assert px.get_order(sid).status == "open" and px.balances()["SOL"] == 0.1
    px.feed("SOL-USD", H, Candle(3 * H, 84, 86, 83, 85, 1))  # high reaches limit: max(85.5, 84)
    assert px.get_order(sid).status == "filled"
    f = px.fills(3 * H)[0]
    assert (f.price, f.reason) == (85.5, "stop")
    assert f.fee == pytest.approx(0.1 * 85.5 * 0.012)


def test_gapped_bracket_target_never_fills(px):
    hold_tenth(px)
    bid = px.place_bracket("SOL-USD", 0.1, 90.0, 85.5, 120.0, "b1")
    px.feed("SOL-USD", H, Candle(H, 80, 82, 78, 81, 1))  # gap: stop triggered, unfilled
    px.feed("SOL-USD", H, Candle(2 * H, 125, 130, 124, 128, 1))  # target is gone; rests at 85.5
    f = px.fills(2 * H)[0]
    assert px.get_order(bid).status == "filled" and (f.price, f.reason) == (125.0, "stop")


def test_gapped_stop_fills_on_later_candle(px):
    hold_tenth(px)
    sid = px.place_stop("SOL-USD", 0.1, 90.0, 85.5, "s1")
    px.feed("SOL-USD", H, Candle(H, 80, 82, 78, 81, 1))
    px.feed("SOL-USD", H, Candle(2 * H, 87, 88, 86, 87, 1))  # max(85.5, 87) = 87
    assert px.get_order(sid).status == "filled"
    f = px.fills(2 * H)[0]
    assert (f.price, f.reason, f.ts) == (87.0, "stop", 2 * H)
    assert f.fee == pytest.approx(0.1 * 87 * 0.012)


def test_stop_fills_at_open_when_gapped_inside_limit(px):
    hold_tenth(px)
    sid = px.place_stop("SOL-USD", 0.1, 90.0, 85.5, "s1")
    px.feed("SOL-USD", H, Candle(H, 88, 89, 87, 88, 1))
    assert px.get_order(sid).status == "filled"
    f = px.fills(H)[0]
    assert (f.price, f.side, f.reason) == (88.0, "sell", "stop")
    assert f.fee == pytest.approx(0.1 * 88 * 0.012)  # taker: 0.1056
    assert px.balances()["SOL"] == 0.0
    assert px.balances()["USD"] == pytest.approx(989.94 + 8.8 - 0.1056)


def test_bracket_stop_wins_when_both_hit(px):
    hold_tenth(px)
    bid = px.place_bracket("SOL-USD", 0.1, 90.0, 85.5, 120.0, "b1")
    px.feed("SOL-USD", H, Candle(H, 100, 125, 85, 95, 1))
    assert px.get_order(bid).status == "filled"
    sells = px.fills(H)
    assert len(sells) == 1
    assert (sells[0].price, sells[0].reason) == (90.0, "stop")
    assert sells[0].fee == pytest.approx(0.1 * 90 * 0.012)


def test_bracket_target_fills_at_maker(px):
    hold_tenth(px)
    bid = px.place_bracket("SOL-USD", 0.1, 90.0, 85.5, 120.0, "b1")
    px.feed("SOL-USD", H, Candle(H, 110, 120, 105, 118, 1))  # high == target: not through
    assert px.get_order(bid).status == "open"
    px.feed("SOL-USD", H, Candle(2 * H, 118, 121, 115, 119, 1))
    assert px.get_order(bid).status == "filled" and px.open_orders() == []
    f = px.fills(2 * H)[0]
    assert (f.price, f.reason) == (120.0, "target")
    assert f.fee == pytest.approx(0.1 * 120 * 0.006)
    assert px.balances()["SOL"] == 0.0


def test_ioc_sell_fills_at_close_or_cancels(px):
    hold_tenth(px)
    a = px.place_ioc_sell("SOL-USD", 0.05, 95.0, "i1")
    px.feed("SOL-USD", H, Candle(H, 96, 98, 94, 97, 1))  # fill at max(95, 97) = 97
    assert px.get_order(a).status == "filled"
    f = px.fills(H)[0]
    assert (f.price, f.reason) == (97.0, "ioc")
    assert f.fee == pytest.approx(0.05 * 97 * 0.012)
    b = px.place_ioc_sell("SOL-USD", 0.05, 95.0, "i2")
    px.feed("SOL-USD", H, Candle(2 * H, 96, 97, 93, 94, 1))  # close 94 < 95
    assert px.get_order(b).status == "cancelled" and px.balances()["SOL"] == pytest.approx(0.05)


def test_duplicate_client_order_id_is_idempotent(px):
    a = px.place_entry("SOL-USD", 0.1, 100.0, "c1")
    b = px.place_entry("SOL-USD", 0.1, 100.0, "c1")
    assert a == b and len(px.open_orders()) == 1
    hold = px.place_entry("SOL-USD", 0.1, 100.0, "c2")
    assert hold != a and len(px.open_orders()) == 2


def test_cannot_oversell_held_coins(px):
    hold_tenth(px)
    px.place_bracket("SOL-USD", 0.05, 90.0, 85.5, 120.0, "b1")
    with pytest.raises(ExchangeError):
        px.place_stop("SOL-USD", 0.06, 90.0, 85.5, "s1")
    assert len(px.open_orders()) == 1
    px.place_stop("SOL-USD", 0.05, 90.0, 85.5, "s2")  # exactly the rest is allowed


def test_fail_next_raises_once(px):
    px.fail_next = "balances"
    with pytest.raises(ExchangeError):
        px.balances()
    assert px.fail_next is None
    assert px.balances()["USD"] == 1000.0


def test_entry_reserves_cash_until_cancelled(px):
    a = px.place_entry("SOL-USD", 9.0, 100.0, "c1")  # reserves 9 * 100 * 1.006 = 905.4
    with pytest.raises(ExchangeError):
        px.place_entry("SOL-USD", 1.0, 100.0, "c2")  # needs 100.6, free 94.6
    px.cancel(a)
    assert px.get_order(a).status == "cancelled"
    px.place_entry("SOL-USD", 1.0, 100.0, "c2")
    assert px.balances()["USD"] == 1000.0  # reservations are not deductions


def test_partial_fill_leaves_rest_open(px):
    oid = px.place_entry("SOL-USD", 0.1, 100.0, "c1")
    px.partial_fill(oid, 0.04, 100.0, 50)
    o = px.get_order(oid)
    assert o.status == "open" and o.filled_size == pytest.approx(0.04)
    assert px.balances()["USD"] == pytest.approx(1000 - 4 - 0.024)
    px.feed("SOL-USD", H, Candle(H, 101, 102, 99, 101, 1))
    o = px.get_order(oid)
    assert o.status == "filled" and o.filled_size == pytest.approx(0.1)
    assert [f.base_size for f in px.fills(0)] == pytest.approx([0.04, 0.06])
    assert px.balances()["SOL"] == pytest.approx(0.1)
    assert px.balances()["USD"] == pytest.approx(989.94)


def test_bid_ask_candles_and_feed_without_fills(px):
    with pytest.raises(ExchangeError):
        px.bid_ask("SOL-USD")
    oid = px.place_entry("SOL-USD", 0.1, 100.0, "c1")
    px.feed("SOL-USD", H, Candle(0, 101, 102, 100.5, 101, 1))
    px.feed("SOL-USD", 86400, Candle(0, 101, 102, 95, 100, 1), fills=False)
    assert px.get_order(oid).status == "open"  # coarse series never fills
    assert px.bid_ask("SOL-USD") == pytest.approx((99.95, 100.05))
    assert [c.ts for c in px.candles("SOL-USD", H, 10)] == [0]
    assert px.candles("SOL-USD", 86400, 10)[0].low == 95


def test_deposits_are_transfers(px):
    px.deposit(50.0, 100)
    assert px.transfers(0) == [Transfer(100, 50.0)] and px.transfers(101) == []
    assert px.balances()["USD"] == 1050.0
    assert px.can_transfer() is False


def test_get_order_by_client_id(px):
    oid = px.place_entry("SOL-USD", 0.1, 100.0, "mine")
    assert px.get_order_by_client_id("mine").order_id == oid
    assert px.get_order_by_client_id("nobody") is None


def test_fail_after_next_performs_the_call_then_raises_once(px):
    px.fail_after_next = "place_entry"
    with pytest.raises(ExchangeError):
        px.place_entry("SOL-USD", 0.1, 100.0, "lost")
    assert px.fail_after_next is None
    o = px.get_order_by_client_id("lost")
    assert o is not None and o.status == "open" and o.base_size == 0.1
    px.place_entry("SOL-USD", 0.1, 100.0, "next")  # only once


def test_set_products_replaces_the_listing(px):
    eth = Product("ETH-USD", "ETH", "USD", 1e-8, 0.01, 1e-8, "online", 5e6)
    px.set_products([SOL, eth])
    assert {p.product_id for p in px.products()} == {"SOL-USD", "ETH-USD"}
    px.place_entry("ETH-USD", 0.1, 100.0, "e1")  # a newly listed product can be traded
    px.set_products([eth])
    assert [p.product_id for p in px.products()] == ["ETH-USD"]


def test_set_products_keeps_products_with_open_orders(px):
    px.place_entry("SOL-USD", 0.1, 100.0, "c1")
    with pytest.raises(ExchangeError):
        px.set_products([])
    assert [p.product_id for p in px.products()] == ["SOL-USD"]
