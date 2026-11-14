import pytest

from bot import orders as ledger
from bot.models import Fill, Order


def order(filled, status="open", size=1.0, avg=None, kind="stop"):
    return Order("o", "c", "SOL-USD", kind, size, filled, status, 95.0, 100.0, None, 0, avg)


def rec(kind="stop", size=1.0, trade="t1", **extra):
    return ledger.new_record(kind, "SOL-USD", "c", size, 100, 90, trade=trade, **extra)


def fill(size, price=100.0, fee=0.5, reason="stop"):
    return Fill("o", "SOL-USD", "sell", price, size, fee, 0, reason)


def filled(kind, amount, trade="t1", final=True, size=None, **extra):
    r = rec(kind, size or amount, trade, **extra)
    ledger.apply_status(r, order(amount, "filled" if final else "open", size or amount))
    return r


def test_apply_status_is_the_only_source_of_quantity():
    r = rec()
    assert ledger.apply_status(r, order(0.0)) == 0.0 and not r["final"]
    assert ledger.apply_status(r, order(0.4)) == pytest.approx(0.4)
    assert ledger.apply_status(r, order(0.4)) == 0.0  # read twice: counted once
    assert ledger.apply_status(r, order(0.3)) == 0.0 and r["filled"] == 0.4  # never shrinks
    assert ledger.remaining(r) == pytest.approx(0.6)
    assert ledger.apply_status(r, order(1.0, "filled", avg=99.0)) == pytest.approx(0.6)
    assert r["final"] and r["status"] == "filled" and r["avg_price"] == 99.0 and ledger.remaining(r) == 0.0
    ledger.apply_status(r, order(1.0, "open"))
    assert r["final"]  # a finished order never re-opens


def test_fills_never_change_a_quantity():
    r = rec()
    ledger.apply_status(r, order(0.5))
    before = (r["filled"], ledger.remaining(r))
    assert ledger.apply_fills(r, [fill(0.2), fill(0.9)])  # even fills beyond the order's filled size
    assert (r["filled"], ledger.remaining(r)) == before
    assert not ledger.apply_fills(r, [fill(0.2)])  # cumulative: fewer fills than recorded change nothing
    assert r["acc_size"] == pytest.approx(1.1)


def test_float_noise_in_venue_sizes_is_dropped():
    r = rec("entry")
    ledger.apply_status(r, order(0.1 + 0.2, kind="entry"))  # 0.30000000000000004
    assert r["filled"] == 0.3


def test_position_size_is_entries_minus_exits_minus_written_off():
    orders = {"e": filled("entry", 1.5), "s1": filled("stop", 0.5), "s2": filled("ioc", 0.25, final=False, size=0.5),
              "other": filled("entry", 9.0, trade="t2")}
    t = {"id": "t1", "written_off": 0.0}
    assert ledger.bought(orders, "t1") == 1.5 and ledger.sold(orders, "t1") == 0.75
    assert ledger.position_size(orders, t) == 0.75
    assert ledger.position_size(orders, {"id": "t1", "written_off": 0.25}) == 0.5
    assert ledger.position_size(orders, {"id": "t1", "written_off": 5.0}) == 0.0  # never negative


def test_sell_room_nets_resting_and_unresolved_sells():
    orders = {"a": rec("stop", 0.4), "b": rec("bracket", 0.3), "i": filled("ioc", 0.1, final=False, size=0.2),
              "dead": filled("stop", 0.0), "e": rec("entry", 5.0), "x": rec("stop", 7.0)}
    orders["x"]["product_id"] = "AVAX-USD"
    assert ledger.open_sells(orders, "SOL-USD") == pytest.approx(0.8)  # 0.4 + 0.3 + the IOC's remaining 0.1
    assert ledger.open_sells(orders, "SOL-USD", ("stop", "bracket")) == pytest.approx(0.7)
    assert ledger.sell_room(orders, {}, "SOL-USD", 1.0) == pytest.approx(0.2)
    pending = {"c1": {"product_id": "SOL-USD", "size": 0.15}, "c2": {"product_id": "AVAX-USD", "size": 3.0}}
    assert ledger.sell_room(orders, pending, "SOL-USD", 1.0) == pytest.approx(0.05)
    assert ledger.sell_room(orders, {}, "SOL-USD", 0.5) == 0.0  # never negative
    # what a forced exit could sell once its stops are cancelled: only the IOC still counts
    assert ledger.sell_room(orders, {}, "SOL-USD", 1.0, cancelling=("stop", "bracket")) == pytest.approx(0.9)


def test_fills_complete_within_tolerance_and_needs_fills():
    r = filled("stop", 1.0)
    assert ledger.needs_fills(r)
    ledger.apply_fills(r, [fill(0.5)])
    assert ledger.needs_fills(r) and not ledger.fills_complete(r)
    ledger.apply_fills(r, [fill(0.5), fill(0.4995)])  # sums to 0.9995: rounding, not a missing fill
    assert ledger.fills_complete(r) and not ledger.needs_fills(r)
    r2 = filled("stop", 1.0)
    r2["given_up"] = True
    assert not ledger.needs_fills(r2)
    assert not ledger.needs_fills(rec())  # nothing filled: nothing to price


def test_price_order_real_fills_then_venue_average_then_partial_fills_then_limit():
    r = filled("stop", 1.0, ref_price=95.0)
    assert ledger.price_of(r) == (95.0, True)
    ledger.apply_fills(r, [fill(0.5, price=98.0)])
    assert ledger.price_of(r) == (98.0, True)  # some fills, but not all
    r["avg_price"] = 97.0
    assert ledger.price_of(r) == (97.0, True)
    ledger.apply_fills(r, [fill(0.5, price=98.0), fill(0.5, price=96.0)])
    assert ledger.price_of(r) == (pytest.approx(97.0), False)


def test_money_scales_fills_to_the_order_quantity():
    r = filled("stop", 1.0, ref_price=95.0)
    assert ledger.money(r, 0.01) == (95.0, pytest.approx(0.95), True)  # no fill: limit price, fee by rate
    ledger.apply_fills(r, [fill(0.9995, price=100.0, fee=0.9995)])
    value, fee, estimated = ledger.money(r, 0.01)
    assert value == pytest.approx(100.0) and fee == pytest.approx(1.0) and not estimated


def test_trade_result_counts_only_what_the_bot_sold():
    entry = filled("entry", 2.0, ref_price=100.0)
    ledger.apply_fills(entry, [fill(2.0, price=100.0, fee=1.0, reason="entry")])
    exit_ = filled("stop", 1.0, ref_price=110.0)
    ledger.apply_fills(exit_, [fill(1.0, price=120.0, fee=0.6)])
    orders = {"e": entry, "s": exit_, "zero": filled("stop", 0.0), "other": filled("ioc", 3.0, trade="t2")}
    r = ledger.trade_result(orders, {"id": "t1", "written_off": 1.0}, 0.005, 0.009)
    assert (r["bought"], r["sold"], r["estimated"]) == (2.0, 1.0, False)
    assert r["entry_price"] == pytest.approx(100.0)
    assert r["pnl_usd"] == pytest.approx(120.0 - 0.6 - (200.0 + 1.0) * 0.5)  # half the cost: half was sold

    exit_["acc_size"] = exit_["acc_value"] = exit_["acc_fee"] = 0.0  # its fills never came
    exit_["given_up"] = True
    r = ledger.trade_result(orders, {"id": "t1"}, 0.005, 0.009)
    assert r["estimated"] and r["proceeds"] == pytest.approx(110.0) and r["sell_fee"] == pytest.approx(0.99)
