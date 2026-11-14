"""The bot's order ledger: one record per order it placed, and all quantity arithmetic.

One rule: QUANTITY comes from the venue's order status (`Order.filled_size`, read with `get_order`
or `open_orders`) and from nothing else. A position's size is the filled size of its trade's entry
orders minus the filled size of its exit orders (minus coins the owner sold by hand, found by
reconcile). `fills()` is used only for prices and fees; it may lag, never arrive, or not sum to
`filled_size`, and none of that can change a quantity.

Records are plain dicts so they persist as JSON. Fields:
  kind, product_id, client_order_id, size (the venue's order size), created_ts, placed_ts,
  trade (id of the trade the order belongs to), ref_price (worst-case price: limit / stop limit),
  filled, status, final (order status, the authority for quantity), avg_price (venue's, if reported),
  acc_size, acc_value, acc_fee, fill_reason (from fills(): prices and fees only),
  given_up (fills did not arrive in time: priced by estimate), plus caller extras.
"""

from decimal import Decimal

EPS = 1e-9
DIGITS = 12  # sizes from the venue are rounded to this many decimals, so sums of them stay exact
FILL_TOL = 1e-3  # fills whose sizes sum to within 0.1% of filled_size are complete enough to price it


def add(a: float, b: float) -> float:
    return float(Decimal(str(a)) + Decimal(str(b)))


def sub(a: float, b: float) -> float:
    return float(Decimal(str(a)) - Decimal(str(b)))


def new_record(kind: str, product_id: str, client_order_id: str, size: float, now: int, created_ts: int,
               **extra) -> dict:
    return {"kind": kind, "product_id": product_id, "client_order_id": client_order_id, "size": size,
            "created_ts": created_ts, "placed_ts": now, "trade": None, "ref_price": None,
            "filled": 0.0, "status": "open", "final": False, "avg_price": None,
            "acc_size": 0.0, "acc_value": 0.0, "acc_fee": 0.0, "fill_reason": None, "given_up": False,
            **extra}


def is_exit(rec: dict) -> bool:
    return rec["kind"] != "entry"


def apply_status(rec: dict, order) -> float:
    """Take the venue's order status. Returns how much the filled size grew (0.0 if it did not).
    The filled size never shrinks and a finished order never re-opens."""
    delta = 0.0
    size, filled = round(order.base_size, DIGITS), round(order.filled_size, DIGITS)  # drop float noise
    if not rec["final"]:
        rec["size"] = size
    if filled > rec["filled"] + EPS:
        delta = sub(filled, rec["filled"])
        rec["filled"] = filled
    avg = getattr(order, "avg_fill_price", None)
    if avg is not None and avg > 0:
        rec["avg_price"] = avg
    if order.status != "open" and not rec["final"]:
        rec["status"], rec["final"] = order.status, True
    return delta


def remaining(rec: dict) -> float:
    """What the order may still fill: nothing once it is finished."""
    return 0.0 if rec["final"] else max(0.0, sub(rec["size"], rec["filled"]))


def of_trade(orders: dict[str, dict], trade_id: str) -> dict[str, dict]:
    return {oid: r for oid, r in orders.items() if r.get("trade") == trade_id}


def bought(orders: dict[str, dict], trade_id: str) -> float:
    total = 0.0
    for r in of_trade(orders, trade_id).values():
        if not is_exit(r):
            total = add(total, r["filled"])
    return total


def sold(orders: dict[str, dict], trade_id: str) -> float:
    total = 0.0
    for r in of_trade(orders, trade_id).values():
        if is_exit(r):
            total = add(total, r["filled"])
    return total


def position_size(orders: dict[str, dict], trade: dict) -> float:
    """Entries' filled size minus exits' filled size minus coins the owner sold by hand."""
    size = sub(sub(bought(orders, trade["id"]), sold(orders, trade["id"])), trade.get("written_off", 0.0))
    return max(0.0, size)


def open_sells(orders: dict[str, dict], product_id: str, kinds: tuple[str, ...] | None = None) -> float:
    """Coins committed to the product's resting sell orders."""
    total = 0.0
    for r in orders.values():
        if r["product_id"] == product_id and is_exit(r) and (kinds is None or r["kind"] in kinds):
            total = add(total, remaining(r))
    return total


def pending_sells(pending: dict[str, dict], product_id: str) -> float:
    """Unresolved sell placements count in full: the order may exist."""
    total = 0.0
    for r in pending.values():
        if r["product_id"] == product_id:
            total = add(total, r["size"])
    return total


def sell_room(orders: dict[str, dict], pending: dict[str, dict], product_id: str, position: float,
              cancelling: tuple[str, ...] = ()) -> float:
    """How much more may be sold: the position net of its resting and unresolved sells. Orders of the
    kinds in `cancelling` are left out (a forced exit asks what it could sell once its stops are
    cancelled, before cancelling them)."""
    resting = 0.0
    for r in orders.values():
        if r["product_id"] == product_id and is_exit(r) and r["kind"] not in cancelling:
            resting = add(resting, remaining(r))
    return max(0.0, sub(sub(position, resting), pending_sells(pending, product_id)))


# ------------------------------------------------------------------------------- prices and fees

def apply_fills(rec: dict, fills: list) -> bool:
    """Record the order's fills as cumulative totals (re-reading a fill never double counts).
    Prices and fees only. True if more was recorded."""
    size = sum(f.base_size for f in fills)
    if size <= rec["acc_size"] + EPS:
        return False
    rec.update(acc_size=size, acc_value=sum(f.price * f.base_size for f in fills),
               acc_fee=sum(f.fee for f in fills), fill_reason=fills[-1].reason)
    return True


def fills_complete(rec: dict) -> bool:
    return rec["filled"] <= EPS or rec["acc_size"] >= rec["filled"] - max(EPS, FILL_TOL * rec["filled"])


def needs_fills(rec: dict) -> bool:
    return rec["filled"] > EPS and not rec["given_up"] and not fills_complete(rec)


def price_of(rec: dict) -> tuple[float | None, bool]:
    """(price per coin, estimated). Complete fills give the real average; otherwise the venue's own
    average fill price, then whatever fills did arrive, then the order's limit / stop-limit price."""
    if rec["acc_size"] > EPS and fills_complete(rec):
        return rec["acc_value"] / rec["acc_size"], False
    if rec.get("avg_price"):
        return rec["avg_price"], True
    if rec["acc_size"] > EPS:
        return rec["acc_value"] / rec["acc_size"], True
    return rec.get("ref_price") or rec.get("limit"), True


def money(rec: dict, fee_rate: float) -> tuple[float, float, bool]:
    """(value, fee, estimated) of the order's filled size. The quantity is always `filled`; fills
    supply the price and the fee, scaled to that quantity when their sizes do not sum to it."""
    price, estimated = price_of(rec)
    value = (price or 0.0) * rec["filled"]
    if rec["acc_size"] > EPS:
        fee = rec["acc_fee"] * rec["filled"] / rec["acc_size"]
    else:
        fee = value * fee_rate
    return value, fee, estimated


def entry_price(orders: dict[str, dict], trade_id: str) -> float | None:
    value = qty = 0.0
    for r in of_trade(orders, trade_id).values():
        if not is_exit(r) and r["filled"] > EPS:
            price, _ = price_of(r)
            value += (price or 0.0) * r["filled"]
            qty += r["filled"]
    return value / qty if qty > EPS else None


def trade_result(orders: dict[str, dict], trade: dict, maker: float, taker: float) -> dict:
    """Profit and loss of a finished trade after fees. Quantities from order status, prices and fees
    from fills (or estimates, flagged). Only the part the bot itself sold counts: coins the owner
    sold by hand have no known proceeds."""
    out = {"bought": 0.0, "buy_value": 0.0, "buy_fee": 0.0, "sold": 0.0, "proceeds": 0.0, "sell_fee": 0.0,
           "estimated": False}
    for r in of_trade(orders, trade["id"]).values():
        if r["filled"] <= EPS:
            continue
        value, fee, estimated = money(r, taker if is_exit(r) else maker)
        out["estimated"] = out["estimated"] or estimated
        if is_exit(r):
            out["sold"] = add(out["sold"], r["filled"])
            out["proceeds"] += value
            out["sell_fee"] += fee
        else:
            out["bought"] = add(out["bought"], r["filled"])
            out["buy_value"] += value
            out["buy_fee"] += fee
    b = out["bought"]
    cost = (out["buy_value"] + out["buy_fee"]) * (out["sold"] / b if b > EPS else 0.0)
    out["pnl_usd"] = out["proceeds"] - out["sell_fee"] - cost
    out["entry_price"] = out["buy_value"] / b if b > EPS else None
    return out
