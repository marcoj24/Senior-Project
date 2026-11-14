from bot.config import Config
from bot.models import Product
from bot.universe import build_universe, prefilter


def product(pid, status="online", volume=1e9, quote="USD"):
    return Product(pid, pid.split("-")[0], quote, 0.001, 0.01, 0.01, status, volume)


PRODUCTS = [
    product("BTC-USD", volume=9e9),
    product("ETH-USD", volume=5e9),
    product("SOL-USD", volume=1e9),
    product("AVAX-USD", volume=2e9),
    product("USDT-USD", volume=8e9),  # stablecoin base
    product("NEW-USD", volume=3e9),  # only 100 days old
    product("HALT-USD", status="cancel_only", volume=4e9),
    product("THIN-USD", volume=1e6),  # below the 24h volume floor
    product("WIDE-USD", volume=1e9),  # spread too wide
    product("SOL-EUR", volume=1e9, quote="EUR"),
]
HISTORY = {p.product_id: 400 for p in PRODUCTS} | {"NEW-USD": 100}
SPREADS = {p.product_id: 0.001 for p in PRODUCTS} | {"WIDE-USD": 0.01}


def test_filters_and_order():
    ids = build_universe(PRODUCTS, HISTORY, SPREADS, Config())
    assert ids == ["BTC-USD", "ETH-USD", "AVAX-USD", "SOL-USD"]  # by volume, descending


def test_always_include_bypasses_liquidity_but_not_status():
    products = [product("BTC-USD", volume=1.0), product("ETH-USD", status="cancel_only"),
                product("SOL-USD", volume=1.0)]
    ids = build_universe(products, {"BTC-USD": 10}, {}, Config())
    assert ids == ["BTC-USD", "SOL-USD"]


def test_missing_measurements_exclude():
    products = [product("AVAX-USD")]
    assert build_universe(products, {}, {"AVAX-USD": 0.001}, Config()) == []
    assert build_universe(products, {"AVAX-USD": 400}, {}, Config()) == []


def test_prefilter_skips_products_not_worth_measuring():
    ids = [p.product_id for p in prefilter(PRODUCTS, Config())]
    assert ids == ["BTC-USD", "ETH-USD", "SOL-USD", "AVAX-USD", "NEW-USD", "WIDE-USD"]
