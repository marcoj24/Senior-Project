from bot.config import Config
from bot.models import Product

EXCLUDED_BASES = frozenset({"USDC", "USDT", "DAI", "PYUSD", "WBTC", "CBETH"})  # stablecoins, wrapped duplicates


def _always(p: Product, cfg: Config) -> bool:
    return p.status == "online" and p.product_id in cfg.always_include


def _listed(p: Product, cfg: Config) -> bool:
    """The checks that need no market data: USD quote, online, liquid, not a stable or wrapped coin."""
    return (p.quote == "USD" and p.status == "online" and p.base not in EXCLUDED_BASES
            and p.volume_24h_usd >= cfg.min_volume_24h_usd)


def prefilter(products: list[Product], cfg: Config) -> list[Product]:
    """Products worth fetching history and spread for (saves API calls on the rest)."""
    return [p for p in products if _always(p, cfg) or _listed(p, cfg)]


def build_universe(products: list[Product], history_days: dict[str, int], spreads: dict[str, float],
                   cfg: Config) -> list[str]:
    """Tradable product ids, by 24h volume descending. A product missing a measurement is excluded.
    `always_include` products are added whenever they are online."""
    chosen = [
        p for p in products
        if _always(p, cfg) or (
            _listed(p, cfg)
            and spreads.get(p.product_id, float("inf")) <= cfg.max_spread
            and history_days.get(p.product_id, 0) >= cfg.min_history_days
        )
    ]
    chosen.sort(key=lambda p: (-p.volume_24h_usd, p.product_id))
    return [p.product_id for p in chosen]
