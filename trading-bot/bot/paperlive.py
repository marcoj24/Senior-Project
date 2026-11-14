"""Feeds a PaperExchange from Coinbase public candles, so the paper bot trades live prices."""

import sys

from bot.config import Config
from bot.exchange.base import ExchangeError
from bot.signals import D1, H4
from bot.universe import prefilter

H1 = 3600
SEED = {D1: 260, H4: 200}  # candles needed before the engine can scan (daily lookback, 4h limit)
ALWAYS_PRODUCT = "BTC-USD"  # the regime and benchmark need it


class PaperFeeder:
    """`data` has products() and candles(product_id, granularity_s, limit); `venue` is a PaperExchange.

    Each call to `feed(now)` hands the venue every 1-hour candle that has closed since the last call
    (fills on) and every completed 4h and daily candle (fills off), and refreshes the product list
    once per UTC day. A product that fails to load is skipped and retried on the next call."""

    def __init__(self, data, venue, cfg: Config):
        self.data, self.venue, self.cfg = data, venue, cfg
        self._pids: list[str] = []
        self._listed_day: int | None = None
        self._last: dict[tuple[str, int], int] = {}

    def feed(self, now: int) -> None:
        self._refresh_products(now)
        for pid in self._pids:
            for g in (D1, H4, H1):
                try:
                    self._feed_one(pid, g, now)
                except ExchangeError as e:
                    print(f"paper feed: {pid} {g}s skipped: {e}", file=sys.stderr)

    def _refresh_products(self, now: int) -> None:
        if self._listed_day == now // D1:
            return
        try:
            products = self.data.products()
            keep = {p.product_id for p in prefilter(products, self.cfg)} | {ALWAYS_PRODUCT}
            listed = [p for p in products if p.product_id in keep]
            self.venue.set_products(listed)
        except ExchangeError as e:  # keep the old list and try again next call
            print(f"paper feed: product refresh failed: {e}", file=sys.stderr)
            return
        self._pids = sorted(p.product_id for p in listed)
        self._listed_day = now // D1

    def _feed_one(self, pid: str, g: int, now: int) -> None:
        latest = now - now % g - g  # start of the newest candle that has closed
        last = self._last.get((pid, g))
        if last is not None and last >= latest:
            return
        limit = SEED[g] if last is None and g in SEED else (1 if last is None else (latest - last) // g)
        for c in self.data.candles(pid, g, limit):
            if c.ts + g > now or (last is not None and c.ts <= last):
                continue
            self.venue.feed(pid, g, c, fills=(g == H1))
            last = c.ts
        if last is not None:
            self._last[(pid, g)] = last
