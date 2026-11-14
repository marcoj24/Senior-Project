"""Historical replay of the real engine over hourly candles, with walk-forward tuning.

Honesty rules:
- No lookahead. The replay steps one hour at a time. At simulated time T the venue has been fed
  only the 1-hour candles that closed by T, plus the 4h and daily candles (aggregated from those
  hours, aligned to the UTC epoch) whose interval ended by T. The venue's `candles()` also filters
  to candles closed by the clock, as a second guard.
- The universe is point in time: each simulated day the product list is rebuilt from data up to
  that moment only (a product appears once it has a candle; 24h dollar volume is the trailing 24
  hours). Products delisted before the data was downloaded are absent (survivorship bias).
- The real Engine, risk limits and paper fill rules run unchanged; the reviewer is disabled and no
  LLM is called. The venue has no bracket orders, like the live Coinbase adapter, so the engine
  manages its own target exactly as it does live.
"""

import csv
import itertools
import math
import os
from bisect import bisect_right
from dataclasses import dataclass, field, fields, replace
from datetime import datetime, timezone
from pathlib import Path

from bot.alerts import Alerts
from bot.config import Config
from bot.engine import BTC, Engine
from bot.exchange.paper import PaperExchange
from bot.models import Candle, Fees, Product
from bot.reviewer import Reviewer
from bot.signals import D1, H4, LOOKBACK_1D
from bot.store import Store

H1 = 3600
WATCH_ROUNDS = 3  # watch_fills calls per simulated hour while needs_watch() is true
PROMPT_PATH = str(Path(__file__).resolve().parent.parent / "prompts" / "trader_system.md")
DEFAULT_INCREMENTS = {"base_increment": 1e-8, "quote_increment": 0.01, "min_base_size": 1e-8}


class History(dict):
    """product_id -> 1-hour candles (oldest first), plus increments and minimum sizes where known."""

    def __init__(self, candles: dict[str, list[Candle]], products: dict[str, dict] | None = None):
        super().__init__(candles)
        self.products = dict(products or {})

    def increments(self, product_id: str) -> tuple[float, float, float]:
        m = {**DEFAULT_INCREMENTS, **self.products.get(product_id, {})}
        return float(m["base_increment"]), float(m["quote_increment"]), float(m["min_base_size"])

    def defaulted(self) -> list[str]:
        """Products whose increments and minimum size were not given and are assumed."""
        keys = set(DEFAULT_INCREMENTS)
        return sorted(pid for pid in self if not keys <= set(self.products.get(pid, {})))


@dataclass
class BacktestResult:
    start_equity: float
    end_equity: float
    trades: int
    win_rate: float
    profit_factor: float
    max_drawdown: float
    btc_hold_return: float
    bot_return: float
    header: str = ""  # window, assumptions and known limits, for printing above the numbers
    params: dict = field(default_factory=dict)  # walk_forward: the Config overrides chosen on train


def load_history(path: str, products: dict[str, dict] | None = None) -> History:
    """Reads `path`/<PRODUCT>.csv files of 1-hour candles (ts,open,high,low,close,volume), as
    written by `download_history`. `products` maps product_id to base_increment, quote_increment
    and min_base_size; the CSVs do not carry them, so missing ones default to 1e-8, 0.01 and 1e-8."""
    out: dict[str, list[Candle]] = {}
    for name in sorted(os.listdir(path)):
        if not name.endswith(".csv"):
            continue
        pid = name[:-4]
        with open(os.path.join(path, name), newline="") as f:
            rows = [Candle(int(r["ts"]), float(r["open"]), float(r["high"]), float(r["low"]),
                           float(r["close"]), float(r["volume"])) for r in csv.DictReader(f)]
        rows.sort(key=lambda c: c.ts)
        for a, b in zip(rows, rows[1:]):
            if a.ts == b.ts:
                raise ValueError(f"{name}: duplicate candle at {a.ts}")
        bad = next((c.ts for c in rows if c.ts % H1), None)
        if bad is not None:
            raise ValueError(f"{name}: candle at {bad} is not on an hour boundary")
        out[pid] = rows
    return History(out, products)


def _bucket(hours: list[Candle], ts: int) -> Candle:
    return Candle(ts, hours[0].open, max(c.high for c in hours), min(c.low for c in hours),
                  hours[-1].close, sum(c.volume for c in hours))


def aggregate(candles_1h: list[Candle], granularity_s: int) -> list[Candle]:
    """Buckets aligned to the UTC epoch (ts % granularity == 0). Only buckets whose interval has
    ended by the end of the last candle are emitted. Hours without a candle had no trades, so a
    bucket aggregates the hours present, as the exchange's own candle would."""
    if not candles_1h:
        return []
    cs = sorted(candles_1h, key=lambda c: c.ts)
    end = cs[-1].ts + H1
    groups: dict[int, list[Candle]] = {}
    for c in cs:
        groups.setdefault(c.ts - c.ts % granularity_s, []).append(c)
    return [_bucket(hs, ts) for ts, hs in groups.items() if ts + granularity_s <= end]


def _max_drawdown(equity: list[float]) -> float:
    peak, worst = -math.inf, 0.0
    for e in equity:
        peak = max(peak, e)
        if peak > 0:
            worst = max(worst, 1 - e / peak)
    return worst


def _trade_stats(pnls: list[float]) -> tuple[float, float]:
    """(win rate, profit factor). Profit factor is gross profit / gross loss: inf with no losses,
    0.0 with no trades."""
    if not pnls:
        return 0.0, 0.0
    gain = sum(p for p in pnls if p > 0)
    loss = -sum(p for p in pnls if p < 0)
    return sum(p > 0 for p in pnls) / len(pnls), gain / loss if loss > 0 else math.inf


def _no_llm(model: str, system: str, user_json: str) -> tuple[str, float]:
    raise RuntimeError("the backtest never calls the LLM")


def _day(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M")


class _Clock:
    def __init__(self) -> None:
        self.t = 0

    def __call__(self) -> int:
        return self.t


class _ReplayVenue(PaperExchange):
    """The paper venue, with `candles()` limited to candles closed by the simulated clock."""

    def __init__(self, clock: _Clock, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._clock = clock

    def candles(self, product_id: str, granularity_s: int, limit: int) -> list[Candle]:
        now = self._clock()
        return [c for c in super().candles(product_id, granularity_s, limit) if c.ts + granularity_s <= now]


class Replay:
    """One engine over one paper venue, fed hour by hour. `run` may be called repeatedly to move on."""

    def __init__(self, history: dict[str, list[Candle]], cfg: Config, fees: Fees, start_equity: float = 25.0):
        self.history = history if isinstance(history, History) else History(history)
        self.cfg = replace(cfg, review_enabled=False, reports_dir="")  # no report files from a replay
        self.fees, self.start_equity = fees, start_equity
        self.clock = _Clock()
        self._h1 = {pid: {c.ts: c for c in cs} for pid, cs in self.history.items() if cs}
        self._pids = sorted(self._h1)
        self._first = {pid: min(self._h1[pid]) for pid in self._pids}
        self._next = min(self._first.values()) + H1 if self._pids else 0  # next hour-close to feed
        self._listed_day: int | None = None
        self.venue = _ReplayVenue(self.clock, start_equity, fees, [], supports_bracket=False,
                                  spread=self.cfg.max_spread / 2)
        self.store = Store(":memory:")
        reviewer = Reviewer(self.cfg, self.store, _no_llm, PROMPT_PATH)
        self.engine = Engine(self.cfg, self.venue, self.store, reviewer, Alerts(), self.clock)
        self.start_ts: int | None = None
        self.equity: list[float] = []

    @property
    def now(self) -> int:
        return self.clock.t

    def run(self, start_ts: int, end_ts: int) -> None:
        """Trade every hour-close from start_ts to end_ts inclusive. On the first call, everything
        that closed before start_ts is fed first, without trading."""
        if start_ts % H1 or end_ts % H1:
            raise ValueError("start_ts and end_ts must be on hour boundaries")
        if end_ts < start_ts:
            raise ValueError("end_ts is before start_ts")
        if self.start_ts is None:
            self.start_ts = start_ts
            for t in range(self._next, start_ts, H1):
                self._feed_hour(t, fills=False)
            self._next = start_ts
            self.equity.append(self.start_equity)
        if start_ts != self._next:
            raise ValueError(f"the replay continues at {self._next}, not {start_ts}")
        for t in range(start_ts, end_ts + H1, H1):
            self._step(t)

    def _step(self, t: int) -> None:
        self._feed_hour(t, fills=True)
        self.clock.t = t
        if self._listed_day != t // D1:
            self._list_products(t)
        for _ in range(WATCH_ROUNDS):
            if not self.engine.needs_watch():
                break
            self.engine.watch_fills()
        self.engine.run_cycle()
        self.equity.append(self.engine.equity())

    def _feed_hour(self, t: int, fills: bool) -> None:
        """Feed every candle that closes at t: the hour [t-1h, t), and any 4h or daily bucket ending at t."""
        self.clock.t = t
        for pid in self._pids:
            h1 = self._h1[pid]
            c = h1.get(t - H1)
            if c is not None:
                self.venue.feed(pid, H1, c, fills=fills)
            for g in (H4, D1):
                if t % g == 0:
                    hours = [h1[s] for s in range(t - g, t, H1) if s in h1]
                    if hours:
                        self.venue.feed(pid, g, _bucket(hours, t - g), fills=False)
        self._next = t + H1

    def _list_products(self, t: int) -> None:
        """Products with data by t, each with its trailing 24h dollar volume."""
        products = []
        for pid in self._pids:
            if self._first[pid] + H1 > t:
                continue
            h1 = self._h1[pid]
            volume = sum(h1[s].close * h1[s].volume for s in range(t - D1, t, H1) if s in h1)
            base, _, quote = pid.partition("-")
            bi, qi, mb = self.history.increments(pid)
            products.append(Product(pid, base, quote, bi, qi, mb, "online", volume))
        self.venue.set_products(products)
        self._listed_day = t // D1

    def _btc_close_at(self, t: int) -> float:
        cs = self.history.get(BTC) or []
        i = bisect_right([c.ts + H1 for c in cs], t)
        if i == 0:
            raise ValueError(f"no {BTC} candle closed by {t}")
        return cs[i - 1].close

    def header(self, end_ts: int) -> str:
        errors = len(self.store.journal_rows("error"))
        lines = [
            f"Backtest {_day(self.start_ts)} to {_day(end_ts)} UTC: the real engine stepped hourly over "
            f"1h candles; maker {self.fees.maker:.4%}, taker {self.fees.taker:.4%}, spread fixed at "
            f"{self.cfg.max_spread / 2:.4%}; LLM review off.",
            "Known limits: products delisted before the data was downloaded are absent, so results "
            "carry survivorship bias; fills are simulated from hourly candles, and IOC exits fill "
            "against the next hourly candle; positions still open at the end are valued at bid "
            "without exit costs; the BTC hold return has no fees.",
        ]
        if self.history.defaulted():
            d = DEFAULT_INCREMENTS
            lines.append(f"Increments and minimum sizes assumed (base {d['base_increment']}, quote "
                         f"{d['quote_increment']}, min size {d['min_base_size']}) for: "
                         f"{', '.join(self.history.defaulted())}.")
        if errors:
            lines.append(f"WARNING: the engine journaled {errors} errors during the replay.")
        return "\n".join(lines)

    def result(self) -> BacktestResult:
        end_ts = self.now
        pnls = [r["data"]["pnl_usd"] for r in self.store.journal_rows("trade_closed")]
        win_rate, pf = _trade_stats(pnls)
        end = self.equity[-1]
        return BacktestResult(
            start_equity=self.start_equity, end_equity=end, trades=len(pnls), win_rate=win_rate,
            profit_factor=pf, max_drawdown=_max_drawdown(self.equity),
            btc_hold_return=self._btc_close_at(end_ts) / self._btc_close_at(self.start_ts) - 1,
            bot_return=end / self.start_equity - 1, header=self.header(end_ts))


def run_backtest(history: dict[str, list[Candle]], cfg: Config, fees: Fees, start_ts: int, end_ts: int,
                 start_equity: float = 25.0) -> BacktestResult:
    """Trade hourly from start_ts to end_ts (hour boundaries), after feeding all earlier data."""
    if end_ts <= start_ts:
        raise ValueError("end_ts must be after start_ts")
    if not history.get(BTC):
        raise ValueError(f"history has no {BTC}: the regime and the benchmark need it")
    r = Replay(history, cfg, fees, start_equity)
    r.run(start_ts, end_ts)
    return r.result()


def walk_forward(history, cfg: Config, fees: Fees, param_grid: dict[str, list], train_days: int,
                 test_days: int) -> list[BacktestResult]:
    """Rolling windows: on each train window every combination of `param_grid` (Config field
    names -> values) is run and the one with the highest end equity is kept (ties keep the earliest
    combination); only the following test window's result is reported. Windows step by test_days.
    The first train window starts LOOKBACK_1D days after the first candle's day, since no signal
    can fire before the daily lookback is filled."""
    names = {f.name for f in fields(Config)}
    unknown = set(param_grid) - names
    if unknown:
        raise ValueError(f"unknown Config fields in param_grid: {sorted(unknown)}")
    if train_days <= 0 or test_days <= 0:
        raise ValueError("train_days and test_days must be positive")
    series = [cs for cs in history.values() if cs]
    if not series:
        return []
    first = min(cs[0].ts for cs in series)
    last_end = max(cs[-1].ts for cs in series) + H1
    s = first - first % D1 + (D1 if first % D1 else 0) + LOOKBACK_1D * D1
    keys = list(param_grid)
    combos = [dict(zip(keys, vals)) for vals in itertools.product(*(param_grid[k] for k in keys))]
    out = []
    while s + (train_days + test_days) * D1 <= last_end:
        mid, end = s + train_days * D1, s + (train_days + test_days) * D1
        best, best_equity = None, -math.inf
        for combo in combos:
            res = run_backtest(history, replace(cfg, **combo), fees, s, mid)
            if res.end_equity > best_equity:
                best, best_equity = combo, res.end_equity
        res = run_backtest(history, replace(cfg, **best), fees, mid, end)
        res.params = dict(best)
        out.append(res)
        s += test_days * D1
    return out
