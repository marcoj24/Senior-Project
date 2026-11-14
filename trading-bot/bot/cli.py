"""Command line: run, check, backtest, status, reset-kill-switch."""

import argparse
import fcntl
import json
import os
import signal
import sys
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from bot.alerts import Alerts
from bot.config import Config, load_config
from bot.engine import Engine
from bot.exchange.base import ExchangeError
from bot.exchange.coinbase import CoinbaseExchange, download_history
from bot.exchange.paper import PaperExchange
from bot.models import Fees
from bot.paperlive import PaperFeeder
from bot.report import scorecard
from bot.reviewer import Reviewer, anthropic_client
from bot.risk import apply_transfer, reset_kill_switch
from bot.signals import LOOKBACK_1D
from bot.store import Store
from bot.universe import prefilter

PROMPT = str(Path(__file__).resolve().parent.parent / "prompts" / "trader_system.md")
OWNER_FEES = Fees(0.005, 0.009)  # the owner's spot tier; paper and backtest use it
PAPER_START_USD = 25.0
PREVIEW_META = "stop_preview_pass_ts"
PREVIEW_MAX_AGE_S = 7 * 86_400
TRANSFER_TOLERANCE_USD = 0.01
DATA_DIR = "data"
BACKTEST_GRID = {"stop_atr_mult": [1.5, 2.0, 2.5]}


@dataclass
class Env:
    """Everything the CLI takes from the outside world; tests replace these."""
    clock: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep
    environ: dict = field(default_factory=lambda: os.environ)
    public_data: Callable[[], object] = lambda: CoinbaseExchange("", "", None)
    live_exchange: Callable[[str, str, str | None], object] = lambda k, s, p: CoinbaseExchange(k, s, p)
    llm_client: Callable[[], Callable] = anthropic_client
    stop: Callable[[], bool] | None = None  # extra stop condition, checked each loop step
    out: Callable[[str], None] = print


class Exit(Exception):
    def __init__(self, code: int, msg: str):
        super().__init__(msg)
        self.code = code


def load_dotenv(path: str, environ: dict) -> None:
    """KEY=VALUE lines of a .env file; real environment variables win. Values are never printed."""
    if not os.path.exists(path):
        return
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = v.strip().strip("\"'").replace("\\n", "\n")
        environ.setdefault(k.strip().removeprefix("export "), v)


def acquire_lock(path: str):
    """Exclusive, non-blocking lock held for the life of the returned file object."""
    f = open(path, "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        raise Exit(2, f"another bot process holds {path}") from None
    return f


def lock_path(cfg: Config) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(cfg.db_path)), "bot.lock")


def keys(env: Env) -> tuple[str, str, str | None]:
    k, s = env.environ.get("COINBASE_API_KEY", ""), env.environ.get("COINBASE_API_SECRET", "")
    if not k or not s:
        raise Exit(2, "COINBASE_API_KEY and COINBASE_API_SECRET are required (environment or .env)")
    return k, s, env.environ.get("COINBASE_PORTFOLIO_ID") or None


def load(args, env: Env) -> Config:
    load_dotenv(".env", env.environ)
    try:
        return load_config(args.config)
    except ValueError as e:
        raise Exit(2, f"invalid config: {e}") from None


def build_engine(cfg: Config, venue, store: Store, env: Env, alerts: Alerts, with_llm: bool) -> Engine:
    client = env.llm_client() if with_llm else (lambda *a: ("", 0.0))
    reviewer = Reviewer(cfg, store, client, PROMPT)
    return Engine(cfg, venue, store, reviewer, alerts, lambda: int(env.clock()))


def usd_cash(venue) -> float:
    return venue.balances().get("USD", 0.0)


def record_cash(store: Store, engine: Engine, venue, env: Env) -> None:
    store.set_meta("last_cash", json.dumps({"usd": usd_cash(venue), "ts": int(env.clock())}))
    store.set_meta("last_equity", json.dumps({"usd": engine.equity(), "ts": int(env.clock())}))


def check_unexplained_cash(store: Store, venue, alerts: Alerts, env: Env) -> None:
    """Live start: USD cash that differs from the last recorded cash, with nothing open to explain
    it, is a deposit or withdrawal made while the bot was off."""
    raw = store.get_meta("last_cash")
    state = store.load_risk_state()
    if raw is None or state is None or store.positions() or venue.open_orders():
        return
    diff = usd_cash(venue) - json.loads(raw)["usd"]
    if abs(diff) <= TRANSFER_TOLERANCE_USD:
        return
    apply_transfer(state, diff)
    store.save_risk_state(state)
    store.set_meta("last_cash", json.dumps({"usd": usd_cash(venue), "ts": int(env.clock())}))  # never apply twice
    store.journal("transfer", None, {"amount_usd": diff, "inferred": "cash changed while the bot was off"},
                  int(env.clock()))
    alerts.send("transfer inferred", f"USD cash changed by {diff:+.2f} while the bot was off; "
                                     "treated as a deposit or withdrawal")


def require_live_gate(store: Store, venue, env: Env) -> None:
    try:
        if venue.can_transfer():
            raise Exit(2, "API key can move funds; create a trade-only key")
    except ExchangeError as e:
        raise Exit(2, f"cannot verify the key's permissions: {e}") from None
    raw = store.get_meta(PREVIEW_META)
    if raw is None or env.clock() - int(raw) > PREVIEW_MAX_AGE_S:
        raise Exit(2, "no stop-order preview PASS in the last 7 days: run `python -m bot check` first")


def loop(engine: Engine, cfg: Config, env: Env, stopping: Callable[[], bool],
         before_cycle: Callable[[int], None], after_cycle: Callable[[], None]) -> None:
    """Single-threaded: one cycle every cycle_minutes; between cycles a fill poll every
    fill_poll_seconds while engine.needs_watch()."""
    interval = cfg.cycle_minutes * 60
    next_cycle = env.clock()
    while not stopping():
        now = env.clock()
        if now >= next_cycle:
            before_cycle(int(now))
            engine.run_cycle()
            after_cycle()
            next_cycle = max(next_cycle + interval, now)
        elif engine.needs_watch():
            engine.watch_fills()
        if stopping():
            break
        env.sleep(max(0.0, min(cfg.fill_poll_seconds, next_cycle - env.clock())))


def cmd_run(args, env: Env) -> int:
    cfg = load(args, env)
    live = cfg.mode == "live"
    if live and not args.i_understand_live:
        raise Exit(2, "live trading needs BOTH `mode: live` in the config AND the --i-understand-live flag")
    lock = acquire_lock(lock_path(cfg))
    store = None
    try:
        if cfg.review_enabled and not env.environ.get("ANTHROPIC_API_KEY"):
            raise Exit(2, "review_enabled needs ANTHROPIC_API_KEY (or set review_enabled: false)")
        store = Store(cfg.db_path)
        alerts = Alerts(cfg.alert_url, cfg.heartbeat_url)
        feeder = None
        if live:
            venue = env.live_exchange(*keys(env))
            require_live_gate(store, venue, env)
            check_unexplained_cash(store, venue, alerts, env)
        else:
            data = env.public_data()
            venue = PaperExchange(PAPER_START_USD, OWNER_FEES, [], supports_bracket=False)
            feeder = PaperFeeder(data, venue, cfg)
        engine = build_engine(cfg, venue, store, env, alerts, cfg.review_enabled)
        stop = {"flag": False}
        old = {s: signal.signal(s, lambda *_: stop.update(flag=True)) for s in (signal.SIGINT, signal.SIGTERM)}
        try:
            if live:
                alerts.send("live mode started", "live trading started")
            env.out(f"{cfg.mode} mode running; Ctrl-C or SIGTERM stops after the current step")

            def stopping() -> bool:
                return stop["flag"] or bool(env.stop and env.stop())

            def before(now: int) -> None:
                if feeder:
                    feeder.feed(now)

            def after() -> None:
                try:
                    record_cash(store, engine, venue, env)
                except Exception as e:
                    store.journal("error", None, {"where": "record_cash", "error": repr(e)}, int(env.clock()))

            loop(engine, cfg, env, stopping, before, after)
            after()
        finally:
            for s, h in old.items():
                signal.signal(s, h)
        env.out("stopped; any stop orders stay on the exchange")
        return 0
    finally:
        if store:
            store.close()
        lock.close()


def cmd_check(args, env: Env) -> int:
    cfg = load(args, env)
    ex = env.live_exchange(*keys(env))
    perms = ex.key_permissions()
    env.out("key permissions: " + ", ".join(f"{k}={v}" for k, v in perms.items()))
    fees = ex.fees()
    env.out(f"fee tier: maker {fees.maker:.4%}, taker {fees.taker:.4%}")
    env.out(f"USD balance: {usd_cash(ex):.2f}")
    products = ex.products()
    env.out(f"universe: {len(prefilter(products, cfg))} products pass the listing filters")
    btc = next((p for p in products if p.product_id == "BTC-USD"), None)
    if btc is None:
        env.out("stop preview FAIL: BTC-USD not listed")
        return 1
    trigger = ex.bid_ask("BTC-USD")[0] * 0.8
    try:
        ex.preview_stop("BTC-USD", btc.min_base_size, trigger, trigger * (1 - cfg.stop_limit_offset))
    except ExchangeError as e:
        env.out(f"stop preview FAIL: {e}")
        return 1
    store = Store(cfg.db_path)
    try:
        store.set_meta(PREVIEW_META, str(int(env.clock())))
    finally:
        store.close()
    env.out("stop preview PASS (nothing was placed)")
    return 0


def cmd_backtest(args, env: Env) -> int:
    cfg = load(args, env)
    from bot.backtest import load_history, walk_forward
    if not (os.path.isdir(DATA_DIR) and any(n.endswith(".csv") for n in os.listdir(DATA_DIR))):
        data = env.public_data()
        pids = sorted({p.product_id for p in prefilter(data.products(), cfg)} | {"BTC-USD"})
        env.out(f"downloading {len(pids)} products into {DATA_DIR}/")
        download_history(pids, args.days + LOOKBACK_1D + 5, DATA_DIR)
    results = walk_forward(load_history(DATA_DIR), cfg, OWNER_FEES, BACKTEST_GRID,
                           train_days=max(args.days // 2, 1), test_days=max(args.days // 4, 1))
    if not results:
        env.out("not enough history for one train and test window")
        return 1
    env.out(results[0].header)
    for i, r in enumerate(results, 1):
        env.out(f"window {i}: {r.params} bot {r.bot_return:+.1%} vs BTC hold {r.btc_hold_return:+.1%} | "
                f"${r.start_equity:.2f} -> ${r.end_equity:.2f}, {r.trades} trades, win {r.win_rate:.0%}, "
                f"PF {r.profit_factor:.2f}, max drawdown {r.max_drawdown:.1%}")
    return 0


def cmd_status(args, env: Env) -> int:
    cfg = load(args, env)
    store = Store(cfg.db_path)
    try:
        eq = store.get_meta("last_equity")
        if eq:
            e = json.loads(eq)
            env.out(f"equity: ${e['usd']:.2f} (at {datetime.fromtimestamp(e['ts'], timezone.utc):%Y-%m-%d %H:%M} UTC)")
        else:
            env.out("equity: not recorded yet")
        positions = store.positions()
        for p in positions:
            env.out(f"position {p.product_id}: {p.base_size:g} @ {p.entry_price:g}, stop {p.stop_price:g}, "
                    f"target {p.target_price:g}")
        if not positions:
            env.out("positions: none")
        s = store.load_risk_state()
        if s:
            env.out(f"limits: kill switch {'ON' if s.kill_switch else 'off'}, daily halt "
                    f"{'ON' if s.halt_day == s.day else 'off'}, peak ${s.peak_equity:.2f}, consecutive "
                    f"losses {s.consecutive_losses}, reduced-risk trades left {s.post_reset_remaining}")
        sc = scorecard(store, cfg)
        env.out(f"scorecard: {sc['reviewed']} reviewed, vetoed avg {sc['vetoed_avg_r']:+.2f}R, taken avg "
                f"{sc['taken_avg_r']:+.2f}R: {sc['verdict']}")
    finally:
        store.close()
    return 0


def cmd_reset(args, env: Env) -> int:
    cfg = load(args, env)
    if not args.confirm:
        raise Exit(2, "reset-kill-switch changes nothing without --confirm")
    lock = acquire_lock(lock_path(cfg))  # a running bot would overwrite the change
    store = Store(cfg.db_path)
    try:
        state = store.load_risk_state()
        if state is None:
            raise Exit(2, "no risk state recorded yet")
        if cfg.mode == "live":
            equity = build_engine(cfg, env.live_exchange(*keys(env)), store, env, Alerts(), False).equity()
        else:
            raw = store.get_meta("last_equity")
            if raw is None:
                raise Exit(2, "paper mode: no recorded equity to reset to")
            equity = json.loads(raw)["usd"]
        reset_kill_switch(state, equity, cfg)
        store.save_risk_state(state)
        store.journal("kill_switch_reset", None, {"equity": equity}, int(env.clock()))
        env.out(f"kill switch reset at equity ${equity:.2f}; risk is halved for {cfg.post_reset_trades} trades")
    finally:
        store.close()
        lock.close()
    return 0


def main(argv: list[str] | None = None, env: Env | None = None) -> int:
    env = env or Env()
    p = argparse.ArgumentParser(prog="python -m bot")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default="config.yaml")
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run", parents=[common])
    r.add_argument("--i-understand-live", action="store_true")
    sub.add_parser("check", parents=[common])
    b = sub.add_parser("backtest", parents=[common])
    b.add_argument("--days", type=int, required=True)
    sub.add_parser("status", parents=[common])
    k = sub.add_parser("reset-kill-switch", parents=[common])
    k.add_argument("--confirm", action="store_true")
    args = p.parse_args(argv)
    handler = {"run": cmd_run, "check": cmd_check, "backtest": cmd_backtest, "status": cmd_status,
               "reset-kill-switch": cmd_reset}[args.command]
    try:
        return handler(args, env)
    except Exit as e:
        print(str(e), file=sys.stderr)
        return e.code
    except ExchangeError as e:
        print(f"exchange error: {e}", file=sys.stderr)
        return 1
