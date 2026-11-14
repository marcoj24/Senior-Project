import json
import os

import pytest
import yaml

from bot import cli
from bot.cli import Env, acquire_lock, main
from bot.config import Config
from bot.exchange.base import ExchangeError
from bot.exchange.paper import PaperExchange
from bot.models import Candle, Fees, Product
from bot.paperlive import PaperFeeder
from bot.risk import RiskState
from bot.store import Store

T0 = 20_000 * 86_400
H, H4, D1 = 3600, 14_400, 86_400


@pytest.fixture(autouse=True)
def in_tmp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


def write_config(**over):
    cfg = {"mode": "paper", "db_path": "bot.db", "review_enabled": False, "reports_dir": "reports", **over}
    with open("config.yaml", "w") as f:
        yaml.safe_dump(cfg, f)


def product(pid="BTC-USD"):
    return Product(pid, pid.split("-")[0], "USD", 1e-8, 0.01, 1e-5, "online", 1e9)


class FakeData:
    """Public data source: one product, flat candles. Counts calls, touches no network."""

    def __init__(self):
        self.calls = []
        self.now = T0

    def products(self):
        self.calls.append("products")
        return [product()]

    def candles(self, pid, g, limit):
        self.calls.append(("candles", pid, g, limit))
        end = self.now - self.now % g
        return [Candle(end - (limit - i) * g, 100, 101, 99, 100, 1) for i in range(limit)]


class Venue:
    def __init__(self, **kw):
        self.kw = kw

    def can_transfer(self):
        return self.kw.get("can_transfer", False)

    def balances(self):
        return {"USD": self.kw.get("usd", 25.0)}

    def open_orders(self):
        return []


def env_with(**over):
    now = {"t": T0}
    e = Env(clock=lambda: now["t"], sleep=lambda s: now.update(t=now["t"] + max(s, 1)),
            environ={"COINBASE_API_KEY": "k", "COINBASE_API_SECRET": "s"}, out=lambda s: None)
    for k, v in over.items():
        setattr(e, k, v)
    return e


def boom(*a):
    raise AssertionError("must not be constructed")


def test_live_mode_without_flag_exits_2_and_builds_no_exchange():
    write_config(mode="live")
    assert main(["run", "--config", "config.yaml"], env_with(live_exchange=boom, public_data=boom)) == 2


def test_unknown_mode_exits_2():
    write_config(mode="Live")
    assert main(["run", "--i-understand-live"], env_with(live_exchange=boom)) == 2


def test_live_refuses_a_key_that_can_transfer():
    write_config(mode="live")
    env = env_with(live_exchange=lambda k, s, p: Venue(can_transfer=True))
    assert main(["run", "--i-understand-live"], env) == 2


def test_live_refuses_without_keys_and_without_a_recent_preview():
    write_config(mode="live")
    assert main(["run", "--i-understand-live"], env_with(environ={}, live_exchange=boom)) == 2
    env = env_with(live_exchange=lambda k, s, p: Venue())
    assert main(["run", "--i-understand-live"], env) == 2  # no preview PASS recorded
    s = Store("bot.db")
    s.set_meta(cli.PREVIEW_META, str(T0 - 8 * D1))
    s.close()
    assert main(["run", "--i-understand-live"], env) == 2  # too old


def test_second_process_cannot_take_the_lock():
    first = acquire_lock("bot.lock")
    with pytest.raises(cli.Exit) as e:
        acquire_lock("bot.lock")
    assert e.value.code == 2
    first.close()
    acquire_lock("bot.lock").close()


def test_reset_kill_switch_without_confirm_changes_nothing():
    write_config()
    s = Store("bot.db")
    s.save_risk_state(RiskState(25, "d", 25, True, 0, 0))
    s.close()
    assert main(["reset-kill-switch"], env_with()) == 2
    s = Store("bot.db")
    assert s.load_risk_state().kill_switch is True
    s.set_meta("last_equity", json.dumps({"usd": 20.0, "ts": T0}))
    s.close()
    assert main(["reset-kill-switch", "--confirm"], env_with()) == 0
    s = Store("bot.db")
    st = s.load_risk_state()
    assert st.kill_switch is False and st.peak_equity == 20.0
    s.close()


def test_paper_run_two_cycles_writes_journal_and_holds_the_lock():
    write_config()
    data, seen = FakeData(), {"cycles": 0, "lock_blocked": False}

    def sleep(s):
        env.clock_t += max(s, 1)
        try:
            acquire_lock("bot.lock")
        except cli.Exit:
            seen["lock_blocked"] = True

    env = env_with(public_data=lambda: data)
    env.clock_t = T0
    env.clock = lambda: env.clock_t
    env.sleep = sleep

    def stop():
        s = Store("bot.db")
        try:
            return len(s.journal_rows("cycle")) >= 2
        finally:
            s.close()

    env.stop = stop
    # a cycle every 15 minutes of simulated time
    assert main(["run", "--config", "config.yaml"], env) == 0
    s = Store("bot.db")
    assert len(s.journal_rows("cycle")) >= 2 and seen["lock_blocked"]
    assert ("candles", "BTC-USD", H, 1) in data.calls
    s.close()
    acquire_lock("bot.lock").close()  # released on exit


def test_unexplained_cash_change_at_live_start_is_a_transfer():
    s = Store("bot.db")
    s.save_risk_state(RiskState(100, "d", 100, False, 0, 0))
    s.set_meta("last_cash", json.dumps({"usd": 100.0, "ts": T0 - 100}))
    sent = []

    class A:
        def send(self, t, b):
            sent.append(t)

    cli.check_unexplained_cash(s, Venue(usd=150.0), A(), env_with())
    st = s.load_risk_state()
    assert st.peak_equity == 150.0 and sent == ["transfer inferred"]
    assert s.journal_rows("transfer")[0]["data"]["amount_usd"] == 50.0
    cli.check_unexplained_cash(s, Venue(usd=150.005), A(), env_with())  # within a cent: nothing
    assert len(sent) == 1
    s.close()


class RecordingVenue:
    def __init__(self):
        self.fed, self.listed = [], 0

    def set_products(self, products):
        self.listed += 1

    def feed(self, pid, g, c, fills=True):
        self.fed.append((pid, g, c.ts, fills))


def test_feeder_feeds_new_closed_candles_once_with_the_right_fill_flags():
    data, venue = FakeData(), RecordingVenue()
    f = PaperFeeder(data, venue, Config())
    data.now = T0 + 60
    f.feed(data.now)
    assert ("BTC-USD", H, T0 - H, True) in venue.fed
    assert all(fills is (g == H) for _, g, _, fills in venue.fed)
    assert any(g == D1 for _, g, _, _ in venue.fed) and any(g == H4 for _, g, _, _ in venue.fed)
    n = len(venue.fed)
    data.now = T0 + 120
    f.feed(data.now)  # nothing new has closed
    assert len(venue.fed) == n and venue.listed == 1
    data.now = T0 + 2 * H
    f.feed(data.now)  # two more hours closed; the next 4h bucket has not
    assert [x[1:] for x in venue.fed[n:]] == [(H, T0, True), (H, T0 + H, True)]
    data.now = T0 + D1 + 60
    f.feed(data.now)
    assert venue.listed == 2  # product list refreshed on a new UTC day


def test_check_places_nothing_and_records_a_pass(monkeypatch):
    write_config(mode="live")
    calls = []

    class Ex:
        def key_permissions(self): return {"can_view": True, "can_trade": True, "can_transfer": False}
        def fees(self): return Fees(0.005, 0.009)
        def balances(self): return {"USD": 25.0}
        def products(self): return [product()]
        def bid_ask(self, pid): return 100.0, 100.1
        def preview_stop(self, *a): calls.append(a)

    assert main(["check"], env_with(live_exchange=lambda k, s, p: Ex())) == 0
    assert calls == [("BTC-USD", pytest.approx(0.05), 80.0, pytest.approx(76.0))]  # $5 at bid 100, rounded down to 1e-5 steps
    s = Store("bot.db")
    assert s.get_meta(cli.PREVIEW_META) == str(T0)
    s.close()

    class Bad(Ex):
        def preview_stop(self, *a): raise ExchangeError("INVALID_STOP_DIRECTION")

    os.remove("bot.db")
    lines = []
    assert main(["check"], env_with(live_exchange=lambda k, s, p: Bad(), out=lines.append)) == 1
    assert any("INVALID_STOP_DIRECTION" in l for l in lines)  # the venue's text is shown
    s = Store("bot.db")
    assert s.get_meta(cli.PREVIEW_META) is None
    s.close()


def test_status_prints_without_a_venue(capsys):
    write_config()
    lines = []
    assert main(["status"], env_with(out=lines.append)) == 0
    assert any(l.startswith("scorecard") for l in lines)


def test_check_refuses_paper_mode_and_a_db_used_by_another_mode():
    write_config()  # paper
    assert main(["check"], env_with(live_exchange=boom)) == 2
    assert not os.path.exists("bot.db")
    write_config(mode="live")
    s = Store("bot.db")
    s.set_meta("mode", "paper")
    s.close()
    assert main(["check"], env_with(live_exchange=boom)) == 2


def test_run_refuses_a_db_recorded_in_the_other_mode_and_records_the_mode():
    write_config(mode="live")
    s = Store("bot.db")
    s.set_meta("mode", "paper")
    s.close()
    assert main(["run", "--i-understand-live"], env_with(live_exchange=boom)) == 2
    os.remove("bot.db")
    write_config()
    data = FakeData()
    env = env_with(public_data=lambda: data)
    env.stop = lambda: True
    assert main(["run"], env) == 0
    s = Store("bot.db")
    assert s.get_meta("mode") == "paper"
    s.close()
    write_config(mode="live")
    assert main(["run", "--i-understand-live"], env_with(live_exchange=boom)) == 2


def test_reset_refuses_when_the_kill_switch_is_not_latched():
    write_config()
    s = Store("bot.db")
    s.save_risk_state(RiskState(25, "d", 10, False, 0, 0))
    s.set_meta("last_equity", json.dumps({"usd": 20.0, "ts": T0}))
    s.close()
    assert main(["reset-kill-switch", "--confirm"], env_with()) == 2
    s = Store("bot.db")
    assert s.load_risk_state().peak_equity == 25
    s.close()
