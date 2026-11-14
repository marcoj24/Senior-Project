import pytest

import bot.backtest as bt
from bot.backtest import (BacktestResult, History, Replay, aggregate, load_history, run_backtest,
                          walk_forward)
from bot.config import Config
from bot.models import Candle, Fees
from bot.signals import LOOKBACK_1D

H, H4, D1 = 3600, 14_400, 86_400
DAY0 = 20_000 * D1  # data starts on a UTC day boundary
WARM_DAYS = 212  # just past the 210-day daily lookback signals need (also covers the 200-day EMA)
W = DAY0 + WARM_DAYS * D1  # the breakout's 4h candle starts here
FEES = Fees(0.001, 0.002)  # low fees, so a 5% stop passes the cost gate
CFG = Config()


def hourly(closes, start_ts, volumes=None, d=0.3):
    """Contiguous 1h candles, each opening at the previous close, with highs/lows d beyond the body."""
    out, prev = [], closes[0]
    for i, c in enumerate(closes):
        v = volumes[i] if volumes else 1000.0
        out.append(Candle(start_ts + i * H, prev, max(prev, c) + d, min(prev, c) - d, c, v))
        prev = c
    return out


def ramp(a, b, hours):
    """`hours` closes moving linearly from just after a to b."""
    return [a + (b - a) * (i + 1) / hours for i in range(hours)]


def rising(start, n, step=0.005):
    return [start + step * i for i in range(n)]


def breakout_closes(days_after=8):
    """Warm-up rise, a 4h breakout on 3x volume, a pullback through the breakout level, a rally past
    the 2R target, a slow fall through the trailed stop, then flat. Constant volume elsewhere, so the
    breakout is the only setup. Returns (closes, volumes) from DAY0, hourly."""
    warm = rising(100.0, WARM_DAYS * 24)
    p0 = warm[-1]
    entry = p0 + 0.3  # the Donchian level: the last warm-up candle's high
    seg = [
        (ramp(p0, p0 + 4.0, 4), 3000.0),  # breakout 4h candle W..W+4h
        (ramp(p0 + 4.0, p0 + 0.2, 4), 1000.0),  # pullback: the last hour's low trades through entry
        ([p0 + 0.2] * 4, 1000.0),
        (ramp(p0 + 0.2, entry * 1.14, 24), 1000.0),  # rally past the 2R target (+10%)
        ([entry * 1.14] * 8, 1000.0),
        (ramp(entry * 1.14, entry * 0.9, 48), 1000.0),  # falls through the trailed stop
    ]
    closes, volumes = list(warm), [1000.0] * len(warm)
    for cs, v in seg:
        closes += cs
        volumes += [v] * len(cs)
    total = (WARM_DAYS + days_after) * 24
    closes += [closes[-1]] * (total - len(closes))
    volumes += [1000.0] * (total - len(volumes))
    return closes, volumes


def breakout_history(days_after=8):
    closes, volumes = breakout_closes(days_after)
    n = len(closes)
    return {
        "SOL-USD": hourly(closes, DAY0, volumes),
        "BTC-USD": hourly(rising(30_000.0, n, 1.0), DAY0, d=30.0),
    }


def flat_history(days):
    n = days * 24
    return {pid: hourly([p] * n, DAY0) for pid, p in (("SOL-USD", 100.0), ("BTC-USD", 30_000.0))}


START = W - 2 * D1  # trading starts two days before the breakout
END = W + 7 * D1


def truncated(history, t):
    return {pid: [c for c in cs if c.ts + H <= t] for pid, cs in history.items()}


def replay(history, start, end, cfg=CFG):
    r = Replay(history, cfg, FEES, 25.0)
    r.run(start, end)
    return r


# ---------------------------------------------------------------- aggregate


def test_aggregate_nine_hours_to_two_4h_candles():
    cs = [Candle(DAY0 + i * H, 10 + i, 20 + i, 5 + i, 11 + i, 1.0 + i) for i in range(9)]
    a, b = aggregate(cs, H4)
    assert a == Candle(DAY0, 10, 23, 5, 14, 1 + 2 + 3 + 4)
    assert b == Candle(DAY0 + H4, 14, 27, 9, 18, 5 + 6 + 7 + 8)


def test_aggregate_aligns_to_utc_epoch_and_drops_unfinished_buckets():
    cs = [Candle(DAY0 + i * H, 1, 2, 0.5, 1, 1) for i in range(2, 9)]  # starts mid-bucket
    out = aggregate(cs, H4)
    assert [c.ts % H4 for c in out] == [0, 0]
    assert [c.ts for c in out] == [DAY0, DAY0 + H4]  # [8h, 12h) has not ended
    assert out[0].volume == 2  # only the hours that traded


# ---------------------------------------------------------------- load_history


def test_load_history_reads_csvs_and_defaults_increments(tmp_path):
    (tmp_path / "SOL-USD.csv").write_text(
        "ts,open,high,low,close,volume\n"
        f"{DAY0 + H},2,3,1,2.5,10\n"
        f"{DAY0},1,2,0.5,1.5,20\n")
    (tmp_path / "BTC-USD.csv").write_text(f"ts,open,high,low,close,volume\n{DAY0},1,1,1,1,1\n")
    (tmp_path / "notes.txt").write_text("ignored")
    meta = {"BTC-USD": {"base_increment": 1e-6, "quote_increment": 0.01, "min_base_size": 1e-5}}
    h = load_history(str(tmp_path), meta)
    assert isinstance(h, History) and isinstance(h, dict)
    assert sorted(h) == ["BTC-USD", "SOL-USD"]
    assert h["SOL-USD"] == [Candle(DAY0, 1, 2, 0.5, 1.5, 20), Candle(DAY0 + H, 2, 3, 1, 2.5, 10)]
    assert h.increments("BTC-USD") == (1e-6, 0.01, 1e-5)
    assert h.increments("SOL-USD") == (1e-8, 0.01, 1e-8)
    assert h.defaulted() == ["SOL-USD"]


def test_load_history_rejects_duplicate_or_unaligned_rows(tmp_path):
    (tmp_path / "SOL-USD.csv").write_text(f"ts,open,high,low,close,volume\n{DAY0},1,1,1,1,1\n{DAY0},1,1,1,1,1\n")
    with pytest.raises(ValueError):
        load_history(str(tmp_path))
    (tmp_path / "SOL-USD.csv").write_text(f"ts,open,high,low,close,volume\n{DAY0 + 60},1,1,1,1,1\n")
    with pytest.raises(ValueError):
        load_history(str(tmp_path))


# ---------------------------------------------------------------- run_backtest


def test_breakout_pullback_rally_makes_one_winning_trade():
    r = replay(breakout_history(), START, END)
    res = r.result()
    assert res.trades == 1, [row["data"] for row in r.store.journal_rows("skip")]
    assert res.end_equity > res.start_equity == 25.0
    assert res.win_rate == 1.0 and res.profit_factor == float("inf")
    assert res.bot_return == pytest.approx(res.end_equity / 25.0 - 1)
    assert 0 < res.max_drawdown < 0.1
    assert r.store.journal_rows("error") == []
    fills = r.venue.fills(0)
    [buy] = [f for f in fills if f.side == "buy"]
    assert buy.ts >= W + H4  # filled only after the breakout candle closed and the entry was placed
    assert {f.reason for f in fills if f.side == "sell"} == {"ioc", "stop"}  # bot-managed target, then the trail
    assert r.venue.balances().get("SOL", 0.0) == 0.0
    assert run_backtest(breakout_history(), CFG, FEES, START, END) == res


def test_flat_history_makes_no_trades():
    res = run_backtest(flat_history(WARM_DAYS + 3), CFG, FEES, DAY0 + WARM_DAYS * D1, DAY0 + (WARM_DAYS + 3) * D1)
    assert res.trades == 0 and res.end_equity == res.start_equity == 25.0
    assert (res.win_rate, res.profit_factor, res.max_drawdown, res.bot_return) == (0.0, 0.0, 0.0, 0.0)
    assert res.btc_hold_return == 0.0


def _rows(r):
    return [(x["kind"], x["product_id"], x["data"], x["ts"]) for x in r.store.journal_rows()]


def test_no_lookahead_truncated_history_gives_the_same_run():
    """At T the engine sees nothing that closes after T. A peek at any hour h only shows when a run is
    cut at h, so the full-history replay is stepped in lockstep and, at every hour from the breakout
    to after the trade closes, compared with a fresh replay of the history cut at that hour."""
    full = breakout_history()
    start = W - 6 * H
    ref = Replay(full, CFG, FEES, 25.0)
    ref.run(start, W - H)
    for t in range(W, W + 52 * H + H, H):
        ref.run(t, t)
        cut = replay(truncated(full, t), start, t)
        assert _rows(cut) == _rows(ref), t
        assert cut.equity == ref.equity, t
        assert cut.venue.fills(0) == ref.venue.fills(0), t
        assert cut.venue.products() == ref.venue.products(), t
        assert [cut.venue.bid_ask(p) for p in full] == [ref.venue.bid_ask(p) for p in full], t
        assert cut.result() == ref.result(), t
    assert ref.result().trades == 1  # the window covered a whole trade


def test_engine_never_receives_an_unclosed_candle(monkeypatch):
    seen = []
    orig = bt._ReplayVenue.candles

    def spy(self, pid, g, limit):
        out = orig(self, pid, g, limit)
        seen.extend(c.ts + g - self._clock() for c in out)
        return out

    monkeypatch.setattr(bt._ReplayVenue, "candles", spy)
    replay(breakout_history(), START, W + D1)
    assert seen and max(seen) <= 0


def test_btc_hold_return_is_last_over_first_close():
    h = breakout_history()
    res = run_backtest(h, CFG, FEES, START, END)
    btc = {c.ts: c.close for c in h["BTC-USD"]}
    assert res.btc_hold_return == pytest.approx(btc[END - H] / btc[START - H] - 1)
    assert res.btc_hold_return > 0


def test_universe_is_point_in_time():
    """A product is listed only once it has data, with the trailing 24h dollar volume at that day."""
    h = flat_history(4)
    late = DAY0 + 2 * D1 + 5 * H  # ETH starts trading mid-day 2
    h["ETH-USD"] = hourly([10.0 + i for i in range((2 * D1 - 5 * H) // H)], late)
    r = Replay(h, CFG, FEES, 25.0)
    r.run(DAY0 + D1, DAY0 + 2 * D1 + 12 * H)
    ids = {p.product_id for p in r.venue.products()}
    assert ids == {"SOL-USD", "BTC-USD"}  # ETH's data starts after the day's listing was built
    r.run(r.now + H, DAY0 + 3 * D1)
    eth = next(p for p in r.venue.products() if p.product_id == "ETH-USD")
    hours = [c for c in h["ETH-USD"] if DAY0 + 2 * D1 <= c.ts < DAY0 + 3 * D1]
    assert eth.volume_24h_usd == pytest.approx(sum(c.close * c.volume for c in hours))
    assert (eth.base, eth.quote, eth.status) == ("ETH", "USD", "online")
    assert (eth.base_increment, eth.quote_increment, eth.min_base_size) == (1e-8, 0.01, 1e-8)


def test_header_names_known_limits_and_defaulted_increments():
    h = History(flat_history(3), {"BTC-USD": {"base_increment": 1e-6, "quote_increment": 0.01,
                                              "min_base_size": 1e-5}})
    res = run_backtest(h, CFG, FEES, DAY0 + D1, DAY0 + 2 * D1)
    assert "delisted" in res.header
    assert "SOL-USD" in res.header and "1e-08" in res.header
    assert "BTC-USD" not in res.header.split("assumed")[1]


def test_spread_is_half_the_max_spread_and_review_is_off():
    cfg = Config(max_spread=0.004)
    r = Replay(flat_history(2), cfg, FEES, 25.0)
    r.run(DAY0 + D1, DAY0 + D1 + H)
    bid, ask = r.venue.bid_ask("SOL-USD")
    assert (ask - bid) / ((ask + bid) / 2) == pytest.approx(0.002)
    assert r.engine.reviewer.cfg.review_enabled is False
    assert cfg.review_enabled is True  # the caller's config is untouched


def test_metrics_from_trades_and_equity():
    assert bt._max_drawdown([25, 30, 24, 27, 33, 22, 40]) == pytest.approx(1 - 22 / 33)
    assert bt._max_drawdown([25, 26, 27]) == 0.0
    assert bt._trade_stats([2.0, -1.0, 3.0, -0.5]) == (0.5, pytest.approx(5.0 / 1.5))
    assert bt._trade_stats([1.0]) == (1.0, float("inf"))
    assert bt._trade_stats([]) == (0.0, 0.0)


def test_rejects_unaligned_or_empty_window():
    with pytest.raises(ValueError):
        run_backtest(flat_history(2), CFG, FEES, DAY0 + D1 + 1, DAY0 + 2 * D1)
    with pytest.raises(ValueError):
        run_backtest(flat_history(2), CFG, FEES, DAY0 + D1, DAY0 + D1)
    with pytest.raises(ValueError):
        run_backtest({"SOL-USD": flat_history(2)["SOL-USD"]}, CFG, FEES, DAY0 + D1, DAY0 + 2 * D1)


# ---------------------------------------------------------------- walk_forward


def test_walk_forward_tunes_on_train_and_reports_only_test(monkeypatch):
    calls = []
    s0 = DAY0 + LOOKBACK_1D * D1  # nothing can trade before the signals' daily lookback is filled

    def fake(history, cfg, fees, start_ts, end_ts, start_equity=25.0):
        calls.append((cfg.target_r, start_ts, end_ts))
        good = 3.0 if start_ts == s0 else 2.0  # 3.0 wins the first train window, 2.0 the second
        return BacktestResult(25.0, 30.0 if cfg.target_r == good else 26.0, 0, 0.0, 0.0, 0.0, 0.0, 0.0)

    monkeypatch.setattr(bt, "run_backtest", fake)
    out = walk_forward(flat_history(LOOKBACK_1D + 10), CFG, FEES, {"target_r": [2.0, 3.0]},
                       train_days=4, test_days=3)
    assert len(out) == 2  # [0,4)+[4,7), [3,7)+[7,10) days after s0; [6,10)+[10,13) does not fit
    d = lambda n: s0 + n * D1
    assert calls == [
        (2.0, d(0), d(4)), (3.0, d(0), d(4)), (3.0, d(4), d(7)),
        (2.0, d(3), d(7)), (3.0, d(3), d(7)), (2.0, d(7), d(10))]
    assert [r.params for r in out] == [{"target_r": 3.0}, {"target_r": 2.0}]


def test_walk_forward_rejects_unknown_parameter():
    with pytest.raises(ValueError):
        walk_forward(flat_history(3), CFG, FEES, {"not_a_field": [1]}, 4, 3)


def test_walk_forward_on_a_real_replay_picks_the_trading_parameters():
    """Windows start at day 210; the breakout is on day 212 and the trade runs to about day 215."""
    grid = {"min_net_rr": [100.0, 1.5]}  # 100 blocks every entry
    out = walk_forward(breakout_history(), CFG, FEES, grid, train_days=2, test_days=2)
    assert len(out) == 4
    assert out[0].params == {"min_net_rr": 100.0}  # train [210,212) is flat: a tie keeps the first
    assert out[0].trades == 0 and out[0].end_equity == 25.0
    assert out[1].params == {"min_net_rr": 1.5}  # train [212,214) held the profitable trade
