"""Read-only market scan with the bot's own rules. Places nothing.
Usage: .venv/bin/python research/daily_scan.py [equity_usd] [maker_fee] [taker_fee]
If .venv is missing: python3 -m venv .venv && .venv/bin/pip install -q -e ".[dev]"
"""
import sys, time
sys.path.insert(0, ".")
from bot.config import Config
from bot.models import Fees
from bot.exchange.coinbase import CoinbaseExchange
from bot.universe import prefilter
from bot.regime import raw_regime, breadth
from bot.signals import find_candidate
from bot.costs import evaluate_costs
from bot.risk import size_position
cfg = Config(); now = int(time.time())
equity = float(sys.argv[1]) if len(sys.argv) > 1 else 25.0
fees = Fees(float(sys.argv[2]) if len(sys.argv) > 2 else 0.005, float(sys.argv[3]) if len(sys.argv) > 3 else 0.009)
ex = CoinbaseExchange("", "", None)
prods = prefilter(ex.products(), cfg)
print("listed after liquidity prefilter:", len(prods))
d1, c4, spread, bid = {}, {}, {}, {}
for p in prods:
    try:
        d1[p.product_id] = ex.candles(p.product_id, 86400, 300)
        c4[p.product_id] = ex.candles(p.product_id, 14400, 300)
        b, a = ex.bid_ask(p.product_id); spread[p.product_id] = (a - b) / ((a + b) / 2); bid[p.product_id] = b
    except Exception as e:
        print("skip", p.product_id, str(e)[:60])
btc = [c for c in d1["BTC-USD"] if c.ts + 86400 <= now]
br = breadth({k: [c for c in v if c.ts + 86400 <= now] for k, v in d1.items()})
print("BTC daily candles:", len(btc), "breadth: %.2f" % br, "raw regime:", raw_regime(btc, br))
print("BTC last close %.0f" % btc[-1].close)
n = 0
for p in prods:
    pid = p.product_id
    if pid not in c4 or len(d1[pid]) < cfg.min_history_days or spread[pid] > cfg.max_spread: continue
    cand = find_candidate(pid, c4[pid], d1[pid], d1["BTC-USD"], now, cfg)
    if not cand: continue
    n += 1
    cc = evaluate_costs(cand.entry, cand.stop, cand.target, fees, spread[pid], cfg)
    sz = size_position(equity, equity, 0.0, 0.0, cand, cc.loss_cost, p, 1.0, cfg)
    print(pid, "bid %.6g entry %.6g stop %.6g target %.6g rs %.3f | cost ok %s rr %.2f (%s) | size %s $%.2f risk $%.2f skip=%s" % (
        bid[pid], cand.entry, cand.stop, cand.target, cand.rs_score, cc.passed, cc.net_rr, cc.reason, sz.base_size, sz.quote_value, sz.risk_usd, sz.skipped))
print("setups found:", n)
