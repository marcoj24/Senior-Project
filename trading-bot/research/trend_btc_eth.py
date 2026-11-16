"""Weekly research 2026-11-16: daily trend following on BTC and ETH with a regime switch.

Hypothesis: holding BTC/ETH only while each is above its long-term trend avoids most of the large
drawdowns and, after costs, beats buy-and-hold on risk-adjusted terms.
Disproved if: after costs it does not beat BOTH holding BTC and regular fixed-amount BTC buying
on return or on drawdown in the later (held-out) part of the data.

No parameters are tuned: three classic, pre-stated rules are tested and all three are reported.
Cost model (conservative): every entry and every exit pays taker 0.90% + 0.10% slippage = 1.00%.
Signals use daily closes; trades happen at the NEXT day's open. Sleeves: $12.50 BTC, $12.50 ETH.
Run from trading-bot/:  .venv/bin/python research/trend_btc_eth.py
"""
import sys
sys.path.insert(0, ".")
from bot.backtest import load_history, aggregate
from bot.indicators import ema

COST = 0.0100
START_CASH = 25.0

hist = load_history("data")
D = {p: aggregate(hist[p], 86400) for p in ("BTC-USD", "ETH-USD")}
n = min(len(D["BTC-USD"]), len(D["ETH-USD"]))
for p in D:
    D[p] = D[p][-n:]
assert [c.ts for c in D["BTC-USD"]] == [c.ts for c in D["ETH-USD"]], "BTC and ETH daily bars are not aligned"
WARM = 200            # every strategy and baseline starts at the same bar
days = n - WARM


def sleeve(candles, rule, cash0):
    """Return (equity per bar from WARM on, number of entries, bars in market)."""
    closes = [c.close for c in candles]
    e50, e100, e200 = ema(closes, 50), ema(closes, 100), ema(closes, 200)
    cash, units, entries, inmkt = cash0, 0.0, 0, 0
    eq = []
    for i in range(WARM, n):
        o = candles[i].open
        want = rule(closes, e50, e100, e200, i - 1)      # decided at the previous close
        if want and units == 0:
            units = cash * (1 - COST) / o; cash = 0.0; entries += 1
        elif not want and units > 0:
            cash = units * o * (1 - COST); units = 0.0
        inmkt += units > 0
        eq.append(cash + units * candles[i].close)
    return eq, entries, inmkt


RULES = {
    "A close > 200-day average": lambda c, e50, e100, e200, j: c[j] > e200[j],
    "B close > 200-day and 50-day > 200-day (the bot's regime rule)": lambda c, e50, e100, e200, j: c[j] > e200[j] and e50[j] > e200[j],
    "C close > 100-day average": lambda c, e50, e100, e200, j: c[j] > e100[j],
}


def stats(eq):
    peak, dd = eq[0], 0.0
    for v in eq:
        peak = max(peak, v); dd = max(dd, 1 - v / peak)
    split = int(len(eq) * 0.6)
    first = eq[split - 1] / eq[0] - 1
    second = eq[-1] / eq[split - 1] - 1
    return eq[-1] / eq[0] - 1, dd, first, second


def line(name, eq, extra=""):
    tot, dd, a, b = stats(eq)
    print(f"{name:66s} total {100*tot:+7.1f}%  max DD {100*dd:5.1f}%  first 60% {100*a:+7.1f}%  held-out last 40% {100*b:+7.1f}%  {extra}")


print(f"BTC/ETH daily bars: {D['BTC-USD'][0].ts} .. {D['BTC-USD'][-1].ts}; evaluated days: {days}; cost {100*COST:.2f}% per side; variants tested: 3 (+3 baselines)")
curves = {}
for name, rule in RULES.items():
    b, eb, mb = sleeve(D["BTC-USD"], rule, START_CASH / 2)
    e, ee, me = sleeve(D["ETH-USD"], rule, START_CASH / 2)
    eq = [x + y for x, y in zip(b, e)]
    curves[name] = eq
    line(name, eq, f"entries BTC {eb} ETH {ee}; in market BTC {100*mb/days:.0f}% ETH {100*me/days:.0f}%")

always = lambda *a: True
hb, _, _ = sleeve(D["BTC-USD"], always, START_CASH)
he, _, _ = sleeve(D["ETH-USD"], always, START_CASH / 2)
hb2, _, _ = sleeve(D["BTC-USD"], always, START_CASH / 2)
line("Baseline: hold BTC (entry cost paid, valued at close)", hb)
line("Baseline: hold 50% BTC / 50% ETH", [x + y for x, y in zip(hb2, he)])

# DCA: equal weekly BTC buys of 25 / weeks, paying the same cost, idle cash earns nothing
weeks = days // 7
amt, cash, units = START_CASH / weeks, START_CASH, 0.0
dca = []
for k, i in enumerate(range(WARM, n)):
    if k % 7 == 0 and cash >= amt - 1e-9:
        units += amt * (1 - COST) / D["BTC-USD"][i].open; cash -= amt
    dca.append(cash + units * D["BTC-USD"][i].close)
line("Baseline: weekly fixed-amount BTC buying (cash idle until spent)", dca)
