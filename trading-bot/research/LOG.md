# Research log

## 2026-11-15 — verified facts from the Coinbase connector (read-only and preview calls; no orders placed)

- Portfolios visible: Default (dust only: ~$0.02 USDC, trace ETH) and "Botty Bot" ($25.00 USD available, no holds).
- Fee tier: Intro, spot 0.50% maker / 0.90% taker. Next tier (0.35% / 0.75%) needs $10,000 of 30-day spot volume.
- Order format check (PREVIEW ONLY): post-only limit BUY BTC-USD 0.0001 @ 60,000 with attached stop-loss 54,000 and take-profit 72,000 in Botty Bot was accepted by the preview: order total $6.03, commission $0.03 (0.50%). Whether the attached exits rest correctly after a real fill is NOT TESTED.
- US futures (CFM) contract sizes at about 02:00 ET, price × contract size = notional per contract; overnight long margin rate in brackets:
  - AVAX perpetual-style (AVP): 10 × $7.20 = $72 (32.6%)
  - DOT (POP): 100 × $0.717 = $72 (65.2%)
  - ADA (ADP): 1,000 × $0.150 = $150 (28.1%)
  - ETH (ETP): 0.1 × $1,796.5 = $180 (24.1%)
  - ONDO (OND): 1,000 × $0.3018 = $302 (34.1%)
  - SOL (SLP): 5 × $70.45 = $352 (36.6%)
  - SUI (SUP): 500 × $0.7176 = $359 (38.7%)
  - LINK (LNP): 50 × $9.078 = $454 (32.1%)
  - XRP (XPP): 500 × $0.9556 = $478 (37.3%)
  - BTC (BIP): 0.01 × $64,480 = $645 (21.0%)
  - XLM (XLP): 5,000 × $0.13684 = $684 (28.1%)
  Minimum order is one contract. Whether this account is approved for futures is NOT TESTED (futures buying power reads $0.02).
- Account size needed for ONE contract under the plan's rule of 3% of equity at risk with a 10% stop (notional may be at most 30% of equity): about $240 for AVAX or DOT, $600 for ETH, $2,150 for BTC. With no leverage at all (notional ≤ equity): $72, $180, $645.
- At $25 one AVAX contract would be about 2.9× leverage and a 10% adverse move would lose about $7.20, 29% of the allocation. Rejected for live use under the $25 loss allowance.

## Earlier results (carried forward so failures are not lost)

- Long-only 4-hour breakout with retest entry, walk-forward, 10 Nov 2025 – 11 May 2026, 23 coins, spot fees: window 1 −2.9% (1 trade) vs BTC hold −21.5%; window 2 −1.4% (3 trades, PF 0.76) vs BTC hold −9.1%. No demonstrated edge; too few trades.
- Mirrored short side, simplified simulation, 13 Apr 2024 – 14 Nov 2026, futures fees, no funding/roll costs, no position caps: 383 trades, 38% winners, average −0.02 R after costs. No edge.
- Daily trend following on BTC/ETH with regime switch: NOT TESTED.
- Weekly cross-sectional momentum: NOT TESTED.
- Regular fixed-amount BTC buying baseline: NOT TESTED.

## 2026-11-16 (Sunday evening Eastern run) — weekly review 1: daily trend following on BTC and ETH with a regime switch

- Hypothesis: holding BTC/ETH only while each is above its long-term trend avoids most large drawdowns and, after costs, beats holding BTC and regular fixed-amount BTC buying. Disproved if it beats neither baseline in the later part of the data.
- Method: `research/trend_btc_eth.py`. Daily bars from the downloaded history (about 13 Apr 2024 to 15 Nov 2026), 745 evaluated days after a 200-day warm-up. Signal on the daily close, trade at the next day's open. Cost 1.00% per side (taker 0.90% + 0.10% slippage), applied to every entry and exit and to the baselines. $12.50 sleeve each in BTC and ETH. No parameters tuned; three pre-stated rules, all reported. Split: first 60% of the evaluated days, then the last 40% ("held-out", but a single market cycle).
- Results (total return / max drawdown / first 60% / last 40%):
  - A close > 200-day average: −7.4% / 35.2% / −1.3% / −6.2% (11 BTC and 11 ETH entries)
  - B close > 200-day and 50-day > 200-day (the bot's regime rule): −19.2% / 36.1% / −8.4% / −11.8% (10 and 7 entries)
  - C close > 100-day average: −20.8% / 51.3% / +5.7% / −25.1% (17 and 22 entries)
  - Hold BTC: −5.7% / 53.1% / +28.0% / −26.3%
  - Hold 50% BTC / 50% ETH: −16.6% / 60.0% / +23.9% / −32.7%
  - Weekly fixed-amount BTC buying: −21.4% / 36.5% / −3.9% / −18.1%
- Verdict: PAPER TEST ONLY at most; nothing here supports adopting a change. Rule A cut the drawdown (35% against 53% for holding BTC) and lost less in the falling last 40%, but it earned nothing over the whole period (−7.4%, slightly worse than holding BTC's −5.7%) and missed the first-60% rise (−1.3% against +28.0%). It made 22 entries in total, one bull-and-bear cycle: too few trades to claim an edge. The bot's own regime rule (B) did worse than A in this sample, which is a prompt to examine it, not a finding.
- Sources of optimism/pessimism: fills at the next open with no gap risk; 1% per side is conservative against maker entries (0.5% + slippage); no funding or tax effects; BTC and ETH only; one cycle.
- NOT TESTED: maker-entry cost variant, other average lengths (deliberately not tuned), weekly momentum among liquid coins (next week's hypothesis), futures-based versions, any live or paper trading.
