# Coinbase Advanced hybrid trading bot — design

Date: 2026-11-14
Status: awaiting owner approval

## Intent

The owner wants a portfolio on Coinbase Advanced that is traded automatically,
starting from $25, with $750,000 as the long-term target. They want it
aggressive but with losses controlled, strong at spotting trends, aware of
trading costs, and diversified. They asked for a "world-class prompt" that
makes Claude the trader, and later asked for futures and leverage to be used
where they offer better opportunities.

$750k from $25 is a 30,000x return. The design treats it as an aspiration, not
a forecast: the bot is built to compound when it has an edge and to stay alive
when it doesn't. Nothing in the bot may take extra risk because it is "behind"
the target.

## Goals

- Trade spot crypto on Coinbase Advanced unattended, 24/7, from a $25 account.
- Catch multi-day trends and momentum moves; sit in cash when there is none.
- Never place a trade whose expected move does not clearly beat its costs.
- Enforce hard risk limits in code that no AI output can loosen.
- Use Claude, driven by a carefully written system prompt, as the judgment
  layer: market regime review and approve / reduce / veto on each entry.
- Diversify across assets as equity grows.
- Add futures (leverage and shorting) as a gated second phase.
- Run in backtest and paper modes before live money.

## Non-goals

- High-frequency trading, scalping, market making, arbitrage.
- Other exchanges, on-chain/DeFi, staking.
- Deposits, withdrawals or transfers of any kind.
- Tax reporting (the trade journal is exportable as CSV; that is all).
- A web dashboard. Logs, a journal database and a daily text summary suffice.

## Anti-goals (failure even if it "works")

- Any code path where Claude's reply raises a position size, moves a stop
  further away, or bypasses a limit.
- Averaging down, martingale sizing, or revenge trading after losses.
- Raising risk to catch up with the $750k target.
- API keys or secrets in the repository or in logs.
- Live trading starting without an explicit, deliberate action by the owner.
- A position left without an on-exchange protective stop.

## Constraints

- Starting equity is $25. Fees at the lowest Coinbase Advanced volume tier are
  around 0.6% maker / 1.2% taker, so a round trip costs roughly 1.2–2.4%.
  The bot reads its actual fee tier from the API; it never hard-codes fees.
- Product minimum order sizes limit how many positions $25 can hold.
- Claude API spend must stay small relative to the account: a few calls per
  day, not one per loop.
- The bot needs an always-on host (owner's machine or a small server). It must
  recover cleanly from restarts and downtime.
- Futures availability depends on the owner's jurisdiction and account
  approval, and contract sizes may be too large for small equity.
- The repository is an unrelated C# project; the bot lives in its own
  `trading-bot/` folder on branch `claude/coinbase-portfolio-trading-1ixr4w`.

## Approaches

| | How it decides | Trade-off |
|---|---|---|
| A. Rules-only | Fixed rules in code, no AI | Cheap, backtestable; no judgment, no prompt |
| B. Full AI agent | Claude decides every cycle | API cost exceeds the account; not backtestable; AI errors hit the account directly |
| C. Hybrid | Code does signals, costs, sizing and limits; Claude reviews regime daily and each candidate entry | Cents per day; judgment where it helps; limits cannot be overridden |

The owner picked **C**, and asked that futures/leverage and diversification be
included.

## Design

### Shape

A single Python process (Python 3.11+) that wakes every 15 minutes.
Libraries: the official `coinbase-advanced-py` SDK, the `anthropic` SDK,
SQLite for state. (Builder's calls: these were not chosen by the owner.)

Each cycle:

1. **Sync** — pull balances, open orders, fills and fee tier from Coinbase and
   reconcile with the local database. The exchange is the source of truth.
2. **Protect** — confirm every open position has a live on-exchange stop; if
   one is missing, replace it before doing anything else. Update trailing
   stops (stops only ever move in the position's favour).
3. **Check limits** — if a halt or kill switch is active, skip to step 7.
4. **Scan** — compute signals for the universe and rank candidates.
5. **Cost gate and sizing** — drop candidates that fail the cost test; size
   the rest.
6. **Review** — send the top candidate(s) to Claude; act on approve / reduce /
   veto; place limit orders.
7. **Record** — write the journal; once a day write a summary.

### Universe

USD spot pairs on Coinbase filtered by liquidity: a minimum 24h dollar volume
and a maximum bid/ask spread, refreshed daily. BTC, ETH and SOL are always
included. Stablecoin pairs and wrapped duplicates are excluded. Expected size
is 10–20 products. Thresholds are configuration.

### Signals (trend and momentum)

- **Market regime**: BTC daily trend (price vs 200-day EMA, 50/200 EMA slope)
  plus breadth (share of the universe above its 50-day EMA). Regimes:
  risk-on, neutral, risk-off. Risk-off means no new long entries.
- **Trend**: 4-hour EMA 20 above EMA 50, daily close above the 200-day EMA.
- **Entry trigger**: a 4-hour close above the 20-period high (Donchian
  breakout) with volume above its 20-period average, or a pullback to the
  4-hour EMA 20 that holds within an established trend.
- **Relative strength**: rank by 7- and 30-day return versus BTC; prefer
  leaders.
- **Volatility**: 14-period ATR sets stop distance and position size.

Exact parameters are configuration and are tuned by backtest, with a
held-out period to avoid curve-fitting.

### Cost gate

For each candidate the bot computes round-trip cost = entry fee + exit fee +
half-spread on each side + a slippage allowance. A trade is allowed only if:

- distance to target ≥ 3 × round-trip cost, and
- reward-to-risk (target distance ÷ stop distance) ≥ 2.

**Targets and exits (builder's call):** the first target is 2 × the stop
distance (2R); the cost gate is measured against it. At the first target half
the position is sold with a limit order and the stop on the rest moves to
break-even, then trails at 2 × ATR below the highest 4-hour close. If the
position is too small to split above the product minimum, the whole position
trails instead once 2R is reached.

Entries are post-only limit orders (maker fee). An unfilled entry is cancelled
after a set time; the bot does not chase. Exits at target are limit orders;
stops are stop-limit orders resting on the exchange.

### Sizing and risk limits (code only)

| Limit | Default |
|---|---|
| Risk per trade (loss if stopped) | 3% of equity |
| Stop distance | 2 × ATR, bounded to 3–12% |
| Max single position | 50% of equity under $100; 35% above |
| Max total spot exposure | 100% of equity |
| Daily loss halt | −6% on the day: no new entries until next UTC day |
| Drawdown kill switch | −25% from equity peak: cancel entries, keep stops, stop trading until the owner restarts it by hand |
| Losing streak brake | after 3 consecutive losses, risk per trade halves until a win |
| Correlation cap | at most 2 positions from the same highly correlated group |

Orders below a product's minimum size are skipped, not rounded up.

### Diversification by equity tier

| Equity | Max concurrent positions |
|---|---|
| under $100 | 2 |
| $100 – $1,000 | 3 |
| $1,000 – $10,000 | 5 |
| over $10,000 | 6, plus a standing BTC/ETH core allowed in risk-on regimes |

At $25, real diversification is not possible without fees eating the account;
it grows with equity. Cash is a valid position at every tier.

### Claude's role and the prompt

The system prompt lives in `trading-bot/prompts/trader_system.md` and is the
"world-class prompt" deliverable. It sets Claude up as a disciplined
discretionary risk reviewer on top of a systematic strategy, and tells it:

- what the strategy is, what the code already guarantees, and what Claude
  cannot change;
- how to judge a setup: regime fit, trend quality, breakout quality and
  extension, volume, relative strength, nearby resistance, cost versus
  expected move, correlation with what is already held, recent journal
  results for similar setups;
- common failure patterns to veto: late entries into extended moves, breakouts
  on thin volume, entries against the regime, entries right after a kill-switch
  reset, setups whose edge barely clears costs;
- that "veto" is the default when evidence is mixed, and that the $750k target
  never justifies a trade.

Two call types:

- **Daily regime review** (once per day): input is the regime data, portfolio
  and last 30 journal entries. Output is a regime label, a risk multiplier
  between 0 and 1 for the day, and notes.
- **Entry review** (only when a candidate passes the cost gate): input is the
  candidate's signals, costs, proposed size and stop, portfolio and regime.
  Output is `approve`, `reduce` (with a multiplier between 0 and 1) or `veto`,
  an invalidation condition and a short reason.

Replies are structured JSON validated against a schema. Claude can only
approve, shrink or block. If the reply is invalid, or the API is unavailable,
the entry is treated as vetoed. Exits, stops and limits never depend on
Claude. Calls are capped per day in configuration. The model is configurable;
the default is a mid-tier Claude model to keep cost to cents per day.

News is not an input in this version (builder's call): it cannot be
backtested and adds cost and an injection surface. Everything passed to Claude
is treated as data, never as instructions.

### Futures and leverage (phase 2, gated)

Built after the spot bot has run live. Off by default. It turns on only when
all of these hold:

- the owner sets `futures_enabled: true`;
- the Coinbase account has futures trading approved;
- equity is at least $500 (configurable) and the contract's margin and minimum
  size fit within the risk limits;
- the live spot record has at least 30 closed trades with positive expectancy
  after fees.

When on:

- it allows **shorts** in risk-off regimes and leveraged longs in risk-on;
- total effective leverage ≤ 2×, per position ≤ 3×;
- the stop must sit no further than halfway to the liquidation price;
- funding, expiry/roll and futures fees are part of the cost gate;
- the 3% risk-per-trade rule is unchanged — leverage changes capital use, not
  the amount at risk;
- the daily halt and kill switch cover spot and futures together.

Phase 2 gets its own plan later, once the owner's jurisdiction and futures
venue (US dated contracts or international perpetuals) are known. Phase 1 only
keeps sizing and limits free of spot-only assumptions (a position has a side
and a margin requirement); it does not build a futures interface.

### Account scope (builder's call)

The bot trades inside a **dedicated Coinbase portfolio** with a key scoped to
that portfolio, funded with the $25. It never touches the owner's other
holdings. Equity, the equity peak and the tier thresholds are adjusted for any
deposit or withdrawal the sync step detects, so a transfer is never counted as
a gain or a loss.

### What "done" means and the gates (builder's call)

Phase 1 is done when the bot works in all three modes and passes its tests.
It is not a promise of profit.

- **Backtest → paper**: the backtest result on the held-out period is reported
  to the owner as it is. Parameters and timeframes may be tuned within the
  trend/momentum family; the held-out period is not used for tuning.
- **Paper → live**: the owner decides. The recommendation is at least two
  weeks of paper trading with positive expectancy after fees. If the backtest
  or paper results show no edge, the bot says so plainly and recommends not
  going live.

### Modes

- **backtest** — replays historical candles through the same signal, cost and
  sizing code, with fees and slippage. Claude review is off by default (a
  small sampled replay may be offered).
- **paper** — live prices, simulated fills, full Claude review. This is the
  default mode.
- **live** — real orders. Requires `mode: live` in configuration **and** a
  command-line confirmation flag. Recommended only after at least two weeks of
  paper trading.

### Secrets and safety

- The owner creates a Coinbase API key with view and trade permission only —
  no transfer/withdraw permission. The bot checks the key's permissions at
  start and refuses to run if withdrawal is enabled.
- Keys are read from environment variables or a git-ignored `.env`.
- Every order carries a client order ID so a retry cannot double-place.
- All decisions (signals, cost numbers, Claude's reply, order results) are
  journaled so any trade can be explained afterwards.

### Testing

Unit tests for signals, cost gate, sizing and every limit; tests that feed
hostile or malformed Claude replies and confirm no limit moves; an
integration test of the full cycle against a fake exchange; a restart test
with open positions.

## Left to the builder

- Module layout inside `trading-bot/`, configuration file format, logging.
- Exact indicator parameters, found by backtest.
- How the daily summary is delivered (file by default).
- Packaging for the always-on host (plain script plus a service file, or a
  container).
- Verifying current Coinbase API details: fee endpoint, stop-limit order
  types, key-permission endpoint, futures product specs and eligibility.

## Risks the owner should know

- The most likely outcome of any small aggressive crypto account is a loss.
  The limits make the loss slow and bounded; they do not make it impossible.
- Stop orders can fill worse than their price in a fast market or gap.
- Backtests overstate real results.
- Each sale is likely a taxable event in most jurisdictions.
