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
  day, not one per loop. Even so, at $25 a dollar or two a month of API cost
  is several percent of the account. It is paid outside the trading account,
  capped per month in configuration, recorded in the journal as an expense,
  and subtracted in the reported "true P&L".
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
included. Stablecoin pairs and wrapped duplicates are excluded. Products with
less than 250 days of history are excluded (the indicators need the history,
and new listings are where pump-and-dumps happen). Products the exchange flags
as trading-disabled, cancel-only or limit-only are skipped. Expected size is
10–20 products. Thresholds are configuration.

### Signals (trend and momentum)

- **Market regime**: BTC daily trend (price vs 200-day EMA, 50/200 EMA slope)
  plus breadth (share of the universe above its 50-day EMA). Regimes:
  risk-on, neutral, risk-off. Risk-off means no new long entries.
- **Trend**: 4-hour EMA 20 above EMA 50, daily close above the 200-day EMA.
- **Entry trigger**: a 4-hour close above the 20-period high (Donchian
  breakout) with volume above its 20-period average marks a *setup*. The
  *entry* is a resting limit order at the retest of the breakout level or the
  4-hour EMA 20, whichever is nearer. The bot does not buy the breakout candle
  itself: a post-only order there fills mainly on the breakouts that fail.
  Setups that never pull back are missed on purpose.
- Signals use closed candles only. The regime label needs two consecutive
  daily closes to change, so it does not flip back and forth at the line.
- **Relative strength**: rank by 7- and 30-day return versus BTC; prefer
  leaders.
- **Volatility**: 14-period ATR sets stop distance and position size.

Exact parameters are configuration and are tuned by backtest, with a
held-out period to avoid curve-fitting.

### Cost gate

For each candidate the bot computes two costs: the winning round trip (maker
entry, maker exit, spread) and the losing round trip (maker entry, **taker**
exit on the stop, spread, slippage allowance). A trade is allowed only if:

- the losing round-trip cost is at most 20% of the stop distance, and
- reward-to-risk **after costs** — (target distance − winning cost) ÷
  (stop distance + losing cost) — is at least 1.5.

Worked at the lowest fee tier (0.6% maker, 1.2% taker, 0.1% spread, 0.1%
slippage): winning cost 1.3%, losing cost 2.0%. The 20% rule then needs a stop
of at least 10%, and a 10% stop with a 2R target gives 1.56 after costs, which
passes. So at base fees the bot only takes trades with 10–15% stops: few,
long trades needing roughly 39% winners to break even. (A floor of 1.8 was
first written here; it is unreachable with a 2R target at these fees and was
corrected to 1.5.) The gate loosens by itself as the fee tier improves.

**Owner's actual fees (reported 2026-11-14):** spot 0.50% maker / 0.90%
taker; futures 0.095% maker / 0.10% taker. On spot that makes the losing cost
1.6%, so the minimum stop is 8% (a 2R target then gives 1.55 after costs) and
break-even is about 39% winners. On futures the losing cost is about 0.4%, a
quarter of spot, so the 5% minimum stop passes easily and break-even drops to
about 35% winners. Futures are therefore the cheaper venue even with no
leverage at all. What keeps them in phase 2 is contract size: one contract
must fit inside the position and leverage limits, which a $25 account almost
certainly cannot do. The phase 2 gate should be set by the smallest contract's
notional value against equity, checked from live product specs, rather than by
the fixed $500 figure alone.

**Targets and exits (builder's call):** the first target is 2 × the stop
distance (2R); the cost gate is measured against it. At the first target half
the position is sold with a limit order and the stop on the rest moves to
break-even, then trails at 2 × ATR below the highest 4-hour close. If the
position is too small to split above the product minimum, the whole position
trails instead once 2R is reached.

Entries are post-only limit orders (maker fee). An unfilled entry is cancelled
after a set time; the bot does not chase.

**Order mechanics.** On spot, coins held by one resting sell order cannot back
a second one, so a separate stop and target cannot both rest on the same
coins. The position is therefore protected in two legs: half the coins sit
under a Coinbase bracket order (stop and 2R target in one order) and the other
half under a plain stop that trails. While an entry order is open the bot
polls for the fill every few seconds and places both legs at once, so the
unprotected window is seconds, not a cycle. If bracket orders prove
unavailable, both halves get plain stops and the bot manages the target
itself.

A stop-limit can be jumped in a gap and left unfilled. The stop's limit price
is set well below its trigger (default 5%), and if a cycle finds price below
the stop with the position still open, the bot exits at once with an
immediate-or-cancel order and raises an alert.

Moving a trailing stop means cancel-and-replace. The bot does it only when the
stop improves by at least half an ATR, verifies the new stop is live, retries,
and alerts if the position is ever without one.

### Sizing and risk limits (code only)

| Limit | Default |
|---|---|
| Risk per trade (loss if stopped, **including fees and slippage**, on the size after rounding to the product's increments) | 3% of equity |
| Total open risk across all positions | 8% of equity |
| Stop distance | 2 × ATR, bounded to 5–15% |
| Max single position | 50% of equity under $100; 35% above |
| Max total spot exposure | 100% of equity |
| Daily loss halt | −6% on the day: no new entries until next UTC day |
| Drawdown kill switch | −25% from equity peak: cancel entries, keep stops, stop trading until the owner restarts it by hand |
| Losing streak brake | after 3 consecutive losses, risk per trade halves until a win |
| Correlation cap | at most 2 positions from the same highly correlated group |

Orders below a product's minimum size are skipped, not rounded up.

Details that close gaps:

- "Equity" is marked to market. The daily halt compares it with equity at the
  start of the UTC day.
- Crypto assets fall together. When the regime is not risk-on, all altcoins
  count as one correlated group.
- Size reductions (Claude's daily multiplier, Claude's entry multiplier, the
  streak brake) multiply together. If the result is under a quarter of the
  base size or under the product minimum, the trade is skipped and logged, so
  stacked reductions cannot quietly stop all trading unnoticed.
- After the owner resets the kill switch, the equity peak restarts at current
  equity and risk per trade is halved for the next 10 trades.

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
Claude. Calls are capped per day and per month in configuration. The model is
configurable; under $1,000 of equity the default is the cheapest Claude model.
The daily review is skipped when the bot is flat and the regime is risk-off.

**Proving the judgment layer earns its place.** Every candidate is journaled
with Claude's decision, including vetoed ones, and the bot tracks what each
vetoed or reduced trade would have done. A scorecard in the daily summary
compares results with and without Claude's decisions. If after 40 reviewed
candidates the vetoes have not improved results, the summary says so and
recommends switching review off. Each decision records the prompt version, so
prompt changes can be compared.

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
- the live spot record has at least 50 closed trades with a profit factor of
  1.3 or better after fees and API cost. (Thirty trades is too few to tell
  skill from luck; fifty is still thin, which is why leverage stays capped.)

When on:

- it allows **shorts** in risk-off regimes and leveraged longs in risk-on;
- total effective leverage ≤ 2×, per position ≤ 3×;
- the stop must sit no further than halfway to the liquidation price;
- funding, expiry/roll and futures fees are part of the cost gate;
- the 3% risk-per-trade rule is unchanged — leverage changes capital use, not
  the amount at risk;
- the daily halt and kill switch cover spot and futures together.

**Owner's risk tolerance (stated 2026-11-14):** the owner accepts aggressive
leveraged trading. The caps above were the builder's conservative defaults and
are superseded by the profile below, to be confirmed by the owner when phase 2
is planned. All of it is configuration.

| Setting | Conservative (original) | Aggressive (proposed) |
|---|---|---|
| Track-record requirement before futures | 50 trades, profit factor 1.3 | none; a warning is shown if the record is thinner |
| Total effective leverage | 2× | 5× |
| Per-position leverage | 3× | 5× |
| Risk per trade | 3% of equity | 5% of equity |
| Total open risk | 8% | 15% |
| Drawdown kill switch | 25% from peak | 40% from peak |
| Minimum equity for futures | $500 | whatever lets one contract fit the leverage cap |

What does not loosen, because these are what stop a single bad trade ending
the account rather than limits on aggression:

- the stop sits no further than halfway to the liquidation price (at 5× that
  means stops of 10% or tighter);
- every position has a protective stop resting on the exchange;
- the daily loss halt and the kill switch exist and only the owner resets the
  kill switch;
- no averaging down, and Claude can still only approve, shrink or veto.

Costs of the aggressive profile the owner should expect: at 5% risk per trade
with a strategy that wins about 4 trades in 10, five losses in a row is
ordinary, which is a 23% drawdown; the 40% kill switch is sized for that.
Leverage does not improve a strategy's edge. It lets the same edge compound
faster and lets a losing streak, a gap through a stop, or an exchange outage
do proportionally more damage. A gap larger than the liquidation distance
loses the whole margin for that position regardless of the stop.

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
  small sampled replay may be offered). To keep the backtest honest: the
  universe is rebuilt as it was on each past date (no picking today's
  survivors); a limit order counts as filled only when price trades through
  it, not on a touch; parameters are few and tuned walk-forward; and results
  are shown next to simply holding BTC over the same period.
- **paper** — live prices, simulated fills, full Claude review. This is the
  default mode.
- **live** — real orders. Requires `mode: live` in configuration **and** a
  command-line confirmation flag. Recommended only after at least two weeks of
  paper trading. Two weeks yields a handful of trades, so paper trading proves
  the machinery works, not that the strategy has an edge; evidence of edge
  comes from the walk-forward backtest and, later, the live record.

### Secrets and safety

- The owner creates a Coinbase API key with view and trade permission only —
  no transfer/withdraw permission. The bot checks the key's permissions at
  start and refuses to run if withdrawal is enabled.
- Keys are read from environment variables or a git-ignored `.env`.
- Every order carries a client order ID so a retry cannot double-place.
- All decisions (signals, cost numbers, Claude's reply, order results) are
  journaled so any trade can be explained afterwards.
- A trade-only key can still lose money if stolen (an attacker can trade
  against the account in a thin market). The key is scoped to the bot's
  portfolio, restricted to the host's IP address where Coinbase allows it, and
  the liquidity filter keeps the bot out of thin markets. The Claude API key
  gets a monthly spending limit in the Anthropic console.
- Dependencies are pinned to exact versions. Logs never contain keys.
- A lock file stops two copies of the bot running against the same account.

### Operations

- **Alerts.** Kill switch, daily halt, a missing stop, a forced exit, repeated
  API errors and live-mode start are pushed to the owner's phone or email
  (channel chosen at build time), not just written to a file.
- **Heartbeat.** The bot pings an external monitor each cycle; if pings stop,
  the monitor alerts the owner. Stops resting on the exchange protect
  positions while the bot is down.
- **Restart.** State is rebuilt from the exchange if the local database is
  lost. Partial fills and leftover dust balances are handled explicitly.
- **Exchange outages.** Coinbase has gone down during sharp moves before. No
  bot can trade through that; small position sizes are the only defence.

### Testing

Unit tests for signals, cost gate, sizing and every limit; tests that feed
hostile or malformed Claude replies and confirm no limit moves; an
integration test of the full cycle against a fake exchange; a restart test
with open positions; a gap-through-stop test; a test that an entry fill is
never left without a stop; a test that stacked size reductions skip rather
than undersize; a two-instance lock test.

## Red-team review (2026-11-14)

The design was attacked for ways it loses money or fails. Corrections are
folded into the sections above.

| # | Weakness found | Severity | Correction |
|---|---|---|---|
| 1 | Fees made the original strategy need ~42% winners to break even | Critical | Cost gate now caps cost at 20% of stop distance and requires reward-to-risk of 1.5 after costs; stops of 10–15% at base fees, fewer trades |
| 2 | Post-only orders on breakouts fill mostly on failed breakouts | Critical | Enter on the retest, not the breakout candle |
| 3 | Stop and target cannot both rest on the same spot coins | Critical | Bracket orders, with a defined fallback |
| 4 | Up to 15 minutes unprotected between entry fill and stop | High | Fill polling every few seconds while an entry is open |
| 5 | Stop-limit can be jumped in a gap | High | Wide limit offset plus forced exit and alert |
| 6 | Risk per trade ignored fees and slippage (real loss ~30% larger) | High | Risk now includes them |
| 7 | Several positions stopping together could lose far more than 6% | High | 8% cap on total open risk; altcoins treated as one group outside risk-on |
| 8 | Backtest could flatter the strategy (survivor coins, optimistic fills, over-tuning) | High | Point-in-time universe, trade-through fills, walk-forward, BTC benchmark |
| 9 | No evidence Claude's vetoes help | High | Shadow tracking and a scorecard; recommend switching off if no benefit |
| 10 | Claude API cost is several percent of a $25 account per month | High | Cheapest model, call caps, skip when idle, cost counted in true P&L |
| 11 | Kill switch or missing stop could go unnoticed | High | Push alerts and an external heartbeat |
| 12 | Stolen trade-only key can still drain via thin markets | Medium | Portfolio scope, IP restriction, liquidity filter, spend cap |
| 13 | Two weeks of paper trading and 30 trades prove little | Medium | Paper proves machinery only; futures gate raised to 50 trades and profit factor 1.3 |
| 14 | Stacked size reductions could silently stop all trading | Medium | Skip-and-log floor |
| 15 | Regime label could whipsaw; new listings lack history | Medium | Two-close confirmation; 250-day history rule |
| 16 | Two bot copies could double-trade; trailing-stop replacement leaves a window | Medium | Lock file; verified cancel-and-replace with alert |

**Not fixable by design:** exchange outages during crashes; a long bear market
in which a long-only spot bot correctly sits in cash for months; and the size
of the goal. Compounding $25 alone, even at 100% a year, takes about 15 years
to reach $750k. Regular deposits once the bot has a live record would do more
for the target than any strategy change, and the equity accounting already
supports them.

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

**Owner jurisdiction (2026-11-14):** United States. Phase 2 therefore targets Coinbase's US-regulated futures venue, not international perpetuals; contract sizes, margin and trading hours must be read from live product specs when phase 2 is planned.
