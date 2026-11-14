# Coinbase trading bot

A spot-only Python bot for Coinbase Advanced Trade. It scans liquid USD pairs for 4-hour breakouts, sizes each
trade from a fixed risk budget after fees, places post-only limit entries with protective stops, and can ask
Claude to approve, reduce or veto an entry (Claude can only make it more cautious).

**What it is not.** It does not promise profit. The $750k figure is an aspiration, not a forecast; a small
account with 0.50% maker and 0.90% taker fees can lose money. Read the backtest and the paper results
before risking anything you cannot lose.

## Read this before going live

- **Coinbase documentation could not be reached while building this bot.** Order formats, the stop
  direction value and several response fields are recorded as unverified in `docs/coinbase-api-notes.md`.
  `python -m bot check` must PASS before going live.
- **Bracket orders are not used.** The bot places two stop orders per position and sells half at the first
  target itself (an IOC limit sell), then moves the stop to break-even.
- **Deposits and withdrawals are inferred from cash changes**, not read from an endpoint. Cash that changes
  while the bot is off, with no position or order to explain it, is treated as a transfer and alerted once.
- **The API price table in `bot/reviewer.py` is unverified.** Set a monthly spending limit in the Anthropic
  console; the bot's own `monthly_budget_usd` is only a second guard.
- **Fees.** The owner's spot fees are 0.50% maker and 0.90% taker. The cost gate requires the losing
  trade's costs to be at most 20% of the stop distance, which in practice means stops of 8% or wider.
  Tighter setups are skipped.
- The aggressive settings table lives in the design doc and is **not** the default config.

## Install

```
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
cp config.example.yaml config.yaml
```

Run commands from `trading-bot/` as `.venv/bin/python -m bot <command> --config config.yaml`.

## Coinbase key and `.env`

1. In Coinbase, create a **dedicated portfolio** for the bot and fund only what you can afford to lose.
2. Create an API key on that portfolio with **View and Trade permissions only**. Never enable Transfer.
   Restrict the key to the IP address of the machine running the bot.
3. Put secrets in a git-ignored `.env` next to `config.yaml` (or in the environment):

```
COINBASE_API_KEY=organizations/.../apiKeys/...
COINBASE_API_SECRET="-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----\n"
COINBASE_PORTFOLIO_ID=optional-portfolio-uuid
ANTHROPIC_API_KEY=sk-ant-...
```

The bot refuses to start live if the key can move funds. If `review_enabled` is true, `ANTHROPIC_API_KEY`
is required; set `review_enabled: false` to run without Claude.

## Alerts and heartbeat

Set `alert_url` to an ntfy-style endpoint (the alert text is POSTed with a `Title` header) and
`heartbeat_url` to a dead-man's-switch monitor (for example a healthchecks.io ping URL). The heartbeat is
sent after every cycle that finished without errors; configure the monitor to alert you when pings stop.
Alert text carries product ids, prices and reasons only, never keys or account identifiers. A daily report
is written to `reports/YYYY-MM-DD.txt` and sent as an alert at the first cycle of each UTC day.

## Order of work

1. `python -m bot backtest --days 180 --config config.yaml` (downloads history into `data/` if missing;
   walk-forward windows are printed beside the BTC hold return).
2. `python -m bot run --config config.yaml` in **paper** mode for two weeks. Paper starts with $25 simulated
   cash, fed by Coinbase public candles (no keys needed). The paper account lives in memory, so begin each
   paper run with a fresh `bot.db`.
3. `python -m bot check --config config.yaml` with real keys: prints key permissions, fee tier, USD balance
   and universe size, then **previews** a stop-limit sell on BTC-USD (nothing is placed). A PASS is recorded
   and stays valid for 7 days.
4. Live: set `mode: live` in the config **and** pass the flag:
   `python -m bot run --i-understand-live --config config.yaml`. Start refuses unless keys are present, the
   key cannot transfer funds, and a `check` PASS is less than 7 days old. Only one bot can run per
   directory (`bot.lock`).

Other commands: `status` (last equity, positions and stops, limits, scorecard) and
`reset-kill-switch --confirm`.

## What the alerts mean

| Alert | Meaning | What to do |
|---|---|---|
| live mode started | Live run began | Nothing |
| daily report | Equity, 24h P&L, true P&L after API spend, scorecard | Read it |
| engine error | Unexpected exception in a cycle step | Look at `error` rows in the journal; stops stay on the exchange |
| cycle failing | Three cycles in a row had errors | Check network, keys, Coinbase status |
| unprotected / missing stop / protection failed | A position has no working stop or a stop could not be placed | Check the position on Coinbase now; place a stop by hand if needed |
| forced exit, forced exit blocked/ended | The bot is selling a position it could not protect | Check the position on Coinbase |
| position reconciled / recovered entry / recovered order | The bot's records were corrected from the venue | Check the journal if unexpected |
| stale price | No bid for a held product | Usually transient; watch for a repeat |
| trade closed on estimated prices | Fill prices never arrived; P&L is an estimate | Compare with Coinbase fills |
| transfer inferred | Cash changed while the bot was off | Check it was a deposit or withdrawal you made |
| kill switch | Drawdown limit hit; no new entries | Review, then reset only if you choose to |

A missing heartbeat means the bot has stopped or is failing every cycle.

## Reset the kill switch

The kill switch latches at 25% drawdown from peak. When you have decided to continue, stop the bot, then
run `python -m bot reset-kill-switch --confirm --config config.yaml`. It uses current equity from the venue
and halves risk for the next 10 trades. Without `--confirm` it does nothing.

## Stop the bot safely

Press Ctrl-C or send SIGTERM. The bot finishes its current step and exits; protective stop orders stay on
the exchange. To close positions, cancel and sell them on Coinbase yourself.
