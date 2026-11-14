"""Shadow-trade resolution, the veto scorecard and the daily report."""

from datetime import datetime, timezone

from bot.config import Config
from bot.models import Candle
from bot.store import Store

HOUR = 3600
DAY = 86_400


def resolve_shadow(shadow: dict, candles_after: list[Candle], cfg: Config) -> float | None:
    """R result of a vetoed candidate had it been taken: +target_r if the target is passed before
    the stop is touched, -1.0 if stopped first (the stop wins a tie within one candle), 0.0 if the
    entry never traded through within entry_ttl_hours, None while still open."""
    entered = False
    deadline = shadow["ts"] + cfg.entry_ttl_hours * HOUR
    for c in sorted(candles_after, key=lambda c: c.ts):
        if c.ts < shadow["ts"]:
            continue
        if not entered:
            if c.ts >= deadline:
                return 0.0
            if c.low < shadow["entry"]:
                entered = True
        if entered:
            if c.low <= shadow["stop"]:
                return -1.0
            if c.high > shadow["target"]:
                return cfg.target_r
    return None


def _avg(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def scorecard(store: Store, cfg: Config) -> dict:
    vetoed = [s["r_multiple"] for s in store.closed_shadows()
              if s["decision"] == "veto" and s["r_multiple"] is not None]
    taken = [r["data"]["r_multiple"] for r in store.journal_rows("trade_closed")
             if r["data"].get("r_multiple") is not None]
    reviewed = len(vetoed) + len(taken)
    v_avg, t_avg = _avg(vetoed), _avg(taken)
    if reviewed < cfg.scorecard_min:
        verdict = "insufficient"
    else:
        verdict = "helping" if v_avg < t_avg else "not helping"
    return {"reviewed": reviewed, "vetoed": len(vetoed), "vetoed_avg_r": v_avg,
            "taken_avg_r": t_avg, "verdict": verdict}


def daily_summary(store: Store, equity: float, now_ts: int, cfg: Config) -> str:
    now = datetime.fromtimestamp(now_ts, timezone.utc)
    month_start = int(now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp())
    day_rows = store.journal_rows("trade_closed", now_ts - DAY)
    day_pnl = sum(r["data"]["pnl_usd"] for r in day_rows)
    month_pnl = sum(r["data"]["pnl_usd"] for r in store.journal_rows("trade_closed", month_start))
    api = store.api_spend(month_start)
    positions = store.positions()
    sc = scorecard(store, cfg)
    lines = [
        f"Daily report {now:%Y-%m-%d} UTC",
        f"Equity: ${equity:.2f}",
        f"P&L, last 24h: ${day_pnl:+.2f} ({len(day_rows)} trades closed)",
        "Open positions: " + (", ".join(f"{p.product_id} {p.base_size:g} stop {p.stop_price:g}"
                                        for p in positions) or "none"),
        f"This month: trading P&L ${month_pnl:+.2f} - API spend ${api:.2f} = true P&L ${month_pnl - api:+.2f}",
        f"Veto scorecard: {sc['reviewed']} reviewed, {sc['vetoed']} vetoed "
        f"(avg {sc['vetoed_avg_r']:+.2f}R) vs taken avg {sc['taken_avg_r']:+.2f}R: {sc['verdict']}",
    ]
    if sc["verdict"] == "not helping":
        lines.append("The AI vetoes are not helping: recommend switching review off (review_enabled: false).")
    return "\n".join(lines)
