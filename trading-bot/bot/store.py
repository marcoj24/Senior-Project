import json
import sqlite3
from dataclasses import asdict

from bot.models import Candidate, Leg, Position
from bot.risk import RiskState

_SCHEMA = """
CREATE TABLE IF NOT EXISTS risk_state (id INTEGER PRIMARY KEY CHECK (id = 1), data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS positions (product_id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS journal (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    product_id TEXT,
    data TEXT NOT NULL,
    ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS journal_kind_ts ON journal (kind, ts);
CREATE TABLE IF NOT EXISTS shadows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate TEXT NOT NULL,
    decision TEXT NOT NULL,
    multiplier REAL NOT NULL,
    ts INTEGER NOT NULL,
    r_multiple REAL,
    closed INTEGER NOT NULL DEFAULT 0
);
"""


class Store:
    """SQLite persistence for risk state, positions, metadata, journal and shadow trades.

    `api_cost` journal rows carry the call's cost in USD under `data["cost_usd"]`.
    """

    def __init__(self, path: str):
        self._db = sqlite3.connect(path)
        self._db.executescript(_SCHEMA)
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    def _write(self, sql: str, params: tuple) -> int:
        with self._db:
            cur = self._db.execute(sql, params)
        return cur.lastrowid

    def load_risk_state(self) -> RiskState | None:
        row = self._db.execute("SELECT data FROM risk_state WHERE id = 1").fetchone()
        return RiskState(**json.loads(row[0])) if row else None

    def save_risk_state(self, s: RiskState) -> None:
        self._write(
            "INSERT INTO risk_state (id, data) VALUES (1, ?) "
            "ON CONFLICT (id) DO UPDATE SET data = excluded.data",
            (json.dumps(asdict(s)),),
        )

    def save_position(self, p: Position) -> None:
        self._write(
            "INSERT INTO positions (product_id, data) VALUES (?, ?) "
            "ON CONFLICT (product_id) DO UPDATE SET data = excluded.data",
            (p.product_id, json.dumps(asdict(p))),
        )

    def delete_position(self, product_id: str) -> None:
        self._write("DELETE FROM positions WHERE product_id = ?", (product_id,))

    def positions(self) -> list[Position]:
        out = []
        for (data,) in self._db.execute("SELECT data FROM positions ORDER BY product_id"):
            d = json.loads(data)
            d["legs"] = [Leg(**leg) for leg in d["legs"]]
            out.append(Position(**d))
        return out

    def get_meta(self, key: str) -> str | None:
        row = self._db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self._write(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def journal(self, kind: str, product_id: str | None, data: dict, ts: int) -> int:
        return self._write(
            "INSERT INTO journal (kind, product_id, data, ts) VALUES (?, ?, ?, ?)",
            (kind, product_id, json.dumps(data), ts),
        )

    def journal_rows(self, kind: str | None = None, since_ts: int = 0) -> list[dict]:
        sql = "SELECT id, kind, product_id, data, ts FROM journal WHERE ts >= ?"
        params: tuple = (since_ts,)
        if kind is not None:
            sql += " AND kind = ?"
            params += (kind,)
        rows = self._db.execute(sql + " ORDER BY ts, id", params)
        return [
            {"id": i, "kind": k, "product_id": pid, "data": json.loads(d), "ts": ts}
            for i, k, pid, d, ts in rows
        ]

    def add_shadow(self, cand: Candidate, decision: str, multiplier: float, ts: int) -> int:
        return self._write(
            "INSERT INTO shadows (candidate, decision, multiplier, ts) VALUES (?, ?, ?, ?)",
            (json.dumps(asdict(cand)), decision, multiplier, ts),
        )

    def open_shadows(self) -> list[dict]:
        """Open shadows as flat dicts: the candidate's fields plus id, decision, multiplier, ts."""
        rows = self._db.execute(
            "SELECT id, candidate, decision, multiplier, ts FROM shadows WHERE closed = 0 ORDER BY id"
        )
        out = []
        for sid, cand, decision, mult, ts in rows:
            d = json.loads(cand)
            d.update(id=sid, decision=decision, multiplier=mult, ts=ts)
            out.append(d)
        return out

    def close_shadow(self, shadow_id: int, r_multiple: float) -> None:
        self._write(
            "UPDATE shadows SET closed = 1, r_multiple = ? WHERE id = ?", (r_multiple, shadow_id)
        )

    def api_spend(self, since_ts: int) -> float:
        return sum(r["data"]["cost_usd"] for r in self.journal_rows("api_cost", since_ts))

    def api_calls(self, since_ts: int) -> int:
        row = self._db.execute(
            "SELECT COUNT(*) FROM journal WHERE kind = 'api_cost' AND ts >= ?", (since_ts,)
        ).fetchone()
        return row[0]
