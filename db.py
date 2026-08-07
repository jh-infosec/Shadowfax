"""
SQLite persistence layer for Shadowfax.

Stores events, alerts and application policy.

Three tables:
  events  - raw ingested activity, one row per event
  alerts  - detector output, one row per fired alert, references an event
  policy  - a single-row table holding the current policy as JSON

Alerts are recomputed (not incrementally patched) whenever new events arrive
for an actor, or whenever the policy changes. This trades a bit of CPU for
correctness and restart-safety: there's no fragile in-memory sliding-window
state to reconstruct after a crash, since every detector is a pure function
of (that actor's ordered event history, current policy).
"""

from __future__ import annotations
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

DB_PATH = Path(__file__).parent / "shadowfax.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    task TEXT,
    event_type TEXT NOT NULL,
    target TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}',
    ingested_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_events_actor ON events(actor_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    actor_id TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    message TEXT NOT NULL,
    target TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_actor ON alerts(actor_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

CREATE TABLE IF NOT EXISTS policy (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def init_db(path: Path | None = None) -> None:
    with get_conn(path) as conn:
        conn.executescript(SCHEMA)
        conn.commit()


@contextmanager
def get_conn(path: Path | None = None) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(path or DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()


# Event storage

def insert_event(conn: sqlite3.Connection, event: dict[str, Any]) -> int:
    cur = conn.execute(
        """INSERT INTO events (timestamp, actor_id, actor_type, task, event_type, target, metadata)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            event["timestamp"],
            event["actor_id"],
            event.get("actor_type", "unknown"),
            event.get("task"),
            event["event_type"],
            event["target"],
            json.dumps(event.get("metadata", {})),
        ),
    )
    return cur.lastrowid


def get_events_for_actor(conn: sqlite3.Connection, actor_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM events WHERE actor_id = ? ORDER BY timestamp ASC", (actor_id,)
    ).fetchall()
    return [_row_to_event(r) for r in rows]


def get_all_events(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM events ORDER BY timestamp ASC").fetchall()
    return [_row_to_event(r) for r in rows]


def distinct_actors(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    rows = conn.execute(
        "SELECT DISTINCT actor_id, actor_type FROM events ORDER BY actor_id"
    ).fetchall()
    return [(r["actor_id"], r["actor_type"]) for r in rows]


def _row_to_event(r: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": r["id"],
        "timestamp": r["timestamp"],
        "actor_id": r["actor_id"],
        "actor_type": r["actor_type"],
        "task": r["task"],
        "event_type": r["event_type"],
        "target": r["target"],
        "metadata": json.loads(r["metadata"]),
    }


#Alert storage

def replace_alerts_for_actor(conn: sqlite3.Connection, actor_id: str, alerts: list[dict[str, Any]]) -> None:
    """Rebuild alerts for a single actor."""
    conn.execute("DELETE FROM alerts WHERE actor_id = ?", (actor_id,))
    for a in alerts:
        conn.execute(
            """INSERT INTO alerts (event_id, actor_id, actor_type, timestamp, severity, category, message, target)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                a["event_id"], a["actor_id"], a["actor_type"], a["timestamp"],
                a["severity"], a["category"], a["message"], a["target"],
            ),
        )


def query_alerts(
    conn: sqlite3.Connection,
    severity: list[str] | None = None,
    actor_type: list[str] | None = None,
    actor_id: str | None = None,
    category: list[str] | None = None,
    search: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    clauses, params = [], []
    if severity:
        clauses.append(f"severity IN ({','.join('?' * len(severity))})")
        params += severity
    if actor_type:
        clauses.append(f"actor_type IN ({','.join('?' * len(actor_type))})")
        params += actor_type
    if actor_id:
        clauses.append("actor_id = ?")
        params.append(actor_id)
    if category:
        clauses.append(f"category IN ({','.join('?' * len(category))})")
        params += category
    if search:
        clauses.append("(actor_id LIKE ? OR target LIKE ? OR message LIKE ? OR category LIKE ?)")
        like = f"%{search}%"
        params += [like, like, like, like]
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?", (*params, limit)
    ).fetchall()
    return [dict(r) for r in rows]


def alert_counts(conn: sqlite3.Connection) -> dict[str, int]:
    rows = conn.execute("SELECT severity, COUNT(*) as n FROM alerts GROUP BY severity").fetchall()
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in rows:
        counts[r["severity"]] = r["n"]
    return counts


def actor_risk_scores(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    weight = {"critical": 10, "high": 5, "medium": 2, "low": 1}
    rows = conn.execute("SELECT actor_id, actor_type, severity, COUNT(*) as n FROM alerts GROUP BY actor_id, severity").fetchall()
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        d = out.setdefault(r["actor_id"], {"actor_type": r["actor_type"], "score": 0,
                                            "critical": 0, "high": 0, "medium": 0, "low": 0})
        d[r["severity"]] = r["n"]
        d["score"] += weight[r["severity"]] * r["n"]
    return out


#Policy

def get_policy(conn: sqlite3.Connection) -> dict[str, Any] | None:
    row = conn.execute("SELECT data FROM policy WHERE id = 1").fetchone()
    return json.loads(row["data"]) if row else None


def set_policy(conn: sqlite3.Connection, policy: dict[str, Any]) -> None:
    conn.execute(
        """INSERT INTO policy (id, data, updated_at) VALUES (1, ?, datetime('now'))
           ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = datetime('now')""",
        (json.dumps(policy),),
    )


def wipe_all(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM alerts")
    conn.execute("DELETE FROM events")
    conn.execute("DELETE FROM policy")
