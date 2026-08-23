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
    id TEXT PRIMARY KEY,
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

-- Per-alert analyst state (acknowledgement, assignment, notes).
--
-- Keyed on the deterministic alert id and deliberately NOT foreign-keyed to
-- alerts: a rescan deletes and reinserts alert rows, and this state must
-- survive that. Because the alert id is a pure function of its content, the
-- state re-attaches to the same alert when it is recomputed. Rows here may
-- outlive an alert that a policy change removed; that is harmless and the
-- state reconnects if the alert reappears.
CREATE TABLE IF NOT EXISTS alert_state (
    alert_id TEXT PRIMARY KEY,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    acknowledged_by TEXT,
    assigned_to TEXT,
    note TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS policy (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def init_db(path: Path | None = None) -> None:
    with get_conn(path) as conn:
        _migrate_legacy_alerts(conn)
        conn.executescript(SCHEMA)
        conn.commit()


def _migrate_legacy_alerts(conn: sqlite3.Connection) -> None:
    """Drop a pre-v0.3 alerts table that used an autoincrement integer id.

    Alerts are derived data -- a pure function of events and policy -- so
    dropping the old table is lossless: startup rescans and rebuilds every
    alert with its new deterministic id. Analyst state in alert_state is keyed
    by that deterministic id and is untouched here.
    """
    exists = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'alerts'"
    ).fetchone()
    if not exists:
        return
    id_col = next(
        (c for c in conn.execute("PRAGMA table_info(alerts)").fetchall() if c["name"] == "id"),
        None,
    )
    if id_col is not None and (id_col["type"] or "").upper() == "INTEGER":
        conn.execute("DROP TABLE alerts")


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
    """Rebuild alerts for a single actor.

    Alert ids are deterministic (see detectors.alert_identity), so this
    delete-and-reinsert reproduces the same id for an unchanged alert. Analyst
    state in alert_state is keyed on that id and is not touched here, so it
    survives the rebuild.
    """
    conn.execute("DELETE FROM alerts WHERE actor_id = ?", (actor_id,))
    for a in alerts:
        conn.execute(
            """INSERT INTO alerts (id, event_id, actor_id, actor_type, timestamp, severity, category, message, target)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                a["id"], a["event_id"], a["actor_id"], a["actor_type"], a["timestamp"],
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
        clauses.append(f"a.severity IN ({','.join('?' * len(severity))})")
        params += severity
    if actor_type:
        clauses.append(f"a.actor_type IN ({','.join('?' * len(actor_type))})")
        params += actor_type
    if actor_id:
        clauses.append("a.actor_id = ?")
        params.append(actor_id)
    if category:
        clauses.append(f"a.category IN ({','.join('?' * len(category))})")
        params += category
    if search:
        clauses.append("(a.actor_id LIKE ? OR a.target LIKE ? OR a.message LIKE ? OR a.category LIKE ?)")
        like = f"%{search}%"
        params += [like, like, like, like]
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    # Left join analyst state so acknowledgement and assignment ride along with
    # each alert. State lives in its own table keyed by the deterministic id.
    rows = conn.execute(
        f"""SELECT a.*,
                   COALESCE(s.acknowledged, 0) AS acknowledged,
                   s.acknowledged_by AS acknowledged_by,
                   s.assigned_to     AS assigned_to,
                   s.note            AS note
            FROM alerts a
            LEFT JOIN alert_state s ON s.alert_id = a.id
            {where} ORDER BY a.timestamp DESC LIMIT ?""",
        (*params, limit),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["acknowledged"] = bool(d["acknowledged"])
        out.append(d)
    return out


def set_alert_state(
    conn: sqlite3.Connection,
    alert_id: str,
    acknowledged: bool | None = None,
    acknowledged_by: str | None = None,
    assigned_to: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    """Create or update analyst state for one alert, keyed by its stable id.

    Only the provided fields change; the rest keep their stored value. The
    alert row need not exist -- state is allowed to outlive or precede its
    alert, and reconnects by id when the alert is (re)computed.
    """
    existing = conn.execute(
        "SELECT acknowledged, acknowledged_by, assigned_to, note FROM alert_state WHERE alert_id = ?",
        (alert_id,),
    ).fetchone()
    current = dict(existing) if existing else {
        "acknowledged": 0, "acknowledged_by": None, "assigned_to": None, "note": None,
    }
    if acknowledged is not None:
        current["acknowledged"] = 1 if acknowledged else 0
    if acknowledged_by is not None:
        current["acknowledged_by"] = acknowledged_by
    if assigned_to is not None:
        current["assigned_to"] = assigned_to
    if note is not None:
        current["note"] = note
    conn.execute(
        """INSERT INTO alert_state (alert_id, acknowledged, acknowledged_by, assigned_to, note, updated_at)
           VALUES (?, ?, ?, ?, ?, datetime('now'))
           ON CONFLICT(alert_id) DO UPDATE SET
               acknowledged    = excluded.acknowledged,
               acknowledged_by = excluded.acknowledged_by,
               assigned_to     = excluded.assigned_to,
               note            = excluded.note,
               updated_at      = excluded.updated_at""",
        (alert_id, current["acknowledged"], current["acknowledged_by"],
         current["assigned_to"], current["note"]),
    )
    return {
        "alert_id": alert_id,
        "acknowledged": bool(current["acknowledged"]),
        "acknowledged_by": current["acknowledged_by"],
        "assigned_to": current["assigned_to"],
        "note": current["note"],
    }


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


def alert_row_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]


def get_alert(conn: sqlite3.Connection, alert_id: str) -> dict[str, Any] | None:
    """One alert with its analyst state merged in, or None if it doesn't exist."""
    row = conn.execute(
        """SELECT a.*,
                  COALESCE(s.acknowledged, 0) AS acknowledged,
                  s.acknowledged_by AS acknowledged_by,
                  s.assigned_to     AS assigned_to,
                  s.note            AS note
           FROM alerts a
           LEFT JOIN alert_state s ON s.alert_id = a.id
           WHERE a.id = ?""",
        (alert_id,),
    ).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["acknowledged"] = bool(d["acknowledged"])
    return d


def wipe_all(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM alerts")
    conn.execute("DELETE FROM alert_state")
    conn.execute("DELETE FROM events")
    conn.execute("DELETE FROM policy")
