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
import ledger
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

# Where the database lives. SHADOWFAX_DB lets a container point it at a mounted
# volume, so the data survives the container and is not baked into the image
# layer. Defaults beside the code, which is what a local checkout wants.
#
# The tests reassign this module attribute directly rather than setting the
# variable, so it stays a plain module-level value and not a function call.
DB_PATH = Path(os.environ.get("SHADOWFAX_DB") or (Path(__file__).parent / "shadowfax.db"))

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
    ingested_at TEXT NOT NULL DEFAULT (datetime('now')),
    -- Tamper-evident ledger (v0.9). Each event chains to the one before it, so
    -- a later edit, deletion or reordering breaks the chain detectably.
    prev_hash TEXT,
    entry_hash TEXT
);

-- The chain's head: how many entries the ledger should hold and the hash it
-- should end on. Kept so truncation is visible -- entries lopped off the end
-- leave a shorter but internally valid chain, which only this record catches.
CREATE TABLE IF NOT EXISTS ledger_head (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    entry_count INTEGER NOT NULL DEFAULT 0,
    head_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
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
    attack TEXT NOT NULL DEFAULT '[]',
    -- Provenance for alerts that came from an ingested findings envelope
    -- (v0.11). NULL for Shadowfax's own detectors, which is the honest
    -- representation: "no external emitter claimed this, we found it".
    -- `validated` is the emitter's own statement about whether it verified the
    -- claim or is repeating what the subject said about itself.
    source_tool TEXT,
    validated INTEGER,
    evidence TEXT,
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

-- Authentication (v0.3). Analysts sign in; agents and services use API keys.

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Opaque bearer tokens. Only the token's SHA-256 fingerprint is stored, so the
-- database never holds a usable session token.
CREATE TABLE IF NOT EXISTS sessions (
    token_fp TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- API keys for programmatic ingest. Same rule: only the fingerprint is stored.
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_fp TEXT UNIQUE NOT NULL,
    prefix TEXT NOT NULL,
    label TEXT,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT
);

-- Sign-in attempts against Shadowfax's own front door (v0.10). This is
-- operational state for the throttle, not evidence: it is pruned freely and is
-- deliberately NOT part of the hash-chained ledger. What belongs in the ledger
-- is the security-relevant outcome (a failed sign-in, a lockout), and app.py
-- writes those there separately.
--
-- Only `outcome = 'failure'` rows drive the throttle; successes are recorded so
-- an admin can see who got in, and they clear the failure history for the scope.
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    source TEXT NOT NULL,
    at TEXT NOT NULL,
    outcome TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_scope
    ON login_attempts(username, source, at);
"""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def init_db(path: Path | None = None) -> None:
    with get_conn(path) as conn:
        _migrate_legacy_alerts(conn)
        conn.executescript(SCHEMA)
        _migrate_ledger(conn)
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
    cols = conn.execute("PRAGMA table_info(alerts)").fetchall()
    id_col = next((c for c in cols if c["name"] == "id"), None)
    names = {c["name"] for c in cols}
    # Any missing column means the table predates a version that added one.
    # Alerts are derived data, so dropping and rebuilding is lossless.
    has_columns = {"attack", "source_tool", "validated", "evidence"} <= names
    outdated = (id_col is not None and (id_col["type"] or "").upper() == "INTEGER") or not has_columns
    if outdated:
        # Old schema (integer id, or pre-v0.4 without the attack column). Alerts
        # are derived, so dropping is lossless: startup rescans and rebuilds them
        # with the current shape. alert_state (keyed by deterministic id) stays.
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

def _migrate_ledger(conn: sqlite3.Connection) -> None:
    """Bring an existing database onto the hash chain.

    Adds the hash columns if they predate v0.9 and backfills the chain over
    whatever is already stored, in insertion order. Backfilling cannot prove
    anything about edits made *before* the ledger existed -- it establishes the
    baseline from which tampering becomes detectable, which is the honest thing
    it can offer.
    """
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(events)")}
    if "prev_hash" not in cols:
        conn.execute("ALTER TABLE events ADD COLUMN prev_hash TEXT")
    if "entry_hash" not in cols:
        conn.execute("ALTER TABLE events ADD COLUMN entry_hash TEXT")

    unchained = conn.execute(
        "SELECT COUNT(*) AS n FROM events WHERE entry_hash IS NULL"
    ).fetchone()["n"]
    head_row = conn.execute("SELECT * FROM ledger_head WHERE id = 1").fetchone()

    if unchained == 0 and head_row is not None:
        return  # already chained

    rows = conn.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
    events = [_row_to_event(r) for r in rows]
    chain = ledger.compute_chain(events)
    for row, (prev, entry) in zip(rows, chain):
        conn.execute("UPDATE events SET prev_hash = ?, entry_hash = ? WHERE id = ?",
                     (prev, entry, row["id"]))
    head = chain[-1][1] if chain else ledger.GENESIS_HASH
    _write_ledger_head(conn, len(chain), head)


def _write_ledger_head(conn: sqlite3.Connection, count: int, head: str) -> None:
    conn.execute(
        """INSERT INTO ledger_head (id, entry_count, head_hash, updated_at)
           VALUES (1, ?, ?, datetime('now'))
           ON CONFLICT(id) DO UPDATE SET
             entry_count = excluded.entry_count,
             head_hash   = excluded.head_hash,
             updated_at  = excluded.updated_at""",
        (count, head),
    )


def get_ledger_head(conn: sqlite3.Connection) -> dict[str, Any]:
    """The recorded head: what the ledger should end on. Export this somewhere
    the database's owner does not control and truncation stops being deniable."""
    row = conn.execute("SELECT * FROM ledger_head WHERE id = 1").fetchone()
    if row is None:
        return {"entry_count": 0, "head_hash": ledger.GENESIS_HASH, "updated_at": None}
    return {"entry_count": row["entry_count"], "head_hash": row["head_hash"],
            "updated_at": row["updated_at"]}


def ledger_entries(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Every entry in insertion order, with its stored chain hashes, ready for
    `ledger.verify_chain`."""
    rows = conn.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
    out = []
    for r in rows:
        e = _row_to_event(r)
        e["prev_hash"] = r["prev_hash"]
        e["entry_hash"] = r["entry_hash"]
        out.append(e)
    return out


def insert_event(conn: sqlite3.Connection, event: dict[str, Any]) -> int:
    # Chain this event to the current head before storing it, so the ledger is
    # append-only by construction rather than by convention.
    head = get_ledger_head(conn)
    prev = head["head_hash"]
    entry = ledger.entry_hash(prev, event)

    cur = conn.execute(
        """INSERT INTO events (timestamp, actor_id, actor_type, task, event_type,
                               target, metadata, prev_hash, entry_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            event["timestamp"],
            event["actor_id"],
            event.get("actor_type", "unknown"),
            event.get("task"),
            event["event_type"],
            event["target"],
            json.dumps(event.get("metadata", {})),
            prev,
            entry,
        ),
    )
    _write_ledger_head(conn, head["entry_count"] + 1, entry)
    return cur.lastrowid


def known_finding_ids(conn: sqlite3.Connection, tool: str,
                      finding_ids: list[str]) -> set[str]:
    """Which of these finding ids this store has already ingested from `tool`.

    The envelope's id is a function of the finding's content, so re-running an
    emitter over unchanged input yields the same ids. Without this check every
    nightly scan would deposit another copy of the same findings and the counts
    would climb for no reason -- the id rule exists precisely so a consumer can
    tell "again" from "new".

    Scoped to one tool, because the envelope is explicit that two tools may
    legitimately produce the same id about the same subject.
    """
    if not finding_ids:
        return set()
    out: set[str] = set()
    # Chunked to stay well under SQLite's parameter limit on a large envelope.
    for start in range(0, len(finding_ids), 400):
        chunk = finding_ids[start:start + 400]
        placeholders = ",".join("?" * len(chunk))
        rows = conn.execute(
            f"""SELECT json_extract(metadata, '$.finding.id') AS fid
                FROM events
                WHERE event_type = 'finding'
                  AND json_extract(metadata, '$.source.tool') = ?
                  AND json_extract(metadata, '$.finding.id') IN ({placeholders})""",
            (tool, *chunk),
        ).fetchall()
        out.update(r["fid"] for r in rows if r["fid"])
    return out


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


def distinct_alert_categories(conn: sqlite3.Connection) -> list[str]:
    """The set of alert categories currently present, used to validate a
    natural-language query's proposed category filters."""
    rows = conn.execute(
        "SELECT DISTINCT category FROM alerts ORDER BY category"
    ).fetchall()
    return [r["category"] for r in rows]


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
            """INSERT INTO alerts (id, event_id, actor_id, actor_type, timestamp,
                                   severity, category, message, target, attack,
                                   source_tool, validated, evidence)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                a["id"], a["event_id"], a["actor_id"], a["actor_type"], a["timestamp"],
                a["severity"], a["category"], a["message"], a["target"],
                json.dumps(a.get("attack", [])),
                a.get("source_tool"),
                None if a.get("validated") is None else int(bool(a["validated"])),
                a.get("evidence"),
            ),
        )


def query_alerts(
    conn: sqlite3.Connection,
    severity: list[str] | None = None,
    actor_type: list[str] | None = None,
    actor_id: str | None = None,
    category: list[str] | None = None,
    search: str | None = None,
    since: str | None = None,
    until: str | None = None,
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
    # Time bounds. Timestamps are stored as ISO-8601 strings, so a lexicographic
    # comparison is also chronological. Bound values are parameterised.
    if since:
        clauses.append("a.timestamp >= ?")
        params.append(since)
    if until:
        clauses.append("a.timestamp <= ?")
        params.append(until)
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
        d["attack"] = json.loads(d.get("attack") or "[]")
        _hydrate_validated(d)
        out.append(d)
    return out


def _hydrate_validated(alert: dict[str, Any]) -> None:
    """SQLite has no boolean, so `validated` comes back 0/1 -- or None for an
    alert Shadowfax raised itself, where "did the emitter verify it" has no
    meaning. None is preserved rather than coerced to False: "nobody claimed
    this" and "somebody claimed it without checking" are different statements."""
    if alert.get("validated") is not None:
        alert["validated"] = bool(alert["validated"])


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
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in rows:
        # An unrecognised severity should never reach the table -- ingest
        # validates the ladder -- but counting it would be better than crashing
        # the stats endpoint over a row nobody can explain.
        counts[r["severity"]] = r["n"]
    return counts


def actor_risk_scores(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    # `info` weighs nothing. The shared severity ladder carries five levels and
    # an informational finding is context, not risk -- a hundred of them must not
    # out-score one critical. This is the only change the ladder forces on
    # Shadowfax's scoring, and it is spelled out in findings-envelope.md.
    weight = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
    rows = conn.execute("SELECT actor_id, actor_type, severity, COUNT(*) as n FROM alerts GROUP BY actor_id, severity").fetchall()
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        d = out.setdefault(r["actor_id"], {"actor_type": r["actor_type"], "score": 0,
                                            "critical": 0, "high": 0, "medium": 0,
                                            "low": 0, "info": 0})
        d[r["severity"]] = r["n"]
        d["score"] += weight.get(r["severity"], 0) * r["n"]
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
    d["attack"] = json.loads(d.get("attack") or "[]")
    _hydrate_validated(d)
    return d


def wipe_all(conn: sqlite3.Connection) -> None:
    # Reset clears activity data only. Users, sessions, API keys and recorded
    # sign-in attempts are left alone -- a data reset should not log you out,
    # delete your admin account, or quietly lift an active lockout. Clearing a
    # lockout is its own explicit, audited action (see the unlock endpoint).
    conn.execute("DELETE FROM alerts")
    conn.execute("DELETE FROM alert_state")
    conn.execute("DELETE FROM events")
    conn.execute("DELETE FROM policy")
    # The ledger restarts from genesis along with the events it describes. A
    # reset is an explicit, authorised wipe -- not a silent edit -- so the head
    # is reset openly rather than left claiming entries that no longer exist.
    _write_ledger_head(conn, 0, ledger.GENESIS_HASH)


# Authentication: users

def count_users(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]


def create_user(conn: sqlite3.Connection, username: str, password_hash: str,
                salt: str, role: str) -> dict[str, Any]:
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
        (username, password_hash, salt, role),
    )
    return {"id": cur.lastrowid, "username": username, "role": role}


def get_user_by_username(conn: sqlite3.Connection, username: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return dict(row) if row else None


def list_users(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT id, username, role, created_at FROM users ORDER BY username"
    ).fetchall()
    return [dict(r) for r in rows]


# Authentication: sessions

def create_session(conn: sqlite3.Connection, token_fp: str, user_id: int, expires_at: str) -> None:
    conn.execute(
        "INSERT INTO sessions (token_fp, user_id, expires_at) VALUES (?, ?, ?)",
        (token_fp, user_id, expires_at),
    )


def get_session_user(conn: sqlite3.Connection, token_fp: str) -> dict[str, Any] | None:
    """The user behind a live session token, or None if unknown or expired.

    Expired sessions are deleted as they are encountered, so the table does not
    accumulate dead tokens over time.
    """
    row = conn.execute(
        """SELECT s.expires_at, u.id, u.username, u.role
           FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.token_fp = ?""",
        (token_fp,),
    ).fetchone()
    if row is None:
        return None
    try:
        expired = datetime.fromisoformat(row["expires_at"]) <= _utc_now()
    except ValueError:
        expired = True
    if expired:
        conn.execute("DELETE FROM sessions WHERE token_fp = ?", (token_fp,))
        conn.commit()
        return None
    return {"id": row["id"], "username": row["username"], "role": row["role"]}


def delete_session(conn: sqlite3.Connection, token_fp: str) -> None:
    conn.execute("DELETE FROM sessions WHERE token_fp = ?", (token_fp,))


# Authentication: API keys

def create_api_key(conn: sqlite3.Connection, key_fp: str, prefix: str,
                   label: str | None, role: str) -> dict[str, Any]:
    cur = conn.execute(
        "INSERT INTO api_keys (key_fp, prefix, label, role) VALUES (?, ?, ?, ?)",
        (key_fp, prefix, label, role),
    )
    return {"id": cur.lastrowid, "prefix": prefix, "label": label, "role": role}


def get_api_key(conn: sqlite3.Connection, key_fp: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM api_keys WHERE key_fp = ?", (key_fp,)).fetchone()
    return dict(row) if row else None


def touch_api_key(conn: sqlite3.Connection, key_id: int) -> None:
    conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (_iso(_utc_now()), key_id))


def list_api_keys(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT id, prefix, label, role, created_at, last_used_at FROM api_keys ORDER BY id"
    ).fetchall()
    return [dict(r) for r in rows]


def delete_api_key(conn: sqlite3.Connection, key_id: int) -> bool:
    cur = conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
    return cur.rowcount > 0


# Authentication: sign-in attempts (v0.10)
#
# The throttle in throttle.py is a pure function; these are the only functions
# that give it something to be pure about. Timestamps are stored as UTC ISO
# strings, consistent with the rest of the schema, and parsed back to aware
# datetimes on the way out so the throttle never has to guess a timezone.

def record_login_attempt(conn: sqlite3.Connection, username: str, source: str,
                         outcome: str, at: datetime | None = None) -> None:
    """Record one sign-in attempt. `outcome` is 'failure', 'success' or 'locked'.

    Called for unknown usernames too -- the throttle must behave identically
    whether or not the account exists, or the endpoint becomes a way to discover
    which usernames are real.
    """
    conn.execute(
        "INSERT INTO login_attempts (username, source, at, outcome) VALUES (?, ?, ?, ?)",
        (username, source, _iso(at or _utc_now()), outcome),
    )


def recent_login_failures(conn: sqlite3.Connection, username: str, source: str,
                          since: datetime) -> list[datetime]:
    """Failure timestamps for one (username, source) scope since `since`.

    Scoped to the pair rather than the account on purpose: locking the account
    would let anyone who knows a username lock its owner out. See throttle.py.
    """
    rows = conn.execute(
        """SELECT at FROM login_attempts
           WHERE username = ? AND source = ? AND outcome = 'failure' AND at >= ?
           ORDER BY at ASC""",
        (username, source, _iso(since)),
    ).fetchall()
    return [ts for ts in (_parse_ts(r["at"]) for r in rows) if ts is not None]


def recent_source_failures(conn: sqlite3.Connection, source: str,
                           since: datetime) -> list[datetime]:
    """Failure timestamps for one source address, across every username tried.

    This is what catches spraying -- one attempt each at many accounts, where no
    single (username, source) scope ever reaches its own threshold.
    """
    rows = conn.execute(
        """SELECT at FROM login_attempts
           WHERE source = ? AND outcome = 'failure' AND at >= ?
           ORDER BY at ASC""",
        (source, _iso(since)),
    ).fetchall()
    return [ts for ts in (_parse_ts(r["at"]) for r in rows) if ts is not None]


def clear_login_failures(conn: sqlite3.Connection, username: str,
                         source: str | None = None) -> int:
    """Forget the failures for a username, optionally only from one source.

    Called on a successful sign-in, so an occasional typo never accumulates
    toward a lockout across weeks, and by the admin unlock endpoint.
    """
    if source is None:
        cur = conn.execute(
            "DELETE FROM login_attempts WHERE username = ? AND outcome = 'failure'",
            (username,),
        )
    else:
        cur = conn.execute(
            """DELETE FROM login_attempts
               WHERE username = ? AND source = ? AND outcome = 'failure'""",
            (username, source),
        )
    return cur.rowcount


def login_failure_scopes(conn: sqlite3.Connection,
                         since: datetime) -> list[dict[str, Any]]:
    """Every (username, source) with failures since `since`, and their times.

    Feeds the admin lockout view. The throttle decides what is *locked*; this
    only supplies the raw history, so there is one implementation of the rule.
    """
    rows = conn.execute(
        """SELECT username, source, at FROM login_attempts
           WHERE outcome = 'failure' AND at >= ?
           ORDER BY username, source, at ASC""",
        (_iso(since),),
    ).fetchall()
    scopes: dict[tuple[str, str], list[datetime]] = {}
    for r in rows:
        ts = _parse_ts(r["at"])
        if ts is not None:
            scopes.setdefault((r["username"], r["source"]), []).append(ts)
    return [{"username": u, "source": s, "failures": times}
            for (u, s), times in scopes.items()]


def prune_login_attempts(conn: sqlite3.Connection, before: datetime) -> int:
    """Drop attempts older than `before`. This table is operational state, not
    evidence -- the ledger holds what actually matters -- so it is safe to
    discard and would otherwise grow without bound under a sustained attack."""
    cur = conn.execute("DELETE FROM login_attempts WHERE at < ?", (_iso(before),))
    return cur.rowcount


def _parse_ts(value: str) -> datetime | None:
    """Parse a stored timestamp as naive UTC.

    Everything in this store is naive-UTC ISO text, and the throttle compares
    these against a clock in the same shape. Normalising an offset-carrying
    value here rather than at the call site means a mixed-format row cannot
    surface as a TypeError deep inside the sign-in path.

    Returns None rather than raising: one unparseable row should not be able to
    take down the sign-in endpoint. A dropped row can only ever make the
    throttle more permissive by one attempt, never less.
    """
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed
