"""
Tamper-evident event ledger (v0.9).

Shadowfax asks whether an actor's behaviour should be trusted. That question is
worth very little if the record of the behaviour cannot itself be trusted -- an
alert history that could have been quietly edited after the fact is not evidence,
it is an assertion. This module makes the event log **tamper-evident**: every
event is hash-chained to the one before it, so any later edit, deletion or
reordering breaks the chain at a detectable point.

The chain
---------
Each stored event carries two hashes::

    entry_hash = sha256( prev_hash | canonical_json(event content) )

where `prev_hash` is the previous entry's `entry_hash`, and the first entry
chains from a fixed `GENESIS_HASH`. Because every link folds in the one before
it, changing any byte of any event changes that entry's hash and every hash
after it -- and the stored `prev_hash` of the following row no longer matches.
`verify_chain()` walks the log and reports the *first* position where the
recomputed value diverges, so a break is localised rather than merely detected.

Insertion order, not event time
-------------------------------
The chain follows the order the store *received* events (the autoincrement id),
not the `timestamp` they claim. Events legitimately arrive out of chronological
order -- a harness uploading a session log, a backdated import -- and reordering
by claimed time would make the chain depend on attacker-supplied data. What is
being proved is "these entries were appended in this order and none has changed
since", which is a statement about the store, not about the world.

What this does and does not give you
------------------------------------
This is tamper-**evident**, not tamper-**proof**. It makes silent modification
and deletion detectable by anyone who can read the log. It does not prevent
them, and it cannot by itself detect *truncation*: lopping entries off the end
leaves a shorter but internally valid chain. That is what `ledger_head`
addresses -- the stored count and head hash are compared against the chain, so a
truncated log fails verification.

An attacker with full write access to the database could rewrite the events, the
chain and the head together. The honest mitigation is to publish the head hash
somewhere the attacker does not control -- `GET /ledger/head` exists so it can
be exported to a log server, a signed commit, or a colleague's inbox. Anchoring
the head off-box is what turns "evident to us" into "provable to a third party",
and it is deliberately left to the operator rather than claimed here.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

# The chain's fixed starting point. The first event chains from this, so an
# empty log has a well-defined head.
GENESIS_HASH = "0" * 64

# The event fields the hash covers: everything an event asserts about what
# happened. Storage bookkeeping (the row id, `ingested_at`) is excluded -- it is
# assigned by the database, not claimed by the emitter, and including it would
# make the hash depend on values that are not part of the evidence.
HASHED_FIELDS = ("timestamp", "actor_id", "actor_type", "task",
                 "event_type", "target", "metadata")


def canonical_payload(event: dict[str, Any]) -> str:
    """The event's content as a stable string.

    Canonical means byte-identical for equal content: keys sorted, no
    incidental whitespace. Without this, re-serialising the same event could
    produce a different hash and a false tamper report."""
    payload = {
        "timestamp": event.get("timestamp"),
        "actor_id": event.get("actor_id"),
        "actor_type": event.get("actor_type", "unknown"),
        "task": event.get("task"),
        "event_type": event.get("event_type"),
        "target": event.get("target"),
        "metadata": event.get("metadata") or {},
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def entry_hash(prev_hash: str, event: dict[str, Any]) -> str:
    """This entry's link in the chain. Pure: same inputs, same hash, always."""
    material = f"{prev_hash}|{canonical_payload(event)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def compute_chain(events: list[dict[str, Any]],
                  start_hash: str = GENESIS_HASH) -> list[tuple[str, str]]:
    """(prev_hash, entry_hash) for each event in order, chaining from
    `start_hash`. Used to build the chain and to backfill an existing log."""
    out: list[tuple[str, str]] = []
    prev = start_hash
    for e in events:
        h = entry_hash(prev, e)
        out.append((prev, h))
        prev = h
    return out


def verify_chain(entries: list[dict[str, Any]],
                 expected_count: int | None = None,
                 expected_head: str | None = None) -> dict[str, Any]:
    """Walk the ledger and report whether it is intact.

    `entries` must be the stored rows in insertion order, each carrying the
    event content plus its stored `prev_hash` and `entry_hash`. Returns a report
    naming the *first* divergence, so a break can be located rather than just
    announced. Never raises -- a malformed row is a finding, not an exception.

    `expected_count` / `expected_head` come from the stored head record and are
    what catches truncation: a log with entries removed from the end still
    chains correctly on its own terms, but no longer matches the head.
    """
    prev = GENESIS_HASH
    for position, row in enumerate(entries):
        stored_prev = row.get("prev_hash")
        stored_entry = row.get("entry_hash")

        if not stored_prev or not stored_entry:
            return _broken(position, row, len(entries),
                           "entry is missing its chain hashes (written before "
                           "the ledger existed, or cleared)")

        if stored_prev != prev:
            return _broken(position, row, len(entries),
                           "this entry does not chain to the one before it -- "
                           "an entry was modified, deleted or reordered")

        recomputed = entry_hash(prev, row)
        if recomputed != stored_entry:
            return _broken(position, row, len(entries),
                           "the entry's content does not match its hash -- "
                           "this event was modified after it was recorded")

        prev = stored_entry

    # The chain is internally consistent. Now check it against the recorded
    # head, which is what makes truncation visible.
    if expected_count is not None and expected_count != len(entries):
        return {
            "ok": False,
            "entries": len(entries),
            "verified": len(entries),
            "head": prev,
            "broken_at": None,
            "reason": (f"the ledger holds {len(entries)} entries but the head "
                       f"record expects {expected_count} -- entries were "
                       f"removed from the end of the log"),
        }
    if expected_head is not None and expected_head != prev:
        return {
            "ok": False,
            "entries": len(entries),
            "verified": len(entries),
            "head": prev,
            "broken_at": None,
            "reason": ("the chain's head does not match the recorded head -- "
                       "the log and its head record disagree"),
        }

    return {
        "ok": True,
        "entries": len(entries),
        "verified": len(entries),
        "head": prev,
        "broken_at": None,
        "reason": None,
    }


def _broken(position: int, row: dict[str, Any], total: int,
            reason: str) -> dict[str, Any]:
    return {
        "ok": False,
        "entries": total,
        "verified": position,          # everything before here checked out
        "head": None,
        "broken_at": {
            "position": position,      # 0-based index in insertion order
            "event_id": row.get("id"),
            "timestamp": row.get("timestamp"),
            "actor_id": row.get("actor_id"),
        },
        "reason": reason,
    }


def describe(report: dict[str, Any]) -> str:
    """One human line for a verification report -- what the CLI prints."""
    if report["ok"]:
        return (f"ledger intact — {report['entries']} entries verified, "
                f"head {report['head'][:16]}…")
    where = report.get("broken_at")
    if where:
        return (f"LEDGER BROKEN at position {where['position']} "
                f"(event id {where['event_id']}, actor {where['actor_id']}): "
                f"{report['reason']}. "
                f"{report['verified']} entries before it verified cleanly.")
    return f"LEDGER BROKEN: {report['reason']}"
