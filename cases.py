"""
Case notes: analysts working an alert or an incident together (v0.35).

An alert says what the engine found. A case says what people did about it: who
looked, what they checked, what they concluded, who has it now. Until v0.35 the
only place for that was a single editable `note` field, which kept the last
thing anyone typed and nothing else.

Notes here are **events**, written under Shadowfax's own `shadowfax-case`
actor, so they go into the same hash-chained ledger as everything else:

* **Append-only.** There is no edit and no delete. A correction is a new note,
  so the record shows what was believed when, which is what an investigation
  is reviewed on afterwards.
* **Tamper-evident.** Changing or removing a note breaks the ledger at that
  point, like any other event.
* **Attributed by the server.** The author is the signed-in user, never a field
  the client sends.

Triage changes (acknowledging, assigning) are recorded in the same timeline as
`case_update` events, so a case reads as one story: notes and actions in order.

Notes are about an alert (`alert:<id>`) or an incident (`incident:<id>`). Both
ids are deterministic, so notes stay attached across rescans. An incident's id
comes from its actor and its first alert, so its notes follow it as long as
that first alert does.

Pure: no database and no FastAPI here.
"""

from __future__ import annotations

import re
from typing import Any

CASE_ACTOR_ID = "shadowfax-case"
CASE_ACTOR_TYPE = "service_account"
NOTE = "case_note"
UPDATE = "case_update"
EVENT_TYPES = (NOTE, UPDATE)
SUBJECT_KINDS = ("alert", "incident")

MAX_NOTE_CHARS = 4000
_SUBJECT_ID = re.compile(r"^[0-9a-f]{16}$")
# Control characters other than newline and tab are refused: they draw nothing
# a reader can see, so a note could say one thing on screen and another in the
# stored record.
_BAD_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def subject_key(kind: str, subject_id: str) -> str:
    return f"{kind}:{subject_id}"


def valid_subject_id(subject_id: str) -> bool:
    return bool(_SUBJECT_ID.match(subject_id or ""))


def clean_body(body: str) -> tuple[str | None, str | None]:
    """(the note as it will be stored, None) or (None, why it was refused)."""
    text = (body or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        return None, "a note can't be empty"
    if len(text) > MAX_NOTE_CHARS:
        return None, f"a note can be at most {MAX_NOTE_CHARS} characters"
    if _BAD_CONTROL.search(text):
        return None, "a note can't contain control characters"
    return text, None


def note_event(kind: str, subject_id: str, author: str, body: str, at: str) -> dict[str, Any]:
    return {
        "timestamp": at, "actor_id": CASE_ACTOR_ID, "actor_type": CASE_ACTOR_TYPE,
        "task": "case_management", "event_type": NOTE,
        "target": subject_key(kind, subject_id),
        "metadata": {"subject_kind": kind, "subject_id": subject_id,
                     "author": author, "body": body},
    }


def update_event(kind: str, subject_id: str, author: str, changes: list[str],
                 at: str) -> dict[str, Any]:
    return {
        "timestamp": at, "actor_id": CASE_ACTOR_ID, "actor_type": CASE_ACTOR_TYPE,
        "task": "case_management", "event_type": UPDATE,
        "target": subject_key(kind, subject_id),
        "metadata": {"subject_kind": kind, "subject_id": subject_id,
                     "author": author, "changes": changes},
    }


def describe_state_change(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """What a triage change did, in words, or [] if nothing actually changed."""
    out: list[str] = []
    if bool(before.get("acknowledged")) != bool(after.get("acknowledged")):
        out.append("acknowledged" if after.get("acknowledged") else "reopened (unacknowledged)")
    old_who, new_who = before.get("assigned_to") or None, after.get("assigned_to") or None
    if old_who != new_who:
        out.append(f"assigned to {new_who}" if new_who else f"unassigned (was {old_who})")
    if (before.get("note") or None) != (after.get("note") or None):
        out.append("changed the alert's short note")
    return out


def timeline(events: list[dict[str, Any]],
             labels: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Case events as entries for the dashboard and CLI, oldest first.

    `labels` maps a subject key to a short description, used when an incident's
    timeline also shows the notes on its member alerts.
    """
    labels = labels or {}
    out = []
    for e in events:
        if e.get("event_type") not in EVENT_TYPES:
            continue
        meta = e.get("metadata") or {}
        entry = {
            "id": e.get("id"),
            "at": e.get("timestamp"),
            "kind": "note" if e["event_type"] == NOTE else "update",
            "author": meta.get("author"),
            "subject_kind": meta.get("subject_kind"),
            "subject_id": meta.get("subject_id"),
            "on": labels.get(e.get("target") or ""),
        }
        if e["event_type"] == NOTE:
            entry["body"] = meta.get("body", "")
        else:
            entry["changes"] = list(meta.get("changes") or [])
        out.append(entry)
    return out
