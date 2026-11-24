"""
Agents handing work to each other (v0.46).

More and more agent systems are teams: a planner hands a task to a coder, a
researcher passes what it found to a writer, an orchestrator fans work out to
helpers. That is also how an attack moves between them. An injection that
lands in one agent's reading doesn't have to be acted on by that agent: it can
be passed on, in a perfectly ordinary-looking hand-off, to another agent that
has the tools to act on it. And a restricted agent can get a better-equipped
one to do what it isn't allowed to do itself.

How Shadowfax sees it:

* The agent handing work over reports an `agent_handoff` event: the target is
  the receiving agent's id, and `metadata.message` is what it passed on
  (shadowfax_agent.Reporter.handoff does this).
* Shadowfax writes the other half itself: a `handoff_received` event in the
  receiving agent's timeline, saying who it came from and carrying the
  message. Nobody can post one of those directly. Writing it into the
  receiver's own history keeps detection a function of one agent's events,
  which is what makes it fast, cacheable and testable.
* If the sender had just read injected content (within the prompt-injection
  window), and the message carries something planted there (a URL, a host, an
  address or a path the sender hadn't used before reading it), the received
  hand-off is marked as tainted, with where the injection came from and which
  agents it has passed through. Taint follows a chain: a tainted hand-off
  passed on again stays tainted.

Then, in the receiving agent's detection:

* The message is read like any other content, so instructions aimed at an AI
  in it raise `prompt_injection`.
* Using something the taint names raises `injection_spread` (critical): the
  injection reached an agent that never read it.
* Doing something within its own permissions that the sender's profile
  wouldn't allow, soon after the hand-off, raises `delegated_escalation`: the
  sender may be getting round its limits through this agent (a confused
  deputy).
* On the sending side, a profile's `allowed_delegates` says which agents it may
  hand work to; anyone else is a `permission_violation`.

Pure: no I/O.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import injection
import memory
import timeutil

HANDOFF = "agent_handoff"
RECEIVED = "handoff_received"
MAX_MESSAGE = 8000


def message_of(event: dict[str, Any]) -> str:
    meta = event.get("metadata") or {}
    for key in ("message", "task_description", "prompt", "content"):
        if isinstance(meta.get(key), str):
            return meta[key][:MAX_MESSAGE]
    return ""


def _ts(event: dict[str, Any]) -> datetime:
    return timeutil.parse(event["timestamp"])


def taint_of(sender_events: list[dict[str, Any]], handoff_event: dict[str, Any],
             window: timedelta) -> dict[str, Any] | None:
    """Whether a hand-off carries something planted by an injection the sender
    read shortly before. `sender_events` are the sender's events up to and
    including the hand-off, in order."""
    message = message_of(handoff_event)
    carried = injection.indicators(message)
    if not carried:
        return None
    at = _ts(handoff_event)
    used: set[str] = set()
    found: list[dict[str, Any]] = []
    for e in sender_events:
        if e is handoff_event or (e.get("id") is not None and e.get("id") == handoff_event.get("id")):
            break
        when = _ts(e)
        if e["event_type"] == "tool_call":
            used |= injection.indicators(injection.call_text(e))
            continue
        if e["event_type"] not in (injection.EVENT_TYPE, RECEIVED, memory.LOADED) or at - when > window:
            continue
        meta = e.get("metadata") or {}
        text = content_text(e)
        planted: set[str] = set()
        source, via = "?", []
        markers = injection.scan(text, in_memory=e["event_type"] == memory.LOADED)
        if markers:
            planted = injection.planted(injection.indicators(text), used)
            source = f"a hand-off from {meta.get('from', '?')}" if e["event_type"] == RECEIVED \
                else injection.source_of(e)
        prior = meta.get("taint") if e["event_type"] == RECEIVED else None
        if isinstance(prior, dict):
            planted |= set(prior.get("indicators") or [])
            if not markers:
                source = prior.get("source", "?")
            via = list(prior.get("via") or [])
        hits = sorted(i for i in planted if i in carried)
        if hits:
            found.append({"source": source, "via": via, "indicators": hits,
                          "read_at": e["timestamp"],
                          "markers": injection.summary(markers) if markers else (prior or {}).get("markers")})
    if not found:
        return None
    latest = found[-1]
    indicators = sorted({i for f in found for i in f["indicators"]})
    return {"source": latest["source"], "read_at": latest["read_at"], "markers": latest["markers"],
            "via": latest["via"] + [handoff_event["actor_id"]], "indicators": indicators}


def content_text(event: dict[str, Any]) -> str:
    """What an agent was given to read: a tool result, a hand-off's message, or
    a memory file it loaded (v0.48)."""
    if event["event_type"] == RECEIVED:
        return message_of(event)
    return injection.content_of(event)


def received(handoff_event: dict[str, Any], taint: dict[str, Any] | None) -> dict[str, Any]:
    """The event Shadowfax writes into the receiving agent's timeline."""
    meta = handoff_event.get("metadata") or {}
    return {
        "timestamp": handoff_event["timestamp"],
        "actor_id": str(handoff_event["target"]),
        "actor_type": "ai_agent",
        "task": handoff_event.get("task"),
        "event_type": RECEIVED,
        "target": handoff_event["actor_id"],
        "metadata": {"from": handoff_event["actor_id"], "message": message_of(handoff_event),
                     "handoff_event_id": handoff_event.get("id"),
                     **({"taint": taint} if taint else {}),
                     **({"from_task": meta.get("task")} if meta.get("task") else {})},
    }


def refusal(handoff_event: dict[str, Any], reserved: set[str] | frozenset[str]) -> str | None:
    """Why a hand-off can't be accepted, or None."""
    to = str(handoff_event.get("target") or "").strip()
    if not to:
        return "a hand-off needs the receiving agent's id as its target"
    if to == handoff_event.get("actor_id"):
        return "an agent can't hand work to itself"
    if to in reserved:
        return f"work can't be handed to Shadowfax's own account {to!r}"
    if len(to) > 200:
        return "the receiving agent's id is too long"
    return None
