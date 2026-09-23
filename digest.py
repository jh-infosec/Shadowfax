"""
Triage digest (v0.8).

An analyst does not want a list of every alert; they want to know which few
things need them today. The detectors decide what fired, correlation groups it,
chain detection says which bursts are real attacks -- this module turns all of
that into a short, ranked queue: *these N need you, and here is why.*

Two things keep it honest:

* **The ranking is deterministic.** Priority is arithmetic over facts Shadowfax
  already computed -- severity, whether the incident completed a kill chain, how
  many of its alerts are still unacknowledged, how long it has been sitting. No
  model orders this queue, and every item carries the `reasons` that produced its
  score, so an analyst can see exactly why something is at the top and disagree
  with it.
* **It ranks; it does not decide.** Nothing is closed, suppressed or acted on.
  An incident leaves the digest only when a human acknowledges its alerts.

`build_digest()` is a pure function of `(incidents, alerts_by_id, now)`. The
investigation assistant may write a covering sentence over the result, but the
order and the reasons are fixed before it ever sees them.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

# Points per incident severity. Deliberately coarse: the point is ordering, not
# false precision.
SEVERITY_POINTS = {"critical": 50, "high": 25, "medium": 10, "low": 5}

# A completed kill chain is the strongest single signal Shadowfax produces -- it
# means the actor got all the way to a terminal objective.
ESCALATED_CHAIN_POINTS = 30
PARTIAL_CHAIN_POINTS = 10

POINTS_PER_UNACKNOWLEDGED = 3
MAX_UNACKNOWLEDGED_POINTS = 30

# Staleness: an unhandled critical that has been sitting for a week is more
# urgent than one raised a minute ago, but the effect is capped so age can never
# outrank severity.
POINTS_PER_DAY_OPEN = 2
MAX_AGE_DAYS_COUNTED = 10

DEFAULT_LIMIT = 5


def _age_days(end: str, now: datetime) -> int:
    try:
        return max(0, (now - datetime.fromisoformat(end)).days)
    except (TypeError, ValueError):
        return 0


def score_incident(incident: dict[str, Any], unacknowledged: int,
                   now: datetime) -> tuple[int, list[str]]:
    """Priority for one incident, and the plain-English reasons behind it.

    Returning the reasons alongside the number is the point: a ranking an
    analyst cannot interrogate is one they cannot trust."""
    reasons: list[str] = []
    severity = incident.get("severity", "low")
    score = SEVERITY_POINTS.get(severity, 0)
    reasons.append(f"{severity} severity")

    chain = incident.get("chain") or {}
    if chain.get("escalated"):
        score += ESCALATED_CHAIN_POINTS
        stages = " → ".join(s["tactic"] for s in chain.get("stages", []))
        reasons.append(f"completed kill chain ({stages})")
    elif chain:
        score += PARTIAL_CHAIN_POINTS
        reasons.append(f"partial attack chain ({chain.get('length', 0)} stages)")

    if unacknowledged:
        score += min(unacknowledged * POINTS_PER_UNACKNOWLEDGED,
                     MAX_UNACKNOWLEDGED_POINTS)
        reasons.append(f"{unacknowledged} unacknowledged alert"
                       f"{'s' if unacknowledged != 1 else ''}")

    days = _age_days(incident.get("end", ""), now)
    if days:
        score += min(days, MAX_AGE_DAYS_COUNTED) * POINTS_PER_DAY_OPEN
        reasons.append(f"open for {days} day{'s' if days != 1 else ''}")

    return score, reasons


def build_digest(incidents: list[dict[str, Any]],
                 alerts_by_id: dict[str, dict[str, Any]],
                 now: datetime | None = None,
                 limit: int = DEFAULT_LIMIT) -> dict[str, Any]:
    """Rank the open incidents into a triage queue.

    An incident is *open* while any of its alerts is unacknowledged; acknowledging
    them is what takes it off the list. Pure and deterministic -- the same inputs
    always produce the same order."""
    now = now or datetime.now()
    scored: list[dict[str, Any]] = []

    for inc in incidents:
        members = [alerts_by_id[a] for a in inc.get("alert_ids", []) if a in alerts_by_id]
        unacked = [a for a in members if not a.get("acknowledged")]
        if not unacked:
            continue  # handled; it has left the queue
        score, reasons = score_incident(inc, len(unacked), now)
        chain = inc.get("chain") or {}
        scored.append({
            "incident_id": inc.get("id"),
            "actor_id": inc.get("actor_id"),
            "actor_type": inc.get("actor_type"),
            "severity": inc.get("severity"),
            "base_severity": inc.get("base_severity"),
            "start": inc.get("start"),
            "end": inc.get("end"),
            "alert_count": inc.get("alert_count"),
            "unacknowledged": len(unacked),
            "priority": score,
            "reasons": reasons,
            "categories": inc.get("categories", []),
            "chain": ({"stages": [s["tactic"] for s in chain.get("stages", [])],
                       "escalated": chain.get("escalated", False)} if chain else None),
            "summary": inc.get("summary"),
        })

    # Highest priority first; ties broken by the most recent activity, so two
    # equally urgent incidents surface newest-first.
    scored.sort(key=lambda i: (i["priority"], i["end"] or ""), reverse=True)

    total_unacked = sum(i["unacknowledged"] for i in scored)
    return {
        "generated_at": now.replace(microsecond=0).isoformat(),
        "open_incidents": len(scored),
        "unacknowledged_alerts": total_unacked,
        "shown": min(limit, len(scored)),
        "items": scored[:limit],
    }


def render_digest(digest: dict[str, Any]) -> str:
    """A plain-text digest -- the thing an analyst could read once a day. Built
    only from the ranked data, with no model involved."""
    if not digest["items"]:
        lines = [f"Shadowfax triage digest — {digest['generated_at']}", "",
                 "Nothing open. Every incident's alerts have been acknowledged."]
        return "\n".join(lines)

    lines = [
        f"Shadowfax triage digest — {digest['generated_at']}",
        "",
        f"{digest['open_incidents']} open incident"
        f"{'s' if digest['open_incidents'] != 1 else ''} "
        f"({digest['unacknowledged_alerts']} unacknowledged alert"
        f"{'s' if digest['unacknowledged_alerts'] != 1 else ''}). "
        f"Top {digest['shown']}:",
        "",
    ]
    for n, item in enumerate(digest["items"], 1):
        lines.append(f"{n}. [{item['severity'].upper()}] {item['actor_id']} "
                     f"— {item['unacknowledged']} unacknowledged "
                     f"(priority {item['priority']})")
        lines.append(f"   why: {'; '.join(item['reasons'])}")
        if item.get("chain") and item["chain"].get("escalated"):
            lines.append(f"   chain: {' → '.join(item['chain']['stages'])}")
        lines.append(f"   incident {item['incident_id']}")
        lines.append("")
    lines.append("Ranked by severity, completed attack chains, unacknowledged "
                 "volume and age. Shadowfax ranks; you decide.")
    return "\n".join(lines)
