"""
Alert correlation and incident reports (v0.4).

An **incident** is a burst of one actor's alerts close together in time. The
detectors say *what* fired; correlation says *these fired together*, turning a
stream of alerts into a smaller set of things an analyst actually works.

`correlate()` is a pure function of `(alerts, window)`: for each actor it sorts
alerts by time and starts a new incident whenever the gap to the previous alert
exceeds the window. No I/O, no LLM -- correlation stays as deterministic and
inspectable as detection. `render_report()` turns an incident into a factual
markdown report from the same data (the v0.5 investigation assistant is where an
LLM gets to *explain*; here we only summarise what is already known).
"""

from __future__ import annotations
import hashlib
from datetime import datetime, timedelta
from typing import Any

import attack

SEVERITY_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Human phrases for the summary sentence, keyed by alert category.
_CATEGORY_PHRASE = {
    "destructive_action": "destructive tool calls",
    "out_of_scope_action": "out-of-scope activity",
    "brute_force_auth": "brute-force authentication attempts",
    "impossible_travel": "impossible-travel sign-ins",
    "privilege_escalation": "unapproved privilege changes",
    "lateral_movement": "lateral movement",
    "exfiltration_volume": "large data transfers",
    "canary_triggered": "honeytoken access",
    "blocked_target_access": "access to blocked targets",
    "allowlist_violation": "allowlist violations",
    "capability_resurrection": "resurrection of blocked capabilities",
    "dormant_reappearance": "reappearance after dormancy",
    "off_hours_access": "off-hours access to sensitive targets",
    "rate_anomaly": "anomalous activity rate",
}


def _incident_id(actor_id: str, first_alert_id: str) -> str:
    return hashlib.sha256(f"{actor_id}|{first_alert_id}".encode()).hexdigest()[:16]


def _worst(severities: list[str]) -> str:
    return min(severities, key=lambda s: SEVERITY_ORDER.get(s, 99)) if severities else "low"


def _fmt_time(ts: str) -> str:
    return ts.replace("T", " ")[:16]


def _neg_ts(ts: str) -> str:
    # Sort key that puts the most recent end first, after severity.
    return "".join(chr(255 - ord(c)) for c in ts)


# --- attack-chain detection (v0.6) -----------------------------------------
#
# Detectors say *what* fired and correlation says *these fired together*; chain
# detection says *these advanced through the kill chain in order*. An attacker
# rarely wins with one move -- they gain access, escalate, move laterally, then
# exfiltrate or destroy. So we look for a run of one incident's alerts whose
# ATT&CK tactics step *forward* through `attack.TACTIC_ORDER` over time. That is
# the "combo move" a single mid-severity alert never shows on its own.
#
# The chain is the longest strictly-increasing-by-tactic-rank subsequence of the
# incident's time-ordered alerts (each alert placed at its lowest-ranked tactic).
# Pure and deterministic, like everything else here -- no LLM decides this.

def _alert_rank(alert: dict[str, Any]) -> tuple[int, str, str] | None:
    """An alert's position on the kill chain as (rank, tactic, technique_id), or
    None if it carries no ranked ATT&CK tactic. When an alert maps to several
    techniques, it sits at its earliest (lowest-rank) tactic."""
    best: tuple[int, str, str] | None = None
    for t in alert.get("attack", []) or []:
        rank = attack.tactic_rank(t.get("tactic", ""))
        if rank is None:
            continue
        if best is None or rank < best[0]:
            best = (rank, t["tactic"], t["id"])
    return best


def _detect_chain(cluster: list[dict[str, Any]], min_stages: int) -> dict[str, Any] | None:
    """The kill chain within one time-ordered incident, or None if its alerts do
    not advance through at least `min_stages` ordered tactics."""
    # One (rank, tactic, technique, alert) step per alert that has a ranked
    # tactic, kept in time order.
    steps: list[tuple[int, str, str, dict[str, Any]]] = []
    for a in cluster:  # cluster is already time-ordered
        placed = _alert_rank(a)
        if placed is not None:
            steps.append((placed[0], placed[1], placed[2], a))
    if len(steps) < min_stages:
        return None

    # Longest strictly-increasing subsequence over the ranks, with predecessor
    # links so we can reconstruct which alerts form the chain.
    n = len(steps)
    length = [1] * n
    prev = [-1] * n
    for i in range(n):
        for j in range(i):
            if steps[j][0] < steps[i][0] and length[j] + 1 > length[i]:
                length[i] = length[j] + 1
                prev[i] = j
    end = max(range(n), key=lambda i: length[i])
    if length[end] < min_stages:
        return None

    chain_idx: list[int] = []
    k = end
    while k != -1:
        chain_idx.append(k)
        k = prev[k]
    chain_idx.reverse()

    stages = [{
        "tactic": steps[i][1],
        "rank": steps[i][0],
        "technique_id": steps[i][2],
        "category": steps[i][3]["category"],
        "time": steps[i][3]["timestamp"],
        "alert_id": steps[i][3]["id"],
    } for i in chain_idx]

    terminal = attack.is_terminal_tactic(stages[-1]["tactic"])
    return {
        "length": len(stages),
        "stages": stages,
        "terminal_tactic": stages[-1]["tactic"] if terminal else None,
        # A completed chain that reaches a terminal tactic (lateral movement,
        # collection, C2, exfiltration or impact) is the actor achieving its
        # objective -- the incident is escalated to critical.
        "escalated": terminal,
    }


def _chain_sentence(chain: dict[str, Any]) -> str:
    arrow = " → ".join(s["tactic"] for s in chain["stages"])
    lead = ("Kill chain reaching " + chain["terminal_tactic"]
            if chain["escalated"] else "Partial attack chain")
    return f"{lead}: {arrow}."


def correlate(alerts: list[dict[str, Any]], window_minutes: int,
              chain_min_stages: int = 3) -> list[dict[str, Any]]:
    """Group alerts into incidents. `alerts` may span many actors; each actor is
    correlated independently. Returns incidents sorted worst-first, then most
    recent first."""
    by_actor: dict[str, list[dict[str, Any]]] = {}
    for a in alerts:
        by_actor.setdefault(a["actor_id"], []).append(a)

    window = timedelta(minutes=window_minutes)
    incidents: list[dict[str, Any]] = []

    for actor_id, actor_alerts in by_actor.items():
        ordered = sorted(actor_alerts, key=lambda a: a["timestamp"])
        cluster: list[dict[str, Any]] = []
        last_ts: datetime | None = None
        for a in ordered:
            ts = datetime.fromisoformat(a["timestamp"])
            if last_ts is not None and ts - last_ts > window:
                incidents.append(_build_incident(actor_id, cluster, chain_min_stages))
                cluster = []
            cluster.append(a)
            last_ts = ts
        if cluster:
            incidents.append(_build_incident(actor_id, cluster, chain_min_stages))

    incidents.sort(key=lambda i: (SEVERITY_ORDER.get(i["severity"], 99), _neg_ts(i["end"])))
    return incidents


def _build_incident(actor_id: str, cluster: list[dict[str, Any]],
                    chain_min_stages: int = 3) -> dict[str, Any]:
    cluster = sorted(cluster, key=lambda a: a["timestamp"])
    first, last = cluster[0], cluster[-1]
    severities = [a["severity"] for a in cluster]
    severity_counts = {s: severities.count(s) for s in ("critical", "high", "medium", "low")}
    start = datetime.fromisoformat(first["timestamp"])
    end = datetime.fromisoformat(last["timestamp"])

    categories: list[str] = []
    for a in cluster:
        if a["category"] not in categories:
            categories.append(a["category"])

    techniques: list[dict[str, str]] = []
    seen_tech: set[str] = set()
    for a in cluster:
        for t in a.get("attack", []) or []:
            if t["id"] not in seen_tech:
                seen_tech.add(t["id"])
                techniques.append(t)

    base_severity = _worst(severities)
    chain = _detect_chain(cluster, chain_min_stages)
    # An escalated kill chain (one that reaches a terminal tactic) lifts the
    # incident to critical, so a burst of individually mid-severity alerts that
    # together complete an attack surfaces at the top. base_severity keeps the
    # un-escalated verdict for transparency.
    severity = "critical" if (chain and chain["escalated"]) else base_severity

    incident = {
        "id": _incident_id(actor_id, first["id"]),
        "actor_id": actor_id,
        "actor_type": first.get("actor_type", "unknown"),
        "start": first["timestamp"],
        "end": last["timestamp"],
        "duration_minutes": round((end - start).total_seconds() / 60),
        "alert_count": len(cluster),
        "severity": severity,
        "base_severity": base_severity,
        "severity_counts": severity_counts,
        "categories": categories,
        "techniques": techniques,
        "chain": chain,
        "risk_score": sum(SEVERITY_WEIGHT.get(s, 0) for s in severities),
        "alert_ids": [a["id"] for a in cluster],
    }
    incident["summary"] = _summary_sentence(incident)
    return incident


def _summary_sentence(incident: dict[str, Any]) -> str:
    phrases = [_CATEGORY_PHRASE.get(c, c.replace("_", " ")) for c in incident["categories"]]
    if len(phrases) > 1:
        listed = ", ".join(phrases[:-1]) + " and " + phrases[-1]
    else:
        listed = phrases[0] if phrases else "suspicious activity"
    dur = incident["duration_minutes"]
    span = f"over {dur} minute{'s' if dur != 1 else ''}" if dur else "at a single moment"
    n = incident["alert_count"]
    kind = incident["actor_type"].replace("_", " ")
    article = "An" if kind[:1].lower() in "aeiou" else "A"
    base = (f"{article} {kind} actor ({incident['actor_id']}) "
            f"raised {n} alert{'s' if n != 1 else ''} {span}, involving {listed}. "
            f"Highest severity: {incident['severity']}.")
    chain = incident.get("chain")
    if chain:
        base += " " + _chain_sentence(chain)
    return base


def render_report(incident: dict[str, Any], alerts_by_id: dict[str, dict[str, Any]]) -> str:
    """A factual markdown report for one incident, built only from its data."""
    sc = incident["severity_counts"]
    sev_line = ", ".join(f"{sc[s]} {s}" for s in ("critical", "high", "medium", "low") if sc[s])

    lines = [
        f"# Incident {incident['id']} — {incident['actor_id']}",
        "",
        f"**Severity:** {incident['severity'].upper()}  ·  "
        f"**Actor:** {incident['actor_id']} ({incident['actor_type']})  ·  "
        f"**Window:** {_fmt_time(incident['start'])} → {_fmt_time(incident['end'])} "
        f"({incident['duration_minutes']} min)",
        f"**Alerts:** {incident['alert_count']} ({sev_line})  ·  "
        f"**Risk contribution:** {incident['risk_score']}",
        "",
        "## Summary",
        "",
        _summary_sentence(incident),
        "",
        "## ATT&CK techniques",
        "",
    ]
    if incident["techniques"]:
        for t in incident["techniques"]:
            lines.append(f"- {t['id']} {t['name']} ({t['tactic']})")
    else:
        lines.append("- none mapped")

    chain = incident.get("chain")
    if chain:
        lines += ["", "## Attack chain", "", _chain_sentence(chain), ""]
        for i, s in enumerate(chain["stages"], 1):
            lines.append(f"{i}. **{s['tactic']}** — {s['category']} "
                         f"({s['technique_id']}) at {_fmt_time(s['time'])}")
        if chain["escalated"]:
            lines += ["",
                      f"> Escalated to CRITICAL: the chain completes at "
                      f"{chain['terminal_tactic']}."]

    lines += ["", "## Timeline", "", "| Time | Severity | Category | Detail | ATT&CK |",
              "|------|----------|----------|--------|--------|"]
    for aid in incident["alert_ids"]:
        a = alerts_by_id.get(aid)
        if not a:
            continue
        tech = " ".join(t["id"] for t in a.get("attack", []) or []) or "—"
        detail = a["message"].replace("|", "\\|")
        lines.append(f"| {_fmt_time(a['timestamp'])} | {a['severity']} | {a['category']} "
                     f"| {detail} | {tech} |")
    lines.append("")
    return "\n".join(lines)
