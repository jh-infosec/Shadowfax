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


def correlate(alerts: list[dict[str, Any]], window_minutes: int) -> list[dict[str, Any]]:
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
                incidents.append(_build_incident(actor_id, cluster))
                cluster = []
            cluster.append(a)
            last_ts = ts
        if cluster:
            incidents.append(_build_incident(actor_id, cluster))

    incidents.sort(key=lambda i: (SEVERITY_ORDER.get(i["severity"], 99), _neg_ts(i["end"])))
    return incidents


def _neg_ts(ts: str) -> str:
    # Sort key that puts the most recent end first, after severity.
    return "".join(chr(255 - ord(c)) for c in ts)


def _build_incident(actor_id: str, cluster: list[dict[str, Any]]) -> dict[str, Any]:
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

    incident = {
        "id": _incident_id(actor_id, first["id"]),
        "actor_id": actor_id,
        "actor_type": first.get("actor_type", "unknown"),
        "start": first["timestamp"],
        "end": last["timestamp"],
        "duration_minutes": round((end - start).total_seconds() / 60),
        "alert_count": len(cluster),
        "severity": _worst(severities),
        "severity_counts": severity_counts,
        "categories": categories,
        "techniques": techniques,
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
    return (f"{article} {kind} actor ({incident['actor_id']}) "
            f"raised {n} alert{'s' if n != 1 else ''} {span}, involving {listed}. "
            f"Highest severity: {incident['severity']}.")


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
