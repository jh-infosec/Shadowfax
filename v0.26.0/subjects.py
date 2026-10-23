"""
Subject pages (v0.26): everything other tools have said about one thing.

Findings arrive about subjects -- a file, a host, a log workspace, or an actor
Shadowfax already watches (v0.11). Until now they were shown the way an
agent's tool calls are: as a timeline of events. That is the right view of
what an actor *did*. It is the wrong view of what has been *found about* a
subject, where the questions are different: who reported what, how bad, did
anyone check it, and does more than one tool agree.

`report()` answers those, from the subject's events and the alerts the
detector raised on them. It is a pure function -- no database, no clock -- so
the same history always gives the same page, like everything else here.

* **Grouped by emitter.** Each tool that reported on the subject, with the
  versions and runs it reported from and when, and its findings worst-first.
* **Corroboration.** A finding key reported by more than one tool is listed
  once, with every tool that reported it. Two scanners agreeing is worth more
  than either alone, and the page should say so rather than make the analyst
  notice.
* **Validated or not**, per finding, as the emitter said (see "Provenance, and
  who checked" in the README). Nothing is downgraded here either.
* **Analyst state** comes from the finding's alert: acknowledged, assigned.
  A finding with no alert is one the detector refused to raise; it is shown,
  marked, rather than hidden.
"""

from __future__ import annotations

from typing import Any

import envelope

SEVERITY_RANK = {s: i for i, s in enumerate(envelope.SEVERITIES)}


def _sev_key(item: dict[str, Any]) -> tuple[int, str]:
    return SEVERITY_RANK.get(item.get("severity"), 99), item.get("title") or ""


def report(actor_id: str, events: list[dict[str, Any]],
           alerts: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The findings report for one subject, or None if nothing was reported
    about it."""
    findings_events = [e for e in events if e.get("event_type") == envelope.EVENT_TYPE]
    if not findings_events:
        return None
    alert_by_event = {a.get("event_id"): a for a in alerts}

    subject: dict[str, Any] = {}
    emitters: dict[str, dict[str, Any]] = {}
    by_key: dict[str, dict[str, Any]] = {}
    totals = {s: 0 for s in envelope.SEVERITIES}

    for e in sorted(findings_events, key=lambda ev: (ev.get("timestamp") or "", ev.get("id") or 0)):
        meta = e.get("metadata") or {}
        source = meta.get("source") or {}
        finding = meta.get("finding") or {}
        subject = subject or dict(meta.get("subject") or {})
        tool = source.get("tool") or "unknown"

        em = emitters.setdefault(tool, {"tool": tool, "versions": [], "runs": [],
                                        "first_reported": e["timestamp"],
                                        "last_reported": e["timestamp"],
                                        "findings": [], "counts": {}})
        if source.get("version") and source["version"] not in em["versions"]:
            em["versions"].append(source["version"])
        if source.get("run_id") and source["run_id"] not in em["runs"]:
            em["runs"].append(source["run_id"])
        em["last_reported"] = e["timestamp"]

        alert = alert_by_event.get(e.get("id"))
        severity = (alert or {}).get("severity") or finding.get("severity")
        item = {
            "finding_id": finding.get("id"),
            "key": finding.get("key"),
            "title": finding.get("title"),
            "severity": severity,
            "validated": finding.get("validated"),
            "evidence": finding.get("evidence"),
            "mitre": finding.get("mitre"),
            "recommendation": finding.get("recommendation"),
            "reported_at": e["timestamp"],
            "version": source.get("version"),
            "run_id": source.get("run_id"),
            "alert_id": (alert or {}).get("id"),
            "acknowledged": bool((alert or {}).get("acknowledged")),
            "assigned_to": (alert or {}).get("assigned_to"),
            "raised": alert is not None,
        }
        em["findings"].append(item)
        if severity in totals:
            totals[severity] += 1
            em["counts"][severity] = em["counts"].get(severity, 0) + 1

        if finding.get("key"):
            k = by_key.setdefault(finding["key"], {"key": finding["key"], "tools": [],
                                                    "worst": severity, "titles": []})
            if tool not in k["tools"]:
                k["tools"].append(tool)
            if SEVERITY_RANK.get(severity, 99) < SEVERITY_RANK.get(k["worst"], 99):
                k["worst"] = severity
            if finding.get("title") and finding["title"] not in k["titles"]:
                k["titles"].append(finding["title"])

    for em in emitters.values():
        em["findings"].sort(key=_sev_key)
        em["worst"] = em["findings"][0]["severity"] if em["findings"] else None

    ordered = sorted(emitters.values(),
                     key=lambda m: (SEVERITY_RANK.get(m["worst"], 99), m["tool"]))
    corroborated = sorted((k for k in by_key.values() if len(k["tools"]) > 1),
                          key=lambda k: (SEVERITY_RANK.get(k["worst"], 99), k["key"]))
    all_items = [f for em in ordered for f in em["findings"]]
    worst = min((f["severity"] for f in all_items if f["severity"] in SEVERITY_RANK),
                key=lambda s: SEVERITY_RANK[s], default=None)
    return {
        "actor_id": actor_id,
        "subject": subject or {"kind": "actor", "id": actor_id},
        "worst": worst,
        "totals": totals,
        "finding_count": len(all_items),
        "unvalidated": sum(1 for f in all_items if f["validated"] is False),
        "open": sum(1 for f in all_items if f["raised"] and not f["acknowledged"]),
        "not_raised": sum(1 for f in all_items if not f["raised"]),
        "emitters": ordered,
        "corroborated": corroborated,
    }


def summary(actor_id: str, events: list[dict[str, Any]],
            alerts: list[dict[str, Any]]) -> dict[str, Any] | None:
    """One line for a list of subjects: the report without the findings."""
    r = report(actor_id, events, alerts)
    if r is None:
        return None
    return {k: r[k] for k in ("actor_id", "subject", "worst", "totals", "finding_count",
                              "unvalidated", "open")} | {
        "tools": [m["tool"] for m in r["emitters"]],
        "corroborated": len(r["corroborated"]),
        "last_reported": max(m["last_reported"] for m in r["emitters"]),
    }
