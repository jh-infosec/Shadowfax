"""
Shadowfax detection engine.

Evaluates one actor's event history against the active policy and
returns any alerts that should be raised.
"""

from __future__ import annotations
from collections import deque
from datetime import datetime, timedelta, time as dtime
from typing import Any


def _mk_alert(event: dict, severity: str, category: str, message: str) -> dict:
    return {
        "event_id": event["id"],
        "actor_id": event["actor_id"],
        "actor_type": event["actor_type"],
        "timestamp": event["timestamp"],
        "severity": severity,
        "category": category,
        "message": message,
        "target": event["target"],
    }


def run_for_actor(events: list[dict[str, Any]], policy: dict[str, Any]) -> list[dict[str, Any]]:
    """events must already be sorted ascending by timestamp and belong to one actor."""
    alerts: list[dict[str, Any]] = []

    last_seen: datetime | None = None
    ever_blocked: set[str] = set()
    touched_targets: set[str] = set()
    auth_failures: deque[datetime] = deque()
    auth_locations: deque[tuple[datetime, str]] = deque()
    recent_targets: deque[tuple[datetime, str]] = deque()
    recent_privilege: str | None = None
    recent_events: deque[datetime] = deque()
    rate_history: list[int] = []

    for e in events:
        ts = datetime.fromisoformat(e["timestamp"])
        meta = e.get("metadata") or {}

        # allowlist
        task = e.get("task")
        if task:
            allowed = policy.get("allowed_targets_by_task", {}).get(task)
            if allowed is not None and e["target"] not in allowed:
                alerts.append(_mk_alert(e, "high", "allowlist_violation",
                    f"target not in allowlist for task '{task}' (allowed: {allowed})"))

        # canary / blocklist
        if e["target"] in policy.get("canary_tokens", []):
            alerts.append(_mk_alert(e, "critical", "canary_triggered",
                "actor touched a canary/honeytoken resource"))
        if e["target"] in policy.get("blocked_targets", []):
            alerts.append(_mk_alert(e, "critical", "blocked_target_access",
                "actor accessed a target explicitly on the blocklist"))

        # dormant reappearance
        if last_seen is not None:
            gap = ts - last_seen
            if gap >= timedelta(minutes=policy.get("dormancy_threshold_minutes", 120)):
                note = " (target previously touched -- possible foothold rebuild)" if e["target"] in touched_targets else ""
                alerts.append(_mk_alert(e, "medium", "dormant_reappearance",
                    f"actor resumed activity after {gap} idle{note}"))

        # capability resurrection
        if meta.get("previously_blocked") or e["target"] in ever_blocked:
            ever_blocked.add(e["target"])
            alerts.append(_mk_alert(e, "critical", "capability_resurrection",
                "actor re-established access previously blocked, possibly via a new mechanism"))
        elif meta.get("mark_blocked"):
            ever_blocked.add(e["target"])

        # brute force
        if e["event_type"] == "auth_failure":
            auth_failures.append(ts)
            window = timedelta(minutes=policy.get("brute_force_window_minutes", 10))
            while auth_failures and ts - auth_failures[0] > window:
                auth_failures.popleft()
            if len(auth_failures) >= policy.get("brute_force_max_failures", 5):
                alerts.append(_mk_alert(e, "high", "brute_force_auth",
                    f"{len(auth_failures)} failed auth attempts within "
                    f"{policy.get('brute_force_window_minutes', 10)} min"))

        # impossible travel
        if e["event_type"] == "auth_success" and meta.get("geo"):
            auth_locations.append((ts, meta["geo"]))
            while len(auth_locations) > 5:
                auth_locations.popleft()
            if len(auth_locations) >= 2:
                prev_time, prev_loc = auth_locations[-2]
                if prev_loc != meta["geo"] and (ts - prev_time) < timedelta(hours=2):
                    alerts.append(_mk_alert(e, "high", "impossible_travel",
                        f"auth from '{meta['geo']}' only {ts - prev_time} after auth from '{prev_loc}'"))

        # privilege escalation
        if e["event_type"] == "privilege_change":
            new_level = meta.get("new_level")
            approved = meta.get("approved", False)
            if new_level and recent_privilege and new_level != recent_privilege and not approved:
                alerts.append(_mk_alert(e, "critical", "privilege_escalation",
                    f"privilege changed '{recent_privilege}' -> '{new_level}' without an approval marker"))
            elif new_level and not recent_privilege and meta.get("elevated") and not approved:
                alerts.append(_mk_alert(e, "high", "privilege_escalation",
                    f"actor granted elevated privilege '{new_level}' without an approval marker"))
            if new_level:
                recent_privilege = new_level

        # lateral movement
        recent_targets.append((ts, e["target"]))
        window = timedelta(minutes=policy.get("lateral_movement_window_minutes", 15))
        while recent_targets and ts - recent_targets[0][0] > window:
            recent_targets.popleft()
        distinct = {t for _, t in recent_targets}
        if len(distinct) >= policy.get("lateral_movement_max_distinct_targets", 6):
            alerts.append(_mk_alert(e, "high", "lateral_movement",
                f"{len(distinct)} distinct targets touched within "
                f"{policy.get('lateral_movement_window_minutes', 15)} min"))

        # off hours
        if e["target"] in policy.get("off_hours_sensitive_targets", []):
            start = dtime(hour=policy.get("business_hours_start", 7))
            end = dtime(hour=policy.get("business_hours_end", 20))
            if not (start <= ts.time() <= end):
                alerts.append(_mk_alert(e, "medium", "off_hours_access",
                    f"sensitive target accessed at {ts.time().isoformat()}, "
                    f"outside business hours {start}-{end}"))

        # exfiltration
        if e["event_type"] == "data_transfer":
            size = meta.get("bytes_transferred", 0)
            external = e["target"] in policy.get("exfil_external_targets", [])
            threshold = policy.get("exfil_bytes_threshold", 500_000_000)
            if size >= threshold:
                sev = "critical" if external else "high"
                dest = "external" if external else "internal"
                alerts.append(_mk_alert(e, sev, "exfiltration_volume",
                    f"{size:,} bytes transferred to {dest} destination (threshold {threshold:,})"))

        # rate anomaly
        recent_events.append(ts)
        rwindow = timedelta(minutes=policy.get("rate_window_minutes", 5))
        while recent_events and ts - recent_events[0] > rwindow:
            recent_events.popleft()
        count = len(recent_events)
        min_baseline = policy.get("rate_anomaly_min_baseline_events", 5)
        if len(rate_history) >= min_baseline:
            baseline = sum(rate_history) / len(rate_history)
            multiplier = policy.get("rate_anomaly_multiplier", 4.0)
            if baseline > 0 and count > baseline * multiplier:
                alerts.append(_mk_alert(e, "medium", "rate_anomaly",
                    f"{count} events in {policy.get('rate_window_minutes', 5)} min vs baseline avg {baseline:.1f}"))
        rate_history.append(count)
        if len(rate_history) > 50:
            rate_history.pop(0)

        last_seen = ts
        touched_targets.add(e["target"])

    return alerts
