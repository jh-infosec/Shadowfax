"""
Shadowfax detection engine.

Evaluates one actor's event history against the active policy and
returns any alerts that should be raised.
"""

from __future__ import annotations
import hashlib
import ipaddress
from collections import deque
from datetime import datetime, timedelta, time as dtime
from typing import Any
from urllib.parse import urlparse

import attack
import envelope

TOOL_NAME = "shadowfax"

# Every category this engine can raise. Ingest consults it so an external
# finding cannot claim one: an alert reading `destructive_action` must mean
# Shadowfax's own detector found it, not that somebody else said so. Kept here,
# beside the detectors that raise them, because a list of categories maintained
# anywhere else is a list that goes stale.
NATIVE_CATEGORIES: frozenset[str] = frozenset({
    "allowlist_violation", "blocked_target_access", "brute_force_auth",
    "canary_triggered", "capability_resurrection", "completion_fraud",
    "destructive_action", "dormant_reappearance", "exfiltration_volume",
    "impossible_travel", "lateral_movement", "off_hours_access",
    "out_of_scope_action", "privilege_escalation", "rate_anomaly",
    "token_spend_anomaly",
})


def external_alert_identity(tool: str, finding_id: str) -> str:
    """The alert id for an ingested finding (v0.11).

    Derived from the emitter's deterministic finding id rather than from the
    event row, so re-ingesting the same finding lands on the same alert and
    carries its acknowledgement, assignment and notes with it -- the property
    `findings-envelope.md` says the id rule exists to provide.

    The emitter's id is *derived from*, never used as, the alert id. It is a
    value from outside Shadowfax, and an emitter that sent an id colliding with
    a native alert's would otherwise inherit that alert's analyst state. Hashing
    it under a fixed `external` namespace makes such a collision impossible by
    construction.
    """
    raw = f"{TOOL_NAME}|external|{tool}|{finding_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def alert_identity(actor_id: str, category: str, event_id: int, discriminator: str = "") -> str:
    """Deterministic alert id: the same alert recomputed from the same input
    yields the same id, so per-alert analyst state survives a rescan.

    This mirrors the findings-envelope id rule
    (sha256(tool | subject | key | discriminator)). Here the subject is the
    actor, the *key* is the machine-stable ``category``, and the discriminator
    is the event that produced the alert. ``message`` is deliberately excluded:
    it is the human-readable sentence, and rewording it must not change what a
    dashboard has been counting or reset an acknowledgement. If a detector ever
    needs to raise two alerts of one category on a single event, it passes an
    extra ``discriminator`` to keep them distinct.
    """
    raw = f"{TOOL_NAME}|{actor_id}|{category}|{event_id}|{discriminator}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _external_alert(event: dict, meta: dict) -> dict | None:
    """Turn one ingested finding back into an alert (v0.11).

    The finding's `key` becomes the alert category, because the envelope says a
    key is what a consumer groups, filters and counts on, while the `title` is
    the sentence a person reads -- rewording a title must not change what a
    dashboard has been counting.

    An unvalidated finding is marked as such in the message rather than being
    downgraded or dropped. The envelope is explicit that a consumer may treat
    unvalidated findings differently but may not treat them as absent, and
    quietly lowering someone else's severity would be a hidden policy. Shadowfax
    says who claimed it and whether they checked, and leaves the judgement to
    the analyst.
    """
    finding = meta.get("finding")
    source = meta.get("source") or {}
    if not isinstance(finding, dict) or not finding.get("key"):
        # A finding event without a finding is a storage anomaly, not an alert.
        return None

    tool = source.get("tool", "unknown")
    message = f"{finding.get('title', '').strip()} — reported by {tool}"
    if finding.get("validated") is False:
        message += " (unvalidated: asserted by the subject, not verified)"

    alert = _mk_alert(event, finding["severity"], finding["key"], message,
                      technique_ids=envelope.techniques_for(finding))
    # Replace the event-derived id with one keyed on the emitter's finding id,
    # so analyst state follows the finding rather than the row it landed in.
    alert["id"] = external_alert_identity(tool, finding.get("id", ""))
    alert["source_tool"] = tool
    alert["validated"] = bool(finding.get("validated"))
    alert["evidence"] = finding.get("evidence")
    return alert


def _mk_alert(event: dict, severity: str, category: str, message: str,
              discriminator: str = "", technique_ids: list[str] | None = None) -> dict:
    # ATT&CK techniques: use the ids the detector supplied (destructive rules
    # carry their own), otherwise fall back to the category's mapping. Ids are
    # resolved against the shared registry; unknown ones are dropped.
    techniques = (attack.enrich(technique_ids) if technique_ids is not None
                  else attack.for_category(category))
    return {
        "id": alert_identity(event["actor_id"], category, event["id"], discriminator),
        "event_id": event["id"],
        "actor_id": event["actor_id"],
        "actor_type": event["actor_type"],
        "timestamp": event["timestamp"],
        "severity": severity,
        "category": category,
        "message": message,
        "target": event["target"],
        "attack": techniques,
    }


# Agent-trace helpers (v0.4.5)
#
# An AI agent's activity arrives as event_type == "tool_call", with the call's
# shape in metadata: tool, arguments, exit_status, duration_ms, and optionally a
# network destination (host/port/url). These helpers keep the two tool-call
# detectors below small and pure.

def _stringify_args(args: Any) -> str:
    if isinstance(args, (list, tuple)):
        return " ".join(str(a) for a in args)
    if isinstance(args, dict):
        return " ".join(f"{k} {v}" for k, v in args.items())
    return str(args) if args is not None else ""


def _tool_call_text(event: dict, meta: dict) -> str:
    """Lower-cased haystack of the tool, its arguments and the target, for
    substring matching against destructive-action patterns."""
    return " ".join([
        str(meta.get("tool", "")),
        _stringify_args(meta.get("arguments", "")),
        str(event.get("target", "")),
    ]).lower()


def _first_match(haystack: str, patterns: list[str]) -> str | None:
    for p in patterns:
        if p and p.lower() in haystack:
            return p
    return None


def _tool_call_destination(event: dict, meta: dict) -> tuple[str | None, int | None]:
    """A tool call's network destination as (host, port), or (None, None) when
    the call has no host/IP/URL to check against the engagement scope."""
    host = meta.get("host")
    port = meta.get("port")
    url = meta.get("url")
    if url and not host:
        parsed = urlparse(url if "://" in url else "//" + url)
        host = parsed.hostname
        port = port or parsed.port
    if not host:
        target = str(event.get("target", ""))
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname
            port = port or parsed.port
        elif (
            "/" not in target and "\\" not in target and " " not in target
            and not target.startswith("~") and "." in target
        ):
            # A bare host or host:port (a dotted domain or an IP). Filesystem
            # paths and symbolic targets are deliberately excluded, so only real
            # network destinations are scope-checked.
            parsed = urlparse("//" + target)
            host = parsed.hostname
            port = port or parsed.port
    return (host.lower() if isinstance(host, str) else None,
            int(port) if isinstance(port, int) else None)


def _scope_violation(event: dict, meta: dict, scope: dict) -> str | None:
    """Message describing how a tool call left the engagement scope, or None."""
    host, port = _tool_call_destination(event, meta)
    if not host:
        return None

    allowed_domains = scope.get("allowed_domains", [])
    allowed_ranges = scope.get("allowed_ip_ranges", [])
    allowed_ports = scope.get("allowed_ports", [])

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    in_scope = False
    if ip is not None:
        for r in allowed_ranges:
            try:
                if ip in ipaddress.ip_network(r, strict=False):
                    in_scope = True
                    break
            except ValueError:
                continue
    else:
        for d in allowed_domains:
            d = d.lower().lstrip(".")
            if host == d or host.endswith("." + d):
                in_scope = True
                break

    if not in_scope:
        return f"tool call reached '{host}', outside the engagement scope"
    if port is not None and allowed_ports and port not in allowed_ports:
        return f"tool call reached '{host}:{port}', a port outside the engagement scope"
    return None


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
    # Agent-trace running totals, for completion-fraud (v0.5).
    tool_call_targets: set[str] = set()
    tool_call_count: int = 0
    # Token-spend window state, same shape as the rate-anomaly detector.
    token_window: deque[tuple[datetime, int]] = deque()
    token_history: list[int] = []

    for e in events:
        ts = datetime.fromisoformat(e["timestamp"])
        meta = e.get("metadata") or {}

        # Ingested findings (v0.11).
        #
        # A finding arrived already adjudicated by another tool, so Shadowfax
        # does not re-judge it -- it carries the emitter's severity, key and
        # evidence through, and stops. The `continue` is the point: running the
        # native heuristics over a finding event would measure the *emitter's*
        # cadence rather than the subject's behaviour, so a tool reporting forty
        # findings at once would trip rate_anomaly, and a scanner that runs
        # nightly would trip dormant_reappearance every single night. Neither
        # tells an analyst anything true.
        if e["event_type"] == envelope.EVENT_TYPE:
            found = _external_alert(e, meta)
            if found:
                alerts.append(found)
            continue

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
        #
        # Exempt actors whose silence is their normal state. A user account that
        # wakes after three idle weeks is worth a look; an event-driven endpoint
        # that only emits when something happens to it is idle by definition, and
        # alerting on that would train an analyst to ignore the category. The
        # exemption lives in the policy rather than in a hardcoded name here, so
        # detectors stay a pure function of (events, policy).
        if last_seen is not None and e["actor_id"] not in policy.get("dormancy_exempt_actors", []):
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

        # lateral movement. A completion_claim is a report, not a target
        # access, so it does not count toward distinct targets touched.
        if e["event_type"] != "completion_claim":
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

        # agent tool calls: destructive actions and engagement-scope breaches
        if e["event_type"] == "tool_call":
            haystack = _tool_call_text(e, meta)
            for rule in policy.get("destructive_action_rules", []):
                match = _first_match(haystack, rule.get("patterns", []))
                if match:
                    alerts.append(_mk_alert(e, rule.get("severity", "high"), "destructive_action",
                        f"{rule.get('label', 'destructive action')} (tool call matched '{match}')",
                        technique_ids=rule.get("attack", [])))
                    break  # one destructive-action alert per tool call

            scope = policy.get("engagement_scope")
            if scope and scope.get("enabled"):
                violation = _scope_violation(e, meta, scope)
                if violation:
                    alerts.append(_mk_alert(e, scope.get("severity", "high"),
                        "out_of_scope_action", violation))

            # running trace totals for the completion-fraud check below
            tool_call_targets.add(e["target"])
            tool_call_count += 1

        # completion fraud: the agent's claim vs what its trace actually shows.
        # A counting problem -- claimed coverage against observed coverage.
        if e["event_type"] == "completion_claim":
            claimed = meta.get("claimed")
            metric = meta.get("metric", "distinct_targets")
            if isinstance(claimed, (int, float)) and claimed > 0:
                actual = tool_call_count if metric == "tool_calls" else len(tool_call_targets)
                tolerance = policy.get("completion_claim_tolerance", 0.9)
                if actual < claimed * tolerance:
                    sev = "critical" if actual < claimed * 0.5 else "high"
                    alerts.append(_mk_alert(e, sev, "completion_fraud",
                        f"agent claimed {int(claimed)} {metric.replace('_', ' ')} "
                        f"but the trace shows {actual}"))

        # token-spend anomaly: spend per actor against the actor's own baseline,
        # the same window shape as the rate anomaly below.
        tokens = int(meta.get("tokens", 0) or 0)
        if tokens > 0:
            token_window.append((ts, tokens))
            twindow = timedelta(minutes=policy.get("token_spend_window_minutes", 5))
            while token_window and ts - token_window[0][0] > twindow:
                token_window.popleft()
            spend = sum(t for _, t in token_window)
            tmin_baseline = policy.get("token_spend_min_baseline", 4)
            if len(token_history) >= tmin_baseline:
                baseline = sum(token_history) / len(token_history)
                multiplier = policy.get("token_spend_multiplier", 4.0)
                if baseline > 0 and spend > baseline * multiplier:
                    alerts.append(_mk_alert(e, "medium", "token_spend_anomaly",
                        f"{spend:,} tokens in {policy.get('token_spend_window_minutes', 5)} min "
                        f"vs baseline avg {baseline:,.0f}"))
            token_history.append(spend)
            if len(token_history) > 50:
                token_history.pop(0)

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
