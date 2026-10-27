"""
A first draft of an agent's permission profile (v0.29).

Writing a profile by hand means knowing every tool an agent needs. The obvious
shortcut -- copy the agent's capability manifest into its profile -- is the one
this module will not take. A profile written from the configuration grants
whatever the agent was given, and "was it given more than it should have been?"
is exactly the question `excess_capability` exists to ask (v0.18). Copying the
manifest would answer it with "no" by definition.

So the draft is built from what the agent **did**, not from what it was given:

* **allowed_tools** -- the tools it has actually called, less the ones on the
  short list of tools that are dangerous to grant by default (shells, netcat,
  PowerShell...). Least privilege from observed need.
* **denied_tools** -- those dangerous tools, wherever the agent has them: in
  its manifest or in its calls. A tool it used that lands here is shown as a
  decision for the analyst, not quietly granted or quietly forbidden.
* **denied_targets** -- the usual secrets (`~/.ssh/*`, `~/.aws/*`, `/etc/*`,
  `*.pem`). No `allowed_targets`: targets vary too much to guess well, and a
  wrong guess either breaks the agent or grants too much. The note says so.
* Configured tools it has **never called** are not granted. Once the profile is
  saved they become `excess_capability` alerts -- which is the point: they are
  candidates to remove from the agent's configuration.

Nothing is saved here. The draft is read-only; an analyst reviews it in the
policy editor and saves it through `PUT /policy`, where `permissions.validate`
checks it like any other profile. And the draft says what it would have done:
every past event it would flag, so nobody saves a profile that would light up
the agent's whole history without knowing.

Pure: events and policy in, a dict out.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

import manifest
import permissions

# Tools that hand an agent a general-purpose shell or a raw socket. Granting
# one is a decision someone should make on purpose, never a default.
RISKY_TOOLS = ("bash", "sh", "zsh", "dash", "cmd", "powershell", "pwsh",
               "nc", "ncat", "netcat", "socat", "telnet")

DEFAULT_DENIED_TARGETS = ["~/.ssh/*", "~/.aws/*", "/etc/*", "*.pem"]

_FAMILY = re.compile(r"^(?P<stem>.+?[-_])\d+$")


def _risky(tool: str) -> bool:
    return any(n in RISKY_TOOLS for n in permissions._tool_spellings(tool))


def family_pattern(actor_id: str) -> str | None:
    """`recon-agent-3` -> `recon-agent-*`: the profile key for every numbered
    instance of the same agent. None when the id has no instance number."""
    m = _FAMILY.match(actor_id)
    return f"{m.group('stem')}*" if m else None


def draft(actor_id: str, events: list[dict[str, Any]],
          policy: dict[str, Any]) -> dict[str, Any] | None:
    """A draft profile for `actor_id`, with the evidence behind it, or None if
    the agent has neither called a tool nor declared a manifest."""
    calls = [e for e in events if e.get("event_type") == "tool_call"]
    manifests = [e for e in events
                 if e.get("event_type") == manifest.EVENT_TYPE and manifest.tools_of(e) is not None]
    if not calls and not manifests:
        return None

    used: Counter[str] = Counter()
    unnamed = 0
    for e in calls:
        tool = str((e.get("metadata") or {}).get("tool") or "").strip().lower()
        if tool:
            used[tool] += 1
        else:
            unnamed += 1
    configured = [t.lower() for t in (manifest.tools_of(manifests[-1]) if manifests else [])]

    allowed = sorted(t for t in used if not _risky(t))
    denied = sorted({t for t in list(used) + configured if _risky(t)})
    risky_used = sorted(t for t in used if _risky(t))
    never_called = sorted(t for t in configured
                          if not any(manifest.is_listed(u, [t]) or u == t for u in used))

    profile: dict[str, Any] = {
        "description": f"Drafted from {actor_id}'s observed activity "
                       f"({len(calls)} tool call(s)); review before saving.",
        "allowed_tools": allowed,
        "denied_tools": denied,
        "denied_targets": list(DEFAULT_DENIED_TARGETS),
    }

    # What the draft would have said about the agent's own history.
    would_flag: list[dict[str, Any]] = []
    for e in events:
        if e.get("event_type") in ("finding", manifest.EVENT_TYPE):
            continue
        for b in permissions.evaluate(e, profile):
            would_flag.append({"event_id": e.get("id"), "timestamp": e.get("timestamp"),
                               "severity": b.severity, "reason": b.reason})

    resolution = permissions.resolve(actor_id, policy)
    family = family_pattern(actor_id)
    notes = [
        "Built from the tools this agent called, not from its configuration: "
        "configured tools it never called are not granted.",
        "No allowed_targets are drafted. Add them by hand if the agent should be "
        "confined to particular targets -- an allow-list is the stronger control.",
    ]
    if risky_used:
        notes.append(f"It used {', '.join(risky_used)}, which the draft denies. "
                     "If it genuinely needs one, move it to allowed_tools on purpose.")
    if unnamed:
        notes.append(f"{unnamed} tool call(s) did not name a tool; under any allow-list "
                     "they are reported, because they cannot be shown to be granted.")
    if never_called:
        notes.append(f"Configured but never called: {', '.join(never_called)}. Once this "
                     "profile is saved they are reported as excess_capability -- "
                     "candidates to remove from the agent's configuration.")
    if family:
        notes.append(f"Saved under '{family}' it would govern every numbered instance; "
                     f"under '{actor_id}' only this one.")
    if resolution.profile is not None:
        notes.append(f"This agent is already governed by '{resolution.name}'. Saving the "
                     f"draft under the same key replaces it.")

    return {
        "actor_id": actor_id,
        "keys": [k for k in (actor_id, family) if k],
        "existing_profile": resolution.name if resolution.profile is not None else None,
        "profile": profile,
        "evidence": {
            "tool_calls": len(calls),
            "used": [{"tool": t, "calls": n, "risky": _risky(t)}
                     for t, n in sorted(used.items(), key=lambda kv: (-kv[1], kv[0]))],
            "unnamed_calls": unnamed,
            "configured": configured,
            "never_called": never_called,
            "manifests_seen": len(manifests),
        },
        "would_flag": would_flag,
        "notes": notes,
    }
