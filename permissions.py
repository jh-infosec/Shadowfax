"""
Agent permissions (v0.16).

Every detector before this one is an inference. Lateral movement is "more
distinct targets than usual", a rate anomaly is "faster than its own baseline",
exfiltration is "more bytes than a threshold". They are good at noticing that
something is unusual and they cannot say that something is *wrong*, because
nothing told them what the agent was for.

A permission profile is that missing statement. It declares, per agent, which
tools it was given and which targets it may touch, and Shadowfax raises
`permission_violation` the moment a recorded action falls outside it. That is
least privilege for autonomous agents, expressed as a policy object, and it is
the one kind of alert here that needs no baseline: an agent's first action can
breach its profile.

    "agent_permissions": {
      "unprofiled_agents": "alert",
      "profiles": {
        "recon-agent-*": {
          "description": "Authorised recon for engagement alpha",
          "allowed_tools":  ["nmap", "curl", "dig"],
          "denied_tools":   ["nc", "ncat", "bash"],
          "denied_targets": ["~/.ssh/*", "/etc/*"]
        }
      }
    }

Design decisions, each one a way this could otherwise fail open:

* **A missing grant means unrestricted; an empty one means nothing.** Leaving
  out `allowed_tools` says the profile does not constrain tools. Writing
  `"allowed_tools": []` says the agent was granted none. Those are different
  statements and are kept different.

* **Deny wins.** Something on both lists is denied. Denials are critical,
  because someone wrote that exact thing down as forbidden; acting outside an
  allow-list is high, because it may only mean the list is incomplete.

* **A deny matches any spelling; an allow must match the resolved one.** An
  agent reporting `/usr/bin/nc` is still running `nc`, so denials are checked
  against the tool's basename as well as its full name. A target written as
  `/repo/../etc/shadow` is *at* `/etc/shadow`, so it is resolved before an
  allow-list is consulted -- otherwise `/repo/*` would grant it -- while denials
  check both spellings. Neither trick can dodge a deny or ride an allow.

* **Unprovable is not granted.** A tool call that does not name its tool, or an
  event with an empty target, cannot be shown to be within an allow-list, so it
  is reported against one. Silence is not permission.

* **Deny lists are a backstop; the allow-list is the control.** A relative path
  such as `../../etc/passwd` cannot be resolved without knowing the agent's
  working directory, so no deny pattern written as `/etc/*` will catch it. An
  allow-list catches it without trying, because it was never granted. That is
  why the profiles in the sample policy lead with what is allowed.

* **Malformed policy is refused, not tolerated.** `"allowed_tools": "nmap"` is a
  string where a list belongs, and iterating it would quietly grant the tools
  "n", "m", "a" and "p". A misspelt key such as `alowed_tools` would leave the
  agent unrestricted with nobody the wiser. `validate()` rejects both at
  `PUT /policy`, before a rescan can make them true.

Like every detector, this is a pure function of (the actor's events, policy):
change a profile and a rescan recomputes every alert it affects, including
ones on events recorded before the profile existed.

Shadowfax still only *observes*. It reports that an agent stepped outside its
grant; it does not stand between the agent and the tool. A monitor that is also
the gate becomes the thing an attacker most wants to stop, and a monitor
that fails closed takes every agent down with it. Enforcement belongs in the
agent's runtime; `GET /actors/{id}/permissions` lets that runtime ask the same
question this module answers.
"""

from __future__ import annotations

import difflib
import fnmatch
import ntpath
import posixpath
import re
from dataclasses import dataclass
from typing import Any

POLICY_KEY = "agent_permissions"

GRANT_KEYS = ("allowed_tools", "denied_tools", "allowed_targets", "denied_targets")
PROFILE_KEYS = frozenset(GRANT_KEYS + ("description",))
SECTION_KEYS = frozenset({"enabled", "unprofiled_agents", "profiles"})
UNPROFILED_MODES = ("ignore", "alert")

# Only AI agents are expected to carry a profile. A person or a service account
# may be given one, and is then held to it, but is never reported for lacking
# one -- that would make every human in the estate an alert.
GOVERNED_ACTOR_TYPE = "ai_agent"

SEVERITY_DENIED = "critical"
SEVERITY_NOT_GRANTED = "high"
SEVERITY_UNDECLARED = "medium"

_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


@dataclass(frozen=True)
class Resolution:
    """Which profile governs an actor, and why."""
    name: str | None
    profile: dict[str, Any] | None
    matched_by: str | None  # "exact", "pattern", or None when undeclared


@dataclass(frozen=True)
class Breach:
    severity: str
    reason: str


# -- reading the policy --------------------------------------------------------

def section(policy: dict[str, Any]) -> dict[str, Any]:
    value = policy.get(POLICY_KEY)
    return value if isinstance(value, dict) else {}


def enabled(policy: dict[str, Any]) -> bool:
    """On whenever the section exists, unless it says `"enabled": false`.

    Writing profiles and forgetting a switch should not leave them silently
    inert, so the default is the one that does what the author evidently meant.
    """
    s = section(policy)
    return bool(s) and s.get("enabled", True) is not False


def alerts_on_unprofiled(policy: dict[str, Any]) -> bool:
    return enabled(policy) and section(policy).get("unprofiled_agents", "ignore") == "alert"


def _literal_length(pattern: str) -> int:
    return len(pattern) - pattern.count("*") - pattern.count("?")


def resolve(actor_id: str, policy: dict[str, Any]) -> Resolution:
    """The profile for `actor_id`: an exact key first, else the most specific
    matching pattern.

    "Most specific" is the pattern with the most literal characters, so
    `recon-agent-prod-*` beats `recon-agent-*` beats `*`. Ties break on the
    pattern text, which keeps the choice deterministic -- the same policy must
    always resolve an actor the same way, or a rescan could move an alert.
    """
    if not enabled(policy):
        return Resolution(None, None, None)
    profiles = section(policy).get("profiles") or {}
    if actor_id in profiles:
        return Resolution(actor_id, profiles[actor_id], "exact")
    matches = [p for p in profiles
               if any(c in p for c in "*?[") and fnmatch.fnmatchcase(actor_id, p)]
    if not matches:
        return Resolution(None, None, None)
    best = min(matches, key=lambda p: (-_literal_length(p), p))
    return Resolution(best, profiles[best], "pattern")


# -- matching ------------------------------------------------------------------

def _is_windows_path(target: str) -> bool:
    return "\\" in target or bool(_WINDOWS_DRIVE.match(target))


def resolved_target(target: str) -> str:
    """The location a target actually names, with `.` and `..` collapsed.

    URLs are left alone (collapsing `//` would break them), as are bare names
    like `finance_db` that are not paths at all.
    """
    if "://" in target:
        return target
    if _is_windows_path(target):
        return ntpath.normpath(target)
    if "/" in target:
        return posixpath.normpath(target)
    return target


def _target_matches(target: str, pattern: str) -> bool:
    # Windows paths are case-insensitive on the system they name, so they are
    # matched that way; everything else is matched exactly.
    if _is_windows_path(target) or _is_windows_path(pattern):
        return fnmatch.fnmatchcase(target.lower().replace("/", "\\"),
                                   pattern.lower().replace("/", "\\"))
    return fnmatch.fnmatchcase(target, pattern)


def _tool_spellings(tool: str) -> set[str]:
    """Every name a tool goes by: as reported, its basename, and without .exe."""
    t = tool.strip().lower()
    base = ntpath.basename(posixpath.basename(t)) or t
    names = {t, base}
    if base.endswith(".exe"):
        names.add(base[:-4])
    return names


def _tool_matches(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p.strip().lower()) for p in patterns)


def _show(target: str, where: str) -> str:
    """A target as reported, plus where it really points when that differs --
    the analyst needs to see the traversal, not just its destination."""
    return f"'{target}'" if where == target else f"'{target}' (resolves to '{where}')"


# -- the check -----------------------------------------------------------------

def evaluate(event: dict[str, Any], profile: dict[str, Any],
             check_tool: bool = True, check_target: bool = True) -> list[Breach]:
    """Every way one event falls outside one profile. Empty means within it."""
    breaches: list[Breach] = []
    meta = event.get("metadata") or {}

    if check_tool and event.get("event_type") == "tool_call":
        raw = meta.get("tool")
        tool = str(raw).strip() if raw not in (None, "") else ""
        denied = profile.get("denied_tools") or []
        allowed = profile.get("allowed_tools")
        if tool and any(_tool_matches(n, denied) for n in _tool_spellings(tool)):
            breaches.append(Breach(SEVERITY_DENIED, f"tool '{tool}' is explicitly denied"))
        elif allowed is not None:
            if not tool:
                breaches.append(Breach(SEVERITY_NOT_GRANTED,
                    "the tool call did not name its tool, so it cannot be shown "
                    "to be within the granted tools"))
            elif not _tool_matches(tool.lower(), allowed):
                breaches.append(Breach(SEVERITY_NOT_GRANTED,
                    f"tool '{tool}' is not among the granted tools"))

    # A completion claim is a report about work, not an access, so it has no
    # target to authorise -- the same exemption lateral movement makes.
    if check_target and event.get("event_type") != "completion_claim":
        target = str(event.get("target") or "")
        where = resolved_target(target) if target else ""
        denied = profile.get("denied_targets") or []
        allowed = profile.get("allowed_targets")
        hit = next((p for p in denied
                    if target and (_target_matches(target, p) or _target_matches(where, p))),
                   None)
        if hit is not None:
            breaches.append(Breach(SEVERITY_DENIED,
                f"target {_show(target, where)} is explicitly denied (matches '{hit}')"))
        elif allowed is not None:
            if not target:
                breaches.append(Breach(SEVERITY_NOT_GRANTED,
                    "the event named no target, so it cannot be shown to be "
                    "within the granted targets"))
            elif not any(_target_matches(where, p) for p in allowed):
                breaches.append(Breach(SEVERITY_NOT_GRANTED,
                    f"target {_show(target, where)} is not among the granted targets"))

    return breaches


def worst(breaches: list[Breach]) -> str:
    return min((b.severity for b in breaches), key=lambda s: _RANK.get(s, 9))


def violation_message(resolution: Resolution, breaches: list[Breach]) -> str:
    return (f"outside declared permissions (profile '{resolution.name}'): "
            + "; ".join(b.reason for b in breaches))


def undeclared_message(actor_id: str) -> str:
    return (f"AI agent '{actor_id}' is acting with no declared permission profile, "
            f"so nothing says what it is for")


# -- describing it to people ---------------------------------------------------

def describe(actor_id: str, policy: dict[str, Any]) -> dict[str, Any]:
    """The governing profile for an actor, shaped for the API and dashboard."""
    r = resolve(actor_id, policy)
    profile = r.profile or {}
    return {
        "enabled": enabled(policy),
        "unprofiled_agents": section(policy).get("unprofiled_agents", "ignore"),
        "profile": r.name,
        "matched_by": r.matched_by,
        "description": profile.get("description"),
        "grants": {k: profile.get(k) for k in GRANT_KEYS} if r.profile is not None else None,
    }


def check(actor_id: str, policy: dict[str, Any], tool: str | None = None,
          target: str | None = None, actor_type: str = GOVERNED_ACTOR_TYPE) -> dict[str, Any]:
    """Would this action be reported? The detector's own answer, asked ahead.

    Only the parts asked about are judged: asking about a tool alone does not
    fail for want of a target.
    """
    r = resolve(actor_id, policy)
    if r.profile is None:
        undeclared = actor_type == GOVERNED_ACTOR_TYPE and alerts_on_unprofiled(policy)
        return {
            "within_permissions": not undeclared,
            "severity": SEVERITY_UNDECLARED if undeclared else None,
            "category": "undeclared_agent" if undeclared else None,
            "reasons": [undeclared_message(actor_id)] if undeclared else [],
        }
    event = {"event_type": "tool_call" if tool is not None else "access",
             "target": target or "", "metadata": {"tool": tool} if tool is not None else {}}
    breaches = evaluate(event, r.profile, check_tool=tool is not None,
                        check_target=target is not None)
    return {
        "within_permissions": not breaches,
        "severity": worst(breaches) if breaches else None,
        "category": "permission_violation" if breaches else None,
        "reasons": [b.reason for b in breaches],
    }


# -- refusing malformed policy -------------------------------------------------

def _suggest(key: str, options) -> str:
    close = difflib.get_close_matches(key, sorted(options), n=1)
    return f" (did you mean '{close[0]}'?)" if close else ""


def validate(policy: dict[str, Any]) -> list[str]:
    """Problems with the `agent_permissions` section, as sentences. Empty is valid.

    Every check here is one where tolerating the mistake would widen a grant or
    switch a profile off without anyone being told.
    """
    if POLICY_KEY not in policy:
        return []
    s = policy[POLICY_KEY]
    where = POLICY_KEY
    if not isinstance(s, dict):
        return [f"{where} must be an object"]

    errors: list[str] = []
    for key in s:
        if key not in SECTION_KEYS:
            errors.append(f"{where}: unknown key '{key}'{_suggest(key, SECTION_KEYS)}")
    if "enabled" in s and not isinstance(s["enabled"], bool):
        errors.append(f"{where}.enabled must be true or false")
    mode = s.get("unprofiled_agents", "ignore")
    if mode not in UNPROFILED_MODES:
        errors.append(f"{where}.unprofiled_agents must be one of "
                      f"{', '.join(UNPROFILED_MODES)} (got {mode!r})")

    profiles = s.get("profiles", {})
    if not isinstance(profiles, dict):
        errors.append(f"{where}.profiles must be an object keyed by actor id or pattern")
        return errors

    for name, profile in profiles.items():
        at = f"{where}.profiles[{name!r}]"
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{where}.profiles: a profile key must be a non-empty actor id or pattern")
            continue
        if not isinstance(profile, dict):
            errors.append(f"{at} must be an object")
            continue
        for key in profile:
            if key not in PROFILE_KEYS:
                errors.append(f"{at}: unknown key '{key}'{_suggest(key, PROFILE_KEYS)} "
                              f"-- an unrecognised grant would leave the agent unrestricted")
        if "description" in profile and not isinstance(profile["description"], str):
            errors.append(f"{at}.description must be text")
        for key in GRANT_KEYS:
            if key not in profile:
                continue
            value = profile[key]
            if isinstance(value, str):
                errors.append(f"{at}.{key} must be a list, not the string {value!r} "
                              f"-- write [{value!r}]")
            elif not isinstance(value, list):
                errors.append(f"{at}.{key} must be a list of names or patterns")
            elif not all(isinstance(v, str) and v.strip() for v in value):
                errors.append(f"{at}.{key} may contain only non-empty text")
    return errors
