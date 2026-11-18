"""
Muting false positives (v0.42).

Every detector has cases where it's right about the event and wrong about the
situation: the backup agent that copies a lot of data every night, the
scanner your red team runs on purpose. Until now the only answer was to change
the policy, which changes it for everyone, or to acknowledge the same alert
again every day. A suppression rule says "alerts of this kind, from these
agents, on these targets, aren't worth anyone's time, for this reason, until
this date."

What it is and isn't:

* **A view, not an edit.** Detection doesn't change. Alerts are still raised,
  stored and kept, with the same ids; a rule only decides whether they show in
  the queue, the counts, incidents, the digest, risk scores, desktop
  notifications and forwarding. `GET /alerts?suppressed=include` shows them
  all, each with the rule that hid it, and the actor timeline always does.
* **Always for a reason, never forever.** A rule needs a reason someone else
  can read, and expires after at most 90 days, when its alerts come back on
  their own. Rules can be ended early, and an ended rule is kept.
* **On the record.** Creating or ending one is written into the evidence ledger
  under `shadowfax-case`, with who did it and why.
* **Narrow by construction.** A rule names one category. It can't match every
  agent and every target at once (that's switching a detector off: change the
  policy instead), it never applies to Shadowfax's own accounts, and a canary
  can't be muted at all, since nothing touches one for a good reason.

Patterns use `*` for "anything" and nothing else, so `backup-agent-*` or
`*.internal`. Matching ignores case.
"""

from __future__ import annotations

import re
from typing import Any

DEFAULT_DAYS = 30
MAX_DAYS = 90
MIN_REASON = 10
MAX_PATTERN = 200
PLATFORM_PREFIX = "shadowfax-"
CHANGE_EVENT = "suppression_change"

# Categories that can't be muted, and why. Alerts about Shadowfax's own
# accounts are excluded by actor instead (PLATFORM_PREFIX), whatever the
# category.
NEVER = {
    "canary_triggered": "a canary is a decoy nothing should ever touch, so there's no false positive to mute",
}

_CATEGORY = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,63}$")


def like(pattern: str) -> str:
    """A `*` pattern as a SQL LIKE pattern (with ESCAPE '\\'), lower case."""
    out = []
    for ch in pattern.lower():
        if ch == "*":
            out.append("%")
        elif ch in "\\%_":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def matches(pattern: str, value: str) -> bool:
    """The same match in Python: what the database does with like()."""
    rx = ".*".join(re.escape(part) for part in pattern.lower().split("*"))
    return re.fullmatch(rx, (value or "").lower(), re.DOTALL) is not None


def _everything(pattern: str) -> bool:
    return pattern.strip("*") == ""


def validate(category: str, actor: str, target: str, reason: str, days: int,
             known_categories: set[str]) -> list[str]:
    """Problems with a proposed rule, in words; empty if it's fine."""
    problems = []
    category = (category or "").strip()
    actor = (actor or "").strip()
    target = (target or "").strip()
    if not _CATEGORY.match(category):
        problems.append("name the alert category the rule is for, e.g. exfiltration_volume")
    elif category in NEVER:
        problems.append(f"{category} can't be muted: {NEVER[category]}")
    elif category not in known_categories:
        problems.append(f"no alerts have the category {category!r}, and it isn't one Shadowfax raises")
    for label, value in (("agent", actor), ("target", target)):
        if not value:
            problems.append(f"give an {label} pattern ('*' for any)" if label == "agent"
                            else "give a target pattern ('*' for any)")
        elif len(value) > MAX_PATTERN:
            problems.append(f"the {label} pattern is over {MAX_PATTERN} characters")
    if actor and target and _everything(actor) and _everything(target):
        problems.append("a rule for every agent and every target switches the detector off; "
                        "narrow it to some agents or some targets, or change the policy instead")
    if actor.lower().startswith(PLATFORM_PREFIX):
        problems.append("alerts about Shadowfax's own accounts can't be muted")
    if len((reason or "").strip()) < MIN_REASON:
        problems.append(f"say why, in at least {MIN_REASON} characters, so whoever reads it later knows")
    if not isinstance(days, int) or not 1 <= days <= MAX_DAYS:
        problems.append(f"a rule lasts between 1 and {MAX_DAYS} days")
    return problems


def describe(rule: dict[str, Any]) -> str:
    """One line for a rule, as the ledger and the dashboard put it."""
    where = []
    if rule["actor"] != "*":
        where.append(f"from {rule['actor']}")
    if rule["target"] != "*":
        where.append(f"on {rule['target']}")
    return f"{rule['category']} " + " ".join(where or ["everywhere"])
