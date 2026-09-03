"""
MITRE ATT&CK mapping for Shadowfax (v0.4).

Two things live here, kept apart on purpose:

- The **registry** (`attack_registry.json`) is the shared, portfolio-wide table
  of technique metadata (id -> name, tactic, url). Technique ids are used
  verbatim from it; nothing here generates one. It is the single place a
  technique id or name is corrected, and the same file is consumed by the other
  tools in the portfolio.

- The **category mapping** (`CATEGORY_TO_TECHNIQUES`) is Shadowfax's own opinion
  about which ATT&CK techniques each of its alert categories corresponds to.
  Destructive-action alerts don't use this: their technique is declared per
  rule in the policy, because `rm -rf` and a database drop map to different
  techniques even though both are `destructive_action`.

`enrich()` turns a list of ids into full technique objects, silently dropping
any id the registry doesn't know -- so a typo shows up as a missing badge, never
an invented technique. `validate()` (used by the tests) asserts every id the
shipped mapping and default policy reference actually exists in the registry.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any

REGISTRY_PATH = Path(__file__).parent / "attack_registry.json"

with open(REGISTRY_PATH, encoding="utf-8") as _f:
    _REGISTRY: dict[str, dict[str, str]] = json.load(_f).get("techniques", {})

# Shadowfax alert category -> ATT&CK technique ids. Categories with no clean
# technique (policy controls like allowlist_violation, or pure anomalies like
# rate_anomaly) map to nothing, which is honest -- not every alert is an ATT&CK
# technique.
CATEGORY_TO_TECHNIQUES: dict[str, list[str]] = {
    "brute_force_auth": ["T1110"],
    "impossible_travel": ["T1078"],
    "privilege_escalation": ["T1548"],
    "lateral_movement": ["T1021"],
    "exfiltration_volume": ["T1048"],
    "canary_triggered": ["T1552"],
    "capability_resurrection": ["T1098"],
    "dormant_reappearance": ["T1078"],
    "off_hours_access": ["T1078"],
    "out_of_scope_action": ["T1041"],
    # destructive_action: technique comes from the matched policy rule, not here.
    # allowlist_violation, blocked_target_access, rate_anomaly: no mapping.
}


def technique(technique_id: str) -> dict[str, str] | None:
    meta = _REGISTRY.get(technique_id)
    if meta is None:
        return None
    return {"id": technique_id, **meta}


def enrich(technique_ids: list[str] | None) -> list[dict[str, str]]:
    """Full technique objects for the given ids, skipping any not in the
    registry (so an unknown id never becomes an invented technique)."""
    out: list[dict[str, str]] = []
    for tid in technique_ids or []:
        meta = technique(tid)
        if meta is not None:
            out.append(meta)
    return out


def for_category(category: str) -> list[dict[str, str]]:
    return enrich(CATEGORY_TO_TECHNIQUES.get(category, []))


def registry() -> dict[str, dict[str, str]]:
    """The full technique table, id -> {name, tactic, url}."""
    return dict(_REGISTRY)


def validate(policy: dict[str, Any] | None = None) -> list[str]:
    """Return any technique ids referenced by the category mapping or the given
    policy's destructive-action rules that are missing from the registry. Empty
    means everything resolves -- the invariant the tests enforce."""
    referenced: set[str] = set()
    for ids in CATEGORY_TO_TECHNIQUES.values():
        referenced.update(ids)
    if policy:
        for rule in policy.get("destructive_action_rules", []):
            referenced.update(rule.get("attack", []))
    return sorted(tid for tid in referenced if tid not in _REGISTRY)
