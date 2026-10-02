"""
Findings-envelope ingest (v0.11).

Three tools in this portfolio produce findings -- maltriage from a file's bytes,
claude-recon-agent from a target's services, Shadowfax from an actor's event
history -- and until now none of them agreed on the shape. `findings-envelope.md`
defines one. This module is Shadowfax's side of it: strict validation of the
wire format, then translation into ordinary Shadowfax events.

The point of a wire format is that neither end knows anything about the other.
Nothing here names maltriage or claude-recon-agent, and nothing here is allowed
to: an emitter that writes the envelope is ingestible, and that is the whole
contract. `maltriage sample.exe --envelope | shadowfax ingest` is a pipe, not an
integration.

Findings become events, not alerts
----------------------------------
The obvious implementation writes an alert row per finding. It would also break
the invariant the rest of Shadowfax rests on: alerts are a pure function of
`(an actor's events, policy)`, recomputed on every rescan and never patched. An
alert with no event behind it would survive until the next rescan of that actor
and then silently vanish.

So a finding is stored as an **event** of type `finding`, carrying the finding in
its metadata, and a detector turns it back into an alert. Rescans reproduce it,
the hash-chained ledger covers it like any other event, correlation and
kill-chain detection see it alongside native alerts, and there is no second code
path holding a second kind of truth.

Validation is the trust boundary
--------------------------------
An envelope arrives from outside Shadowfax. `validate()` rejects the whole
document on any structural error, with the exact field path at fault, rather
than quietly dropping the findings it dislikes: a partially-accepted envelope
hides an emitter bug, and the next person to write an emitter deserves to be
told what is wrong with theirs. The one thing silently dropped is an unknown
ATT&CK technique id, which matches the existing `attack.enrich()` rule -- a typo
shows up as a missing badge, never an invented technique.

Keys may not impersonate a detector
-----------------------------------
A finding's `key` becomes the alert's category, because the spec says a key is
what a consumer groups, filters and counts on. An emitter may therefore not use
a key that collides with one of Shadowfax's own detector categories: an alert
reading `destructive_action` must mean Shadowfax's detector found it, not that
somebody else said so. The rejection names the collision.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

ENVELOPE_VERSION = "1.0"
SUPPORTED_MAJOR = "1"

# The ladder, ordered. Five levels, and an emitter may not invent a sixth.
SEVERITIES = ("critical", "high", "medium", "low", "info")

# What a subject can be. Shadowfax is actor-centric; everything else becomes a
# namespaced pseudo-actor. See `actor_for()`.
SUBJECT_KINDS = ("file", "host", "log_workspace", "actor")

# Non-actor subjects are not people, agents or service accounts, so they get
# their own actor type rather than being filed under one they are not.
EXTERNAL_ACTOR_TYPE = "external"

EVENT_TYPE = "finding"

KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")

REQUIRED_FINDING_FIELDS = ("id", "key", "severity", "title", "evidence", "validated")


class EnvelopeError(ValueError):
    """A rejected envelope. `path` is the field at fault, for the API message."""

    def __init__(self, message: str, path: str = ""):
        super().__init__(message)
        self.message = message
        self.path = path

    def describe(self) -> str:
        return f"{self.path}: {self.message}" if self.path else self.message


def validate(doc: Any, native_categories: frozenset[str] = frozenset()) -> dict[str, Any]:
    """Check an envelope and return it, or raise `EnvelopeError`.

    `native_categories` are Shadowfax's own detector categories, passed in rather
    than imported so this module stays a pure function of its arguments and the
    test can drive the collision rule directly.
    """
    if not isinstance(doc, dict):
        raise EnvelopeError("envelope must be a JSON object")

    version = doc.get("envelope_version")
    if not version:
        raise EnvelopeError("required", "envelope_version")
    if not isinstance(version, str) or version.split(".")[0] != SUPPORTED_MAJOR:
        # A major version bump means the shape changed; guessing at it would be
        # worse than saying plainly that this build does not speak it.
        raise EnvelopeError(
            f"unsupported envelope version {version!r}; this build speaks "
            f"{SUPPORTED_MAJOR}.x", "envelope_version")

    generated = doc.get("generated")
    if not generated:
        raise EnvelopeError("required", "generated")
    if _parse_generated(generated) is None:
        raise EnvelopeError("must be an ISO 8601 UTC timestamp", "generated")

    source = doc.get("source")
    if not isinstance(source, dict):
        raise EnvelopeError("required, and must be an object", "source")
    for field in ("tool", "version"):
        value = source.get(field)
        if not isinstance(value, str) or not value.strip():
            raise EnvelopeError("required, and must be a non-empty string",
                                f"source.{field}")

    subject = doc.get("subject")
    if not isinstance(subject, dict):
        raise EnvelopeError("required, and must be an object", "subject")
    kind = subject.get("kind")
    if kind not in SUBJECT_KINDS:
        raise EnvelopeError(
            f"must be one of {', '.join(SUBJECT_KINDS)}", "subject.kind")
    if not isinstance(subject.get("id"), str) or not subject["id"].strip():
        raise EnvelopeError("required, and must be a non-empty string", "subject.id")

    findings = doc.get("findings")
    if not isinstance(findings, list):
        # An empty array is a result -- "we looked and found nothing" is worth
        # recording -- but a missing one is a malformed document.
        raise EnvelopeError("required, and must be an array (empty is allowed)",
                            "findings")

    seen_ids: set[str] = set()
    for index, finding in enumerate(findings):
        _validate_finding(finding, f"findings[{index}]", native_categories, seen_ids)

    return doc


def _validate_finding(finding: Any, path: str, native_categories: frozenset[str],
                      seen_ids: set[str]) -> None:
    if not isinstance(finding, dict):
        raise EnvelopeError("must be an object", path)

    for field in REQUIRED_FINDING_FIELDS:
        if field not in finding:
            raise EnvelopeError("required", f"{path}.{field}")

    finding_id = finding["id"]
    if not isinstance(finding_id, str) or not finding_id.strip():
        raise EnvelopeError("must be a non-empty string", f"{path}.id")
    if finding_id in seen_ids:
        # Two findings with one id inside a single envelope is an emitter bug:
        # the id is meant to be a function of the content, so a duplicate means
        # either a collision or a discriminator that was never applied.
        raise EnvelopeError(f"duplicate finding id {finding_id!r} in this envelope",
                            f"{path}.id")
    seen_ids.add(finding_id)

    key = finding["key"]
    if not isinstance(key, str) or not KEY_PATTERN.match(key):
        raise EnvelopeError("must be snake_case: lowercase, digits and underscores, "
                            "starting with a letter", f"{path}.key")
    if key in native_categories:
        raise EnvelopeError(
            f"{key!r} is one of Shadowfax's own detector categories; an external "
            f"finding may not claim it. Choose another key.", f"{path}.key")

    if finding["severity"] not in SEVERITIES:
        raise EnvelopeError(f"must be one of {', '.join(SEVERITIES)}",
                            f"{path}.severity")

    for field in ("title", "evidence"):
        if not isinstance(finding[field], str) or not finding[field].strip():
            raise EnvelopeError("must be a non-empty string", f"{path}.{field}")

    if not isinstance(finding["validated"], bool):
        # Required, and strictly a boolean, because its absence or vagueness is
        # exactly the ambiguity it exists to remove: did the emitter verify this,
        # or is it repeating what the subject said about itself?
        raise EnvelopeError("must be a boolean (true = the emitter verified this "
                            "claim; false = the input asserted it)",
                            f"{path}.validated")

    refs = finding.get("refs")
    if refs is not None and not isinstance(refs, list):
        raise EnvelopeError("must be an array when present", f"{path}.refs")

    data = finding.get("data")
    if data is not None and not isinstance(data, dict):
        raise EnvelopeError("must be an object when present", f"{path}.data")

    mitre = finding.get("mitre")
    if mitre is not None and not isinstance(mitre, str):
        raise EnvelopeError("must be a string like 'T1027 - Obfuscated Files or "
                            "Information' when present", f"{path}.mitre")


def actor_for(subject: dict[str, Any]) -> str:
    """The Shadowfax actor a subject maps to.

    `kind: actor` lands on that actor's existing timeline, which is the point --
    a finding about `recon-agent-3` should correlate with what Shadowfax already
    knows about `recon-agent-3`. Every other kind is namespaced by its kind, so a
    file called `admin` cannot quietly become the user `admin`.
    """
    if subject["kind"] == "actor":
        return subject["id"]
    return f"{subject['kind']}:{subject['id']}"


def to_events(doc: dict[str, Any],
              actor_types: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Translate a validated envelope into Shadowfax events, one per finding.

    `actor_types` maps known actor ids to their actor type, so a finding about an
    actor Shadowfax already tracks inherits that actor's type instead of
    introducing a second type for the same actor. It is passed in rather than
    looked up, which keeps this function pure and the database out of it.
    """
    actor_types = actor_types or {}
    subject = doc["subject"]
    source = doc["source"]
    actor_id = actor_for(subject)
    actor_type = (actor_types.get(actor_id, "unknown")
                  if subject["kind"] == "actor" else EXTERNAL_ACTOR_TYPE)
    timestamp = _parse_generated(doc["generated"])

    # The task line is what an analyst sees as provenance on the timeline.
    run = source.get("run_id")
    task = f"{source['tool']} {source['version']}" + (f" run {run}" if run else "")

    events = []
    for finding in doc["findings"]:
        events.append({
            "timestamp": timestamp.isoformat(),
            "actor_id": actor_id,
            "actor_type": actor_type,
            "task": task,
            "event_type": EVENT_TYPE,
            # The label is for people and may be absent or ambiguous, so the id
            # is what we fall back to -- never the other way round.
            "target": subject.get("label") or subject["id"],
            "metadata": {
                "envelope_version": doc["envelope_version"],
                "source": {"tool": source["tool"], "version": source["version"],
                           **({"run_id": run} if run else {})},
                "subject": {k: subject[k] for k in ("kind", "id") if k in subject}
                           | ({"label": subject["label"]} if subject.get("label") else {}),
                "finding": _clean_finding(finding),
            },
        })
    return events


def _clean_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """The finding as stored: required fields, plus optional ones when present.

    Unknown fields are dropped rather than stored. An envelope is a contract;
    carrying whatever else an emitter happened to send would make the stored
    shape depend on the emitter, which is the coupling this whole format exists
    to avoid.
    """
    out = {field: finding[field] for field in REQUIRED_FINDING_FIELDS}
    for field in ("mitre", "recommendation", "refs", "data"):
        if finding.get(field) not in (None, [], {}):
            out[field] = finding[field]
    return out


def techniques_for(finding: dict[str, Any]) -> list[str]:
    """ATT&CK technique ids from a finding's `mitre` string.

    The envelope carries `"T1027 - Obfuscated Files or Information"`; Shadowfax
    stores ids and resolves names from its own registry, so only the id is taken.
    An id the registry does not know is dropped by `attack.enrich()` downstream --
    a missing badge, never an invented technique.
    """
    mitre = finding.get("mitre")
    if not isinstance(mitre, str):
        return []
    match = re.match(r"^\s*(T\d{4}(?:\.\d{3})?)\b", mitre)
    return [match.group(1)] if match else []


def summarise(doc: dict[str, Any]) -> dict[str, Any]:
    """A short description of what an envelope contains, for an API response."""
    counts: dict[str, int] = {}
    for finding in doc["findings"]:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return {
        "tool": doc["source"]["tool"],
        "version": doc["source"]["version"],
        "subject": actor_for(doc["subject"]),
        "findings": len(doc["findings"]),
        "by_severity": counts,
    }


def _parse_generated(value: Any) -> datetime | None:
    """Parse `generated` into a naive UTC datetime, or None if it is unparseable.

    The event store is naive-UTC throughout and the detectors compare timestamps
    directly, so an offset-aware value mixed in would not be a style blemish but
    a TypeError the first time one was subtracted from another. An offset is
    honoured and then normalised away, rather than being rejected or ignored.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed.replace(microsecond=0)
