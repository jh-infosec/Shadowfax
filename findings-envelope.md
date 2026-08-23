# Findings Envelope

Version 1.0

## Purpose

Three tools in this portfolio produce findings: maltriage from a file's bytes,
claude-recon-agent from a target's services and from a log workspace, and
Shadowfax from an actor's event history. All three already carry a severity, a
description and some evidence. None of them agree on the shape.

This document defines one shape. Once an emitter writes it, Shadowfax ingests
that emitter without knowing anything about it, and `maltriage sample.exe
--envelope | shadowfax ingest` works as a pipe rather than as an integration.

This is a wire format, not a library. A tool may hold findings internally in
whatever structure suits it and translate on the way out. maltriage's
`report.findings` and Shadowfax's `alerts` table both stay as they are.

## The severity ladder

Five levels, ordered: `critical`, `high`, `medium`, `low`, `info`.

No emitter is required to use all five. Every emitter is forbidden from
inventing a sixth, and from redefining one.

The three current emitters use different subsets, deliberately:

- maltriage emits `high` through `info` and does not emit `critical`. Its
  severity discipline reserves `high` for content that lies about what it is,
  and nothing static triage can observe from bytes alone warrants a level
  above that. This is a local rule and it stays local. The envelope permits
  `critical`; maltriage declines to use it.
- claude-recon-agent's hunt side emits all five.
- Shadowfax emits `critical` through `low` and does not currently emit `info`.

A consumer must therefore handle all five and must not assume any are present.
Shadowfax's risk weighting takes `info` at 0, which is the only new decision
this ladder forces on it.

## Finding identity

Every finding carries an `id` that is a deterministic function of its content:

```
id = sha256(f"{source.tool}|{subject.id}|{key}|{discriminator}")[:16]
```

`discriminator` is whatever distinguishes two findings that share a key on the
same subject: a section name, a port number, a source IP, an offset. It may be
empty when a key can only fire once per subject.

The same finding recomputed from the same input produces the same id. This is
the property Shadowfax records as missing under "Alert identity is not
stable", and it is the precondition for any per-alert analyst state such as
acknowledgement or triage notes. Adopting the envelope therefore closes that
constraint as a side effect rather than as separate work.

An id is not a primary key. Two different tools may legitimately produce the
same finding about the same subject; `source.tool` distinguishes them.

## Structure

```json
{
  "envelope_version": "1.0",
  "generated": "2026-08-23T09:14:02Z",
  "source": {
    "tool": "maltriage",
    "version": "0.2.0",
    "run_id": "a3f9c1b2"
  },
  "subject": {
    "kind": "file",
    "id": "sha256:9f86d081884c7d65...",
    "label": "dropper.exe"
  },
  "findings": [
    {
      "id": "4c1f8a02b3d7e619",
      "key": "writable_executable_section",
      "severity": "medium",
      "title": "Section .text1 is both writable and executable",
      "evidence": "characteristics=0xE0000020 (MEM_WRITE|MEM_EXECUTE|CNT_CODE)",
      "validated": true,
      "mitre": "T1027 - Obfuscated Files or Information",
      "recommendation": "Unpack in a sandbox before further static analysis.",
      "refs": [],
      "data": {"section": ".text1", "entropy": 7.91}
    }
  ]
}
```

### Envelope fields

| Field | Required | Notes |
|---|---|---|
| `envelope_version` | yes | This spec's version, not the emitter's |
| `generated` | yes | ISO 8601, UTC, `Z` suffix |
| `source.tool` | yes | Stable short name |
| `source.version` | yes | Emitter's own version |
| `source.run_id` | no | Correlates findings from one run |
| `subject.kind` | yes | `file`, `host`, `log_workspace`, `actor` |
| `subject.id` | yes | Stable identifier: content hash, IP, actor id |
| `subject.label` | no | Human-facing name, may be absent or ambiguous |
| `findings` | yes | May be empty. An empty array is a result |

`envelope_version` is separate from each emitter's own schema version.
maltriage's `SCHEMA_VERSION` describes `report.data`, which the envelope does
not carry. The two move independently and neither implies the other.

### Finding fields

| Field | Required | Notes |
|---|---|---|
| `id` | yes | Deterministic, per the rule above |
| `key` | yes | Machine-stable finding key, `snake_case` |
| `severity` | yes | One of the five levels |
| `title` | yes | One human sentence |
| `evidence` | yes | See below |
| `validated` | yes | See below |
| `mitre` | no | `Txxxx - Name`, verbatim from the registry |
| `recommendation` | no | What a human should do next |
| `refs` | no | Array of URLs or CVE ids |
| `data` | no | Emitter-specific structured detail |

`key` and `title` are separate on purpose. maltriage already makes this split
and the other two do not. A key is what a consumer groups, filters and counts
on; a title is what a person reads. A title that changes wording must not
change what a dashboard has been counting.

## Evidence must be observed, not narrated

`evidence` carries what was actually seen: the log line, the byte offset, the
header field, the port banner. It does not carry a model's description of what
was seen.

This is the rule that keeps an LLM out of the finding path. In
claude-recon-agent both agents are told to distinguish what they can prove
from what they suspect, and the envelope is where that distinction becomes
mechanical: if a tool did not produce the bytes, they do not go in `evidence`.
A model's reasoning about a finding belongs in `recommendation` or in the
surrounding report, and is not evidence.

## Validated

`validated` is a boolean, and it is required rather than optional, because its
absence is exactly the ambiguity it exists to remove.

`true` means the emitter verified the claim by a mechanism it controls.
`false` means the emitter is reporting something asserted by the input.

maltriage already does this correctly for Authenticode: the certificate's
common names are reported with `"validated": false`, because a crafted file
can put any string in that blob and nothing in the tool checks a chain. The
same distinction applies to a service banner, a `Server:` header, a user agent
and a claimed hostname. All of these are the subject telling you about itself.

A consumer may treat unvalidated findings differently. It may not treat them
as absent.

## What the envelope does not carry

Raw tool output, full file contents, log bodies beyond the evidence lines,
model prose, and any secret material the emitter detected. A finding says a
high-entropy string that looks like a credential was found at an offset. It
does not carry the string.

That last rule matters most for the shared secret engine, whose whole job is
locating credentials. An envelope is a thing that gets piped, stored and
shared, and putting recovered secrets in it turns a detection into a leak.

## Adoption order

1. maltriage emits it. It has the most mature findings model and a bounded
   key set, so it is the cheapest first emitter and it proves the shape.
2. claude-recon-agent emits it from `finish_session` and `finish_hunt`.
3. Shadowfax ingests it, and separately adopts the deterministic id rule for
   its own alerts, which closes its stable-identity constraint.

Emitting is additive in every case. No tool changes its existing output to
adopt this; each adds an envelope alongside what it already produces.
