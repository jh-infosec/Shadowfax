# Evidence and history

The hash-chained ledger, and keeping it fast and manageable as history grows. Back to the [README](../README.md).

## Evidence integrity

There's not much point asking whether an agent's behaviour can be trusted if the
record of that behaviour could have been edited afterwards. So every event is
hash-chained to the one before it:

```
entry_hash = sha256( prev_hash | canonical_json(event content) )
```

Changing any byte of any event breaks that entry and every one after it.
Verification recomputes the whole chain and reports the first place it breaks,
and tells you whether an event was edited, deleted or reordered, or whether the
log was cut short.

```bash
python cli.py verify     # exit 0 if intact, 1 if broken
```

```
ledger intact: 39 entries verified, head 491329ea531869ec…

LEDGER BROKEN at position 24 (event id 25, actor recon-agent-3): the entry's
content does not match its hash, so this event was modified after it was
recorded. 24 entries before it verified cleanly.
```

The dashboard shows the same check as a badge and re-checks whenever the event
count changes.

The chain follows the order events were received, not the timestamps they
claim, because events can legitimately arrive out of order and the proof
shouldn't depend on data the sender controls.

This is tamper evident, not tamper proof. Someone with full write access to the
database could rewrite the events, the chain and the head together. The fix for
that is to copy the head somewhere they can't reach. `GET /ledger/head` returns
the entry count and head hash for that purpose, and an API key can read it, so
a scheduled job on another machine can save it every hour. To check a copy
later, `GET /ledger/head?at=63` returns the head as it was at entry 63. If it no
longer matches what you saved, history before that point was rewritten, even
if `verify` passes. The [deployment guide](deployment.md#6-keep-a-copy-of-the-ledger-head-somewhere-else)
has the exact commands.

## Long histories

### Recording stays fast

Alerts are worked out from an agent's whole history, so up to v0.40 every new
event meant reading and judging everything that agent had ever done. Fine for a
demo, slow for a busy agent: at 50,000 events, recording one more took most of
a second. Now each agent's scan is kept running between events and only the new
ones are fed to it, and only alerts that are new get written.

`bench.py` measures it. It fills a throwaway database with one agent's events,
records more one at a time through the API with an agent's key, and reports the
median, with the kept scans on and off:

```bash
python bench.py           # a well-behaved agent
python bench.py --noisy   # one that breaks its allowlist on most calls
```

| Events already stored | Scanning everything (v0.40) | Kept scan (v0.41) |
| ---: | ---: | ---: |
| 1,000 | 24 ms | 7 ms |
| 10,000 | 183 ms | 7 ms |
| 50,000 | 829 ms | 11 ms |
| 50,000, noisy (about 33,000 alerts) | 1,196 ms | 9 ms |

Those are from a small cloud VM on SQLite; yours will differ, the shape won't.
The first event after a restart still scans the whole history once.

This is the same calculation resumed, not an approximation, and it's careful
about when it can resume. A scan is only kept going while the policy and every
threat intel feed are exactly what it started with, and while new events sort
after everything it has seen. Before trusting a kept scan, Shadowfax checks the
agent's event count and the ledger hash of the last event it saw, which catches
a rolled-back write, a reset or an archive. Anything else starts a fresh scan.
The test suite runs with `SHADOWFAX_VERIFY_SCANS=1`, which does a full scan as
well every time and fails the run if the two ever disagree, and it throws a
random stream of late, early and same-second events at it to make sure.

### Archiving old events

Shadowfax keeps every event it's sent. That's the right default for evidence,
but the database only grows. `archive.py` moves old events into a file and out
of the database, and the ledger carries on from that file:

```bash
python archive.py run --older-than 365 --dry-run   # what would go
python archive.py run --older-than 365             # do it
python archive.py verify archives/*.jsonl.gz --against-db

# with Docker
docker exec -it shadowfax python archive.py run --older-than 365
```

The file is gzipped JSON Lines holding the events with their ledger hashes, the
alerts that leave the database with them, and a copy of any analyst notes on
those alerts. By default it goes in `archives/` beside the database, which in
Docker is the data volume. Copy it somewhere safe: it's the only copy now.

Some things it's careful about:

- The ledger is a chain in the order events were stored, so it can only be cut
  at one point. The archive takes the oldest stored events up to the first one
  that's newer than the cutoff. An old event that was uploaded late stays until
  the newer ones before it go too, and `--dry-run` tells you how many.
- The part being archived is verified first. Archiving a broken chain would
  hide the break, so it's refused.
- The database records each archive's file name, sha256 and last hash.
  `/ledger/verify` checks that what's still stored chains on from the last
  archive, and the dashboard's ledger badge says so. `archive.py verify` checks
  the files: each one's chain, that each starts where the one before ended, and
  with `--against-db` that they're the files the database recorded, byte for
  byte. Alerts in the file aren't part of the chain, so that last check is what
  protects them.
- It's written into the ledger and raises `evidence_archived` (medium, mapped to
  ATT&CK T1070). Routine housekeeping looks exactly like someone covering their
  tracks, so it's never silent.

The agents whose history was archived have their alerts worked out again from
what's left. Anything that depended on the archived events leaves with them
(it's in the file), and a finding that's raised once per agent, like
`undeclared_agent`, can come back on the first event that's left. On SQLite the
database file doesn't shrink until it's compacted, so add `--vacuum`.
