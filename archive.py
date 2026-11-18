"""
Move old events out of the database into an archive file (v0.41).

    python archive.py run --older-than 365 --dry-run    # what would go
    python archive.py run --older-than 365              # do it
    python archive.py run --before 2026-01-01 --out /backups/shadowfax
    python archive.py verify archives/*.jsonl.gz        # check the files
    python archive.py verify archives/*.jsonl.gz --against-db

    docker exec -it shadowfax python archive.py run --older-than 365

Shadowfax keeps every event it's sent, and until now kept them forever. That's
the right default for evidence, but a busy deployment's database only grows.
This is the way to let go of old history without losing the ability to prove
what it said:

* Events are moved, not deleted. They go into a gzipped JSON Lines file with
  their ledger hashes, along with every alert that leaves the database with
  them and a copy of any analyst notes on those alerts.
* The ledger is cut at one point, never in pieces. It's a hash chain in the
  order events were stored, so the archive takes the longest run of stored
  events, from the start, that are all older than the cutoff. An old event
  stored after a newer one (a late upload, say) stays until the newer one
  goes too. `--dry-run` says how many that is.
* The ledger carries on from the archive. A row in `ledger_archives` records
  the file's name, its sha256, and the hash of the last event in it.
  `/ledger/verify` then checks the events still stored chain on from that
  hash, and `archive.py verify` checks the files themselves: each one's chain,
  that each starts where the one before ended, and with `--against-db` that
  they're the files the database recorded, byte for byte.
* The ledger part being archived is checked before anything moves. An archive
  of a broken chain would launder the break, so it's refused.
* It's written into the ledger as `events_archived` under `shadowfax-ingest`,
  and raises `evidence_archived` (medium). Routine housekeeping looks exactly
  like someone covering their tracks, so it's never silent.

What changes for the agents whose history was archived: their alerts are
worked out again from the events that are left, so anything that depended on
the archived events goes with them (it's in the file). A finding that's raised
once per agent, like `undeclared_agent`, can be raised again on the first
event that's left.

On SQLite the file doesn't shrink until it's compacted: add `--vacuum`.
"""

from __future__ import annotations

import argparse
import getpass
import gzip
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import db
import ledger

FORMAT = "shadowfax-archive"
FORMAT_VERSION = 1
EVENT_TYPE = "events_archived"
ALERT_FIELDS = ("id", "event_id", "actor_id", "actor_type", "timestamp", "severity", "category",
                "message", "target", "attack", "source_tool", "validated", "evidence")


def _os_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # no passwd entry for the uid, as in some containers
        return "unknown"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def default_folder() -> Path:
    """Beside the database file, so it lands on the same volume in Docker."""
    if db.DATABASE_URL:
        raise SystemExit("with PostgreSQL there's no database file to put archives beside: use --out")
    return db.DB_PATH.parent / "archives"


def plan(conn, cutoff: str) -> dict[str, Any]:
    """What an archive at `cutoff` would take. Read-only."""
    archived, start_hash = db.ledger_checkpoint(conn)
    first_new = conn.execute("SELECT MIN(id) AS i FROM events WHERE timestamp >= ?", (cutoff,)).fetchone()["i"]
    if first_new is None:
        through = conn.execute("SELECT MAX(id) AS i FROM events").fetchone()["i"]
    else:
        through = conn.execute("SELECT MAX(id) AS i FROM events WHERE id < ?", (first_new,)).fetchone()["i"]
    events = 0 if through is None else conn.execute(
        "SELECT COUNT(*) AS n FROM events WHERE id <= ?", (through,)).fetchone()["n"]
    stuck = conn.execute("SELECT COUNT(*) AS n FROM events WHERE timestamp < ? AND id > ?",
                         (cutoff, through or 0)).fetchone()["n"]
    actors = [r["actor_id"] for r in conn.execute(
        "SELECT DISTINCT actor_id FROM events WHERE id <= ? ORDER BY actor_id", (through or 0,))]
    return {"cutoff": cutoff, "through_event_id": through or 0, "events": events,
            "older_but_kept": stuck, "actors": actors,
            "start_count": archived, "start_hash": start_hash}


def _alert_row(r) -> dict[str, Any]:
    a = {k: r[k] for k in ALERT_FIELDS}
    a["attack"] = json.loads(a["attack"] or "[]")
    return a


def _write(path: Path, header: dict, events: list[dict], alerts: list[dict], states: list[dict]) -> str:
    """Write the file next to its final name and move it into place, so a
    half-written archive never has the real name. Returns its sha256."""
    tmp = path.with_name(path.name + ".partial")
    with open(tmp, "wb") as raw:
        # mtime=0: the same archive is the same bytes, whenever it's written.
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
            for line in ([header] + [{"event": e} for e in events] + [{"alert": a} for a in alerts]
                         + [{"alert_state": s} for s in states]):
                gz.write((json.dumps(line, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"))
        raw.flush()
        os.fsync(raw.fileno())
    os.replace(tmp, path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(cutoff: str, folder: Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Archive every event up to the ledger cut for `cutoff`. Returns what was
    done. Raises ValueError when there's nothing to archive or the ledger
    being archived doesn't verify."""
    import app

    now = now or _now()
    folder.mkdir(parents=True, exist_ok=True)
    with db.get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")     # one writer: the head can't move under us
        p = plan(conn, cutoff)
        if not p["events"]:
            conn.rollback()
            raise ValueError(f"no events recorded before {cutoff} can be archived"
                             + (f" ({p['older_but_kept']} older ones were stored after newer ones)"
                                if p["older_but_kept"] else ""))
        through = p["through_event_id"]
        events = db.ledger_entries(conn, through)
        end_count = p["start_count"] + len(events)
        check = ledger.verify_chain(events, end_count, events[-1]["entry_hash"],
                                    start_hash=p["start_hash"], start_count=p["start_count"])
        if not check["ok"]:
            conn.rollback()
            raise ValueError("the part of the ledger to be archived doesn't verify, so it can't be "
                             f"archived (that would hide the break): {ledger.describe(check)}")

        cols = ", ".join(ALERT_FIELDS)
        before: dict[str, dict] = {}
        for actor in p["actors"]:
            for r in conn.execute(f"SELECT {cols} FROM alerts WHERE actor_id = ?", (actor,)):
                before[r["id"]] = _alert_row(r)
        conn.execute("DELETE FROM alerts WHERE event_id <= ?", (through,))
        conn.execute("DELETE FROM events WHERE id <= ?", (through,))
        for actor in p["actors"]:
            app._rescan_actor(conn, actor)
        kept = {r["id"] for r in conn.execute(
            f"SELECT id FROM alerts WHERE actor_id IN ({', '.join('?' * len(p['actors']))})", p["actors"])}
        gone = [a for i, a in sorted(before.items()) if i not in kept]
        gone_ids = [a["id"] for a in gone]
        states = []
        for i in range(0, len(gone_ids), 500):
            chunk = gone_ids[i:i + 500]
            states += [dict(r) for r in conn.execute(
                f"SELECT * FROM alert_state WHERE alert_id IN ({', '.join('?' * len(chunk))})", chunk)]
        # Analyst state is copied, not moved: it's keyed by alert id and is
        # allowed to outlive its alert, so it reattaches if the alert is ever
        # raised again.

        header = {"format": FORMAT, "version": FORMAT_VERSION, "created_at": now.isoformat(),
                  "cutoff": cutoff, "through_event_id": through, "events": len(events), "alerts": len(gone),
                  "start_count": p["start_count"], "start_hash": p["start_hash"],
                  "end_count": end_count, "end_hash": events[-1]["entry_hash"]}
        name = f"shadowfax-archive-{end_count:010d}-{cutoff[:10]}.jsonl.gz"
        path = folder / name
        if path.exists():
            conn.rollback()
            raise ValueError(f"{path} already exists")
        digest = _write(path, header, events, gone, states)
        try:
            conn.execute(
                """INSERT INTO ledger_archives (archived_at, cutoff, through_event_id, events, alerts,
                                                start_count, start_hash, end_count, end_hash,
                                                file_name, file_sha256)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (now.isoformat(), cutoff, through, len(events), len(gone), p["start_count"],
                 p["start_hash"], end_count, header["end_hash"], name, digest))
            db.insert_event(conn, {
                "timestamp": now.isoformat(), "actor_id": app.INGEST_ACTOR_ID,
                "actor_type": app.SELF_ACTOR_TYPE, "task": "platform_ingest",
                "event_type": EVENT_TYPE, "target": name,
                "metadata": {"cutoff": cutoff, "events": len(events), "alerts": len(gone),
                             "through_event_id": through, "file": name, "file_sha256": digest,
                             "end_count": end_count, "end_hash": header["end_hash"],
                             "agents": len(p["actors"]), "os_user": _os_user()},
            })
            app._rescan_actor(conn, app.INGEST_ACTOR_ID)
            conn.commit()
        except BaseException:
            conn.rollback()
            path.unlink(missing_ok=True)    # the database never pointed at it
            raise
    app._forget_scans()
    return {**header, "file": str(path), "file_sha256": digest, "agents": len(p["actors"]),
            "older_but_kept": p["older_but_kept"]}


def read(path: Path) -> tuple[dict, list[dict], list[dict], list[dict]]:
    header, events, alerts, states = None, [], [], []
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for n, line in enumerate(f):
            obj = json.loads(line)
            if n == 0:
                header = obj
            elif "event" in obj:
                events.append(obj["event"])
            elif "alert" in obj:
                alerts.append(obj["alert"])
            elif "alert_state" in obj:
                states.append(obj["alert_state"])
    if not header or header.get("format") != FORMAT:
        raise ValueError(f"{path.name} isn't a Shadowfax archive")
    return header, events, alerts, states


def verify(paths: list[Path], against_db: bool = False) -> tuple[bool, list[str]]:
    """Check archive files: each one's hash chain, that they follow on from
    each other, and optionally that they're the files the database recorded
    and that the ledger still stored carries on from the last one."""
    ok, lines = True, []
    files = []
    for path in paths:
        try:
            header, events, _alerts, _states = read(path)
        except (OSError, ValueError, EOFError) as exc:
            ok = False
            lines.append(f"FAIL {path.name}: can't be read ({exc})")
            continue
        files.append((path, header))
        r = ledger.verify_chain(events, header["end_count"], header["end_hash"],
                                start_hash=header["start_hash"], start_count=header["start_count"])
        if r["ok"]:
            lines.append(f"ok   {path.name}: entries {header['start_count'] + 1} to {header['end_count']} "
                         f"chain cleanly, ending on {header['end_hash'][:16]}…")
        else:
            ok = False
            lines.append(f"FAIL {path.name}: {ledger.describe(r)}")

    files.sort(key=lambda f: f[1]["start_count"])
    if files and files[0][1]["start_count"] != 0:
        lines.append(f"note the first file given starts after entry {files[0][1]['start_count']}; "
                     "the archives before it weren't checked")
    for (pa, a), (pb, b) in zip(files, files[1:]):
        if (b["start_count"], b["start_hash"]) != (a["end_count"], a["end_hash"]):
            ok = False
            lines.append(f"FAIL {pb.name} doesn't start where {pa.name} ends: an archive is missing "
                         "or one was altered")

    if against_db:
        with db.get_conn() as conn:
            recorded = {a["end_count"]: a for a in db.ledger_archives(conn)}
            checkpoint = db.ledger_checkpoint(conn)
            first = conn.execute("SELECT id, prev_hash FROM events ORDER BY id ASC LIMIT 1").fetchone()
        for path, h in files:
            row = recorded.get(h["end_count"])
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if row is None:
                ok = False
                lines.append(f"FAIL {path.name}: the database has no record of an archive ending at "
                             f"entry {h['end_count']}")
            elif (row["end_hash"], row["file_sha256"]) != (h["end_hash"], digest):
                ok = False
                lines.append(f"FAIL {path.name}: not the file the database recorded (its sha256 or last "
                             "hash differs)")
            else:
                lines.append(f"ok   {path.name}: the file the database recorded, byte for byte")
        if files and files[-1][1]["end_count"] == checkpoint[0]:
            last = files[-1][1]
            if first is not None and first["prev_hash"] != last["end_hash"]:
                ok = False
                lines.append("FAIL the first event still stored doesn't chain on from the last archive")
            else:
                lines.append("ok   the ledger still stored carries on from the last archive "
                             "(GET /ledger/verify checks the rest)")
        missing = sorted(set(recorded) - {h["end_count"] for _, h in files})
        if missing:
            lines.append(f"note the database records {len(missing)} archive(s) not given here")
    return ok, lines


def _cutoff(args) -> str:
    if args.before:
        try:
            return datetime.fromisoformat(args.before).isoformat() if "T" in args.before \
                else datetime.fromisoformat(args.before).date().isoformat()
        except ValueError:
            raise SystemExit(f"--before {args.before!r} isn't a date like 2026-01-31")
    return (_now() - timedelta(days=args.older_than)).replace(microsecond=0).isoformat()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="archive.py", description=__doc__.split("\n\n")[0].strip())
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="archive old events")
    when = r.add_mutually_exclusive_group(required=True)
    when.add_argument("--before", help="archive events recorded before this date (2026-01-31)")
    when.add_argument("--older-than", type=int, metavar="DAYS", help="archive events older than this")
    r.add_argument("--out", type=Path, help="where to write the file (default: archives/ beside the database)")
    r.add_argument("--dry-run", action="store_true", help="say what would be archived, change nothing")
    r.add_argument("--vacuum", action="store_true", help="compact the SQLite file afterwards")
    r.add_argument("--yes", action="store_true", help="don't ask for confirmation (for scripts)")
    v = sub.add_parser("verify", help="check archive files")
    v.add_argument("files", nargs="+", type=Path)
    v.add_argument("--against-db", action="store_true",
                   help="also check them against the archives the database recorded")
    args = p.parse_args(argv)

    if args.cmd == "verify":
        good, lines = verify(args.files, args.against_db)
        print("\n".join(lines))
        print("All archives check out." if good else "Something doesn't check out (see FAIL above).")
        return 0 if good else 1

    if not db.DATABASE_URL and not db.DB_PATH.exists():
        print(f"error: no database at {db.DB_PATH} -- set SHADOWFAX_DB to the file the server uses",
              file=sys.stderr)
        return 1
    cutoff = _cutoff(args)
    with db.get_conn() as conn:
        pl = plan(conn, cutoff)
    print(f"Events recorded before {cutoff}: {pl['events']:,} can be archived "
          f"(event ids up to {pl['through_event_id']}, from {len(pl['actors'])} agent(s)).")
    if pl["older_but_kept"]:
        print(f"{pl['older_but_kept']:,} older event(s) stay for now: they were stored after newer ones, and "
              "the ledger can only be cut at one point.")
    if args.dry_run or not pl["events"]:
        return 0
    folder = args.out or default_folder()
    if not args.yes:
        print(f"They'll be moved into a file in {folder} and removed from the database. This raises a "
              "medium alert (evidence_archived).")
        try:
            answer = input("Type archive to continue: ")
        except EOFError:
            answer = ""
        if answer.strip() != "archive":
            print("Not confirmed; nothing changed.", file=sys.stderr)
            return 1
    try:
        res = run(cutoff, folder)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Archived {res['events']:,} event(s) and {res['alerts']:,} alert(s) into {res['file']}")
    print(f"  sha256 {res['file_sha256']}")
    print(f"  the ledger now carries on from {res['end_hash'][:16]}… (entry {res['end_count']:,})")
    print("Keep that file somewhere safe: it's the only copy now. Check it any time with")
    print(f"  python archive.py verify {res['file']} --against-db")
    if args.vacuum and not db.DATABASE_URL:
        with db.get_conn() as conn:
            conn.execute("VACUUM")
        print("SQLite file compacted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
