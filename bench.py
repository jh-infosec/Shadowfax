"""
How long it takes to record one event for an agent with a long history (v0.41).

    python bench.py                    # 1,000, 10,000 and 50,000 events
    python bench.py --sizes 2000 --repeat 5
    python bench.py --noisy            # an agent that breaks its allowlist constantly

For each size it builds a throwaway database holding that many events for one
agent, then records more events for it one at a time through the API, exactly
as an agent connector would (with an ingest key), and reports the median time per event. It does
this twice: with each agent's scan kept between events (the default since
v0.41) and with it switched off (SHADOWFAX_SCAN_CACHE_ACTORS=0), which is how
every version before v0.41 behaved.

Nothing here touches your real database: each run uses a temporary file.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).parent
AGENT = "bench-agent"
TARGETS = ["internal_eval_harness", "sandbox_package_registry"]
NOISY_TARGETS = ["internal_repo_readonly", "internal_eval_harness", "sandbox_package_registry"]


def _event(i: int, start: datetime) -> dict:
    # A busy, well-behaved agent: tool calls on the targets its task allows.
    # With --noisy, two calls in three go somewhere its task doesn't allow,
    # so it piles up an alert for each.
    noisy = os.environ.get("BENCH_NOISY") == "1"
    return {"timestamp": (start + timedelta(seconds=20 * i)).strftime("%Y-%m-%dT%H:%M:%S"),
            "actor_id": AGENT, "actor_type": "ai_agent",
            "task": "code_review_task" if noisy else "cyber_benchmark_eval",
            "event_type": "tool_call", "target": (NOISY_TARGETS if noisy else TARGETS)[i % 3 if noisy else i % 2],
            "metadata": {"tool": "read_file", "n": i}}


def _child(size: int, repeat: int) -> dict:
    """Runs in a fresh interpreter, so each measurement starts cold."""
    import db
    db.DB_PATH = Path(os.environ["SHADOWFAX_DB"])
    from fastapi.testclient import TestClient

    import app as app_module
    app_module.SELF_MONITOR = False
    with TestClient(app_module.app) as client:
        tok = client.post("/auth/login", json={"username": "admin", "password": "admin"}).json()["token"]
        key = client.post("/api-keys", json={"label": "bench"},
                          headers={"Authorization": f"Bearer {tok}"}).json()["api_key"]
        # An ingest key, as an agent connector uses: its response is a count.
        client.headers.update({"X-API-Key": key})
        start = datetime(2026, 1, 1, 9, 0, 0)
        with db.get_conn() as conn:
            for i in range(size):
                db.insert_event(conn, _event(i, start))
            conn.commit()
        # The first event after a restart always scans the whole history.
        t = time.perf_counter()
        client.post("/events", json=[_event(size, start)])
        first = time.perf_counter() - t
        times = []
        for k in range(repeat):
            t = time.perf_counter()
            r = client.post("/events", json=[_event(size + 1 + k, start)])
            times.append(time.perf_counter() - t)
            assert r.status_code == 200, r.text
    return {"first": first, "median": statistics.median(times)}


def _measure(size: int, repeat: int, keep_scans: bool, noisy: bool) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ, SHADOWFAX_DB=str(Path(tmp) / "bench.db"),
                   SHADOWFAX_SCAN_CACHE_ACTORS="2000" if keep_scans else "0",
                   SHADOWFAX_ADMIN_PASSWORD="admin", BENCH_NOISY="1" if noisy else "0")
        env.pop("SHADOWFAX_DATABASE_URL", None)
        env.pop("SHADOWFAX_VERIFY_SCANS", None)
        out = subprocess.run([sys.executable, __file__, "--child", str(size), str(repeat)],
                             env=env, cwd=ROOT, capture_output=True, text=True)
        if out.returncode != 0:
            raise SystemExit(out.stderr[-2000:])
        return json.loads(out.stdout.strip().splitlines()[-1])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--sizes", type=int, nargs="+", default=[1000, 10000, 50000])
    p.add_argument("--repeat", type=int, default=9)
    p.add_argument("--child", type=int, nargs=2, help=argparse.SUPPRESS)
    p.add_argument("--noisy", action="store_true", help="an agent with an alert for most of its events")
    p.add_argument("--json", action="store_true", help="print the results as JSON")
    args = p.parse_args(argv)
    if args.child:
        print(json.dumps(_child(*args.child)))
        return 0

    rows = []
    for size in args.sizes:
        before = _measure(size, args.repeat, keep_scans=False, noisy=args.noisy)
        after = _measure(size, args.repeat, keep_scans=True, noisy=args.noisy)
        rows.append({"history": size, "full_scan_ms": round(before["median"] * 1000, 1),
                     "kept_scan_ms": round(after["median"] * 1000, 1),
                     "first_after_restart_ms": round(after["first"] * 1000, 1)})
    if args.json:
        print(json.dumps(rows))
        return 0
    print(f"{'events already stored':>22} {'scan everything':>16} {'scan kept':>10} {'first after restart':>20}")
    for r in rows:
        print(f"{r['history']:>22,} {r['full_scan_ms']:>13.1f} ms {r['kept_scan_ms']:>7.1f} ms"
              f" {r['first_after_restart_ms']:>17.1f} ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
