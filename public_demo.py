"""
A public, read-only demo that resets itself (v0.44).

    docker run -p 8000:8000 -e SHADOWFAX_DEMO=1 ghcr.io/jh-infosec/shadowfax

Set SHADOWFAX_DEMO=1 and the server becomes something you can put a link to
in a CV or a README:

* **Anyone can look.** The sign-in page gets a "Look around as a visitor"
  button, which signs in to a shared account called `visitor` with the
  viewer role. Viewers can read everything and change nothing, which the
  server enforces on every endpoint; the visitor account additionally can't
  change its password or turn on two-factor, either of which would lock every
  other visitor out.
* **It's never empty and never stale.** On start, and then every
  SHADOWFAX_DEMO_RESET_MINUTES (60 by default), the server replays the
  scripted attack from demo.py against itself: the data is reset to the
  sample set and the four acts are played out, so there is always a fresh
  kill chain, a prompt injection and a brute force on screen. The replay runs
  with `--assert`, so a reset that stops raising what it should is logged.
* **Nothing a visitor does persists past the next reset,** and since they
  can't write, there's nothing to persist anyway.
* **No model calls on a stranger's behalf.** The investigation assistant uses
  its deterministic explanations in demo mode, even if ANTHROPIC_API_KEY is
  set, unless SHADOWFAX_DEMO_ALLOW_MODEL=1.

The replay signs in as `demo-operator`, an admin account whose password is
made up fresh each time the server starts and never leaves the process. It
talks to the server over loopback (SHADOWFAX_DEMO_SELF_URL, by default
http://127.0.0.1:8000, the port the image listens on). Your own admin account
still works as normal.
"""

from __future__ import annotations

import contextlib
import io
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

ENABLED = os.environ.get("SHADOWFAX_DEMO") == "1"
VISITOR = "visitor"
OPERATOR = "demo-operator"
MAX_VISITOR_SESSIONS = 500


def _minutes() -> int:
    try:
        return max(1, int(os.environ.get("SHADOWFAX_DEMO_RESET_MINUTES", "60")))
    except ValueError:
        return 60


RESET_MINUTES = _minutes()
SELF_URL = (os.environ.get("SHADOWFAX_DEMO_SELF_URL") or "http://127.0.0.1:8000").rstrip("/")
ALLOW_MODEL = os.environ.get("SHADOWFAX_DEMO_ALLOW_MODEL") == "1"

# (method, path, body, token) -> (status, body). None means real HTTP to
# SELF_URL; the tests put the API's own test client here.
Caller = Callable[[str, str, Any, "str | None"], "tuple[int, Any]"]


class State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.last_reset: datetime | None = None
        self.next_reset: datetime | None = None
        self.runs = 0
        self.last_problem: str | None = None

    def as_dict(self) -> dict[str, Any]:
        with self.lock:
            iso = lambda t: t.isoformat() if t else None   # noqa: E731
            return {"enabled": ENABLED, "reset_minutes": RESET_MINUTES,
                    "last_reset_at": iso(self.last_reset), "next_reset_at": iso(self.next_reset),
                    "resets": self.runs, "visitor": VISITOR}


STATE = State()


def replay(username: str, password: str, caller: Caller | None = None) -> list[str]:
    """Reset the data and play the scripted attack once. Returns what didn't
    happen that should have (empty when everything did)."""
    import demo

    class _Replay(demo.Demo):
        def call(self, method, path, body=None, token=...):   # noqa: D401
            if caller is None:
                return super().call(method, path, body, token)
            return caller(method, path, body, self.token if token is ... else token)

    run = _Replay(SELF_URL, 0.0, False, assert_expectations=True, username=username, password=password)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = run.run()
    if code != 0 and not run.failures:
        return [out.getvalue().strip().splitlines()[-1] if out.getvalue().strip() else f"exit {code}"]
    return list(run.failures)


def reset_once(username: str, password: str, caller: Caller | None = None) -> list[str]:
    try:
        problems = replay(username, password, caller)
    except Exception as exc:   # the loop must outlive one bad run
        problems = [f"{type(exc).__name__}: {exc}"]
    # Timed from when the replay finished, which is when the loop starts waiting.
    now = datetime.now(timezone.utc).replace(microsecond=0)
    with STATE.lock:
        STATE.last_reset = now
        STATE.next_reset = now + timedelta(minutes=RESET_MINUTES)
        STATE.runs += 1
        STATE.last_problem = "; ".join(problems) or None
    if problems:
        print(f"[demo] the reset replay didn't raise everything it should: {'; '.join(problems)}", flush=True)
    return problems


def start(username: str, password: str, stop: threading.Event, caller: Caller | None = None) -> threading.Thread:
    """Reset now, then every RESET_MINUTES until `stop` is set."""
    def loop() -> None:
        # Give the server a moment to start listening before talking to it.
        if caller is None and stop.wait(2):
            return
        while True:
            reset_once(username, password, caller)
            if stop.wait(RESET_MINUTES * 60):
                return

    t = threading.Thread(target=loop, name="shadowfax-demo", daemon=True)
    t.start()
    return t
