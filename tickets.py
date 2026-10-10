"""
Single-use stream tickets (v0.17.1).

The dashboard's live updates arrive over Server-Sent Events, and the browser's
EventSource cannot set an Authorization header. Until v0.17.1 the session token
therefore rode in the URL -- `GET /stream?token=<bearer>` -- and a URL is the
one part of a request that every web server, reverse proxy and load balancer
writes to its access log by default. Anyone who could read those logs could
lift a twelve-hour session and act as that analyst.

A ticket is what goes in the URL instead. The dashboard asks for one with its
bearer token in a header (`POST /stream/ticket`), then opens the stream with the
ticket. A ticket:

* is **single-use** -- redeeming it removes it, so a ticket copied out of a log
  has already been spent by the connection that put it there;
* **expires in 30 seconds** if nobody redeems it;
* is **bound to the session that asked for it**, so the stream it opens ends
  when that session does (sign out, and every stream it opened closes);
* is stored only as a SHA-256 fingerprint, like sessions and API keys, so a
  memory dump does not yield a usable ticket either.

A session may hold only a handful of unredeemed tickets at once; asking for more
evicts the oldest. A client minting tickets in a loop therefore costs a bounded
amount of memory rather than an unbounded one.

Tickets live in memory, in the one process that serves the stream. That matches
`bus.py`, which is already single-process; a multi-process deployment would move
both to shared storage together.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable

TTL_SECONDS = 30.0
MAX_PER_SESSION = 5


@dataclass(frozen=True)
class Grant:
    """What a redeemed ticket proves: which user, through which session."""
    user_id: int
    session_fp: str


def _fingerprint(ticket: str) -> str:
    return hashlib.sha256(ticket.encode()).hexdigest()


class TicketBook:
    """Issues and redeems tickets. Thread-safe; the clock is injectable so
    expiry can be tested without sleeping."""

    def __init__(self, ttl: float = TTL_SECONDS, per_session: int = MAX_PER_SESSION,
                 clock: Callable[[], float] = time.monotonic):
        self._ttl = ttl
        self._per_session = per_session
        self._clock = clock
        self._lock = threading.Lock()
        # fingerprint -> (grant, expires_at, issued_order)
        self._tickets: dict[str, tuple[Grant, float, int]] = {}
        self._issued = 0

    def issue(self, user_id: int, session_fp: str) -> str:
        ticket = secrets.token_urlsafe(32)
        now = self._clock()
        with self._lock:
            self._prune(now)
            mine = sorted((order, fp) for fp, (g, _, order) in self._tickets.items()
                          if g.session_fp == session_fp)
            # Oldest first out, so the newest request always gets a live ticket.
            for _, fp in mine[: max(0, len(mine) - self._per_session + 1)]:
                del self._tickets[fp]
            self._issued += 1
            self._tickets[_fingerprint(ticket)] = (
                Grant(user_id, session_fp), now + self._ttl, self._issued)
        return ticket

    def redeem(self, ticket: str | None) -> Grant | None:
        """The grant behind a ticket, exactly once. None if unknown, already
        used, or expired."""
        if not ticket:
            return None
        with self._lock:
            entry = self._tickets.pop(_fingerprint(ticket), None)
        if entry is None:
            return None
        grant, expires_at, _ = entry
        return grant if self._clock() < expires_at else None

    def outstanding(self) -> int:
        with self._lock:
            self._prune(self._clock())
            return len(self._tickets)

    def _prune(self, now: float) -> None:
        for fp in [fp for fp, (_, exp, _) in self._tickets.items() if exp <= now]:
            del self._tickets[fp]
