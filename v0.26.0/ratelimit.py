"""
Ingest rate limiting (v0.20).

v0.17.1 bounded each request: a body, a batch, a field. Nothing bounded how
many requests one client sends. A runaway agent harness -- or a stolen API key
-- could post a thousand valid events a second for as long as it liked, and
every one is written, chained into the ledger and rescanned.

Each ingest credential (an API key, or a signed-in user) now has a budget of
events per minute, as a token bucket: it holds up to a minute's worth, refills
continuously, and a request spends one token per event it carries -- a manifest
or an empty batch still spends one, so a flood of tiny requests is counted too.
A request that does not fit is refused whole with 429 and an honest
Retry-After, and nothing in it is stored. Half a batch would be worse than none:
the client could not tell which half.

**A flood is also a finding.** The first refusal of an episode is written into
Shadowfax's own ledger as an `ingest_throttled` event under the actor
`shadowfax-ingest`, and the detector raises `ingest_flood` (high) on it. A
credential pushing past its budget is either misconfigured or not in the hands
it was issued to, and an analyst should hear about it the same way they hear
about a brute-force attempt on the front door. Refusals within the same episode
are not recorded again -- the event is the episode, not each request in it, or
a flood would turn into a flood of evidence.

Budgets are in memory, in the one process that serves ingest, like tickets.py
and bus.py. A restart refills every bucket, which errs towards accepting
evidence.
"""

from __future__ import annotations

import math
import os
import threading
import time
from dataclasses import dataclass
from typing import Callable

DEFAULT_EVENTS_PER_MINUTE = 6000
# A credential whose last refusal was this long ago starts a new episode.
EPISODE_QUIET_SECONDS = 60.0
# Buckets idle for this long are full again anyway, so they are dropped.
IDLE_DROP_SECONDS = 600.0


@dataclass(frozen=True)
class Decision:
    allowed: bool
    remaining: int
    retry_after_seconds: int = 0
    new_episode: bool = False     # the first refusal after a quiet period


class TokenBucket:
    """Holds up to `capacity` tokens, refilling at `capacity` per minute."""

    def __init__(self, capacity: int, now: float):
        self.capacity = capacity
        self.tokens = float(capacity)
        self.updated = now
        self.last_refused: float | None = None

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self.updated)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.capacity / 60.0)
        self.updated = now

    def spend(self, cost: int, now: float) -> Decision:
        self._refill(now)
        if cost <= self.tokens:
            self.tokens -= cost
            return Decision(True, int(self.tokens))
        rate = self.capacity / 60.0
        retry = max(1, math.ceil((cost - self.tokens) / rate))
        new_episode = (self.last_refused is None
                       or now - self.last_refused >= EPISODE_QUIET_SECONDS)
        self.last_refused = now
        return Decision(False, int(self.tokens), retry, new_episode)


class RateLimiter:
    """One bucket per credential. Thread-safe; the clock is injectable."""

    def __init__(self, per_minute: int = DEFAULT_EVENTS_PER_MINUTE,
                 clock: Callable[[], float] = time.monotonic):
        if per_minute <= 0:
            raise ValueError("the ingest budget must be a positive number of events per minute")
        self.per_minute = per_minute
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: dict[str, TokenBucket] = {}

    @classmethod
    def from_env(cls, max_batch: int) -> "RateLimiter":
        raw = os.environ.get("SHADOWFAX_INGEST_EVENTS_PER_MINUTE")
        try:
            per_minute = int(raw) if raw else DEFAULT_EVENTS_PER_MINUTE
        except ValueError:
            raise ValueError(f"SHADOWFAX_INGEST_EVENTS_PER_MINUTE must be a whole number, got {raw!r}")
        if per_minute < max_batch:
            # Otherwise a full-size batch could never be accepted, however long
            # the client waited -- a limit that silently becomes a ban.
            raise ValueError(
                f"SHADOWFAX_INGEST_EVENTS_PER_MINUTE ({per_minute}) is smaller than the "
                f"largest batch allowed ({max_batch}); a full batch could never fit")
        return cls(per_minute)

    def spend(self, principal: str, cost: int) -> Decision:
        cost = max(1, cost)
        now = self._clock()
        with self._lock:
            if len(self._buckets) > 1000:
                self._drop_idle(now)
            bucket = self._buckets.get(principal)
            if bucket is None:
                bucket = self._buckets[principal] = TokenBucket(self.per_minute, now)
            return bucket.spend(cost, now)

    def _drop_idle(self, now: float) -> None:
        for key in [k for k, b in self._buckets.items() if now - b.updated > IDLE_DROP_SECONDS]:
            del self._buckets[key]


def principal_of(identity: dict) -> tuple[str, str]:
    """(bucket key, human label) for an ingest identity. Keyed on ids, which
    nothing outside Shadowfax chooses; labelled with names an admin chose."""
    if identity.get("kind") == "service":
        return f"key:{identity['api_key_id']}", f"API key '{identity.get('label') or identity['api_key_id']}'"
    return f"user:{identity['id']}", f"user '{identity['username']}'"
