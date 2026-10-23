"""
Login throttling and lockout (v0.10).

Shadowfax has shipped a `brute_force_auth` detector since v0.1. It fires when an
actor racks up failed authentications inside a window -- and until this version,
Shadowfax's own login endpoint would have sailed straight past it. A tool that
detects the attack it is itself vulnerable to is not a serious tool, so this
module closes that gap: the front door now resists what the engine has always
been able to see.

Two controls, one after the other
---------------------------------
**Backoff** comes first and is deliberately gentle. After a few failures the
caller must wait a growing interval between attempts (2s, 4s, 8s … to a cap).
Someone who fat-fingered their password twice notices nothing; a script trying
a wordlist is slowed by orders of magnitude. **Lockout** follows: past
`max_failures` in the window, the scope is refused outright until the lockout
expires.

Neither control sleeps. A server that answers a flood of bad logins by holding
the connection open has turned its own defence into a resource-exhaustion
vector; Shadowfax answers immediately with `429` and an honest `Retry-After`,
and lets the client wait on its own time.

Why the scope is (username, source) and not the account
-------------------------------------------------------
Locking an *account* after N failures hands anyone who knows a username a
denial-of-service against that user: fail their login five times and they are
out. Locking the **(username, source)** pair means an attacker locks only the
pair they are hammering, while the real user signing in from their own machine
is unaffected. The trade is that an attacker with many source addresses gets
more attempts -- which is why backoff and the audit trail matter, and why this
is honest about being a slowdown rather than a wall.

`source` is the socket peer address. `X-Forwarded-For` is deliberately **not**
consulted: it is set by the client, and keying a security control on a value the
attacker chooses hands them the control -- rotate the header, reset the counter.
An operator running Shadowfax behind a proxy must therefore terminate it
somewhere that sets the peer address correctly, and that is called out in the
README rather than papered over here.

Configuration lives here, not in the detection policy
------------------------------------------------------
Shadowfax's policy governs **detection** -- what counts as suspicious. This is
**enforcement** of the platform's own front door. Putting it in the policy would
blur the line the whole project rests on ("observability, not enforcement") and
would also put an auth control behind `PUT /policy`, where any analyst could
widen it to nothing. So these settings come from the environment, like the
session TTL, and the detection policy stays about detection.

Purity
------
`evaluate()` is a pure function of `(failure timestamps, now, settings)`. It
reads no clock and touches no store, which is what lets the tests drive a
lockout, a backoff and an expiry in microseconds instead of waiting fifteen
real minutes for a result.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True)
class Settings:
    """How hard the front door pushes back. See `from_env()`."""

    # Failures within this many minutes count toward the total.
    window_minutes: int = 15
    # Failures in the window before the scope is locked out entirely.
    max_failures: int = 5
    # How long a lockout lasts, measured from the last failure.
    lockout_minutes: int = 15
    # Backoff starts once this many failures are in the window. Below it,
    # attempts are unimpeded -- a typo should cost nothing.
    backoff_after: int = 3
    # Required gap doubles per failure past the threshold, up to the cap.
    backoff_base_seconds: int = 2
    backoff_cap_seconds: int = 30
    # Whether reaching `max_failures` locks the scope outright. The source-wide
    # scope sets this False: see `for_source()`.
    lockout_enabled: bool = True
    # The same controls applied to a whole source address, across every
    # username it has tried. See `for_source()`.
    source_backoff_after: int = 10
    source_backoff_cap_seconds: int = 60

    @staticmethod
    def from_env(env: dict[str, str] | None = None) -> "Settings":
        """Settings from the environment, falling back to the defaults above.

        A malformed or negative value falls back rather than raising: a typo in
        a deployment variable should not stop the API from starting, and the
        default is the safe direction to fail in.
        """
        src = os.environ if env is None else env

        def _int(name: str, default: int, minimum: int = 0) -> int:
            try:
                value = int(src[name])
            except (KeyError, TypeError, ValueError):
                return default
            return value if value >= minimum else default

        return Settings(
            window_minutes=_int("SHADOWFAX_LOGIN_WINDOW_MINUTES", 15, 1),
            max_failures=_int("SHADOWFAX_LOGIN_MAX_FAILURES", 5, 1),
            lockout_minutes=_int("SHADOWFAX_LOGIN_LOCKOUT_MINUTES", 15, 1),
            backoff_after=_int("SHADOWFAX_LOGIN_BACKOFF_AFTER", 3, 1),
            backoff_base_seconds=_int("SHADOWFAX_LOGIN_BACKOFF_BASE_SECONDS", 2, 1),
            backoff_cap_seconds=_int("SHADOWFAX_LOGIN_BACKOFF_CAP_SECONDS", 30, 1),
            source_backoff_after=_int("SHADOWFAX_LOGIN_SOURCE_BACKOFF_AFTER", 10, 1),
            source_backoff_cap_seconds=_int(
                "SHADOWFAX_LOGIN_SOURCE_BACKOFF_CAP_SECONDS", 60, 1),
        )

    def for_source(self) -> "Settings":
        """The same rules applied to a source address rather than a scope.

        Per-(username, source) limits alone leave an obvious hole: spray one
        attempt each at a hundred usernames and no single scope ever reaches its
        threshold, so nothing trips. Worse, each miss costs Shadowfax a full
        PBKDF2 derivation -- the very work that makes the endpoint
        constant-time also makes it expensive -- so unthrottled spraying is a
        CPU exhaustion vector as much as a guessing one.

        This scope **slows but never locks**, which is the whole point of
        separating it. A source address is not a person: an office, a VPN exit
        or a NAT gateway is shared, so locking one out would let a single
        attacker deny sign-in to everyone behind it -- the attack the control
        was meant to prevent, delivered by the control itself. Backoff has no
        such failure mode. At the cap an attacker gets one guess a minute,
        which ends password spraying, while a colleague behind the same address
        waits a minute and gets in.
        """
        return Settings(
            window_minutes=self.window_minutes,
            # Irrelevant while lockout_enabled is False, but kept sane.
            max_failures=self.source_backoff_after,
            lockout_minutes=self.lockout_minutes,
            lockout_enabled=False,
            backoff_after=self.source_backoff_after,
            backoff_base_seconds=self.backoff_base_seconds,
            backoff_cap_seconds=self.source_backoff_cap_seconds,
        )


@dataclass(frozen=True)
class Decision:
    """What the front door does with this attempt, and why."""

    allowed: bool
    # "locked_out", "backoff", or None when allowed.
    reason: str | None
    # What to put in Retry-After. Always >= 1 when refused, because a
    # Retry-After of 0 invites an immediate retry and defeats the point.
    retry_after_seconds: int
    # Failures currently inside the window.
    failures: int
    locked_until: datetime | None

    @property
    def locked(self) -> bool:
        return self.reason == "locked_out"

    def message(self) -> str:
        """What the caller is told. Deliberately says nothing about whether the
        username exists -- see `evaluate()`."""
        if self.allowed:
            return "ok"
        if self.locked:
            return (f"too many failed sign-in attempts; locked out for "
                    f"{self.retry_after_seconds}s")
        return (f"too many sign-in attempts; wait {self.retry_after_seconds}s "
                f"before trying again")


ALLOWED = Decision(allowed=True, reason=None, retry_after_seconds=0,
                   failures=0, locked_until=None)


def evaluate(failures: list[datetime], now: datetime,
             settings: Settings) -> Decision:
    """Decide whether this sign-in attempt may proceed.

    `failures` is the timestamps of previous *failed* attempts for this scope,
    in any order; only those inside the window are counted. Successful sign-ins
    clear the history, so a legitimate user never accumulates a lockout across
    weeks of occasional typos.

    This runs **before** the username is looked up, and the caller records a
    failure whether or not the account exists. That is what keeps the endpoint
    from becoming a user-enumeration oracle: an unknown username locks out
    exactly like a known one, and the refusal is byte-identical.
    """
    window = timedelta(minutes=settings.window_minutes)
    recent = sorted(t for t in failures if now - t < window)
    count = len(recent)

    if count == 0:
        return ALLOWED

    last = recent[-1]

    # Lockout first: it subsumes backoff. A scope with lockout disabled falls
    # straight through to backoff no matter how high the count climbs.
    if settings.lockout_enabled and count >= settings.max_failures:
        locked_until = last + timedelta(minutes=settings.lockout_minutes)
        if now < locked_until:
            return Decision(
                allowed=False,
                reason="locked_out",
                retry_after_seconds=_seconds_until(now, locked_until),
                failures=count,
                locked_until=locked_until,
            )
        # The lockout has elapsed. Nothing to do here -- the failures have
        # aged out of the window too, since the lockout runs from the last one.
        return Decision(True, None, 0, count, None)

    if count >= settings.backoff_after:
        required = required_gap_seconds(count, settings)
        elapsed = (now - last).total_seconds()
        if elapsed < required:
            return Decision(
                allowed=False,
                reason="backoff",
                retry_after_seconds=max(1, math.ceil(required - elapsed)),
                failures=count,
                locked_until=None,
            )

    return Decision(True, None, 0, count, None)


def strictest(*decisions: Decision) -> Decision:
    """The decision that refuses hardest.

    Several scopes guard one sign-in (the (username, source) pair, and the
    source as a whole). They are evaluated independently and the harshest wins,
    so adding a scope can only ever tighten the door, never loosen it.
    """
    refusals = [d for d in decisions if not d.allowed]
    if not refusals:
        # All allowed: report the one that has seen the most failures, so the
        # caller logs the most informative count.
        return max(decisions, key=lambda d: d.failures, default=ALLOWED)
    # A lockout outranks a backoff; between equals, the longer wait wins.
    return max(refusals, key=lambda d: (d.locked, d.retry_after_seconds))


def required_gap_seconds(failures: int, settings: Settings) -> int:
    """The gap required before the next attempt, given `failures` in the window.

    Doubles per failure past `backoff_after`, capped. Exponential is the right
    shape: it stays invisible to a human retrying a typo and becomes brutal for
    anything working through a list.
    """
    if failures < settings.backoff_after:
        return 0
    steps = failures - settings.backoff_after + 1
    # Cap the exponent before computing, so a large failure count cannot
    # produce an absurd intermediate value on its way to being capped.
    steps = min(steps, 32)
    return int(min(settings.backoff_base_seconds ** steps,
                   settings.backoff_cap_seconds))


def lockout_expiry(failures: list[datetime], now: datetime,
                   settings: Settings) -> datetime | None:
    """When the current lockout ends, or None if the scope is not locked."""
    decision = evaluate(failures, now, settings)
    return decision.locked_until if decision.locked else None


def _seconds_until(now: datetime, when: datetime) -> int:
    return max(1, math.ceil((when - now).total_seconds()))
