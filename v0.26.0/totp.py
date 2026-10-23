"""
Time-based one-time passwords for sign-in (v0.25).

A password can leak -- phished, reused, read over a shoulder. Throttling slows
someone guessing it; it does nothing for someone who already has it. A second
factor does: the six-digit code from an authenticator app on the owner's phone.

This is RFC 6238 TOTP with the parameters every authenticator app assumes --
HMAC-SHA1, 30-second steps, six digits -- in the standard library alone, so
there is no dependency to audit and nothing here that a reviewer cannot read in
one sitting. The secret is 160 random bits, the size RFC 4226 recommends.

Three properties matter more than the arithmetic:

* **A code works once.** The step a code was accepted for is stored, and a code
  for that step or an earlier one is refused, so a code read over a shoulder or
  out of a proxy log cannot be replayed within its 90-second acceptance window.
* **Clock drift is tolerated by one step either way** -- the usual allowance,
  and no more: every extra step accepted is another million-to-one chance for a
  guesser.
* **Comparison is constant-time**, like every other credential check here.

Recovery codes are for the lost phone. Ten are issued when two-factor is turned
on, shown once, stored only as SHA-256 fingerprints -- each is about 59 random bits,
far beyond guessing, so a slow password hash would add nothing -- and each
works once.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

STEP_SECONDS = 30
DIGITS = 6
DRIFT_STEPS = 1            # accept the previous and next step as well
SECRET_BYTES = 20          # 160 bits (RFC 4226 section 4)
RECOVERY_CODE_COUNT = 10
ISSUER = "Shadowfax"

# Recovery codes are typed by people, from paper, in a hurry: no i, l, o, 0
# or 1 to confuse with each other.
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"


def new_secret() -> str:
    """A fresh secret, base32 without padding, as authenticator apps take it."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    padded = secret.upper() + "=" * (-len(secret) % 8)
    return base64.b32decode(padded)


def code_at(secret: str, step: int) -> str:
    """The code for one time step (RFC 4226 HOTP with the step as counter)."""
    digest = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** DIGITS).zfill(DIGITS)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP_SECONDS)


def normalise_code(code: str) -> str:
    """Apps show '123 456'; people type it that way."""
    return "".join(ch for ch in (code or "") if not ch.isspace())


def verify(secret: str, code: str, *, last_step: int | None = None,
           now: float | None = None) -> int | None:
    """The step `code` is valid for, or None.

    Steps at or before `last_step` -- the step of the last accepted code -- are
    never matched, which is what makes a code single-use.
    """
    code = normalise_code(code)
    if len(code) != DIGITS or not code.isdigit():
        return None
    step = current_step(now)
    matched = None
    for candidate in range(step - DRIFT_STEPS, step + DRIFT_STEPS + 1):
        # Every candidate is compared, match or not, so the time taken does
        # not depend on which step (if any) matched.
        if hmac.compare_digest(code_at(secret, candidate), code):
            if last_step is None or candidate > last_step:
                matched = candidate if matched is None else max(matched, candidate)
    return matched


def provisioning_uri(secret: str, username: str, issuer: str = ISSUER) -> str:
    """The otpauth:// URI an authenticator app reads from a QR code."""
    label = quote(f"{issuer}:{username}", safe=":@")
    params = urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1",
                        "digits": DIGITS, "period": STEP_SECONDS})
    return f"otpauth://totp/{label}?{params}"


def new_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Codes like 'k7rm-3qxp-vb2d': 12 characters from a 31-letter alphabet."""
    def one() -> str:
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(12))
        return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"
    return [one() for _ in range(count)]


def recovery_fingerprint(code: str) -> str:
    cleaned = "".join(ch for ch in (code or "").lower() if ch.isalnum())
    return hashlib.sha256(f"shadowfax-recovery:{cleaned}".encode()).hexdigest()
