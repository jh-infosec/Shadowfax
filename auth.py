"""
Shadowfax authentication primitives.

Pure, dependency-free helpers for passwords, session tokens, API keys and role
comparison. No database access and no FastAPI here -- that wiring lives in
app.py, and the storage lives in db.py. Keeping the crypto in one small,
importable module is what lets the tests reach it directly.

Design notes:

- Passwords are hashed with PBKDF2-HMAC-SHA256 and a per-user salt, using only
  the standard library. This is a deliberate choice for a local-development
  tool: no native build step, nothing to install. bcrypt or argon2 would be the
  upgrade for a real deployment.
- Session tokens and API keys are random, and only their SHA-256 hash is stored,
  so a leaked database does not hand over usable credentials.
"""

from __future__ import annotations
import hashlib
import hmac
import secrets

# Roles, ordered. A higher rank includes everything a lower rank may do.
ROLE_RANK: dict[str, int] = {"viewer": 1, "analyst": 2, "admin": 3}
ROLES = tuple(ROLE_RANK)

PBKDF2_ITERATIONS = 200_000
API_KEY_PREFIX = "sk_shadowfax_"


# Passwords

def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Return (hash_hex, salt_hex). Generates a salt if none is given."""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return dk.hex(), salt


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    candidate, _ = hash_password(password, salt)
    return hmac.compare_digest(candidate, expected_hash)


# Session tokens

def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def token_fingerprint(token: str) -> str:
    """The value stored for a token. The raw token is never persisted."""
    return hashlib.sha256(token.encode()).hexdigest()


# API keys

def new_api_key() -> str:
    """A fresh API key, shown to the caller once and never stored in the clear."""
    return API_KEY_PREFIX + secrets.token_urlsafe(24)


def api_key_fingerprint(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def api_key_display_prefix(key: str) -> str:
    """A short, non-secret identifier for showing which key is which."""
    return key[: len(API_KEY_PREFIX) + 6]


# Roles

def role_at_least(role: str | None, minimum: str) -> bool:
    return ROLE_RANK.get(role or "", 0) >= ROLE_RANK.get(minimum, 99)


def is_valid_role(role: str) -> bool:
    return role in ROLE_RANK
