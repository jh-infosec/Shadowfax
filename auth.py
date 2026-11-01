"""
Shadowfax authentication primitives.

Pure, dependency-free helpers for passwords, session tokens, API keys and role
comparison. No database access and no FastAPI here -- that wiring lives in
app.py, and the storage lives in db.py. Keeping the crypto in one small,
importable module is what lets the tests reach it directly.

Design notes:

- Passwords are hashed with argon2id (v0.33), using the OWASP-recommended
  settings: 19 MiB of memory, two passes, one lane. Before v0.33 they were
  PBKDF2-HMAC-SHA256 with 200,000 rounds; those hashes still verify, and are
  replaced with argon2id the next time their owner signs in.
- Session tokens and API keys are random, and only their SHA-256 hash is stored,
  so a leaked database does not hand over usable credentials.
"""

from __future__ import annotations
import hashlib
import hmac
import secrets
import threading

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# Roles, ordered. A higher rank includes everything a lower rank may do.
ROLE_RANK: dict[str, int] = {"viewer": 1, "analyst": 2, "admin": 3}
ROLES = tuple(ROLE_RANK)

PBKDF2_ITERATIONS = 200_000   # the pre-v0.33 scheme; only ever verified now
API_KEY_PREFIX = "sk_shadowfax_"

# argon2id with OWASP's recommended minimum: m=19 MiB, t=2, p=1. Memory-hard,
# so guessing on a GPU costs far more than with PBKDF2.
ARGON2_TIME_COST = 2
ARGON2_MEMORY_KIB = 19 * 1024
ARGON2_PARALLELISM = 1
_HASHER = PasswordHasher(time_cost=ARGON2_TIME_COST, memory_cost=ARGON2_MEMORY_KIB,
                         parallelism=ARGON2_PARALLELISM)
# The salt column is kept (and NOT NULL) for old databases; an argon2 hash
# carries its own salt inside the string, so this marker is all it holds.
ARGON2_SALT_MARKER = "argon2id"

# Each hash holds 19 MiB while it runs. Forty sign-in requests at once would be
# most of a gigabyte, so only a few run at a time and the rest wait their turn.
# This bounds memory; the sign-in throttle bounds how often anyone gets a turn.
MAX_CONCURRENT_HASHES = 4
_HASH_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_HASHES)


# Passwords

def _pbkdf2_hex(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return dk.hex()


def is_legacy_hash(stored_hash: str) -> bool:
    """True for a pre-v0.33 PBKDF2 hash."""
    return not stored_hash.startswith("$argon2")


def hash_password(password: str) -> tuple[str, str]:
    """Return (hash, salt column value) for a new password."""
    with _HASH_SLOTS:
        return _HASHER.hash(password), ARGON2_SALT_MARKER


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    """Check a password against what is stored, in either scheme."""
    if is_legacy_hash(expected_hash):
        try:
            with _HASH_SLOTS:
                candidate = _pbkdf2_hex(password, salt)
        except ValueError:          # a salt that is not hex: nothing can match
            return False
        return hmac.compare_digest(candidate, expected_hash)
    try:
        with _HASH_SLOTS:
            return _HASHER.verify(expected_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """Should this hash be replaced the next time we know the password? Yes for
    PBKDF2, and for argon2 made with weaker settings than today's."""
    if is_legacy_hash(stored_hash):
        return True
    try:
        return _HASHER.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


# Password policy (v0.19). Length is what makes a password hard to guess; the
# usual composition rules (one digit, one symbol...) mostly produce "Password1!".
# So: long enough, not absurdly long, not the username, not one of the handful
# of passwords that are always tried first. The upper bound keeps one request
# from asking for a key derivation over megabytes of input.
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 1024
COMMON_PASSWORDS = frozenset({
    "password", "password1", "password12", "password123", "password1234",
    "passwordpassword", "123456789012", "1234567890123", "qwertyuiopas",
    "administrator", "adminadminadmin", "changemechangeme", "letmeinletmein",
    "shadowfaxshadowfax", "iloveyouiloveyou", "welcome12345", "qwerty123456",
})


def password_problems(password: str, username: str = "") -> list[str]:
    """Why a new password is not acceptable, as sentences. Empty means fine."""
    problems = []
    if len(password) < PASSWORD_MIN_LENGTH:
        problems.append(f"must be at least {PASSWORD_MIN_LENGTH} characters")
    if len(password) > PASSWORD_MAX_LENGTH:
        problems.append(f"may be at most {PASSWORD_MAX_LENGTH} characters")
    if username and password.strip().lower() == username.strip().lower():
        problems.append("may not be the username")
    if password.strip().lower() in COMMON_PASSWORDS:
        problems.append("is one of the first passwords anyone would try")
    return problems


def generate_password() -> str:
    """A random password for an admin reset: 24 URL-safe characters."""
    return secrets.token_urlsafe(18)


# A real argon2 hash of a password nobody knows, made once at start-up with the
# current settings. It protects nothing; it exists so dummy_verify does the
# same work a real check does.
_DUMMY_HASH = _HASHER.hash(secrets.token_urlsafe(24))


def dummy_verify(password: str) -> bool:
    """Spend the same time a real verification would, and return False.

    Without this, `POST /auth/login` is a user-enumeration oracle: a known
    username costs an argon2 verification while an unknown one would return
    immediately, and the difference is easy to measure over the network.
    Verifying against a throwaway hash with the same settings makes the two
    paths cost the same. Always returns False; the return value exists only so
    callers cannot accidentally optimise the call away.
    """
    verify_password(password, ARGON2_SALT_MARKER, _DUMMY_HASH)
    return False


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
