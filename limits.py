"""
Request size limits (v0.17.1).

Every ingest request is written to SQLite, chained into the ledger and followed
by a rescan of each actor it touched. Until v0.17.1 nothing bounded any of
that: one authenticated client -- a misconfigured harness, or a compromised API
key -- could post a million events, or one event whose metadata was a hundred
megabytes, and Shadowfax would try to hold, store and rescan all of it.

Three layers, each catching what the one before cannot:

1. **The whole body**, checked before it is parsed. `BodySizeLimit` refuses a
   declared `Content-Length` over the limit without reading a byte, and counts
   the bytes of a body sent without one (chunked), stopping the moment it goes
   over. This is the layer that protects memory: the others run only after
   FastAPI has parsed the JSON, and parsing a gigabyte is the attack.
2. **The batch**: how many events, or findings, one request may carry. Bounds
   the rescan work a single request can trigger.
3. **Each field**: identifiers short enough to be identifiers, and metadata
   small enough to be metadata. An actor id of 900 KB is not an actor id.

A refusal is a 413 that names the limit, so a well-behaved client can split its
batch and resend. Limits come from the environment, like the sign-in throttle:
they protect the platform, and the detection policy is not the place for them.

What this does not do is rate-limit. A client can still send many small,
well-formed requests, and the event store grows with every one -- by design,
since an append-only evidence log that discarded events under load would be a
worse problem. Bounding *volume over time* belongs in front of Shadowfax, at
whatever proxy exposes it to other systems.
"""

from __future__ import annotations

import json
import re
import os
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from fastapi import HTTPException

# Identifiers and short labels. Generous for anything real, small enough that a
# field cannot be used as storage.
FIELD_MAX_LENGTH = {
    "timestamp": 64,
    "actor_id": 256,
    "actor_type": 64,
    "event_type": 64,
    "task": 256,
    "target": 2048,
}


@dataclass(frozen=True)
class Limits:
    max_body_bytes: int = 2 * 1024 * 1024
    max_events_per_request: int = 1000
    max_metadata_bytes: int = 16 * 1024

    @classmethod
    def from_env(cls) -> "Limits":
        def read(name: str, default: int) -> int:
            raw = os.environ.get(name)
            if not raw:
                return default
            try:
                value = int(raw)
            except ValueError:
                raise ValueError(f"{name} must be a whole number of bytes or events, got {raw!r}")
            if value <= 0:
                raise ValueError(f"{name} must be positive, got {value}")
            return value
        d = cls()
        return cls(
            max_body_bytes=read("SHADOWFAX_MAX_BODY_BYTES", d.max_body_bytes),
            max_events_per_request=read("SHADOWFAX_MAX_EVENTS_PER_REQUEST", d.max_events_per_request),
            max_metadata_bytes=read("SHADOWFAX_MAX_METADATA_BYTES", d.max_metadata_bytes),
        )


class BodyTooLarge(HTTPException):
    """413, raised while the body is still arriving.

    A subclass of HTTPException on purpose: FastAPI turns any *other* exception
    raised while reading a body into a generic 400 "error parsing the body",
    which would tell the client nothing about what to change.
    """

    def __init__(self, limit: int):
        super().__init__(413, f"request body exceeds {limit:,} bytes "
                              f"(SHADOWFAX_MAX_BODY_BYTES); split it and resend")


def metadata_size(metadata: Any) -> int:
    return len(json.dumps(metadata, separators=(",", ":"), default=str).encode())


class BodySizeLimit:
    """ASGI middleware enforcing the whole-body limit before anything parses it."""

    def __init__(self, app, limit: Callable[[], int]):
        self.app = app
        self.limit = limit  # read per request, so a test can change it

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.limit()

        declared = None
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = None
                break
        if declared is not None and declared > limit:
            # Refused without reading the body at all.
            await _send_413(send, BodyTooLarge(limit).detail)
            return

        received = 0

        async def counted_receive() -> dict:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise BodyTooLarge(limit)
            return message

        started = False

        async def tracking_send(message: dict) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counted_receive, tracking_send)
        except BodyTooLarge as exc:
            # Normally FastAPI has already answered 413 from the HTTPException;
            # this covers a body read outside a route (e.g. by other middleware).
            if not started:
                await _send_413(send, exc.detail)


async def _send_413(send: Callable[[dict], Awaitable[None]], detail: str) -> None:
    body = json.dumps({"detail": detail}).encode()
    await send({"type": "http.response.start", "status": 413,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


# -- text that can't be stored (v0.48.1) -------------------------------------------
#
# JSON can spell a character UTF-8 can't encode: a lone surrogate, "\udc90",
# which is what text read with the wrong encoding and "surrogateescape" turns
# into when it's sent on. Python accepts it in a str, so it got past
# validation, and then failed where the text was finally encoded: hashing the
# event into the ledger. One such character in a batch of events was a 500 for
# the whole batch, and a client retrying a 500 retried it forever. Any lone
# surrogate in a JSON body is replaced with U+FFFD before the body is parsed,
# so the request is judged on what it says. Proper pairs (an emoji written as
# "😀") decode to one character and are untouched.

_SURROGATE_ESCAPE = re.compile(rb"\\u[dD][89a-fA-F][0-9a-fA-F]{2}")
_LONE = re.compile("[\ud800-\udfff]")


def clean_text(value: Any) -> Any:
    """`value` with every lone surrogate in its strings (keys too) replaced."""
    if isinstance(value, str):
        return _LONE.sub("�", value)
    if isinstance(value, list):
        return [clean_text(v) for v in value]
    if isinstance(value, dict):
        return {clean_text(k): clean_text(v) for k, v in value.items()}
    return value


def clean_json_body(body: bytes) -> bytes:
    """A JSON body with lone surrogates replaced; unchanged when there are none
    or it isn't JSON at all (that is the parser's to refuse)."""
    if not _SURROGATE_ESCAPE.search(body):
        return body
    try:
        parsed = json.loads(body)
    except ValueError:
        return body
    cleaned = clean_text(parsed)
    if cleaned == parsed:
        return body
    return json.dumps(cleaned, ensure_ascii=False).encode("utf-8")


class CleanText:
    """ASGI middleware applying clean_json_body to JSON requests. Sits inside
    BodySizeLimit, so the size limit is applied to what was sent."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope.get("method") not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        if b"json" not in headers.get(b"content-type", b""):
            await self.app(scope, receive, send)
            return
        chunks = []
        while True:
            message = await receive()
            if message["type"] != "http.request":
                # The client went away mid-body; let the app see that.
                async def gone(last: dict = message) -> dict:
                    return last
                await self.app(scope, gone, send)
                return
            chunks.append(message.get("body", b""))
            if not message.get("more_body"):
                break
        body = clean_json_body(b"".join(chunks))
        sent = False

        async def replay() -> dict:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        scope = dict(scope)
        scope["headers"] = [(k, v) for k, v in scope.get("headers") or [] if k != b"content-length"] + [
            (b"content-length", str(len(body)).encode())]
        await self.app(scope, replay, send)
