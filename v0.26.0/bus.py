"""
In-process publish/subscribe for server-sent change notifications.

A single uvicorn process holds a set of subscriber queues, one per open SSE
connection. Mutating endpoints call `publish()` when data changes; the `/stream`
endpoint drains a queue and forwards each message to its client.

`publish()` is safe to call from FastAPI's sync threadpool (where the event
endpoints run): it hops onto the event loop captured at startup with
`call_soon_threadsafe`, so the queue is only ever touched from the loop thread.

This is not durable and not cross-process. It is the smallest thing that turns
the dashboard's poll into a push, and it is replaced by a real broker if
Shadowfax ever runs as more than one process.
"""

from __future__ import annotations
import asyncio
from typing import Any

_subscribers: set[asyncio.Queue] = set()
_loop: asyncio.AbstractEventLoop | None = None


def set_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Record the running event loop so publish() can reach it from a thread."""
    global _loop
    _loop = loop


def subscribe() -> asyncio.Queue:
    """A new subscriber queue. Call from within the event loop (the SSE handler)."""
    q: asyncio.Queue = asyncio.Queue(maxsize=64)
    _subscribers.add(q)
    return q


def unsubscribe(q: asyncio.Queue) -> None:
    _subscribers.discard(q)


def subscriber_count() -> int:
    return len(_subscribers)


def _deliver(message: dict[str, Any]) -> None:
    # Runs on the loop thread. A slow client that has filled its queue drops the
    # update rather than blocking everyone else -- the next fetch reconciles it.
    for q in list(_subscribers):
        try:
            q.put_nowait(message)
        except asyncio.QueueFull:
            pass


def publish(message: dict[str, Any]) -> None:
    """Fan a change message out to every subscriber. Safe from any thread."""
    if _loop is not None and _loop.is_running():
        _loop.call_soon_threadsafe(_deliver, message)
    else:
        _deliver(message)
