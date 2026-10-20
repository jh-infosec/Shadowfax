"""
Timestamps (v0.21).

Every timestamp an ingest client sends is a claim the engine computes with, so
it is held to one shape on the way in and read back defensively.

An outside review of v0.20 found two ways a single crafted timestamp broke the
platform for everyone. `datetime.fromisoformat` in Python 3.11 accepts *any*
character between the date and the time, and timezone offsets: so
"2026-10-14<U+4E2D>03:00" crashed incident sorting (and with it /incidents and
/digest) until an admin wiped all data, and a single "+00:00" on the first event
of Shadowfax's own auth actor made every later comparison between naive and
aware datetimes raise -- switching off the login throttle and its audit trail.

* `normalise()` is the gate: one strict ISO 8601 shape, offsets converted to
  UTC, stored naive. Anything else is refused at the door.
* `parse()` is for reading stored values: lenient, but it always returns naive
  UTC, so rows written before v0.21 cannot make two datetimes incomparable.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

_ISO = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:?\d{2})?$")


def normalise(text: str) -> str:
    """The canonical form of a client-supplied timestamp, or ValueError."""
    if not isinstance(text, str) or not _ISO.match(text.strip()):
        raise ValueError("must be an ISO 8601 timestamp such as 2026-10-14T09:30:00 "
                         "or 2026-10-14T09:30:00Z")
    value = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.isoformat()


def parse(text: str) -> datetime:
    """A stored timestamp as naive UTC, whatever form it was stored in."""
    value = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value
