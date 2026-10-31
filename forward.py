"""
Alert forwarding to a SIEM (v0.31).

A detection that only shows on Shadowfax's own dashboard is a detection someone
has to remember to look at. Most teams already watch one place -- Splunk,
Elastic, Sentinel, QRadar -- and Shadowfax should arrive there like everything
else. This module sends each new alert, once, to:

* a **webhook** -- JSON over HTTPS, signed with HMAC-SHA256 when a secret is
  set, so the receiver can tell a real alert from a forged one; and/or
* **syslog** -- RFC 5424 over UDP or TCP, carrying **CEF** (the format nearly
  every SIEM parses out of the box) or JSON.

How it stays correct:

* **Each alert is sent once per destination.** Alert ids are deterministic, so
  a rescan that rebuilds an unchanged alert produces the same id; the outbox is
  keyed on (alert id, destination) and an alert already in it is never queued
  again. Restarts and sample-data resets do not re-send.
* **Sending never blocks ingest.** New alerts are written to the outbox in the
  same transaction as the alerts themselves (so a crash cannot lose one), and a
  background thread delivers them, retrying with exponential backoff.
* **Turning it on does not flood the SIEM with history.** The first time a
  destination is seen, every alert that already exists is recorded as a
  baseline and not sent. `SHADOWFAX_FORWARD_BACKFILL=1` sends them instead.
* **A SIEM that stops receiving is itself a finding.** When an alert is given
  up on after its last retry, an event is written under `shadowfax-forward`
  and the detector raises `forwarding_failed` (high): an attacker who can cut
  the path to the SIEM has blinded it, and that should not be silent.
* **Nothing is followed.** No redirects (a redirect could carry the signature
  elsewhere); a short timeout; the URL comes from the environment, never from
  an API call, so the API cannot be used to make the server send requests.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import urlparse

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
CEF_SEVERITY = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}
SYSLOG_SEVERITY = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}
SYSLOG_FACILITY = 13  # log audit

MAX_ATTEMPTS = 8
BASE_BACKOFF_SECONDS = 5
MAX_BACKOFF_SECONDS = 3600
TIMEOUT_SECONDS = 5
BATCH = 50
FORWARD_ACTOR_ID = "shadowfax-forward"


class ForwardError(Exception):
    pass


@dataclass(frozen=True)
class Destination:
    name: str              # "webhook" or "syslog"
    url: str
    fmt: str = "json"      # syslog: "cef" or "json"
    secret: str | None = None

    def describe(self) -> str:
        # Never the secret; the URL without credentials or query.
        p = urlparse(self.url)
        return f"{self.name} {p.scheme}://{p.hostname}{':' + str(p.port) if p.port else ''}{p.path or ''}"


@dataclass
class Config:
    destinations: list[Destination] = field(default_factory=list)
    min_severity: str = "medium"
    backfill: bool = False

    @property
    def enabled(self) -> bool:
        return bool(self.destinations)

    def wants(self, alert: dict[str, Any]) -> bool:
        return SEVERITY_RANK.get(alert.get("severity"), 99) <= SEVERITY_RANK[self.min_severity]

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Config":
        env = os.environ if env is None else env
        dests: list[Destination] = []
        hook = (env.get("SHADOWFAX_FORWARD_WEBHOOK_URL") or "").strip()
        if hook:
            scheme = urlparse(hook).scheme
            if scheme not in ("https", "http"):
                raise ValueError("SHADOWFAX_FORWARD_WEBHOOK_URL must be an http(s) URL")
            dests.append(Destination("webhook", hook, "json",
                                     (env.get("SHADOWFAX_FORWARD_WEBHOOK_SECRET") or "").strip() or None))
        syslog = (env.get("SHADOWFAX_FORWARD_SYSLOG") or "").strip()
        if syslog:
            p = urlparse(syslog)
            if p.scheme not in ("udp", "tcp") or not p.hostname:
                raise ValueError("SHADOWFAX_FORWARD_SYSLOG must look like udp://host:514 or tcp://host:6514")
            fmt = (env.get("SHADOWFAX_FORWARD_SYSLOG_FORMAT") or "cef").strip().lower()
            if fmt not in ("cef", "json"):
                raise ValueError("SHADOWFAX_FORWARD_SYSLOG_FORMAT must be cef or json")
            dests.append(Destination("syslog", syslog, fmt))
        minimum = (env.get("SHADOWFAX_FORWARD_MIN_SEVERITY") or "medium").strip().lower()
        if minimum not in SEVERITY_RANK:
            raise ValueError(f"SHADOWFAX_FORWARD_MIN_SEVERITY must be one of {', '.join(SEVERITY_RANK)}")
        backfill = (env.get("SHADOWFAX_FORWARD_BACKFILL") or "").strip().lower() in ("1", "true", "yes", "on")
        return cls(dests, minimum, backfill)


# ---- formats ----------------------------------------------------------------

def payload(alert: dict[str, Any], version: str) -> dict[str, Any]:
    """What a webhook receives, and what JSON syslog carries."""
    return {
        "source": "shadowfax",
        "shadowfax_version": version,
        "alert": {
            "id": alert["id"],
            "severity": alert["severity"],
            "category": alert["category"],
            "message": alert["message"],
            "actor_id": alert["actor_id"],
            "actor_type": alert.get("actor_type"),
            "target": alert.get("target"),
            "timestamp": alert["timestamp"],
            "attack": [t["id"] if isinstance(t, dict) else t for t in (alert.get("attack") or [])],
            "reported_by": alert.get("source_tool") or "shadowfax",
            "validated": alert.get("validated"),
            "evidence": alert.get("evidence"),
        },
    }


def _cef_header(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _cef_ext(value: Any) -> str:
    return (str(value).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\n", "\\n").replace("\r", "\\r"))


def cef(alert: dict[str, Any], version: str) -> str:
    """ArcSight Common Event Format. Header fields escape | and \\; extension
    values escape = and \\ and newlines -- an alert message is partly
    attacker-chosen text, and must not be able to forge a field."""
    try:
        rt = int(datetime.fromisoformat(alert["timestamp"]).replace(tzinfo=timezone.utc).timestamp() * 1000)
    except (ValueError, TypeError):
        rt = int(time.time() * 1000)
    attack = ",".join(t["id"] if isinstance(t, dict) else str(t) for t in (alert.get("attack") or []))
    ext = {
        "rt": rt,
        "suser": alert["actor_id"],
        "cs1Label": "actorType", "cs1": alert.get("actor_type") or "",
        "cs2Label": "target", "cs2": alert.get("target") or "",
        "cs3Label": "attack", "cs3": attack,
        "cs4Label": "alertId", "cs4": alert["id"],
        "cs5Label": "reportedBy", "cs5": alert.get("source_tool") or "shadowfax",
        "msg": alert["message"],
    }
    header = "|".join(_cef_header(v) for v in (
        "CEF:0", "Shadowfax", "Shadowfax", version, alert["category"],
        alert["category"].replace("_", " "), CEF_SEVERITY.get(alert["severity"], 5)))
    return header + "|" + " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items())


def syslog_line(alert: dict[str, Any], version: str, fmt: str, hostname: str | None = None) -> str:
    """RFC 5424: <PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG."""
    pri = SYSLOG_FACILITY * 8 + SYSLOG_SEVERITY.get(alert["severity"], 5)
    now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    host = (hostname or socket.gethostname() or "-").replace(" ", "_")[:255]
    body = cef(alert, version) if fmt == "cef" else json.dumps(payload(alert, version), separators=(",", ":"))
    return f"<{pri}>1 {now} {host} shadowfax - {alert['category'][:32]} - {body}"


def signature(secret: str, timestamp: str, body: bytes) -> str:
    """HMAC-SHA256 over "timestamp.body". The receiver recomputes it and
    rejects old timestamps, so a captured request cannot be replayed."""
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


# ---- delivery ---------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


_OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(
    context=ssl.create_default_context()))


def send(dest: Destination, alert: dict[str, Any], version: str) -> None:
    """Deliver one alert, or raise ForwardError saying why not."""
    try:
        if dest.name == "webhook":
            body = json.dumps(payload(alert, version), separators=(",", ":")).encode()
            ts = str(int(time.time()))
            headers = {"Content-Type": "application/json", "User-Agent": f"Shadowfax/{version}",
                       "X-Shadowfax-Timestamp": ts, "X-Shadowfax-Alert-Id": alert["id"]}
            if dest.secret:
                headers["X-Shadowfax-Signature"] = signature(dest.secret, ts, body)
            req = urllib.request.Request(dest.url, data=body, headers=headers, method="POST")
            with _OPENER.open(req, timeout=TIMEOUT_SECONDS) as resp:
                if not 200 <= resp.status < 300:
                    raise ForwardError(f"HTTP {resp.status}")
            return
        p = urlparse(dest.url)
        line = syslog_line(alert, version, dest.fmt).encode("utf-8", "replace")
        if p.scheme == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(TIMEOUT_SECONDS)
                s.sendto(line[:8192], (p.hostname, p.port or 514))
        else:
            with socket.create_connection((p.hostname, p.port or 6514), timeout=TIMEOUT_SECONDS) as s:
                s.sendall(str(len(line)).encode() + b" " + line)   # RFC 6587 octet counting
    except ForwardError:
        raise
    except urllib.error.HTTPError as exc:
        raise ForwardError(f"HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise ForwardError(str(getattr(exc, "reason", exc))[:200]) from None


def backoff(attempts: int) -> int:
    return min(MAX_BACKOFF_SECONDS, BASE_BACKOFF_SECONDS * 2 ** max(0, attempts - 1))


class Worker:
    """Delivers the outbox in the background. One per process; `run_once` is
    the whole of one pass, so tests can drive it without a thread."""

    def __init__(self, config: Config, version: str, get_conn: Callable, record_failure: Callable,
                 sender: Callable = send, interval: float = 2.0):
        self.config, self.version = config, version
        self.get_conn, self.record_failure, self.sender = get_conn, record_failure, sender
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is None and self.config.enabled:
            self._thread = threading.Thread(target=self._loop, name="shadowfax-forward", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.run_once()
            except Exception:   # a bad pass must not kill delivery for good
                pass

    def run_once(self, now: datetime | None = None) -> dict[str, int]:
        import db  # local: db imports nothing from here, but keep the module standalone
        now = now or datetime.now(timezone.utc).replace(tzinfo=None)
        sent = failed = retried = 0
        by_name = {d.name: d for d in self.config.destinations}
        with self.get_conn() as conn:
            due = db.forward_due(conn, now, BATCH)
            given_up: dict[str, list[str]] = {}
            for row in due:
                dest = by_name.get(row["destination"])
                alert = db.get_alert(conn, row["alert_id"])
                if dest is None or alert is None:
                    db.forward_mark(conn, row["alert_id"], row["destination"], "dropped",
                                    row["attempts"], None,
                                    "destination no longer configured" if dest is None else "alert no longer exists")
                    continue
                try:
                    self.sender(dest, alert, self.version)
                    db.forward_mark(conn, row["alert_id"], row["destination"], "sent",
                                    row["attempts"] + 1, None, None)
                    sent += 1
                except ForwardError as exc:
                    attempts = row["attempts"] + 1
                    if attempts >= MAX_ATTEMPTS:
                        db.forward_mark(conn, row["alert_id"], row["destination"], "failed",
                                        attempts, None, str(exc))
                        given_up.setdefault(dest.describe(), []).append((row["alert_id"], str(exc)))
                        failed += 1
                    else:
                        db.forward_mark(conn, row["alert_id"], row["destination"], "pending",
                                        attempts, now + timedelta(seconds=backoff(attempts)), str(exc))
                        retried += 1
            conn.commit()
            for where, items in given_up.items():
                self.record_failure(conn, where, [i for i, _ in items], items[-1][1])
                conn.commit()
        return {"sent": sent, "failed": failed, "retried": retried}
