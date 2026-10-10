"""
Shadowfax API

REST backend for the Shadowfax security platform.

The API accepts events, evaluates them against the active policy and
returns alerts for the dashboard or other clients.

Run locally:

    uvicorn app:app --reload --port 8000

Interactive API documentation:

    /docs

Shadowfax is an observability platform. It analyses activity and produces
alerts, but never blocks or modifies events.
"""

from __future__ import annotations
import asyncio
import json
import os
import secrets
import sqlite3
from pathlib import Path
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import assistant
import attack
import auth
import bus
import correlate
import db
import detectors
import digest as digest_mod
import envelope
import ledger
import permissions
import throttle
from seed_data import SAMPLE_EVENTS, DEFAULT_POLICY

APP_NAME = "Shadowfax API"
VERSION = "0.17.0"
SESSION_TTL_HOURS = 12

# Sign-in throttling (v0.10). Read once at import, from the environment rather
# than the detection policy: this is enforcement of Shadowfax's own front door,
# and the policy governs detection. See throttle.py for the reasoning.
LOGIN_THROTTLE = throttle.Settings.from_env()

# Recorded sign-in attempts are operational state for the throttle, not
# evidence, so they are pruned. The ledger keeps what matters.
LOGIN_ATTEMPT_RETENTION_HOURS = 24

# Self-monitoring (v0.10). Shadowfax has always been able to detect brute-force
# authentication; from this version its own front door is one of the things it
# watches. Failed sign-ins against the platform are ingested as ordinary events
# under this actor, so the existing brute_force_auth detector fires on attacks
# against Shadowfax itself with no special-casing anywhere in the engine.
#
# One actor, not one per attempted username: the username on a failed sign-in is
# attacker-controlled, so keying actors on it would let anyone mint actors at
# will -- or worse, post events into a real actor's timeline by "signing in" as
# them, poisoning the evidence for an unrelated investigation. The attempted
# name travels in metadata, where it is plainly untrusted data.
# An actor with no alerts at all. `info` is in the ladder from v0.11 and weighs
# nothing in the score -- see db.actor_risk_scores.
EMPTY_RISK = {"score": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

SELF_ACTOR_ID = "shadowfax-auth"
SELF_ACTOR_TYPE = "service_account"
SELF_TARGET = "shadowfax_login"

# Off only if explicitly disabled. The volume is bounded by the throttle itself:
# a scope can log at most `max_failures` failures before it is locked out, so
# the thing that stops the brute force is also what stops the audit trail from
# becoming an unauthenticated write amplifier.
SELF_MONITOR = os.environ.get("SHADOWFAX_SELF_MONITOR", "1").strip().lower() not in (
    "0", "false", "no", "off")

# Application startup

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Capture the running loop so bus.publish() can signal it from the sync
    # threadpool where the mutating endpoints run.
    bus.set_loop(asyncio.get_running_loop())
    db.init_db()
    with db.get_conn() as conn:
        _bootstrap_admin(conn)
        if db.get_policy(conn) is None:
            db.set_policy(conn, DEFAULT_POLICY)
            conn.commit()
        if not db.get_all_events(conn):
            _load_events(conn, SAMPLE_EVENTS)
            conn.commit()
        elif db.alert_row_count(conn) == 0:
            # Events survived a restart or a schema migration but alerts did
            # not (the pre-v0.3 alerts table is dropped on upgrade). Rebuild
            # them: alerts are a pure function of events and the active policy.
            _rescan_all(conn)
            conn.commit()
    yield


def _bootstrap_admin(conn: sqlite3.Connection) -> None:
    """Create the first admin account on a fresh database.

    Username and password come from SHADOWFAX_ADMIN_USERNAME /
    SHADOWFAX_ADMIN_PASSWORD. What happens when no password is given depends on
    where Shadowfax is running:

    * **From source** (`uvicorn app:app`): admin/admin, with a loud warning.
      Convenient for development and tests, and it looks like what it is.
    * **From the published image** (v0.17): the Dockerfile sets
      SHADOWFAX_GENERATE_ADMIN_PASSWORD, and a random password is generated and
      printed to the log once. An image anyone can `docker run` must not carry a
      credential everyone already knows -- a security tool shipping admin/admin
      is the finding it exists to raise.

    An empty SHADOWFAX_ADMIN_PASSWORD counts as unset. `SHADOWFAX_ADMIN_PASSWORD=`
    with nothing after it is a mistake, and honouring it literally would create
    an admin whose password is the empty string.
    """
    if db.count_users(conn) > 0:
        return
    username = os.environ.get("SHADOWFAX_ADMIN_USERNAME") or "admin"
    password = os.environ.get("SHADOWFAX_ADMIN_PASSWORD") or None
    generate = os.environ.get("SHADOWFAX_GENERATE_ADMIN_PASSWORD", "") not in ("", "0", "false")

    source = "environment"
    if password is None:
        if generate:
            password = secrets.token_urlsafe(18)
            source = "generated"
        else:
            password = "admin"
            source = "default"

    pw_hash, salt = auth.hash_password(password)
    db.create_user(conn, username, pw_hash, salt, "admin")
    conn.commit()

    # The warning follows the password, not where it came from: docker-compose
    # sets admin/admin explicitly for local use, and that deserves the same
    # warning as falling back to it.
    if source == "default" or password == "admin":
        print(
            "\n" + "=" * 72 + "\n"
            f"  SHADOWFAX: created an admin account with a known password  ->  {username} / admin\n"
            "  FOR LOCAL DEVELOPMENT ONLY. Set SHADOWFAX_ADMIN_USERNAME and\n"
            "  SHADOWFAX_ADMIN_PASSWORD, and change this password, before exposing\n"
            "  the API beyond your machine.\n"
            + "=" * 72 + "\n"
        )
    elif source == "generated":
        # Printed once, on the start that created the account, and never stored
        # anywhere but as a PBKDF2 hash. Lose it and the fix is a fresh volume,
        # or SHADOWFAX_ADMIN_PASSWORD on the first start.
        print(
            "\n" + "=" * 72 + "\n"
            "  SHADOWFAX: created the first admin account with a generated password\n"
            f"    username: {username}\n"
            f"    password: {password}\n"
            "  It is shown once, here. Set SHADOWFAX_ADMIN_PASSWORD on first start\n"
            "  to choose your own instead.\n"
            + "=" * 72 + "\n"
        )
    else:
        print(f"SHADOWFAX: created admin account '{username}' from the environment.")


def _cors_origins() -> list[str]:
    """Allowed dashboard origins. Override with SHADOWFAX_CORS_ORIGINS (a
    comma-separated list). CORS is no longer open to all origins."""
    raw = os.environ.get("SHADOWFAX_CORS_ORIGINS")
    if raw:
        return [o.strip() for o in raw.split(",") if o.strip()]
    return ["http://localhost:5173", "http://127.0.0.1:5173"]


app = FastAPI(
    title=APP_NAME,
    version=VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request models

class EventRequest(BaseModel):
    timestamp: str
    actor_id: str
    actor_type: str
    task: str | None = None
    event_type: str
    target: str
    metadata: dict[str, Any] = {}


class AlertStateUpdate(BaseModel):
    """Analyst state for an alert. Every field is optional; only those provided
    are changed. Keyed on the stable alert id, so it survives a rescan.

    `acknowledged_by` is not accepted from the client: it is set from the
    authenticated session, so an acknowledgement always records who really made
    it."""
    acknowledged: bool | None = None
    assigned_to: str | None = None
    note: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"


class CreateApiKeyRequest(BaseModel):
    label: str | None = None


class SearchRequest(BaseModel):
    query: str


# Authentication dependencies

def _identity(
    authorization: str | None = Header(None),
    x_api_key: str | None = Header(None),
) -> dict[str, Any]:
    """Resolve the caller from an `Authorization: Bearer <token>` session or an
    `X-API-Key` service key. Raises 401 if neither identifies a live caller."""
    with db.get_conn() as conn:
        if x_api_key:
            row = db.get_api_key(conn, auth.api_key_fingerprint(x_api_key))
            if row:
                db.touch_api_key(conn, row["id"])
                conn.commit()
                return {"kind": "service", "role": row["role"], "label": row["label"],
                        "api_key_id": row["id"]}
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
            user = db.get_session_user(conn, auth.token_fingerprint(token))
            if user:
                return {"kind": "user", "id": user["id"],
                        "username": user["username"], "role": user["role"]}
    raise HTTPException(status_code=401, detail="authentication required",
                        headers={"WWW-Authenticate": "Bearer"})


def require_user(identity: dict[str, Any] = Depends(_identity)) -> dict[str, Any]:
    if identity["kind"] != "user":
        raise HTTPException(403, "a signed-in user is required for this action")
    return identity


def require_role(minimum: str):
    def dep(identity: dict[str, Any] = Depends(require_user)) -> dict[str, Any]:
        if not auth.role_at_least(identity["role"], minimum):
            raise HTTPException(403, f"this action requires the '{minimum}' role or higher")
        return identity
    return dep


def allow_ingest(identity: dict[str, Any] = Depends(_identity)) -> dict[str, Any]:
    """Ingestion is open to a service API key or to an analyst-or-higher user."""
    if identity["kind"] == "service":
        return identity
    if auth.role_at_least(identity.get("role"), "analyst"):
        return identity
    raise HTTPException(403, "ingest requires a service API key or an analyst (or higher) user")


def _user_from_token(token: str | None) -> dict[str, Any] | None:
    """Resolve a session token to a user, for the SSE stream where the browser
    EventSource cannot send an Authorization header."""
    if not token:
        return None
    with db.get_conn() as conn:
        user = db.get_session_user(conn, auth.token_fingerprint(token))
    if user is None:
        return None
    return {"kind": "user", "id": user["id"], "username": user["username"], "role": user["role"]}


# Internal helpers

def _rescan_actor(conn: sqlite3.Connection, actor_id: str) -> list[dict[str, Any]]:
    policy = db.get_policy(conn) or DEFAULT_POLICY
    events = db.get_events_for_actor(conn, actor_id)
    alerts = detectors.run_for_actor(events, policy)
    db.replace_alerts_for_actor(conn, actor_id, alerts)
    return alerts


def _rescan_all(conn: sqlite3.Connection) -> None:
    for actor_id, _ in db.distinct_actors(conn):
        _rescan_actor(conn, actor_id)


def _load_events(conn: sqlite3.Connection, events: list[dict[str, Any]]) -> None:
    for e in events:
        db.insert_event(conn, e)
    _rescan_all(conn)


# Self-monitoring: Shadowfax's own front door (v0.10)

def _naive_utc_now() -> datetime:
    """UTC, without a tzinfo, to match the event corpus.

    Every timestamp in the event store is a naive ISO string, and the detectors
    compare them directly. Mixing an aware timestamp in would not be a style
    inconsistency, it would be a TypeError the first time a detector subtracted
    one from the other -- so self-monitoring events are written in the same
    shape as everything else.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


def _client_source(request: Request) -> str:
    """The peer address this request arrived from.

    `X-Forwarded-For` is deliberately ignored. It is set by the client, so
    keying the throttle on it would let an attacker reset their own counter by
    changing a header -- the control would belong to them, not to us. An
    operator behind a proxy needs the proxy to present the real peer address;
    that requirement is documented rather than quietly assumed away.
    """
    client = getattr(request, "client", None)
    host = getattr(client, "host", None) if client else None
    return host or "unknown"


def _record_auth_event(conn: sqlite3.Connection, event_type: str, username: str,
                       source: str, at: datetime, **detail: Any) -> None:
    """Write one front-door event into Shadowfax's own hash-chained log.

    This is the point of the whole feature: an attack on the monitoring platform
    lands in the same append-only ledger, raises alerts through the same
    detectors and appears in the same dashboard as an attack on anything else
    Shadowfax watches. There is no separate audit path to keep in sync, and no
    privileged log a compromised admin could edit more quietly than the rest.

    The attempted username is recorded as metadata, never as the actor id --
    it is attacker-supplied text, and it is fenced as data accordingly.
    """
    if not SELF_MONITOR:
        return
    db.insert_event(conn, {
        "timestamp": at.isoformat(),
        "actor_id": SELF_ACTOR_ID,
        "actor_type": SELF_ACTOR_TYPE,
        "task": "platform_authentication",
        "event_type": event_type,
        "target": SELF_TARGET,
        "metadata": {"attempted_username": username, "source": source, **detail},
    })
    _rescan_actor(conn, SELF_ACTOR_ID)
    bus.publish({"type": "change", "reason": "auth", "actors": [SELF_ACTOR_ID]})


# Event endpoints

@app.post("/events")
def ingest_events(events: list[EventRequest], identity: dict = Depends(allow_ingest)):
    """Ingest one or more events and refresh alerts for the affected actors."""
    if not events:
        raise HTTPException(400, "no events provided")
    with db.get_conn() as conn:
        affected_actors: set[str] = set()
        for ev in events:
            db.insert_event(conn, ev.model_dump())
            affected_actors.add(ev.actor_id)
        new_alerts: list[dict[str, Any]] = []
        for actor_id in affected_actors:
            new_alerts.extend(_rescan_actor(conn, actor_id))
        conn.commit()
    bus.publish({"type": "change", "reason": "ingest", "actors": list(affected_actors)})
    return {"ingested": len(events), "affected_actors": list(affected_actors), "alerts": new_alerts}


@app.get("/findings")
def export_findings(actor_id: str | None = None,
                    identity: dict = Depends(require_role("viewer"))):
    """Export Shadowfax's findings as envelopes (v0.15). See
    `findings-envelope.md`.

    v0.11 made Shadowfax a consumer of the shared format; this makes it a
    producer, so the portfolio's other tools can read Shadowfax the way
    Shadowfax reads them. Read-only.

    One envelope per actor, because the format describes a single subject.
    Without `actor_id` the response is a JSON array of them -- the array is
    Shadowfax's own convenience and is **not** part of the format; each element
    is a conformant envelope, and a consumer that wants one takes one.

    Worth knowing: Shadowfax's own ingest will refuse these. A finding's key
    becomes an alert category and `POST /findings` rejects any key that
    collides with a native detector category -- which is every key in here.
    That is not an oversight. It means Shadowfax cannot be fed its own output,
    and the feedback loop is closed by construction rather than by a rule
    somebody has to remember.
    """
    with db.get_conn() as conn:
        if actor_id is not None:
            if not db.get_events_for_actor(conn, actor_id):
                raise HTTPException(404, f"no events for actor '{actor_id}'")
            actors = [actor_id]
        else:
            actors = [a for a, _ in db.distinct_actors(conn)]

        envelopes = []
        for aid in actors:
            alerts = db.query_alerts(conn, actor_id=aid, limit=1000)
            events = db.get_events_for_actor(conn, aid)
            envelopes.append(envelope.from_alerts(aid, alerts, events, VERSION))

    return envelopes[0] if actor_id is not None else envelopes


@app.post("/findings")
def ingest_findings(doc: dict[str, Any], identity: dict = Depends(allow_ingest)):
    """Ingest a findings envelope (v0.11). See `findings-envelope.md`.

    Shadowfax knows nothing about the emitter. Anything that writes the envelope
    is ingestible, which is what makes
    `maltriage sample.exe --envelope | shadowfax ingest` a pipe rather than an
    integration.

    Findings are stored as ordinary events and turned back into alerts by a
    detector, so they obey the same invariant as everything else: alerts are a
    pure function of (an actor's events, policy), recomputed on every rescan.
    Writing alert rows directly would have been fewer lines and would have left
    rows that quietly disappeared at the next rescan of that actor.
    """
    try:
        envelope.validate(doc, detectors.NATIVE_CATEGORIES)
    except envelope.EnvelopeError as err:
        # Reject the whole document rather than keeping the findings we happen
        # to like. A partially-accepted envelope hides an emitter's bug, and
        # whoever is writing the next emitter deserves to be told exactly which
        # field is wrong.
        raise HTTPException(400, f"invalid findings envelope — {err.describe()}")

    tool = doc["source"]["tool"]
    actor_id = envelope.actor_for(doc["subject"])

    with db.get_conn() as conn:
        actor_types = dict(db.distinct_actors(conn))
        events = envelope.to_events(doc, actor_types)

        already = db.known_finding_ids(
            conn, tool, [e["metadata"]["finding"]["id"] for e in events])
        fresh = [e for e in events if e["metadata"]["finding"]["id"] not in already]

        for event in fresh:
            db.insert_event(conn, event)
        alerts = _rescan_actor(conn, actor_id) if fresh else []
        conn.commit()

    if fresh:
        bus.publish({"type": "change", "reason": "findings", "actors": [actor_id]})

    return {
        "accepted": len(fresh),
        "skipped": len(already),
        "actor_id": actor_id,
        "envelope": envelope.summarise(doc),
        "alerts": alerts,
    }


@app.get("/events")
def list_events(actor_id: str | None = None, identity: dict = Depends(require_role("viewer"))):
    with db.get_conn() as conn:
        if actor_id:
            return db.get_events_for_actor(conn, actor_id)
        return db.get_all_events(conn)


# Alert endpoints

@app.get("/alerts")
def list_alerts(
    severity: list[str] | None = Query(None),
    actor_type: list[str] | None = Query(None),
    actor_id: str | None = None,
    category: list[str] | None = Query(None),
    search: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 500,
    identity: dict = Depends(require_role("viewer")),
):
    with db.get_conn() as conn:
        return db.query_alerts(conn, severity, actor_type, actor_id, category,
                               search, since, until, limit)


@app.patch("/alerts/{alert_id}/state")
def update_alert_state(alert_id: str, update: AlertStateUpdate,
                       identity: dict = Depends(require_role("analyst"))):
    """Acknowledge, assign or annotate a single alert.

    State attaches to the alert's deterministic id and lives in its own table,
    so it persists across the rescans that rebuild the alert on every new event
    for that actor. `acknowledged_by` is taken from the signed-in analyst, not
    from the request body.
    """
    with db.get_conn() as conn:
        if db.get_alert(conn, alert_id) is None:
            raise HTTPException(404, f"no alert with id '{alert_id}'")
        state = db.set_alert_state(
            conn,
            alert_id,
            acknowledged=update.acknowledged,
            acknowledged_by=identity["username"] if update.acknowledged else None,
            assigned_to=update.assigned_to,
            note=update.note,
        )
        conn.commit()
    bus.publish({"type": "change", "reason": "alert_state", "alert_id": alert_id})
    return state


@app.get("/alerts/{alert_id}/explain")
def explain_alert(alert_id: str, identity: dict = Depends(require_role("viewer"))):
    """A natural-language explanation of one alert, for an analyst.

    Read-only: it assembles an evidence brief from the stored alert and its
    actor's events and asks the investigation assistant to describe it. It
    creates and changes nothing -- the assistant explains, it never decides.
    With no model configured the narrative is generated deterministically from
    the same brief.
    """
    with db.get_conn() as conn:
        alert = db.get_alert(conn, alert_id)
        if alert is None:
            raise HTTPException(404, f"no alert with id '{alert_id}'")
        events = db.get_events_for_actor(conn, alert["actor_id"])
    brief = assistant.build_alert_brief(alert, events)
    return assistant.explain(brief)


@app.get("/healthz")
def healthz():
    """Liveness, for a container runtime. Unauthenticated by necessity and
    deliberately uninteresting: a health check that needed a credential would be
    useless to an orchestrator, and one that reported internals would be a free
    reconnaissance endpoint. It says the process is up and which version is
    running -- nothing about the data, the users or the configuration."""
    return {"status": "ok", "service": APP_NAME, "version": VERSION}


@app.get("/stats")
def stats(identity: dict = Depends(require_role("viewer"))):
    with db.get_conn() as conn:
        return {
            "alert_counts": db.alert_counts(conn),
            "actor_count": len(db.distinct_actors(conn)),
            "event_count": len(db.get_all_events(conn)),
        }


# Live stream

@app.get("/stream")
async def stream(token: str | None = None, authorization: str | None = Header(None)):
    """Server-Sent Events: a `change` event is pushed whenever alerts change,
    replacing the dashboard's poll loop.

    Auth is by `?token=<bearer>` because the browser EventSource API cannot set
    an Authorization header; a Bearer header is accepted too, for non-browser
    clients. Any signed-in user may stream; service API keys may not.
    """
    tok = token
    if not tok and authorization and authorization.lower().startswith("bearer "):
        tok = authorization[7:].strip()
    if _user_from_token(tok) is None:
        raise HTTPException(status_code=401, detail="authentication required")

    queue = bus.subscribe()

    async def gen():
        try:
            # An immediate hello confirms the connection is open.
            yield "event: hello\ndata: {}\n\n"
            while True:
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"event: change\ndata: {json.dumps(message)}\n\n"
                except asyncio.TimeoutError:
                    # A comment line keeps proxies and the browser from timing
                    # the idle connection out.
                    yield ": keepalive\n\n"
        finally:
            bus.unsubscribe(queue)

    return StreamingResponse(gen(), media_type="text/event-stream")


# Actor endpoints

@app.get("/actors")
def list_actors(identity: dict = Depends(require_role("viewer"))):
    with db.get_conn() as conn:
        actors = db.distinct_actors(conn)
        risk = db.actor_risk_scores(conn)
        out = []
        for actor_id, actor_type in actors:
            events = db.get_events_for_actor(conn, actor_id)
            r = risk.get(actor_id, EMPTY_RISK)
            out.append({
                "actor_id": actor_id,
                "actor_type": actor_type,
                "event_count": len(events),
                "risk_score": r["score"],
                "critical": r["critical"], "high": r["high"], "medium": r["medium"],
                "low": r["low"], "info": r["info"],
            })
        out.sort(key=lambda a: a["risk_score"], reverse=True)
        return out


@app.get("/actors/{actor_id}")
def actor_detail(actor_id: str, identity: dict = Depends(require_role("viewer"))):
    with db.get_conn() as conn:
        events = db.get_events_for_actor(conn, actor_id)
        if not events:
            raise HTTPException(404, f"no events for actor '{actor_id}'")
        alerts = db.query_alerts(conn, actor_id=actor_id, limit=1000)
        risk = db.actor_risk_scores(conn).get(actor_id, EMPTY_RISK)
        policy = db.get_policy(conn) or DEFAULT_POLICY
        return {"actor_id": actor_id, "events": events, "alerts": alerts, "risk": risk,
                "permissions": permissions.describe(actor_id, policy)}


@app.get("/actors/{actor_id}/permissions")
def actor_permissions(
    actor_id: str,
    tool: str | None = Query(None, description="a tool the actor might call"),
    target: str | None = Query(None, description="a target the actor might touch"),
    actor_type: str = Query(permissions.GOVERNED_ACTOR_TYPE),
    identity: dict = Depends(require_role("viewer")),
):
    """The permission profile that governs an actor, and -- given a tool, a
    target, or both -- whether that action would be reported (v0.16).

    This is the detector's own judgement asked in advance, for writing a profile
    or for an agent runtime that wants to refuse before it acts. It deliberately
    does not 404 for an actor with no events: the most useful time to ask what a
    new agent may do is before it has done anything.
    """
    with db.get_conn() as conn:
        policy = db.get_policy(conn) or DEFAULT_POLICY
    out = {"actor_id": actor_id, **permissions.describe(actor_id, policy)}
    if tool is not None or target is not None:
        out["check"] = {"tool": tool, "target": target,
                        **permissions.check(actor_id, policy, tool, target, actor_type)}
    return out


# Incident endpoints (correlation)

@app.get("/incidents")
def list_incidents(identity: dict = Depends(require_role("viewer"))):
    """Alerts correlated into incidents: a burst of one actor's alerts within
    the policy's correlation window. Computed on read from stored alerts."""
    with db.get_conn() as conn:
        policy = db.get_policy(conn) or DEFAULT_POLICY
        alerts = db.query_alerts(conn, limit=100_000)
    window = policy.get("correlation_window_minutes", 30)
    chain_min = policy.get("attack_chain_min_stages", 3)
    return correlate.correlate(alerts, window, chain_min)


@app.get("/incidents/{incident_id}")
def incident_detail(incident_id: str, identity: dict = Depends(require_role("viewer"))):
    with db.get_conn() as conn:
        policy = db.get_policy(conn) or DEFAULT_POLICY
        alerts = db.query_alerts(conn, limit=100_000)
    window = policy.get("correlation_window_minutes", 30)
    chain_min = policy.get("attack_chain_min_stages", 3)
    incidents = correlate.correlate(alerts, window, chain_min)
    incident = next((i for i in incidents if i["id"] == incident_id), None)
    if incident is None:
        raise HTTPException(404, f"no incident with id '{incident_id}'")
    by_id = {a["id"]: a for a in alerts}
    members = [by_id[aid] for aid in incident["alert_ids"] if aid in by_id]
    return {**incident, "alerts": members, "report": correlate.render_report(incident, by_id)}


@app.get("/incidents/{incident_id}/explain")
def explain_incident(incident_id: str, identity: dict = Depends(require_role("viewer"))):
    """A natural-language threat summary of one correlated incident.

    Read-only, like /alerts/{id}/explain: correlation and detection have already
    decided the facts; the assistant only turns the incident's evidence brief
    into prose. Falls back to a deterministic narrative when no model is set.
    """
    with db.get_conn() as conn:
        policy = db.get_policy(conn) or DEFAULT_POLICY
        alerts = db.query_alerts(conn, limit=100_000)
    window = policy.get("correlation_window_minutes", 30)
    chain_min = policy.get("attack_chain_min_stages", 3)
    incidents = correlate.correlate(alerts, window, chain_min)
    incident = next((i for i in incidents if i["id"] == incident_id), None)
    if incident is None:
        raise HTTPException(404, f"no incident with id '{incident_id}'")
    by_id = {a["id"]: a for a in alerts}
    members = [by_id[aid] for aid in incident["alert_ids"] if aid in by_id]
    brief = assistant.build_incident_brief(incident, members)
    return assistant.explain(brief)


@app.post("/search")
def nl_search(req: SearchRequest, identity: dict = Depends(require_role("viewer"))):
    """Natural-language alert search (v0.5.2). The assistant *translates* the
    plain-English query into a Shadowfax alert filter; every proposed value is
    validated against known enums, then the deterministic `query_alerts` runs
    it. Read-only: it creates nothing and decides nothing -- it only chooses
    which existing alerts to show, and returns how it read the query so the
    analyst can see and adjust it."""
    with db.get_conn() as conn:
        categories = db.distinct_alert_categories(conn)
        translated = assistant.translate_query(req.query, categories)
        f = translated["filters"]
        alerts = db.query_alerts(
            conn,
            severity=f.get("severity"),
            actor_type=f.get("actor_type"),
            actor_id=f.get("actor_id"),
            category=f.get("category"),
            search=f.get("search"),
            since=f.get("since"),
            until=f.get("until"),
        )
    return {**translated, "count": len(alerts), "alerts": alerts}


@app.get("/digest")
def triage_digest(limit: int = digest_mod.DEFAULT_LIMIT, narrative: bool = True,
                  identity: dict = Depends(require_role("viewer"))):
    """The triage queue (v0.8): the open incidents that most need an analyst.

    Read-only. The ranking is computed deterministically by `digest.py` from
    facts already on record -- severity, completed attack chains, unacknowledged
    volume, age -- and every item carries the reasons behind its position. The
    assistant may add a covering narrative, but it cannot re-order the queue and
    nothing here acknowledges, closes or acts on anything: an incident leaves the
    digest only when a human acknowledges its alerts.
    """
    with db.get_conn() as conn:
        policy = db.get_policy(conn) or DEFAULT_POLICY
        alerts = db.query_alerts(conn, limit=100_000)
    window = policy.get("correlation_window_minutes", 30)
    chain_min = policy.get("attack_chain_min_stages", 3)
    incidents = correlate.correlate(alerts, window, chain_min)
    by_id = {a["id"]: a for a in alerts}
    result = digest_mod.build_digest(incidents, by_id, limit=limit)
    result["text"] = digest_mod.render_digest(result)
    if narrative:
        explained = assistant.explain(assistant.build_digest_brief(result))
        result["narrative"] = explained.get("narrative")
        result["source"] = explained.get("source")
    return result


@app.get("/ledger/verify")
def verify_ledger(identity: dict = Depends(require_role("viewer"))):
    """Verify the tamper-evident event ledger (v0.9).

    Recomputes the hash chain over every stored event in insertion order and
    compares it with the stored links and the recorded head. Reports the *first*
    position where they diverge, so a break is located rather than merely
    announced. Read-only, and safe to run on a schedule.
    """
    with db.get_conn() as conn:
        entries = db.ledger_entries(conn)
        head = db.get_ledger_head(conn)
    report = ledger.verify_chain(entries, head["entry_count"], head["head_hash"])
    report["summary"] = ledger.describe(report)
    report["recorded_head"] = head
    return report


@app.get("/ledger/head")
def ledger_head(identity: dict = Depends(require_role("viewer"))):
    """The ledger's current head hash and entry count.

    Export this somewhere outside the database's own trust boundary -- a log
    server, a signed commit, a colleague's inbox. Anchoring the head off-box is
    what turns "we can tell it changed" into something a third party can check.
    """
    with db.get_conn() as conn:
        return db.get_ledger_head(conn)


@app.get("/assistant/status")
def assistant_status(identity: dict = Depends(require_role("viewer"))):
    """Whether explanations come from a model or the deterministic fallback, so
    the dashboard can label them honestly."""
    return assistant.status()


# Policy endpoints

@app.get("/attack")
def attack_registry(identity: dict = Depends(require_role("viewer"))):
    """The shared MITRE ATT&CK technique registry (id -> name, tactic, url).
    Alerts reference these ids; this is where the metadata lives."""
    return attack.registry()


@app.get("/policy")
def get_policy(identity: dict = Depends(require_role("viewer"))):
    with db.get_conn() as conn:
        return db.get_policy(conn) or DEFAULT_POLICY


@app.put("/policy")
def update_policy(policy: dict[str, Any], identity: dict = Depends(require_role("analyst"))):
    # Refused before it is stored, not after: a malformed permission profile
    # does not fail loudly when it runs, it quietly grants more than it says.
    problems = permissions.validate(policy)
    if problems:
        raise HTTPException(400, {"message": "policy refused", "problems": problems})
    with db.get_conn() as conn:
        db.set_policy(conn, policy)
        _rescan_all(conn)
        conn.commit()
    bus.publish({"type": "change", "reason": "policy"})
    return {"status": "policy updated, all actors rescanned"}


# Administrative endpoints

@app.post("/reset")
def reset(identity: dict = Depends(require_role("admin"))):
    with db.get_conn() as conn:
        db.wipe_all(conn)
        db.set_policy(conn, DEFAULT_POLICY)
        _load_events(conn, SAMPLE_EVENTS)
        conn.commit()
    bus.publish({"type": "change", "reason": "reset"})
    return {"status": "reset to bundled sample data"}


# Authentication endpoints

@app.post("/auth/login")
def login(req: LoginRequest, request: Request):
    """Sign in, subject to backoff and lockout (v0.10).

    The order below is deliberate. The throttle is consulted *before* the
    username is looked up, and a failure is recorded whether or not the account
    exists, so a caller cannot tell real usernames from imaginary ones by how
    the endpoint behaves. When there is no such user, `auth.dummy_verify` burns
    the same PBKDF2 work a real check would, closing the timing side channel
    that a straight early return leaves open.

    Every refusal is recorded, and the security-relevant ones are written into
    Shadowfax's own hash-chained ledger -- see `_record_auth_event`.
    """
    source = _client_source(request)
    now = _naive_utc_now()
    window_start = now - timedelta(minutes=LOGIN_THROTTLE.window_minutes)

    with db.get_conn() as conn:
        failures = db.recent_login_failures(conn, req.username, source, window_start)
        # Two scopes: this username from this source, and this source across
        # every username it has tried. The second is what stops spraying, where
        # no single scope ever reaches its own threshold.
        source_failures = db.recent_source_failures(conn, source, window_start)
        decision = throttle.strictest(
            throttle.evaluate(failures, now, LOGIN_THROTTLE),
            throttle.evaluate(source_failures, now, LOGIN_THROTTLE.for_source()),
        )

        if not decision.allowed:
            # Refused before any credential work: a locked-out caller costs us
            # a cheap index read, not a 200,000-round key derivation. That is
            # the difference between a throttle and a self-inflicted DoS, and
            # it is also why the refusal is not recorded as another row --
            # a flood must not be able to grow our own tables.
            conn.commit()
            raise HTTPException(
                429, decision.message(),
                headers={"Retry-After": str(decision.retry_after_seconds)},
            )

        user = db.get_user_by_username(conn, req.username)
        if user is None:
            ok = auth.dummy_verify(req.password)
        else:
            ok = auth.verify_password(req.password, user["salt"], user["password_hash"])

        if not ok:
            db.record_login_attempt(conn, req.username, source, "failure", now)
            _record_auth_event(conn, "auth_failure", req.username, source, now)

            # Re-evaluate including the failure just recorded, so the lockout
            # event is emitted exactly once -- at the attempt that trips it,
            # not on every refused attempt afterwards.
            after = throttle.strictest(
                throttle.evaluate(failures + [now], now, LOGIN_THROTTLE),
                throttle.evaluate(source_failures + [now], now,
                                  LOGIN_THROTTLE.for_source()),
            )
            if after.locked:
                _record_auth_event(conn, "auth_lockout", req.username, source, now,
                                   locked_for_seconds=after.retry_after_seconds,
                                   failures=after.failures)
                # Rare and bounded, so a good moment to take out the rubbish
                # without putting a DELETE on every failed sign-in.
                db.prune_login_attempts(
                    conn, now - timedelta(hours=LOGIN_ATTEMPT_RETENTION_HOURS))
            conn.commit()
            # One message for both branches. "Invalid username or password" is
            # the whole point: naming which half was wrong is a free gift to
            # anyone enumerating accounts.
            raise HTTPException(401, "invalid username or password")

        token = auth.new_session_token()
        expires = datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_HOURS)
        db.create_session(conn, auth.token_fingerprint(token), user["id"], expires.isoformat())
        db.record_login_attempt(conn, req.username, source, "success", now)
        # A successful sign-in clears the scope's failures, so a user who
        # mistypes twice and then gets it right carries nothing forward.
        db.clear_login_failures(conn, req.username, source)
        db.prune_login_attempts(conn, now - timedelta(hours=LOGIN_ATTEMPT_RETENTION_HOURS))
        conn.commit()

    return {
        "token": token,
        "user": {"username": user["username"], "role": user["role"]},
        "expires_at": expires.isoformat(),
    }


@app.get("/auth/lockouts")
def list_lockouts(identity: dict = Depends(require_role("admin"))):
    """Scopes currently locked out, and those partway there.

    Read-only. The throttle decides what "locked" means here exactly as it does
    on the sign-in path -- one implementation of the rule, so this view cannot
    drift from the behaviour it describes.
    """
    now = _naive_utc_now()
    window_start = now - timedelta(minutes=LOGIN_THROTTLE.window_minutes)
    out = []
    with db.get_conn() as conn:
        for scope in db.login_failure_scopes(conn, window_start):
            decision = throttle.evaluate(scope["failures"], now, LOGIN_THROTTLE)
            out.append({
                "username": scope["username"],
                "source": scope["source"],
                "failures": len(scope["failures"]),
                "locked": decision.locked,
                "locked_until": decision.locked_until.isoformat() if decision.locked_until else None,
                "retry_after_seconds": decision.retry_after_seconds if not decision.allowed else 0,
                "last_failure": max(scope["failures"]).isoformat() if scope["failures"] else None,
            })
    out.sort(key=lambda s: (not s["locked"], -s["failures"]))
    return {
        "now": now.isoformat(),
        "settings": {
            "window_minutes": LOGIN_THROTTLE.window_minutes,
            "max_failures": LOGIN_THROTTLE.max_failures,
            "lockout_minutes": LOGIN_THROTTLE.lockout_minutes,
            "backoff_after": LOGIN_THROTTLE.backoff_after,
        },
        "scopes": out,
    }


@app.delete("/auth/lockouts/{username}")
def clear_lockout(username: str, identity: dict = Depends(require_role("admin"))):
    """Release a locked-out user (admin only).

    Lockouts expire on their own, so this is for the case where a colleague is
    locked out and needs back in now. It is an explicit, attributable action
    rather than a side effect of something else -- and it is written into the
    ledger, because "the lockout went away" is exactly the kind of event whose
    absence from an audit trail would be suspicious.
    """
    now = _naive_utc_now()
    with db.get_conn() as conn:
        cleared = db.clear_login_failures(conn, username)
        if cleared:
            _record_auth_event(conn, "auth_lockout_cleared", username, "admin", now,
                               cleared_by=identity["username"], cleared=cleared)
        conn.commit()
    return {"username": username, "cleared_failures": cleared}


@app.post("/auth/logout")
def logout(authorization: str | None = Header(None),
           identity: dict = Depends(require_user)):
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        with db.get_conn() as conn:
            db.delete_session(conn, auth.token_fingerprint(token))
            conn.commit()
    return {"status": "logged out"}


@app.get("/auth/me")
def whoami(identity: dict = Depends(require_user)):
    return {"username": identity["username"], "role": identity["role"]}


# User management (admin only)

@app.get("/users")
def list_users(identity: dict = Depends(require_role("admin"))):
    with db.get_conn() as conn:
        return db.list_users(conn)


@app.post("/users")
def create_user(req: CreateUserRequest, identity: dict = Depends(require_role("admin"))):
    if not auth.is_valid_role(req.role):
        raise HTTPException(400, f"invalid role '{req.role}', expected one of {list(auth.ROLES)}")
    with db.get_conn() as conn:
        if db.get_user_by_username(conn, req.username):
            raise HTTPException(409, f"user '{req.username}' already exists")
        pw_hash, salt = auth.hash_password(req.password)
        user = db.create_user(conn, req.username, pw_hash, salt, req.role)
        conn.commit()
    return user


# API keys for programmatic ingest (admin only)

@app.get("/api-keys")
def list_api_keys(identity: dict = Depends(require_role("admin"))):
    with db.get_conn() as conn:
        return db.list_api_keys(conn)


@app.post("/api-keys")
def create_api_key(req: CreateApiKeyRequest, identity: dict = Depends(require_role("admin"))):
    key = auth.new_api_key()
    with db.get_conn() as conn:
        rec = db.create_api_key(conn, auth.api_key_fingerprint(key),
                                auth.api_key_display_prefix(key), req.label, "service")
        conn.commit()
    # The plaintext key is returned exactly once and never stored in the clear.
    return {**rec, "api_key": key, "note": "store this now; it will not be shown again"}


@app.delete("/api-keys/{key_id}")
def delete_api_key(key_id: int, identity: dict = Depends(require_role("admin"))):
    with db.get_conn() as conn:
        deleted = db.delete_api_key(conn, key_id)
        conn.commit()
    if not deleted:
        raise HTTPException(404, f"no API key with id {key_id}")
    return {"status": "deleted"}


# Serving the dashboard (v0.12)
#
# When a built dashboard is present, the API serves it from its own origin. This
# is what makes the packaged container a single process on a single port: no
# second web server, no CORS to configure, and no "works on my machine" gap
# between the port the dashboard was built for and the port it ends up on.
#
# The mount is registered last, after every API route, because routes are
# matched in order -- so /alerts, /docs and the rest keep winning and only
# genuinely unclaimed paths fall through to a file. The dashboard has no
# client-side router, so there are no deep links for this to mishandle.
#
# In development there is no dist/ directory and nothing is mounted: the Vite
# dev server serves the dashboard on :5173 and talks to this API on :8000,
# which is the CORS allowlist's reason for existing.
_DASHBOARD_DIST = Path(__file__).parent / "frontend" / "dist"

if _DASHBOARD_DIST.is_dir():
    app.mount("/", StaticFiles(directory=str(_DASHBOARD_DIST), html=True),
              name="dashboard")
