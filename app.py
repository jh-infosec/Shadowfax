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
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import auth
import bus
import db
import detectors
from seed_data import SAMPLE_EVENTS, DEFAULT_POLICY

APP_NAME = "Shadowfax API"
VERSION = "0.4.5"
SESSION_TTL_HOURS = 12

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
    SHADOWFAX_ADMIN_PASSWORD. If the password is unset, a default admin/admin is
    created and a loud warning is printed -- convenient for local development and
    tests, unsafe anywhere else.
    """
    if db.count_users(conn) > 0:
        return
    username = os.environ.get("SHADOWFAX_ADMIN_USERNAME", "admin")
    password = os.environ.get("SHADOWFAX_ADMIN_PASSWORD")
    using_default = password is None
    if using_default:
        password = "admin"
    pw_hash, salt = auth.hash_password(password)
    db.create_user(conn, username, pw_hash, salt, "admin")
    conn.commit()
    if using_default:
        print(
            "\n" + "=" * 72 + "\n"
            "  SHADOWFAX: created a default admin account  ->  admin / admin\n"
            "  FOR LOCAL DEVELOPMENT ONLY. Set SHADOWFAX_ADMIN_USERNAME and\n"
            "  SHADOWFAX_ADMIN_PASSWORD, and change this password, before exposing\n"
            "  the API beyond your machine.\n"
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
    limit: int = 500,
    identity: dict = Depends(require_role("viewer")),
):
    with db.get_conn() as conn:
        return db.query_alerts(conn, severity, actor_type, actor_id, category, search, limit)


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
            r = risk.get(actor_id, {"score": 0, "critical": 0, "high": 0, "medium": 0, "low": 0})
            out.append({
                "actor_id": actor_id,
                "actor_type": actor_type,
                "event_count": len(events),
                "risk_score": r["score"],
                "critical": r["critical"], "high": r["high"], "medium": r["medium"], "low": r["low"],
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
        risk = db.actor_risk_scores(conn).get(actor_id, {"score": 0, "critical": 0, "high": 0, "medium": 0, "low": 0})
        return {"actor_id": actor_id, "events": events, "alerts": alerts, "risk": risk}


# Policy endpoints

@app.get("/policy")
def get_policy(identity: dict = Depends(require_role("viewer"))):
    with db.get_conn() as conn:
        return db.get_policy(conn) or DEFAULT_POLICY


@app.put("/policy")
def update_policy(policy: dict[str, Any], identity: dict = Depends(require_role("analyst"))):
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
def login(req: LoginRequest):
    with db.get_conn() as conn:
        user = db.get_user_by_username(conn, req.username)
        if not user or not auth.verify_password(req.password, user["salt"], user["password_hash"]):
            raise HTTPException(401, "invalid username or password")
        token = auth.new_session_token()
        expires = datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_HOURS)
        db.create_session(conn, auth.token_fingerprint(token), user["id"], expires.isoformat())
        conn.commit()
    return {
        "token": token,
        "user": {"username": user["username"], "role": user["role"]},
        "expires_at": expires.isoformat(),
    }


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
