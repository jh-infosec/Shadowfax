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
import sqlite3
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import db
import detectors
from seed_data import SAMPLE_EVENTS, DEFAULT_POLICY

APP_NAME = "Shadowfax API"
VERSION = "0.1.0"

app = FastAPI(
    title=APP_NAME,
    version=VERSION,
)

app.add_middleware(
    CORSMiddleware,
    # Fine for local development.
    # Restrict this before exposing the API outside your machine.
    allow_origins=["*"],  
    allow_methods=["*"],
    allow_headers=["*"],
)

# Application startup

@app.on_event("startup")
def initialise_application() -> None:
    db.init_db()
    with db.get_conn() as conn:
        if db.get_policy(conn) is None:
            db.set_policy(conn, DEFAULT_POLICY)
            conn.commit()
        if not db.get_all_events(conn):
            _load_events(conn, SAMPLE_EVENTS)
            conn.commit()


# Request models

class EventRequest(BaseModel):
    timestamp: str
    actor_id: str
    actor_type: str
    task: Optional[str] = None
    event_type: str
    target: str
    metadata: dict[str, Any] = {}


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
def ingest_events(events: list[EventRequest]):
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
    return {"ingested": len(events), "affected_actors": list(affected_actors), "alerts": new_alerts}


@app.get("/events")
def list_events(actor_id: Optional[str] = None):
    with db.get_conn() as conn:
        if actor_id:
            return db.get_events_for_actor(conn, actor_id)
        return db.get_all_events(conn)


# Alert endpoints

@app.get("/alerts")
def list_alerts(
    severity: Optional[list[str]] = Query(None),
    actor_type: Optional[list[str]] = Query(None),
    actor_id: Optional[str] = None,
    category: Optional[list[str]] = Query(None),
    search: Optional[str] = None,
    limit: int = 500,
):
    with db.get_conn() as conn:
        return db.query_alerts(conn, severity, actor_type, actor_id, category, search, limit)


@app.get("/stats")
def stats():
    with db.get_conn() as conn:
        return {
            "alert_counts": db.alert_counts(conn),
            "actor_count": len(db.distinct_actors(conn)),
            "event_count": len(db.get_all_events(conn)),
        }


# Actor endpoints

@app.get("/actors")
def list_actors():
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
def actor_detail(actor_id: str):
    with db.get_conn() as conn:
        events = db.get_events_for_actor(conn, actor_id)
        if not events:
            raise HTTPException(404, f"no events for actor '{actor_id}'")
        alerts = db.query_alerts(conn, actor_id=actor_id, limit=1000)
        risk = db.actor_risk_scores(conn).get(actor_id, {"score": 0, "critical": 0, "high": 0, "medium": 0, "low": 0})
        return {"actor_id": actor_id, "events": events, "alerts": alerts, "risk": risk}


# Policy endpoints

@app.get("/policy")
def get_policy():
    with db.get_conn() as conn:
        return db.get_policy(conn) or DEFAULT_POLICY


@app.put("/policy")
def update_policy(policy: dict[str, Any]):
    with db.get_conn() as conn:
        db.set_policy(conn, policy)
        _rescan_all(conn)
        conn.commit()
    return {"status": "policy updated, all actors rescanned"}


# Administrative endpoints

@app.post("/reset")
def reset():
    with db.get_conn() as conn:
        db.wipe_all(conn)
        db.set_policy(conn, DEFAULT_POLICY)
        _load_events(conn, SAMPLE_EVENTS)
        conn.commit()
    return {"status": "reset to bundled sample data"}
