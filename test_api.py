"""
Basic integration test for the Shadowfax API.

Runs the backend against a temporary database and verifies the
main API endpoints behave as expected.
"""
import os
import sys

# use an isolated DB file for this test run
os.environ.setdefault("SHADOWFAX_TEST", "1")
import db as db_module
db_module.DB_PATH = db_module.Path(__file__).parent / "test_shadowfax.db"
if db_module.DB_PATH.exists():
    db_module.DB_PATH.unlink()

from fastapi.testclient import TestClient
from app import app

client = TestClient(app)
client.__enter__()  # trigger startup lifespan event so seed data + admin load


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}")
    if not condition:
        sys.exit(1)


def as_user(username, password):
    """A TestClient authenticated as the given user."""
    tok = client.post("/auth/login", json={"username": username, "password": password}).json()["token"]
    c = TestClient(app)
    c.headers.update({"Authorization": f"Bearer {tok}"})
    return c


print("== authentication ==")
# Endpoints are protected now: an unauthenticated read is rejected.
anon = TestClient(app)
check("unauthenticated GET /alerts is 401", anon.get("/alerts").status_code == 401)
# The bootstrap created a default admin (admin/admin) because no env vars are set.
r = client.post("/auth/login", json={"username": "admin", "password": "admin"})
check("admin login returns 200", r.status_code == 200)
check("bad password is rejected", client.post("/auth/login", json={"username": "admin", "password": "nope"}).status_code == 401)
admin_token = r.json()["token"]
# From here the main client acts as admin for every subsequent call.
client.headers.update({"Authorization": f"Bearer {admin_token}"})
check("/auth/me reports the admin role", client.get("/auth/me").json()["role"] == "admin")

print("\n== startup / seed data ==")
r = client.get("/stats")
check("GET /stats returns 200", r.status_code == 200)
stats = r.json()
print("  stats:", stats)
check("seed data loaded (27 events)", stats["event_count"] == 27)
check("critical alerts present from seed scenario", stats["alert_counts"]["critical"] >= 5)

print("\n== actors ==")
r = client.get("/actors")
actors = r.json()
check("GET /actors returns 200", r.status_code == 200)
check("4 actors present", len(actors) == 4)
top_actor = actors[0]
print("  top risk actor:", top_actor["actor_id"], "score:", top_actor["risk_score"])
check("actors sorted by risk descending", actors[0]["risk_score"] >= actors[-1]["risk_score"])

print("\n== actor detail ==")
r = client.get(f"/actors/{top_actor['actor_id']}")
check("GET /actors/{id} returns 200", r.status_code == 200)
detail = r.json()
check("detail includes events and alerts", "events" in detail and "alerts" in detail)

print("\n== alerts filtering ==")
r = client.get("/alerts", params={"severity": ["critical"]})
crit_alerts = r.json()
check("filtered critical-only alerts all critical", all(a["severity"] == "critical" for a in crit_alerts))
print(f"  {len(crit_alerts)} critical alerts returned")

print("\n== live ingestion + rescan ==")
r = client.get("/stats")
before = r.json()["alert_counts"]
new_events = [
    {"timestamp": "2026-08-05T03:00:00", "actor_id": "user-newthreat", "actor_type": "human",
     "event_type": "auth_failure", "target": "vpn_gateway", "metadata": {}},
    {"timestamp": "2026-08-05T03:01:00", "actor_id": "user-newthreat", "actor_type": "human",
     "event_type": "auth_failure", "target": "vpn_gateway", "metadata": {}},
    {"timestamp": "2026-08-05T03:02:00", "actor_id": "user-newthreat", "actor_type": "human",
     "event_type": "auth_failure", "target": "vpn_gateway", "metadata": {}},
    {"timestamp": "2026-08-05T03:03:00", "actor_id": "user-newthreat", "actor_type": "human",
     "event_type": "auth_failure", "target": "vpn_gateway", "metadata": {}},
]
r = client.post("/events", json=new_events)
check("POST /events returns 200", r.status_code == 200)
ingest_result = r.json()
print("  ingest result:", ingest_result["ingested"], "events,", len(ingest_result["alerts"]), "new alerts")
check("brute_force_auth alert fired on live ingestion",
      any(a["category"] == "brute_force_auth" for a in ingest_result["alerts"]))

r = client.get("/stats")
after = r.json()["alert_counts"]
check("alert count increased after live ingestion", sum(after.values()) > sum(before.values()))

print("\n== policy update + rescan ==")
r = client.get("/policy")
policy = r.json()
check("GET /policy returns 200", r.status_code == 200)
policy["brute_force_max_failures"] = 100  # loosen threshold drastically
r = client.put("/policy", json=policy)
check("PUT /policy returns 200", r.status_code == 200)
r = client.get("/alerts", params={"actor_id": "user-newthreat", "category": ["brute_force_auth"]})
check("brute_force alert disappears after loosening threshold + rescan", len(r.json()) == 0)

print("\n== stable alert identity ==")
import re
import detectors

r = client.get("/alerts", params={"actor_id": "eval-agent-7"})
agent_alerts = r.json()
check("eval-agent-7 has alerts to work with", len(agent_alerts) > 0)
target_alert = agent_alerts[0]
alert_id = target_alert["id"]
print("  chosen alert id:", alert_id, "category:", target_alert["category"])

check("alert id is a 16-char hex string", bool(re.fullmatch(r"[0-9a-f]{16}", str(alert_id))))

# The id is a pure function of actor, category and event -- not the message.
expected_id = detectors.alert_identity(
    target_alert["actor_id"], target_alert["category"], target_alert["event_id"]
)
check("alert id matches the deterministic derivation (message excluded)", alert_id == expected_id)
check("alerts carry analyst state, unacknowledged by default", target_alert["acknowledged"] is False)

# Acknowledge and assign it. acknowledged_by is set from the session (admin
# here), not from the request body, even though the body tries to spoof it.
r = client.patch(f"/alerts/{alert_id}/state",
                 json={"acknowledged": True, "acknowledged_by": "spoofed", "assigned_to": "analyst-2"})
check("PATCH /alerts/{id}/state returns 200", r.status_code == 200)
check("state reports acknowledged", r.json()["acknowledged"] is True)
check("acknowledged_by is the session user, not the client-supplied value",
      r.json()["acknowledged_by"] == "admin")

# Patching a bogus id is a 404, not a silent create.
r = client.patch("/alerts/deadbeefdeadbeef/state", json={"acknowledged": True})
check("PATCH on unknown alert id 404s", r.status_code == 404)

# Now ingest a NEW, later event for the same actor. This rescans eval-agent-7,
# deleting and rebuilding all of its alerts. The acknowledged alert must come
# back with the SAME id and its acknowledgement intact.
r = client.post("/events", json=[
    {"timestamp": "2026-12-31T12:00:00", "actor_id": "eval-agent-7", "actor_type": "ai_agent",
     "event_type": "heartbeat", "target": "status_page", "metadata": {}},
])
check("rescan-triggering ingest returns 200", r.status_code == 200)

r = client.get("/alerts", params={"actor_id": "eval-agent-7"})
after_rescan = {a["id"]: a for a in r.json()}
check("acknowledged alert still exists with the same id after rescan", alert_id in after_rescan)
survivor = after_rescan.get(alert_id, {})
check("acknowledgement survived the rescan", survivor.get("acknowledged") is True)
check("acknowledged_by survived the rescan", survivor.get("acknowledged_by") == "admin")
check("assignment survived the rescan", survivor.get("assigned_to") == "analyst-2")

print("\n== roles and access control ==")
client.post("/users", json={"username": "analyst1", "password": "pw", "role": "analyst"})
client.post("/users", json={"username": "viewer1", "password": "pw", "role": "viewer"})
analyst = as_user("analyst1", "pw")
viewer = as_user("viewer1", "pw")

check("duplicate username is rejected (409)",
      client.post("/users", json={"username": "analyst1", "password": "x", "role": "analyst"}).status_code == 409)
check("invalid role is rejected (400)",
      client.post("/users", json={"username": "bad", "password": "x", "role": "superuser"}).status_code == 400)

check("viewer can read alerts", viewer.get("/alerts").status_code == 200)
some_alert = client.get("/alerts").json()[0]["id"]
check("viewer cannot acknowledge (403)",
      viewer.patch(f"/alerts/{some_alert}/state", json={"acknowledged": True}).status_code == 403)
check("analyst can acknowledge (200)",
      analyst.patch(f"/alerts/{some_alert}/state", json={"acknowledged": True}).status_code == 200)
acked = next(a for a in client.get("/alerts").json() if a["id"] == some_alert)
check("acknowledged_by recorded as the acting analyst", acked["acknowledged_by"] == "analyst1")
check("analyst cannot reset (403)", analyst.post("/reset").status_code == 403)
check("analyst cannot create users (403)",
      analyst.post("/users", json={"username": "z", "password": "z", "role": "viewer"}).status_code == 403)
check("viewer cannot create API keys (403)", viewer.post("/api-keys", json={}).status_code == 403)

print("\n== api keys ==")
r = client.post("/api-keys", json={"label": "agent-harness"})
check("admin creates an API key", r.status_code == 200)
key = r.json()["api_key"]
check("API key is returned once, in the sk_shadowfax_ form", key.startswith("sk_shadowfax_"))
check("listing API keys never exposes the secret",
      all("api_key" not in k for k in client.get("/api-keys").json()))
svc_event = [{"timestamp": "2026-09-01T10:00:00", "actor_id": "svc-harness", "actor_type": "service_account",
              "event_type": "auth_failure", "target": "vpn_gateway", "metadata": {}}]
check("ingest with a valid API key works (200)",
      TestClient(app).post("/events", headers={"X-API-Key": key}, json=svc_event).status_code == 200)
check("ingest with a bad API key is 401",
      TestClient(app).post("/events", headers={"X-API-Key": "sk_shadowfax_nope"}, json=svc_event).status_code == 401)
check("an API key cannot read alerts (403)",
      TestClient(app).get("/alerts", headers={"X-API-Key": key}).status_code == 403)

print("\n== agent traces (v0.4.5) ==")
trace_events = [
    # in scope + benign
    {"timestamp": "2026-09-02T09:00:00", "actor_id": "trace-test", "actor_type": "ai_agent",
     "task": "engagement_alpha", "event_type": "tool_call", "target": "10.10.5.20",
     "metadata": {"tool": "nmap", "arguments": "-sV -p 443 10.10.5.20", "host": "10.10.5.20", "port": 443}},
    # out-of-scope destination host
    {"timestamp": "2026-09-02T09:01:00", "actor_id": "trace-test", "actor_type": "ai_agent",
     "task": "engagement_alpha", "event_type": "tool_call", "target": "http://evil.example/x",
     "metadata": {"tool": "curl", "arguments": "http://evil.example/x", "url": "http://evil.example/x"}},
    # destructive command
    {"timestamp": "2026-09-02T09:02:00", "actor_id": "trace-test", "actor_type": "ai_agent",
     "task": "engagement_alpha", "event_type": "tool_call", "target": "/data",
     "metadata": {"tool": "bash", "arguments": "rm -rf /data"}},
]
r = client.post("/events", json=trace_events)
check("tool-call ingest returns 200", r.status_code == 200)
produced = r.json()["alerts"]
cats = [a["category"] for a in produced]
check("destructive_action fires on 'rm -rf'", "destructive_action" in cats)
check("destructive_action is critical",
      any(a["severity"] == "critical" for a in produced if a["category"] == "destructive_action"))
check("out_of_scope_action fires on an off-scope host", "out_of_scope_action" in cats)
check("in-scope tool call raises no destructive/scope alert",
      all(a["category"] not in ("destructive_action", "out_of_scope_action")
          for a in produced if a["target"] == "10.10.5.20"))

print("\n== MITRE ATT&CK mapping ==")
import attack
from seed_data import DEFAULT_POLICY as _POLICY

check("every referenced technique id exists in the registry", attack.validate(_POLICY) == [])
r = client.get("/attack")
check("GET /attack returns the shared registry", r.status_code == 200 and "T1110" in r.json())

# canary_triggered persists here (the earlier policy test only loosened brute
# force, which removed those alerts).
canary = client.get("/alerts", params={"category": ["canary_triggered"]}).json()
check("canary_triggered alerts map to T1552 Unsecured Credentials",
      bool(canary) and all(any(t["id"] == "T1552" for t in a["attack"]) for a in canary))

dest = [a for a in produced if a["category"] == "destructive_action"]
check("a destructive rm -rf maps to T1485 Data Destruction",
      any(any(t["id"] == "T1485" for t in a["attack"]) for a in dest))

av = client.get("/alerts", params={"category": ["allowlist_violation"]}).json()
check("an unmapped category (allowlist_violation) carries no ATT&CK techniques",
      bool(av) and all(a["attack"] == [] for a in av))

print("\n== incident correlation (v0.4) ==")
r = client.get("/incidents")
check("GET /incidents returns 200", r.status_code == 200)
incidents = r.json()
check("alerts correlate into incidents", len(incidents) > 0)

recon = [i for i in incidents if i["actor_id"] == "recon-agent-3"]
check("recon-agent-3's alerts form a single incident", len(recon) == 1)
inc = recon[0]
check("the incident is critical", inc["severity"] == "critical")
check("the incident unions its categories",
      "destructive_action" in inc["categories"] and "out_of_scope_action" in inc["categories"])
check("the incident unions ATT&CK techniques", any(t["id"] == "T1485" for t in inc["techniques"]))

r = client.get(f"/incidents/{inc['id']}")
check("GET /incidents/{id} returns 200", r.status_code == 200)
detail = r.json()
check("incident detail carries its member alerts", len(detail["alerts"]) == inc["alert_count"])
check("incident report is markdown with a timeline",
      "## Timeline" in detail["report"] and f"Incident {inc['id']}" in detail["report"])
check("unknown incident id 404s", client.get("/incidents/deadbeefdeadbeef").status_code == 404)

print("\n== server-sent events ==")
import bus

# The auth gate returns before any streaming, so these don't open a stream.
# (The live hello/push path is exercised end-to-end in the browser, since the
# sync TestClient cannot cleanly consume an open-ended SSE stream.)
check("unauthenticated /stream is 401", anon.get("/stream").status_code == 401)
check("/stream with a bad token is 401", TestClient(app).get("/stream?token=nope").status_code == 401)

# The bus fans a published change out to every subscriber.
q = bus.subscribe()
bus._deliver({"type": "change", "reason": "unit-test"})
check("bus delivers a published change to subscribers", q.get_nowait().get("reason") == "unit-test")
bus.unsubscribe(q)

print("\n== reset ==")
r = client.post("/reset")
check("POST /reset returns 200", r.status_code == 200)
r = client.get("/stats")
check("reset restores 27 seed events", r.json()["event_count"] == 27)

print("\nAll checks passed.")
