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
client.__enter__()  # trigger startup lifespan event so seed data loads


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}")
    if not condition:
        sys.exit(1)


print("== startup / seed data ==")
r = client.get("/stats")
check("GET /stats returns 200", r.status_code == 200)
stats = r.json()
print("  stats:", stats)
check("seed data loaded (22 events)", stats["event_count"] == 22)
check("critical alerts present from seed scenario", stats["alert_counts"]["critical"] >= 5)

print("\n== actors ==")
r = client.get("/actors")
actors = r.json()
check("GET /actors returns 200", r.status_code == 200)
check("3 actors present", len(actors) == 3)
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

print("\n== reset ==")
r = client.post("/reset")
check("POST /reset returns 200", r.status_code == 200)
r = client.get("/stats")
check("reset restores 22 seed events", r.json()["event_count"] == 22)

print("\nAll checks passed.")
