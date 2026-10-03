"""
Scripted attack replay (v0.12).

Shadowfax's README can tell you it detects a kill chain. This makes it happen
while you watch: it drives a compromise through a running Shadowfax one step at
a time, and because the dashboard is live over Server-Sent Events, the alerts
appear as the attack does. Leave the browser open at http://localhost:8000 and
run this; nothing needs refreshing.

    python demo.py                 # ~90 seconds, paced for watching
    python demo.py --fast          # no pauses, for a terminal-only check
    python demo.py --speed 3       # three times slower, for talking over

It is a narrated scenario, not a test. Every step prints what the attacker did
and what Shadowfax should make of it, so the detection can be judged against the
behaviour rather than taken on trust -- and so a step that *doesn't* fire is
visible rather than quietly absent.

The scenario is deliberately one story told three ways, covering the three
things Shadowfax claims to do that a static screenshot cannot show:

  Act 1  An AI agent exceeds its brief, and the separate alerts turn out to be
         one kill chain running Reconnaissance -> Exfiltration.
  Act 2  Another tool's findings arrive over the shared envelope and attach to
         the same actor, from a tool Shadowfax knows nothing about.
  Act 3  The attacker turns on Shadowfax itself, and Shadowfax's own front door
         raises an ordinary brute-force alert about the attack on Shadowfax.

Nothing here is privileged. Every step is an HTTP call any client could make,
with the same authentication and the same roles. The replay has no more access
to Shadowfax than a shell script would.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

DEFAULT_URL = "http://127.0.0.1:8000"

# The attack's own clock. Events carry timestamps a few minutes apart so the
# detectors' windows behave as they would in life; the *replay* is paced by
# --speed, which is a separate thing entirely. Conflating the two would mean a
# fast replay quietly stopped tripping the time-windowed detectors.
START = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0) - timedelta(minutes=30)

ACTOR = "demo-agent-1"

RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
RED = "\033[31m"
AMBER = "\033[33m"
GREEN = "\033[32m"
CYAN = "\033[36m"


class Demo:
    def __init__(self, url: str, speed: float, colour: bool):
        self.url = url.rstrip("/")
        self.speed = speed
        self.colour = colour
        self.token: str | None = None
        self.step = 0
        # Alert ids already shown. /events returns every alert for the actor
        # after the rescan, not just the new ones -- which is correct for the
        # API and useless for a narration, since step five would reprint
        # everything from steps one to four. Each step shows only what it added.
        self.seen: set[str] = set()

    # -- plumbing ----------------------------------------------------------

    def _c(self, text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if self.colour else text

    def call(self, method: str, path: str, body=None, token: str | None = ...):
        token = self.token if token is ... else token
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(self.url + path, data=data,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, json.loads(resp.read() or "null")
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw or "null")
            except ValueError:
                return exc.code, {"detail": raw.decode("utf-8", "replace")}

    def pause(self, seconds: float) -> None:
        if self.speed > 0:
            time.sleep(seconds * self.speed)

    def act(self, number: int, title: str, why: str) -> None:
        print()
        print(self._c(f"━━ ACT {number} · {title} ", BOLD + CYAN))
        print(self._c(f"   {why}", DIM))
        print()
        self.pause(1.5)

    def narrate(self, what: str, expect: str) -> None:
        self.step += 1
        print(f"  {self._c(f'{self.step:>2}.', DIM)} {what}")
        print(f"      {self._c('expect →', DIM)} {self._c(expect, DIM)}")
        self.pause(1.2)

    def observed(self, alerts: list[dict]) -> None:
        """Print what this step newly raised, which may be nothing."""
        alerts = [a for a in alerts if a["id"] not in self.seen]
        self.seen.update(a["id"] for a in alerts)
        if not alerts:
            note = "· no alert (this step is setup, or a detector disagreed)"
            print(f"      {self._c(note, DIM)}")
            return
        for a in alerts:
            colour = {"critical": RED, "high": AMBER, "medium": AMBER}.get(
                a["severity"], DIM)
            techniques = " ".join(t["id"] for t in a.get("attack") or [])
            print(f"      {self._c('▸ ' + a['severity'].upper().ljust(8), colour)}"
                  f"{a['category']}  {self._c(techniques, DIM)}")
        self.pause(0.4)

    # -- the events --------------------------------------------------------

    def send(self, minute: int, event_type: str, target: str, **meta) -> list[dict]:
        """One event from the attacker, and whatever Shadowfax made of it."""
        at = (START + timedelta(minutes=minute)).isoformat()
        status, body = self.call("POST", "/events", [{
            "timestamp": at, "actor_id": ACTOR, "actor_type": "ai_agent",
            "task": "customer_churn_analysis", "event_type": event_type,
            "target": target, "metadata": meta,
        }])
        if status != 200:
            raise SystemExit(f"ingest failed ({status}): {body}")
        return [a for a in body.get("alerts", []) if a["actor_id"] == ACTOR]

    # -- the scenario ------------------------------------------------------

    def run(self) -> int:
        print(self._c("\nSHADOWFAX — scripted attack replay", BOLD))
        print(self._c(f"against {self.url} · watch the dashboard while this runs",
                      DIM))

        status, body = self.call("POST", "/auth/login", {
            "username": "admin", "password": "admin"}, token=None)
        if status != 200:
            print(f"\ncould not sign in ({status}): {body.get('detail')}")
            print("Is Shadowfax running, and is the admin password still the "
                  "default? Set SHADOWFAX_ADMIN_PASSWORD and pass --password.")
            return 1
        self.token = body["token"]

        # Start from the bundled sample data, so the replay reads the same way
        # every time -- including after someone has already run it once.
        self.call("POST", "/reset")
        self.pause(1)

        self.act(1, "An agent exceeds its brief",
                 "A churn-analysis agent is scoped to one dataset. Watch what "
                 "it actually does.")

        self.narrate("Agent reads the dataset it was actually given.",
                     "nothing — this is the agent doing its job")
        self.observed(self.send(0, "file_access", "customer_churn_dataset"))

        self.narrate("It grants itself root, with no approval marker.",
                     "privilege_escalation (T1548)")
        self.observed(self.send(2, "privilege_change", "analysis_workstation",
                                new_level="root", elevated=True))

        self.narrate("Four failed logins against the internal VPN.",
                     "brute_force_auth (T1110) once the window fills")
        for n in range(4):
            alerts = self.send(4 + n, "auth_failure", "corp_vpn",
                               source_ip="10.10.5.44")
        self.observed(alerts)

        self.narrate("It touches six databases in eleven minutes.",
                     "lateral_movement (T1021) past the distinct-target threshold")
        for n, target in enumerate(["finance_db", "hr_records_db", "billing_db",
                                    "crm_db", "payroll_db", "audit_db"]):
            alerts = self.send(8 + n, "file_access", target)
        self.observed(alerts)

        self.narrate("500 MB leaves for an internal staging bucket.",
                     "exfiltration_volume (T1048), and the chain completes")
        self.observed(self.send(15, "data_transfer", "internal_staging_bucket",
                                bytes_transferred=500_000_000))

        self.pause(1)
        incident = self.show_chain()

        self.act(2, "Another tool reports on the same agent",
                 "Shadowfax did not call this tool and knows nothing about it. "
                 "It wrote the shared findings envelope, which is the whole "
                 "contract.")

        self.narrate("A recon tool posts findings about the same actor.",
                     "ingested as events, raising alerts with the emitter named")
        status, body = self.call("POST", "/findings", {
            "envelope_version": "1.0",
            "generated": (START - timedelta(minutes=5)).isoformat() + "Z",
            "source": {"tool": "claude-recon-agent", "version": "0.4.1",
                       "run_id": "demo-hunt"},
            "subject": {"kind": "actor", "id": ACTOR},
            "findings": [
                {"id": "demo-recon-1", "key": "host_enumeration",
                 "severity": "medium",
                 "title": "Agent enumerated 14 internal hosts before any authorised task",
                 "evidence": "14 distinct 10.10.5.0/24 addresses probed in 90s "
                             "(session log lines 204-218)",
                 "validated": True, "mitre": "T1595 - Active Scanning"},
                {"id": "demo-recon-2", "key": "service_banner", "severity": "info",
                 "title": "Agent's egress host claims OpenSSH 7.4",
                 "evidence": "SSH-2.0-OpenSSH_7.4", "validated": False,
                 "mitre": "T1046 - Network Service Discovery"},
            ],
        })
        if status != 200:
            print(f"      findings rejected ({status}): {body.get('detail')}")
        else:
            got = f"▸ {body['accepted']} finding(s) from {body['envelope']['tool']}"
            print(f"      {self._c(got, GREEN)}")
            self.observed([a for a in body["alerts"]
                           if a.get("source_tool")][:3])

        self.narrate("The same envelope is sent again, unchanged.",
                     "skipped — the finding id is a function of its content")
        _, body = self.call("POST", "/findings", {
            "envelope_version": "1.0",
            "generated": (START - timedelta(minutes=5)).isoformat() + "Z",
            "source": {"tool": "claude-recon-agent", "version": "0.4.1"},
            "subject": {"kind": "actor", "id": ACTOR},
            "findings": [
                {"id": "demo-recon-1", "key": "host_enumeration",
                 "severity": "medium",
                 "title": "Agent enumerated 14 internal hosts before any authorised task",
                 "evidence": "14 distinct 10.10.5.0/24 addresses probed in 90s "
                             "(session log lines 204-218)",
                 "validated": True, "mitre": "T1595 - Active Scanning"}],
        })
        again = (f"▸ {body.get('accepted', 0)} accepted, "
                 f"{body.get('skipped', 0)} already known")
        print(f"      {self._c(again, DIM)}")
        self.pause(1)

        print()
        print("      The recon finding sits at Reconnaissance, earlier than "
              "anything")
        print("      Shadowfax saw itself — so the chain now starts one stage "
              "further back:")
        self.show_chain(indent="      ")

        self.act(3, "The attacker turns on Shadowfax",
                 "A monitoring platform is a target. This is what Shadowfax "
                 "makes of an attack on Shadowfax.")

        self.narrate("A patient attacker guesses at a Shadowfax account, "
                     "waiting out each refusal.",
                     "401s, then 429s — and Shadowfax alerting on the attempt")
        self.brute_force("j.bartlett")
        self.pause(1)

        status, detail = self.call("GET", "/actors/shadowfax-auth")
        if status == 200:
            self.observed([a for a in detail["alerts"]][:2])
            note = "· the platform logs its own front door as an ordinary actor"
            print(f"      {self._c(note, DIM)}")
        else:
            note = "· self-monitoring is off (SHADOWFAX_SELF_MONITOR=0)"
            print(f"      {self._c(note, DIM)}")

        self.pause(1)
        self.finish(incident)
        return 0

    def brute_force(self, username: str, attempts: int = 5) -> None:
        """Guess at a Shadowfax account, honouring the server's own Retry-After.

        Hammering without waiting only ever collects 429s: the backoff stops the
        guessing before the detector has enough failures to call it brute force,
        which is the throttle doing its job. A real attacker waits, so the demo
        waits too -- otherwise it would be demonstrating the throttle while
        quietly failing to demonstrate the detection.
        """
        # Clear anything a previous run left behind, the same way the replay
        # resets the event data. Recorded sign-in failures deliberately survive
        # POST /reset -- a data reset must not be a way to lift a lockout -- so
        # releasing one is its own explicit, audited call.
        self.call("DELETE", f"/auth/lockouts/{username}")

        landed = 0
        throttled = 0
        while landed < attempts:
            status, body = self.call("POST", "/auth/login",
                                     {"username": username,
                                      "password": "Password123!"}, token=None)
            if status == 429:
                throttled += 1
                wait = 2
                detail = str(body.get("detail", ""))
                if throttled == 1:
                    print(f"      {self._c('▸ throttled — ' + detail, AMBER)}")
                if "locked out" in detail:
                    print(f"      {self._c('▸ locked out — the guessing stops here', AMBER)}")
                    break
                # Real seconds, even with --fast: the wait is the mechanism
                # being demonstrated, not the pacing of the narration.
                time.sleep(wait)
                continue
            landed += 1
        summary = (f"· {landed} guesses landed, {throttled} refused outright "
                   f"— each one slower than the last")
        print(f"      {self._c(summary, DIM)}")

    def show_chain(self, indent: str = "  ") -> dict | None:
        """Print the kill chain for the demo actor's incident, if there is one."""
        status, incidents = self.call("GET", "/incidents")
        if status != 200:
            return None
        mine = next((i for i in incidents if i["actor_id"] == ACTOR), None)
        if not mine:
            return None
        _, detail = self.call("GET", f"/incidents/{mine['id']}")
        chain = detail.get("chain")
        if not chain:
            return detail
        stages = " → ".join(s["tactic"] for s in chain["stages"])
        print()
        print(f"{indent}{self._c('⛓ KILL CHAIN', BOLD + RED)}  {stages}")
        if chain.get("escalated"):
            esc = f"  escalated to CRITICAL — the chain reached {chain['terminal_tactic']}"
            print(f"{indent}{self._c(esc, RED)}")
        corr = (f"  correlated from {len(detail['alerts'])} separate alerts, "
                f"deterministically")
        print(f"{indent}{self._c(corr, DIM)}")
        print()
        self.pause(1.5)
        return detail

    def finish(self, incident: dict | None) -> None:
        _, stats = self.call("GET", "/stats")
        _, ledger = self.call("GET", "/ledger/verify")
        counts = stats.get("alert_counts", {})
        print()
        print(self._c("━━ WHAT JUST HAPPENED", BOLD + CYAN))
        print()
        print(f"  {counts.get('critical', 0)} critical · {counts.get('high', 0)} high · "
              f"{counts.get('medium', 0)} medium · {counts.get('low', 0)} low · "
              f"{counts.get('info', 0)} info      "
              f"{self._c(str(stats.get('event_count', 0)) + ' events', DIM)}")
        print()
        print("  Every alert above came from a deterministic rule reading an "
              "event history.")
        print("  No model decided any of it. The assistant can explain a "
              "finding; it cannot")
        print("  create, rank or suppress one.")
        print()
        print(f"  {self._c('ledger:', DIM)} {ledger.get('summary', 'unavailable')}")
        print()
        print("  Try next:")
        print(f"    {self._c('shadowfax digest', BOLD)}            "
              "what most needs an analyst, ranked with its reasons")
        print(f"    {self._c('shadowfax verify', BOLD)}            "
              "prove the event log has not been edited")
        print(f"    {self._c('shadowfax lockouts', BOLD)}          "
              "who is failing to sign in to Shadowfax itself")
        print(f"    {self._c('open ' + self.url, BOLD)}  "
              f"the dashboard, which has been live this whole time")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Replay a scripted attack against a running Shadowfax.")
    parser.add_argument("--url", default=DEFAULT_URL,
                        help=f"Shadowfax base URL (default {DEFAULT_URL})")
    parser.add_argument("--speed", type=float, default=1.0,
                        help="pause multiplier; 2 is twice as slow (default 1)")
    parser.add_argument("--fast", action="store_true",
                        help="no pauses at all — for a terminal-only check")
    parser.add_argument("--no-colour", action="store_true", help="plain output")
    args = parser.parse_args(argv)

    demo = Demo(args.url, 0.0 if args.fast else args.speed,
                not args.no_colour and sys.stdout.isatty())
    try:
        return demo.run()
    except KeyboardInterrupt:
        print("\nstopped.")
        return 130
    except urllib.error.URLError as exc:
        print(f"\ncannot reach Shadowfax at {args.url}: {exc.reason}")
        print("Start it with `docker compose up`, or `uvicorn app:app --port 8000`.")
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
