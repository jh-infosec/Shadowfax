# Shadowfax

[![CI](https://github.com/jh-infosec/Shadowfax/actions/workflows/ci.yml/badge.svg)](https://github.com/jh-infosec/Shadowfax/actions/workflows/ci.yml)

> AI Security Operations Platform for Monitoring Autonomous AI Agents

---

## Why Shadowfax?

As autonomous AI agents become more capable, they are increasingly being
trusted to write code, use tools, access APIs and make decisions with minimal
human supervision.

Traditional security tooling was designed to monitor human users, service
accounts and infrastructure, not autonomous AI systems.

Shadowfax explores what a modern security operations platform might look like
if AI agents became first-class identities inside an organisation.

The project is being developed alongside my studies in offensive security and
artificial intelligence, with the goal of combining practical cybersecurity
engineering with modern AI workflows.

---

## Project Goals

Shadowfax is designed to answer three questions:

- What is this agent doing?
- Why is it doing it?
- Should this behaviour be trusted?

Rather than acting as a security boundary, Shadowfax focuses on visibility,
investigation and explainability.

---

## Current Features

- REST API built with FastAPI
- SQLite event database
- Rule-based detection engine across twenty-seven alert categories, including AI-agent tool-call analysis
- Policy management with full rescan on change
- Actor risk scoring
- Stable, deterministic alert identity that survives a rescan
- Acknowledge and assign alerts, with analyst state that persists across rescans
- Authentication with user accounts, roles (admin / analyst / viewer) and API keys
- Subject pages — everything other tools reported about a file, host or workspace, grouped by tool, with findings two tools agree on called out
- Two-factor sign-in — codes from any authenticator app (QR enrolment from the dashboard), single-use and throttled, with recovery codes; removing it raises an alert
- Password changes and admin resets — the current password required and throttled, other sessions signed out, admin-reset passwords forced to change before anything else works
- Dashboard sign-in, with the UI adapting to the signed-in user's role
- Live push over Server-Sent Events — the dashboard updates the instant data changes
- Agent-trace ingest — flags destructive tool calls and out-of-scope actions by AI agents
- Agent permissions — declare which tools and targets each agent was given; the first step outside its profile is reported, with no baseline needed, and undeclared agents are flagged
- Capability manifests — the tools an agent is configured with, compared with what it is allowed (excess tools flagged before they are used) and with what it calls (tools its own configuration does not list)
- MITRE ATT&CK mapping — every alert tagged with technique IDs from a shared registry
- Alert correlation — related alerts grouped into incidents, each with a generated report
- Attack-chain detection — incidents whose alerts advance through the ATT&CK kill chain in order are flagged, and completed chains escalate to critical
- Completion-fraud detection — flags agents that claim more coverage than their trace shows
- Token-spend anomaly — flags spend spikes against an actor's own baseline
- AI investigation assistant — explains an alert or incident in plain English for an analyst; it explains, never decides, and works without an API key (deterministic fallback)
- Natural-language alert search — ask in plain English; the assistant translates the query into a validated filter and shows how it read it (detection stays deterministic)
- React dashboard with a live alert table
- Actor timelines, showing alerts attached to the events that produced them
- Filtering by severity, actor type, category and free-text search
- Policy editing from the dashboard
- Triage digest — the open incidents that most need an analyst, ranked deterministically with the reasons shown
- Command-line interface — ingest, query, explain and gate on alerts from a shell; `--json` everywhere for agents
- Tamper-evident event ledger — every event hash-chained to the one before it, so an edit, deletion or reordering breaks the chain at a locatable point
- Sign-in throttling and lockout — backoff then lockout on the platform's own login, with no enumeration oracle and no sleeping
- Accounts screen — admins add users, change roles, disable and re-enable accounts, and issue or revoke API keys from the dashboard; passwords and keys are generated, shown once, and every change is in the ledger
- Console recovery — a lost admin password is reset from the server's own shell, never over the network, and raises an alert
- History that cannot be quietly rewritten — when a new upload makes alerts disappear, Shadowfax records which ones and who sent it, and raises `history_rewritten`
- Self-monitoring — attacks on Shadowfax's own front door become ordinary events and raise ordinary alerts, through the same detectors as everything else
- Findings-envelope ingest — any tool that writes the shared envelope can post findings, and Shadowfax needs to know nothing about it
- Findings-envelope export — Shadowfax speaks the format as well as reads it, so the portfolio's other tools can consume it in turn
- One-command packaging — `docker compose up`, plus a scripted attack replay that makes the engine demonstrate itself
- CI that builds the image and replays the attack against it, so every commit proves the detections still happen
- Published image — every GitHub release ships `ghcr.io/jh-infosec/shadowfax`, only after the tests and the replay pass, with provenance and an SBOM, signed with Sigstore cosign, and never with a known password
- Ingest budgets — each API key and user gets events per minute; a credential that floods is refused whole and raises an alert about itself
- Dashboard checked in a real browser — building a bundle proves it compiles, not that anything reaches the screen
- Automated API testing

---

## Architecture

```
                        Browser
                           │
                           ▼
                Dashboard (React)
                           │
                           ▼
                   Shadowfax API
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
           SQLite                  Detection Engine
```

Every event enters through the API.

The detection engine evaluates the actor's behaviour against the active
policy and generates alerts.

The dashboard communicates only with the API and never accesses the database
directly. It decides how an alert looks, never whether it exists.

See `architecture.md` for the full design.

---

## Technology

Current stack

- Python
- FastAPI
- SQLite
- React
- Vite

Also

- Docker (one-command packaging)

Planned

- PostgreSQL
- Electron desktop client

---

## Roadmap

### v0.1

- Backend API
- SQLite
- Detection Engine
- REST Endpoints

### v0.2

- Dashboard
- Timeline View
- Alert Filtering
- Policy Editor

### v0.3 — shipped

- Stable Alert Identity
- Acknowledge & Assign
- Authentication, roles and API keys
- Live push (Server-Sent Events), replacing the poll loop

### v0.4

- MITRE ATT&CK Mapping — shipped (v0.4.6)
- Correlation Engine — shipped (v0.4.7)
- Incident Reports — shipped (v0.4.7)

### v0.4.5 — shipped

- Agent-trace ingest (`tool_call` events)
- Destructive-action detectors
- Engagement scope in policy (`out_of_scope_action`)

### v0.5

- Completion-fraud detector — shipped (v0.5)
- Token-spend anomaly — shipped (v0.5)
- AI Investigation Assistant — shipped (v0.5.1)
- Threat Summaries — shipped (v0.5.1)
- Natural Language Search — shipped (v0.5.2)

### v0.6

- Attack-Chain Correlation — shipped (v0.6.0)

### v0.7

- Command-Line Interface — shipped (v0.7.0)

### v0.8

- Triage Digest — shipped (v0.8.0)

### v0.9

- Tamper-Evident Event Ledger — shipped (v0.9.0)

### v0.10

- Sign-in Throttling & Lockout — shipped (v0.10.0)
- Platform Self-Monitoring — shipped (v0.10.0)

### v0.11

- Findings-Envelope Ingest — shipped (v0.11.0)
- The `info` severity level — shipped (v0.11.0)

### v0.12

- Docker packaging, one command — shipped (v0.12.0)
- Scripted attack replay — shipped (v0.12.0)

### v0.13

- CI: test suite, image build, and the replay asserted end to end — shipped (v0.13.0)

### v0.14

- Dashboard tests in a real browser — shipped (v0.14.0)

### v0.15

- Findings-Envelope Export — shipped (v0.15.0)

### v0.16

- Agent permission profiles — shipped (v0.16.0)

### v0.17

- Published image on ghcr.io, released from CI — shipped (v0.17.0)
- No session tokens in URLs; request size limits — shipped (v0.17.1)

### v0.18

- Capability manifests: configured tools vs. permitted vs. used — shipped (v0.18.0)

### v0.19

- Change and reset passwords — shipped (v0.19.0)

### v0.20

- Ingest budgets per credential; signed images — shipped (v0.20.0)

### v0.21

- Fixes from an independent security review — shipped (v0.21.0)

### v0.22

- Console recovery of a lost admin password; Escape closes drawers — shipped (v0.22.0)

### v0.23

- Users and API keys managed from the dashboard — shipped (v0.23.0)

### v0.24

- Change roles; disable and re-enable accounts — shipped (v0.24.0)

### v0.25

- Two-factor sign-in (TOTP) with recovery codes — shipped (v0.25.0)

### v0.26

- Subject pages: findings grouped by the tool that reported them — shipped (v0.26.0)

### v0.27

- Two-factor required for admins (a switch); new recovery codes — shipped (v0.27.0)

### v0.28

- Dashboard build toolchain updated (Vite 8, Node 22); npm audit clean — shipped (v0.28.0)

### v0.29

- Draft a permission profile from what an agent did — shipped (v0.29.0)

### v1.0

- Electron Desktop Application
- PostgreSQL
- Multi-user Support
- Docker Deployment

---

## Running Shadowfax

The quickest way, with nothing to clone or build — the published image:

```bash
docker run -d --name shadowfax -p 8000:8000 -v shadowfax-data:/data \
  ghcr.io/jh-infosec/shadowfax
docker logs shadowfax        # the admin password, generated on first start
```

Open `http://localhost:8000` and sign in as `admin` with the password from the
log, then change it with **Change password** in the top bar. The published
image never starts with a password everyone knows: without
`SHADOWFAX_ADMIN_PASSWORD` it generates one, prints it once, and keeps only its
hash. To choose your own, add `-e SHADOWFAX_ADMIN_PASSWORD=...` to the first
`docker run`. Each release is also tagged by version (`:0.17.0`, `:0.17`), and
carries build provenance and an SBOM.

Every release is signed by this repository's CI. To check the image you pulled
really came from it ([cosign](https://docs.sigstore.dev/cosign/system_config/installation/)):

```bash
cosign verify ghcr.io/jh-infosec/shadowfax:latest \
  --certificate-identity-regexp '^https://github.com/jh-infosec/Shadowfax/.github/workflows/ci.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

From the source in front of you instead:

```bash
docker compose up --build
```

Open `http://localhost:8000` and sign in as `admin` / `admin` — compose sets
these for local use, and Shadowfax warns about them on startup. One process, one
port: the API serves the dashboard from its own origin, so there is no second
server to start and no CORS allowlist to reconcile with whichever port the
dashboard ended up on.

### Watch it work

Reading that a tool detects a kill chain is not the same as seeing one form.
Leave the dashboard open and run:

```bash
docker compose exec shadowfax python demo.py
# or, with the published image:
docker exec shadowfax python demo.py --password <the password from the log>
```

A scripted attack unfolds against the running instance, in three acts. Because
the dashboard is live over Server-Sent Events, the alerts appear as the attack
does — nothing needs refreshing.

```
━━ ACT 1 · An agent exceeds its brief

   2. It grants itself root, with no approval marker.
      expect → privilege_escalation (T1548)
      ▸ HIGH    privilege_escalation  T1548
   ...
  ⛓ KILL CHAIN  Privilege Escalation → Credential Access → Lateral Movement → Exfiltration
    escalated to CRITICAL — the chain reached Exfiltration
    correlated from 9 separate alerts, deterministically
```

Act 2 has another tool post findings over the shared envelope, which attach to
the same actor and push the chain back a stage to Reconnaissance. Act 3 turns
the attack on Shadowfax itself, and Shadowfax raises an ordinary brute-force
alert about it.

Every step prints what the attacker did *and* what Shadowfax should make of it,
so the detection can be judged against the behaviour rather than taken on trust
— and a step that does not fire is visible rather than quietly absent.

`--fast` drops the pauses; `--speed 3` slows them down for talking over.

`docker compose down` keeps the event store; `down -v` discards it.

### Without Docker

The backend and the dashboard run as two processes.

Backend, from the repository root:

```bash
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Dashboard, in a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` and sign in. Interactive API documentation is at
`http://127.0.0.1:8000/docs`, and `GET /healthz` answers without a credential.

The dashboard reads `VITE_API_BASE` for the backend URL, defaulting to
`http://127.0.0.1:8000`. Setting it to the **empty** string means "same origin",
which is how the container serves it. If you serve the dashboard from another
origin, add that origin to `SHADOWFAX_CORS_ORIGINS` on the backend.

`SHADOWFAX_DB` chooses where the database lives; it defaults to beside the code.

---

## Testing

Run the backend test suite:

```bash
pip install -r requirements-dev.txt
python test_api.py
```

`requirements-dev.txt` adds what only the suite needs (`httpx`, which
`fastapi.testclient` imports internally). A deployment still needs nothing
beyond `requirements.txt` — the shipped container carries no test client.

### The dashboard, in a real browser

Building the dashboard proves it compiles, not that it works. Vite exits 0 on a
page that renders nothing — a component throwing on mount, an API field quietly
renamed, a filter that drops every row all ship green.

```bash
python demo.py --fast          # put something on the dashboard first
python test_dashboard.py
```

Fifty-seven checks, each one an assertion a person makes when they glance at the
dashboard and believe it: that the alerts the engine found are rendered as rows,
that rows carry a severity and an ATT&CK technique, that an ingested finding
names the tool that reported it, that the ledger badge reads verified, that a
correlated kill chain is *drawn* with its tactics and its escalation, that
filtering actually filters, that an agent's declared permissions are shown
beside the breaches of them along with the tools it was configured with, and
that the live stream connects without the session token appearing in any URL
the page requests, and that a user whose password an admin reset must choose a
new one before the dashboard shows anything — and that an admin can add a user
and issue and revoke an API key from the Accounts drawer, with the password shown
on screen being the one that signs in.

They refuse to run against an empty instance, because a test that passes on a
dashboard rendering nothing is worse than no test. `--headed` shows the browser.

Playwright is a developer dependency (`requirements-dev.txt`), not a runtime
one: the shipped container has neither it nor a browser, and should not.

### The replay is also a test

`demo.py` prints what each step expects before it happens. With `--assert`,
those claims are checked and the run exits non-zero naming any that failed:

```bash
python demo.py --fast --assert
```

```
━━ ASSERTIONS FAILED

  ✗ step 8: expected shadowfax-auth / brute_force_auth — not raised
```

That turns the demo into an end-to-end check of the whole stack — ingest,
twenty-seven detectors, correlation, kill-chain ordering, findings-envelope ingest,
the front door and the ledger — against a real server over real HTTP. It is a
different kind of evidence from the unit suite, which never leaves the process.

Expectations are recorded qualified by actor as well as category: Act 1 and
Act 3 both raise `brute_force_auth`, and an unqualified check would pass on
Act 1's alert and never notice that self-monitoring had stopped working.

Without `--assert` it is still a demo and still returns 0 whatever happens.

### Continuous integration

Every push runs two jobs. **checks** runs the test suite and builds the
dashboard. **container** builds the Docker image, starts it, and replays the
attack against it — proving that the image builds, runs as a non-root user,
serves the dashboard from the API's own origin, does not let the static mount
shadow an API route, raises the detections the README claims, and that
`shadowfax check` still exits non-zero when alerts match.

A README that says `docker compose up` and a Dockerfile nobody builds is a
promise with nothing behind it. Since v0.17 it also checks a fresh container
started without credentials: `admin/admin` must be refused, and the generated
password from its log must work.

### Releasing

Publishing a release on github.com (**Releases → Draft a new release**, tag
`v0.17.0`) runs a third job, **publish**, after the other two have passed on
that commit. It refuses a tag that disagrees with the version in `app.py`,
`frontend/package.json` and the changelog; pushes the image to
`ghcr.io/jh-infosec/shadowfax` as `:0.17.0`, `:0.17` and `:latest` (a release
marked as a pre-release never becomes `:latest`); signs it with Sigstore cosign
using the job's GitHub identity (no stored key) and verifies the signature
against that exact identity (v0.20); then pulls back what it published, by
digest, and checks that it starts, reports the right version,
runs as non-root and generated its admin password. Pushing to `main` never
publishes anything.

The first time, GitHub makes the package private. The job says so in a warning;
make it public once under **your profile → Packages → shadowfax → Package
settings → Change visibility**.

---

## Command line

The CLI talks to the same HTTP API as the dashboard, so authentication and roles
apply identically — it is a convenience, never a way around the security model.

```bash
python cli.py login -u admin            # stores a token in ~/.shadowfax/config.json
python cli.py status
python cli.py alerts --severity critical
python cli.py incidents --json
python cli.py explain incident <id>
python cli.py search "critical destructive actions by ai agents"
cat trace.json | python cli.py ingest -  # a harness emitting its own trace
```

Every command takes `--json` for machine consumption. Exit codes are meaningful
(`0` ok, `1` failure, `2` usage, `3` auth, `4` unreachable), and `check` exits
non-zero when alerts match — so an agent harness can gate its own run:

```bash
python cli.py check --severity critical || echo "agent tripped a detector"
```

The triage queue — what most needs an analyst right now:

```bash
python cli.py digest              # ranked queue with a covering summary
python cli.py digest --plain      # the deterministic text, no model involved
```

The ranking is computed deterministically (severity, completed attack chains,
unacknowledged volume, age) and every item shows the reasons behind its
position. Shadowfax ranks the queue; you decide. An incident leaves the list
when its alerts are acknowledged.

Verify that the event log has not been tampered with (see Evidence integrity):

```bash
python cli.py verify              # exit 0 if intact, 1 if broken
```

Ingest findings from any tool that speaks the shared envelope — the kind of
JSON is detected, so the same command takes events or an envelope:

```bash
maltriage sample.exe --envelope | python cli.py ingest -
python cli.py ingest findings.json
```

See who is failing to sign in, and let a locked-out colleague back in:

```bash
python cli.py lockouts            # exit 1 while any scope is locked
python cli.py lockouts --unlock j.bartlett
```

Write Shadowfax's own findings out for another tool to read — the mirror of
`ingest`:

```bash
python cli.py export --actor apt-agent-9 | some-other-tool --envelope -
python cli.py export > shadowfax-findings.json
```

Ask what an agent is allowed to do — or whether one action would be reported,
with an exit code a harness can act on (see Agent permissions):

```bash
python cli.py permissions recon-agent-3              # the profile that governs it
python cli.py permissions recon-agent-3 --tool nc    # exit 1: outside permissions
```

Change your password, or (admin) reset someone else's — passwords are always
prompted for, never taken as flags, where they would land in shell history:

```bash
python cli.py passwd                          # asks for the current one first
python cli.py passwd --user alice --generate   # prints a one-time password
```

Tell Shadowfax what an agent was started with, and refuse to start it if that
exceeds its profile (see Capability manifests):

```bash
python cli.py manifest build-agent-2 tools.json || exit 1
```

Point it elsewhere with `--url`, `SHADOWFAX_URL`, or the stored config.

---

## Agent permissions

Every other detector here infers that something is *wrong* from the fact that
it is *unusual* — more targets than usual, faster than its baseline, more bytes
than a threshold. None of them knows what an agent was for. A permission profile
says so: which tools the agent was given, and which targets it may touch.

```json
"agent_permissions": {
  "unprofiled_agents": "alert",
  "profiles": {
    "recon-agent-*": {
      "description": "Authorised recon for engagement alpha: scan and fetch, never a shell.",
      "allowed_tools":  ["nmap", "curl", "dig", "nikto"],
      "denied_tools":   ["nc", "ncat", "netcat", "bash", "sh", "powershell"],
      "denied_targets": ["~/.ssh/*", "/etc/*", "*.pem"]
    }
  }
}
```

An action outside the profile raises `permission_violation` — **critical** if
it was explicitly denied, **high** if it was merely never granted — naming the
profile and each way the event breached it. It needs no baseline, so an agent's
very first action can trip it. With `"unprofiled_agents": "alert"`, an AI agent
that nobody declared raises one `undeclared_agent` alert.

The rules are chosen so that the profile cannot quietly fail open:

| Rule | Why |
|---|---|
| A grant left out means *unrestricted*; an empty list means *nothing* | Two different statements, kept different |
| Deny wins over allow | Something written down as forbidden stays forbidden |
| A deny matches any spelling of a tool (`/usr/bin/nc`, `NC`, `nc.exe`) | Renaming the binary must not dodge a denial |
| An allow matches only as written, against the *resolved* target | `/repo/../etc/shadow` is not under `/repo/*`, and a `python` in `/tmp` is not the granted one |
| A tool call with no tool name, or an event with no target, is not granted | Silence is not permission |
| Malformed profiles are refused at `PUT /policy` with every problem listed | `"allowed_tools": "nmap"` would grant `n`, `m`, `a` and `p`; `alowed_tools` would grant everything |
| One alert per distinct breach | Forty retries of one denied tool are one finding, not forty |

Deny lists are a backstop; **the allow-list is the control**. A relative path
such as `../../etc/passwd` cannot be resolved without the agent's working
directory, so no deny pattern will reliably catch it — but it was never granted,
so an allow-list catches it without trying.

Profiles are keyed by actor id or by pattern. An exact id wins; otherwise the
most specific pattern does (`build-prod-*` over `build-*` over `*`), the same
way every time. Because a profile is policy, changing one rescans history:
declare a profile for an agent that has run for a month and every recorded
action is judged against it.

The actor drawer shows the governing profile beside the timeline, so an alert
reading *outside declared permissions* sits next to what was declared.

**Asking ahead.** `GET /actors/{id}/permissions?tool=nc&target=...` (or
`shadowfax permissions`) answers whether an action would be reported — the
detector's own judgement, asked in advance, and held by a test to the same
answer the detector gives afterwards. An agent runtime can use it to refuse a
call before making it. Shadowfax itself still only observes: a monitor that is
also the gate becomes the thing an attacker most wants to stop, and enforcement
belongs in the runtime.

### Capability manifests

A profile says what an agent may do. The framework running it knows what it
*can* do — its tool list, its MCP servers. A **manifest** is that list, posted
by whatever starts the agent:

```bash
curl -X POST http://localhost:8000/agents/build-agent-2/manifest \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"tools": ["read_file", "run_tests", "bash"],
       "mcp_servers": {"github": {"tools": [{"name": "create_issue"}]}}}'
```

Bare names, Anthropic/MCP tool objects, OpenAI function tools and MCP
`tools/list` results are all accepted; MCP tools become `mcp__github__create_issue`,
as Claude Code names them. Only names are kept — descriptions and schemas, where
an injected instruction would sit, are dropped on arrival. Anything Shadowfax
cannot read rejects the whole manifest, because quietly dropping a tool would
report it absent.

| Alert | Severity | Means |
|---|---|---|
| `excess_capability` | high if denied, else medium | configured with a tool the profile does not grant — caught *before* it is used |
| `capability_drift` | low | a later manifest added tools |
| `unlisted_tool_call` | medium | the agent called a tool its own manifest does not list |

The last is what neither side shows alone: an agent calling a tool its
configuration does not account for has either a wrong manifest or a tool from
somewhere else — an injected server, a tool added at runtime. The actor drawer
shows every configured tool marked against the profile, and what changed since
the previous manifest.

---

### Drafting a profile

Writing a profile by hand means knowing every tool an agent needs. **Draft a
profile from what it did** (in an agent's drawer, for analysts; `GET
/agents/{id}/profile-draft`; `shadowfax permissions <agent> --draft`) builds a
first draft from the agent's **tool calls** — not from its manifest. A profile
copied from the configuration would grant whatever the agent was given, which is
exactly what `excess_capability` is there to question.

- the tools it called are granted, except shells and raw sockets (`bash`, `sh`,
  `powershell`, `nc`…), which are denied wherever the agent has them;
- configured tools it never called are not granted — saved, they become
  `excess_capability`, candidates to remove from its configuration;
- the usual secrets (`~/.ssh/*`, `~/.aws/*`, `/etc/*`, `*.pem`) are denied, and
  no target allow-list is guessed;
- it shows every past event the draft would have flagged.

Nothing is saved: **Open in policy editor** puts the draft into the policy text
under the agent's id or its family pattern (`recon-agent-*`), and it takes effect
only when an analyst saves it.

## Evidence integrity

Shadowfax asks whether an actor's behaviour should be trusted. That question is
worth very little if the record of the behaviour cannot itself be trusted — an
event history that could have been quietly edited after the fact is not evidence,
it is an assertion.

Every event is hash-chained to the one before it:

```
entry_hash = sha256( prev_hash | canonical_json(event content) )
```

Because each link folds in the one before it, changing any byte of any event
invalidates that entry and every entry after it. Verification recomputes the
whole chain and reports the **first** position where it diverges, so a break is
located rather than merely announced — and the three failure modes read
differently: content that no longer matches its hash (edited), an entry that no
longer chains to its predecessor (deleted or reordered), and a valid chain that
is shorter than the recorded head (truncated).

```bash
python cli.py verify     # exit 0 if intact, 1 if broken
```

```
ledger intact — 39 entries verified, head 491329ea531869ec…

LEDGER BROKEN at position 24 (event id 25, actor recon-agent-3): the entry's
content does not match its hash -- this event was modified after it was
recorded. 24 entries before it verified cleanly.
```

The dashboard carries the same check as a badge beside the connection
indicator — both answer "can I believe what I am looking at right now" — and it
re-verifies itself whenever the event count changes.

The chain follows the order events were **received**, not the `timestamp` they
claim. Events legitimately arrive out of chronological order, and ordering by
data the emitter supplies would make the proof depend on the thing being
audited. What is proven is *"these entries were appended in this order and none
has changed since"* — a statement about the store, not about the world.

This is tamper-**evident**, not tamper-**proof**. It makes silent modification
and deletion detectable by anyone who can read the log; it does not prevent
them. An attacker with full write access to the database could rewrite the
events, the chain and the recorded head together. The honest mitigation is to
anchor the head somewhere that attacker does not control — `GET /ledger/head`
returns the entry count and head hash for exactly that purpose, and where it
gets published is deliberately left to the operator rather than claimed here.

---

## The front door

Shadowfax has shipped a `brute_force_auth` detector since v0.1. Until v0.10 its
own sign-in endpoint would have sailed straight past it — unlimited attempts, no
delay, no record. A tool that detects the attack it is itself vulnerable to is
not a serious tool.

**Backoff, then lockout.** After a few failures the caller must wait a growing
interval between attempts (2s, 4s, 8s … capped). Someone who fat-fingered their
password notices nothing; a script working through a wordlist is slowed by
orders of magnitude. Past the limit the scope is locked outright. Nothing
sleeps: answering a flood by holding connections open would turn the defence
into a resource-exhaustion vector, so Shadowfax replies at once with `429` and
an honest `Retry-After`.

**Hard lockout applies to a (username, source) pair, never to the account.**
Locking an account after N failures hands anyone who knows a username a
denial-of-service against its owner. A second, looser scope covers a source
address across every username it tries — that is what catches password spraying
— and it **slows but never locks**, because an office, a VPN exit or a NAT
gateway is shared, and locking one out would let a single attacker deny sign-in
to everyone behind it.

**No enumeration oracle.** The throttle is consulted before the username is
looked up, and a failure is recorded whether or not the account exists, so an
imaginary username locks out exactly like a real one. When there is no such
user, `auth.dummy_verify` burns the same PBKDF2 work a real check would — the
old early return made response time a reliable signal for which accounts exist.

```bash
python cli.py lockouts
```

```
sign-in throttle: lock after 5 failures in 15 min, for 15 min (backoff from 3)

USERNAME       SOURCE       FAILS  STATE     LAST FAILURE
j.bartlett     127.0.0.1    5      LOCKED    2026-09-30T12:02:11
```

### Shadowfax watches itself

Failed sign-ins and lockouts are ingested as **ordinary events**, under the
actor `shadowfax-auth`, into the same hash-chained ledger as everything else.
The existing `brute_force_auth` detector fires on them with the same `T1110`
mapping, and they appear in the same alert table — with no special-casing
anywhere in the engine. There is no separate audit path to keep in sync, and no
privileged log that a compromised admin could edit more quietly than the rest.

The attempted username travels in metadata, never as the actor id: it is
attacker-controlled text, and keying actors on it would let anyone mint actors
at will — or post events into a real actor's timeline by "signing in" as them,
poisoning the evidence for an unrelated investigation.

Set `SHADOWFAX_SELF_MONITOR=0` to turn it off.

### Locked out of your own Shadowfax

If the only admin password is lost — or the generated one has scrolled out of the
container log — reset it from the machine Shadowfax runs on:

```bash
docker exec -it shadowfax python recover.py admin       # the published image
docker exec -it shadowfax python recover.py admin --remove-2fa   # phone lost too
docker compose exec shadowfax python recover.py admin   # with docker compose
python recover.py admin                                  # from source
```

It asks you to type the username again, then prints a newly generated password
once. That password must be changed at the next sign-in; every session the
account had is ended and its sign-in failures are cleared. It works on the
database file directly, so it is not reachable over the network, and anyone able
to run it could already rewrite that file. It is also not quiet: the reset is
written into the ledger and raises a high `console_recovery` alert naming the
account and the OS user — even with self-monitoring switched off, because a
reset that bypassed sign-in is exactly what an analyst should see. Your events
are untouched; nothing is discarded.

### Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `SHADOWFAX_LOGIN_MAX_FAILURES` | 5 | failures before a scope is locked |
| `SHADOWFAX_LOGIN_WINDOW_MINUTES` | 15 | how far back failures count |
| `SHADOWFAX_LOGIN_LOCKOUT_MINUTES` | 15 | how long a lockout lasts |
| `SHADOWFAX_LOGIN_BACKOFF_AFTER` | 3 | failures before backoff starts |
| `SHADOWFAX_LOGIN_BACKOFF_CAP_SECONDS` | 30 | longest per-scope wait |
| `SHADOWFAX_LOGIN_SOURCE_BACKOFF_AFTER` | 10 | failures from one source before it is slowed |
| `SHADOWFAX_LOGIN_SOURCE_BACKOFF_CAP_SECONDS` | 60 | longest per-source wait |
| `SHADOWFAX_SELF_MONITOR` | on | ingest front-door events into the log |
| `SHADOWFAX_REQUIRE_ADMIN_2FA` | off | admins must turn on two-factor before anything else works |

These live in the environment, **not** in the detection policy. The policy
governs detection; this is enforcement of the platform's own door, and putting
it behind `PUT /policy` would let any analyst widen it to nothing.

**Behind a proxy:** `X-Forwarded-For` is deliberately ignored — it is set by the
client, so keying a security control on it would hand the control to the
attacker, who would simply rotate the header. Terminate the proxy somewhere that
presents the real peer address, or every request will share one source scope.

This slows credential guessing. It does not stop a distributed attacker with
many source addresses, and it is not a substitute for good passwords or a second
factor.

---

## Ingesting other tools' findings

`findings-envelope.md` defines a wire format shared across this portfolio:
maltriage produces findings from a file's bytes, claude-recon-agent from a
target's services, Shadowfax from an actor's event history. Shadowfax ingests
that envelope, and **knows nothing about the tool that sent it** — anything that
writes the format is ingestible, which is what makes this a pipe rather than an
integration.

```bash
maltriage sample.exe --envelope | python cli.py ingest -
```

```
maltriage 0.2.0 -> file:sha256:9f86d081884c7d65: 2 finding(s) ingested
  medium: 1  info: 1
  medium   writable_executable_section
  info     authenticode_common_name  [unvalidated]
```

### Findings become events, not alerts

The obvious implementation writes an alert row per finding. It would also break
the invariant the rest of Shadowfax rests on: alerts are a pure function of
`(an actor's events, policy)`, recomputed on every rescan and never patched — so
an alert with no event behind it would survive until the next rescan of that
actor and then silently vanish.

A finding is therefore stored as an **event**, and a detector turns it back into
an alert. Rescans reproduce it, the hash-chained ledger covers it, and
correlation sees it alongside native alerts. The payoff is composition: a
reconnaissance finding from another tool can form the **first stage of a kill
chain** whose later stages Shadowfax detected itself —

```
Reconnaissance → Privilege Escalation → Credential Access → Lateral Movement → Exfiltration
   (recon agent)   ·········· Shadowfax's own detectors ··········
```

— with no special-casing anywhere in the engine.

### What Shadowfax will not accept

Validation is the trust boundary, and a malformed envelope is rejected **whole**,
naming the field at fault. Keeping the findings we happen to like would hide the
emitter's bug, and whoever writes the next emitter deserves to be told what is
wrong with theirs.

```
400 invalid findings envelope — findings[0].severity: must be one of
critical, high, medium, low, info
```

A finding's `key` becomes the alert category, so an emitter **may not use one of
Shadowfax's own twenty-seven detector categories**. An alert reading
`destructive_action` must mean Shadowfax's detector found it, not that somebody
else said so.

### Provenance, and who checked

Every ingested alert carries the tool that reported it, that tool's observed
evidence, and its `validated` flag — shown as a `via <tool>` badge, an
`unvalidated` marker and the evidence line beneath the message.

`validated: false` means the emitter is repeating something the subject asserted
about itself: a certificate common name, a service banner, a `Server:` header.
Shadowfax marks these and **does not downgrade them**. The envelope is explicit
that a consumer may treat unvalidated findings differently but may not treat
them as absent, and quietly lowering another tool's severity would be a hidden
policy. An alert Shadowfax raised itself carries no `validated` flag at all —
"nobody claimed this, we found it" is a different statement from "somebody
claimed it without checking".

Ingested evidence is fenced as untrusted in the investigation assistant's
prompt, alongside agent-reported fields. It is another tool's report of a file's
bytes or a service's banner, which is exactly where an injection would be
planted.

### Re-running an emitter

A finding's id is a function of its content, so re-running a scanner over
unchanged input produces the same ids and Shadowfax skips them. Analyst state
follows the finding rather than the row it landed in: acknowledge a finding
today, re-run the scanner tomorrow, and the acknowledgement is still there.

```
maltriage 0.2.0 -> file:sha256:9f86d081884c7d65: 0 finding(s) ingested, 2 already known
```

Shadowfax derives its alert id *from* the emitter's id rather than using it
directly, under a fixed namespace, so an emitter cannot send a crafted id that
inherits an unrelated alert's acknowledgement.

### Speaking the format, not just reading it

Shadowfax emits the envelope as well as ingesting it, so the portfolio's other
tools can consume Shadowfax the way it consumes them. `GET /findings` returns
one envelope per actor; `?actor_id=` returns a single one.

Writing a producer and a consumer against the same document is the only real
test of a wire format — a spec with one implementation is a spec with one
opinion. The test suite round-trips it: what the producer emits is handed
straight to the consumer's own validator.

**The id needed no new scheme.** `alert_identity` has followed the envelope's
rule since v0.3, so a Shadowfax alert id already *is* a conformant finding id.
Re-exporting unchanged data produces the same ids, and a consumer can tell
"again" from "new".

**Ingested findings are not re-emitted.** An alert carrying a `source_tool` came
from somebody else; restating it under `source.tool: shadowfax`, with
Shadowfax's `validated` flag on it, would make this a laundering service. Ask
Shadowfax what Shadowfax found and you get exactly that.

**Metadata is quoted from an allowlist.** An envelope is piped, stored and
shared, and the spec forbids carrying secret material — so the question is not
what to strip but what is known safe. Counts, thresholds and levels are; an
agent's `tool` and `arguments` strings are not, because a tool call is exactly
where a credential ends up.

**`validated: true`, with a stated scope.** Every alert is a conclusion
Shadowfax's own engine computed over the record it holds, not a self-description
passed along. But what is verified is a property of the *recorded history*, not
of the world: the events came from the thing being watched. Same scope the
ledger claims, and said out loud rather than implied.

**Shadowfax refuses its own envelope.** Every key in the export is a native
detector category, and ingest rejects those — so Shadowfax cannot be fed its own
output. The loop is closed by the shape of the thing, not by a rule anyone has
to remember.

### Subject pages

The **Subjects** button lists everything findings have been reported about —
files, hosts, log workspaces and actors — worst first. A subject's drawer leads
with its **findings report**: the tools that reported on it, each with the
versions and runs it reported from, their findings worst first with evidence,
ATT&CK reference and recommendation; which findings were `unvalidated`; which
are acknowledged or assigned; and, called out at the top, any finding **two
tools agree on** — two scanners reporting the same key is worth more than either
alone. The same report is `GET /subjects/{id}` (`GET /subjects` for the list)
and `shadowfax subjects [id]`.

### Subjects and the `info` level

A `kind: actor` subject lands on that actor's real timeline and inherits its
existing actor type. Every other kind is namespaced — `file:sha256:…`,
`host:10.0.0.9`, `log_workspace:ws-7` — under a new `external` actor type, so a
file called `admin` cannot quietly become the user `admin`.

The envelope's ladder has five levels; Shadowfax's own detectors emit the top
four and `info` arrives from outside. It is **weighted 0** in risk scoring,
incident scoring and the triage digest: informational findings are context, and
a hundred of them must not out-score one critical.

---

## Security

Every endpoint requires authentication. Analysts sign in for a bearer token
(12-hour sessions); agents and harnesses ingest events with an API key. Access
is role-based: `viewer` reads, `analyst` acknowledges, assigns and edits
policy, `admin` manages users, keys and resets. Passwords are hashed with
PBKDF2 and a per-user salt, and only credential fingerprints are stored, never
the secrets. CORS is restricted to the dashboard origin. The sign-in endpoint
is throttled and locks out, and costs the same whether or not the username
exists — see The front door above.

On a fresh database the first admin comes from `SHADOWFAX_ADMIN_USERNAME` and
`SHADOWFAX_ADMIN_PASSWORD`. If those are unset, running from source creates
`admin` / `admin` with a warning, and the published image generates a random
password and prints it once — set real credentials before exposing the API.

Passwords must be at least 12 characters, not the username and not one of the
handful always tried first. Changing one requires the current password — through
the same throttle as sign-in — and signs out every other session. An admin reset
ends all of the user's sessions and marks the new password must-change: until
the owner replaces it, the server allows nothing else. Changes and resets are
written into the ledger.

Admins manage accounts from the dashboard's **Accounts** drawer (or the same
`/users` and `/api-keys` endpoints). New users get a generated password they
must change at first sign-in; API keys are shown once and revoked at a click.
Creating an account and issuing or revoking a key are written into the ledger
with who did it, and a new **administrator** raises `admin_account_created`
(medium, ATT&CK T1136) — an extra admin is the classic way to keep a foothold.
Promoting an existing account to admin raises `admin_role_granted` (medium,
T1098). Disabling an account signs it out everywhere and refuses its sign-in
without deleting anything it did; an admin cannot change their own role or
disable themselves, and the last enabled admin can be neither demoted nor
disabled. `recover.py` re-enables the account it recovers.

**Two-factor sign-in** (TOTP, RFC 6238) is available to every account from the
dashboard's **Two-factor** button: scan the QR code (or type the key) into any
authenticator app and confirm with a first code. Sign-in then asks for a code
after the password. A code works once, one 30-second step of clock drift is
allowed either way, and wrong codes count towards the same backoff and lockout
as wrong passwords. Ten recovery codes, shown once and stored as fingerprints,
cover a lost phone. Turning it off takes the password and a code; an admin can
remove it from someone else's account (their sessions end), which raises
`mfa_removed` (medium, ATT&CK T1556). The TOTP secret is stored in the database
as it must be readable to check a code — whoever can read the database file can
read it. `shadowfax login` prompts for the code; `recover.py` keeps two-factor
unless given `--remove-2fa`.

Set `SHADOWFAX_REQUIRE_ADMIN_2FA=1` to **require** it for administrators: an
admin without it signs in to the enrolment screen and nothing else — the API,
ingest and the live stream all refuse that session until two-factor is on — and
an admin cannot turn their own off while it is required (another admin removes
it for a lost phone). Other roles and API keys are unaffected. It is an
environment setting rather than policy because analysts can edit the policy.
**New recovery codes** (the password and a current code) replace the old list
at once.

A lost admin password is recovered with `recover.py` on the server itself (see
Locked out of your own Shadowfax above), never over the API; the recovery is
recorded and raises `console_recovery`.

The session token never appears in a URL. The dashboard's live stream is opened
with a single-use ticket that expires in 30 seconds (`POST /stream/ticket`),
because a URL is what access logs record; signing out ends any stream the
session opened. Requests are bounded before they are parsed — 2 MiB per body,
1,000 events or findings per request, 16 KiB of metadata per event, with fixed
limits on identifiers — and each refusal names the setting that controls it
(`SHADOWFAX_MAX_BODY_BYTES`, `SHADOWFAX_MAX_EVENTS_PER_REQUEST`,
`SHADOWFAX_MAX_METADATA_BYTES`). Each ingest credential also has a budget —
6,000 events a minute by default (`SHADOWFAX_INGEST_EVENTS_PER_MINUTE`) — past
which requests are refused whole with `429` and `Retry-After`, and the first
refusal raises an `ingest_flood` alert naming the credential. Findings and manifests arrive only through the
endpoints that validate them — `POST /events` refuses both event types, and an
envelope may not claim to come from Shadowfax.

Timestamps must be ISO 8601 and are stored in UTC, so `+02:00` and `Z` sort
and compare as the same instant. Because detection reads the whole history,
a new event dated in the past can change what was concluded about the past —
so when an upload makes existing alerts disappear, Shadowfax writes an
`alerts_retired` event naming them and the credential that sent it, and raises
`history_rewritten` (high). Nobody can ingest under Shadowfax's own actors
(`shadowfax`, `shadowfax-ingest`), tool names in findings are restricted to
letters, digits, `.`, `_` and `-`, and an external tool's finding ids are
scoped to the subject they describe. The ledger takes a write lock before it
reads the chain head, so two writers cannot fork it. The command line only
sends a saved token to the server it was saved for, and does not follow
redirects. Hashing is
stdlib PBKDF2 rather than bcrypt/argon2; that, and the still-single-writer
SQLite backend, are the reasons Shadowfax remains a local-development tool.

---

## Investigation assistant

The dashboard can explain any alert or incident in plain English: a "✦ explain"
link on each alert, and an "Explain this incident" threat summary in the
Incidents view. This is the only part of Shadowfax that uses a language model,
and it is deliberately confined to explaining. It is handed an evidence brief
assembled from facts the deterministic engine already produced, and it creates
nothing, decides nothing and has no tools — the explain endpoints are read-only.
Fields reported by the monitored agent are treated as untrusted data in the
prompt, and because the assistant cannot act, a prompt-injected narrative can be
wrong but can never make Shadowfax do anything.

The same assistant powers **natural-language search**: the search box above the
alert table takes a plain-English request ("critical destructive actions by AI
agents last week") and the assistant *translates* it into a filter. It only
translates — every value it proposes is validated against Shadowfax's known
severities, actor types and categories before the query runs, so a hallucinated
value is dropped rather than executed, and the banner shows exactly how the
query was read. Detection and the query itself stay deterministic.

Set `ANTHROPIC_API_KEY` (optionally `SHADOWFAX_LLM_MODEL`) to have a model write
the narratives and translate searches. With no key configured, explanations use
the deterministic brief and search uses a keyword parser, so both features work
out of the box and the test suite needs no network. Each result is labelled with
its source.

---

## Philosophy

Shadowfax is intended to assist analysts, not replace them.

Detection remains deterministic and policy-driven. Every rule is explicit and
lives in one file, where the policy governs it and tests can reach it.

Large language models are used only to explain, correlate and summarise
activity. They are never treated as the security boundary.
