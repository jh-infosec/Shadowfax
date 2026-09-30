# Shadowfax

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
- Rule-based detection engine across sixteen alert categories, including AI-agent tool-call analysis
- Policy management with full rescan on change
- Actor risk scoring
- Stable, deterministic alert identity that survives a rescan
- Acknowledge and assign alerts, with analyst state that persists across rescans
- Authentication with user accounts, roles (admin / analyst / viewer) and API keys
- Dashboard sign-in, with the UI adapting to the signed-in user's role
- Live push over Server-Sent Events — the dashboard updates the instant data changes
- Agent-trace ingest — flags destructive tool calls and out-of-scope actions by AI agents
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
- Self-monitoring — attacks on Shadowfax's own front door become ordinary events and raise ordinary alerts, through the same detectors as everything else
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

### v1.0

- Electron Desktop Application
- PostgreSQL
- Multi-user Support
- Docker Deployment

---

## Running Shadowfax

The backend and the dashboard run as two processes.

Backend, from the repository root

```bash
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Interactive API documentation is available at

```
http://127.0.0.1:8000/docs
```

Dashboard, in a second terminal

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` and sign in. On a fresh database the default
login is `admin` / `admin` (see Security); create further accounts from the
API as an admin.

The dashboard reads `VITE_API_BASE` for the backend URL, defaulting to
`http://127.0.0.1:8000`. Set it in `frontend/.env` if the backend runs
elsewhere. If you serve the dashboard from another origin, add it to
`SHADOWFAX_CORS_ORIGINS` on the backend.

---

## Testing

Run the backend test suite

```bash
python test_api.py
```

The dashboard has no automated tests yet.

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

See who is failing to sign in, and let a locked-out colleague back in:

```bash
python cli.py lockouts            # exit 1 while any scope is locked
python cli.py lockouts --unlock j.bartlett
```

Point it elsewhere with `--url`, `SHADOWFAX_URL`, or the stored config.

---

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
`SHADOWFAX_ADMIN_PASSWORD`. If those are unset, a default `admin` / `admin` is
created and a warning is printed — fine for local development, but set real
credentials and change the password before exposing the API. Hashing is
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
