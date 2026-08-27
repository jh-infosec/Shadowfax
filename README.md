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
- Rule-based detection engine across twelve alert categories
- Policy management with full rescan on change
- Actor risk scoring
- Stable, deterministic alert identity that survives a rescan
- Acknowledge and assign alerts, with analyst state that persists across rescans
- Authentication with user accounts, roles (admin / analyst / viewer) and API keys
- Dashboard sign-in, with the UI adapting to the signed-in user's role
- Live push over Server-Sent Events — the dashboard updates the instant data changes
- React dashboard with a live alert table
- Actor timelines, showing alerts attached to the events that produced them
- Filtering by severity, actor type, category and free-text search
- Policy editing from the dashboard
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
- MITRE ATT&CK mapping
- Electron desktop client
- AI-assisted investigations

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

- MITRE ATT&CK Mapping
- Correlation Engine
- Incident Reports

### v0.5

- AI Investigation Assistant
- Natural Language Search
- Threat Summaries

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

## Security

Every endpoint requires authentication. Analysts sign in for a bearer token
(12-hour sessions); agents and harnesses ingest events with an API key. Access
is role-based: `viewer` reads, `analyst` acknowledges, assigns and edits
policy, `admin` manages users, keys and resets. Passwords are hashed with
PBKDF2 and a per-user salt, and only credential fingerprints are stored, never
the secrets. CORS is restricted to the dashboard origin.

On a fresh database the first admin comes from `SHADOWFAX_ADMIN_USERNAME` and
`SHADOWFAX_ADMIN_PASSWORD`. If those are unset, a default `admin` / `admin` is
created and a warning is printed — fine for local development, but set real
credentials and change the password before exposing the API. Hashing is
stdlib PBKDF2 rather than bcrypt/argon2; that, and the still-single-writer
SQLite backend, are the reasons Shadowfax remains a local-development tool.

---

## Philosophy

Shadowfax is intended to assist analysts, not replace them.

Detection remains deterministic and policy-driven. Every rule is explicit and
lives in one file, where the policy governs it and tests can reach it.

Large language models are used only to explain, correlate and summarise
activity. They are never treated as the security boundary.
