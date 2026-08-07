# Shadowfax

> AI Security Operations Platform for Monitoring Autonomous AI Agents

---

## Why Shadowfax?

As autonomous AI agents become more capable, they are increasingly being trusted to write code, use tools, access APIs and make decisions with minimal human supervision.

Traditional security tooling was designed to monitor human users, service accounts and infrastructure—not autonomous AI systems.

Shadowfax explores what a modern security operations platform might look like if AI agents became first-class identities inside an organisation.

The project is being developed alongside my studies in offensive security and artificial intelligence, with the goal of combining practical cybersecurity engineering with modern AI workflows.

---

## Project Goals

Shadowfax is designed to answer three questions:

- What is this agent doing?
- Why is it doing it?
- Should this behaviour be trusted?

Rather than acting as a security boundary, Shadowfax focuses on visibility, investigation and explainability.

---

## Current Features

- REST API built with FastAPI
- SQLite event database
- Rule-based detection engine
- Policy management
- Actor timelines
- Risk scoring
- Live event ingestion
- Automated API testing

---

## Architecture

```
                 Dashboard
                      │
                      ▼
               Shadowfax API
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
 Detection Engine            SQLite Database
        │
        ▼
 Alert Generation
```

Every event enters through the API.

The detection engine evaluates the actor's behaviour against the active policy and generates alerts.

The dashboard communicates only with the API and never accesses the database directly.

---

## Technology

Current stack

- Python
- FastAPI
- SQLite

Planned

- Electron Desktop Client
- PostgreSQL
- WebSockets
- MITRE ATT&CK Mapping
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
- Live Charts

### v0.3

- Live Event Streaming
- Authentication
- WebSockets

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

Install the dependencies

```bash
pip install -r requirements.txt
```

Start the API

```bash
uvicorn app:app --reload --port 8000
```

Interactive API documentation is available at

```
http://127.0.0.1:8000/docs
```

---

## Testing

Run the test suite

```bash
python test_api.py
```

---

## Philosophy

Shadowfax is intended to assist analysts—not replace them.

Detection remains deterministic and policy-driven.

Large language models are used only to explain, correlate and summarise activity. They are never treated as the security boundary.