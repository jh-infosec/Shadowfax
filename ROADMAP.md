# Shadowfax Roadmap

## Version 0.1

- [x] FastAPI backend
- [x] SQLite persistence
- [x] REST API
- [x] Detection engine
- [x] Sample data
- [x] Integration tests

---

## Version 0.2

- [x] React dashboard
- [x] Live alert table
- [x] Actor timelines
- [x] Risk score visualisation
- [x] Alert filtering
- [x] Policy editor

---

## Version 0.2.1

Defects found reviewing the v0.2 dashboard. Small, and worth clearing before
new work.

- [ ] Unticking every severity or actor type shows all alerts instead of none
- [ ] Debounce the search box, which currently fires a request per keystroke
- [ ] Wire category filtering to the sidebar, the API already supports it
- [ ] Fix `cd ../backend` in the frontend README, the backend is at the root
- [ ] Replace the deprecated `@app.on_event("startup")` with a lifespan
      handler
- [ ] Align `Optional[str]` in app.py with `str | None` used elsewhere

---

## Version 0.3

- [ ] Stable alert identity, so analyst state can attach to an alert
- [ ] Acknowledge and assign an alert
- [ ] Authentication
- [ ] User accounts
- [ ] API keys
- [ ] Role-based access control
- [ ] WebSocket or SSE push, replacing the poll loop
- [ ] Restrict CORS to the dashboard origin

---

## Version 0.4

- [ ] MITRE ATT&CK mapping
- [ ] Alert correlation
- [ ] Threat intelligence feeds
- [ ] Incident reports

---

## Version 0.5

- [ ] AI investigation assistant
- [ ] Natural language search
- [ ] Threat summaries

---

## Version 1.0

- [ ] Electron desktop application
- [ ] PostgreSQL support
- [ ] Multi-user support
- [ ] Docker images
- [ ] SIEM integrations
- [ ] Production deployment
