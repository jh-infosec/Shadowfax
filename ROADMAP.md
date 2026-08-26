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

- [x] Unticking every severity or actor type shows all alerts instead of none
- [x] Debounce the search box, which currently fires a request per keystroke
- [x] Wire category filtering to the sidebar, the API already supports it
- [x] Fix `cd ../backend` in the frontend README, the backend is at the root
      (already corrected in the V2 README; the path now points to the root)
- [x] Replace the deprecated `@app.on_event("startup")` with a lifespan
      handler
- [x] Align `Optional[str]` in app.py with `str | None` used elsewhere

---

## Version 0.3

- [x] Stable alert identity, so analyst state can attach to an alert.
      Deterministic id = `sha256(shadowfax | actor | category | event_id)`.
      `category` is the machine-stable key and `message` is excluded, so
      rewording a detector's sentence never changes an id or resets an
      acknowledgement (this diverged from the "actor, event, category and
      message" wording deliberately, per `findings-envelope.md`). `AlertTable`
      and `ActorDrawer` now update rows in place because the id is stable.
- [x] Acknowledge and assign an alert. API `PATCH /alerts/{id}/state` backed by
      an `alert_state` table that survives rescans, plus per-row Acknowledge and
      Assign controls in the dashboard. (Acting analyst is a placeholder until
      authentication lands.)
- [x] Authentication (opaque bearer tokens, 12h sessions, PBKDF2 passwords)
- [x] User accounts (admin-managed, created via `POST /users`)
- [x] API keys (ingest-only, for agents and harnesses)
- [x] Role-based access control (admin > analyst > viewer)
- [ ] WebSocket or SSE push, replacing the poll loop
- [x] Restrict CORS to the dashboard origin

---

## Version 0.4

- [ ] MITRE ATT&CK mapping. Technique ids come verbatim from a registry
      shared with the rest of the portfolio, the same table `claude-recon-
      agent` and `maltriage` consume. One registry, three consumers, one place
      a technique id is corrected. Nothing generates a technique id.
- [ ] Alert correlation
- [ ] Threat intelligence feeds
- [ ] Incident reports

---

## Version 0.4.5

Agent traces as events. The current event schema describes what an actor did
to a system; an AI agent produces a different shape, and this release ingests
it.

- [ ] Agent-trace event type: tool name, arguments, target, exit status,
      duration, emitted by a harness or parsed from a session log
- [ ] Destructive-action detectors: shutdown, delete, drop, recursive remove,
      credential writes, outbound requests to hosts outside the allowlist,
      rule-based and evaluated against policy
- [ ] Engagement scope as a policy object: allowed domains, IP ranges, ports;
      an action touching anything outside it fires `out_of_scope_action`. Scope
      lives in policy because `detectors.run_for_actor` is a pure function of
      an actor's history and the policy, and policy is the only input a user
      is meant to change.
- [ ] Settle the rescan-cost strategy before trace volume forces it: bound the
      recompute window or accept the linear cost deliberately and record the
      decision. "Rescan cost grows with actor history" in `architecture.md` is
      linear in history, and a recon session is one actor with hundreds of
      tool calls, so what is invisible at a dozen events per actor is not at
      trace scale.

---

## Version 0.5

- [ ] AI investigation assistant
- [ ] Natural language search
- [ ] Threat summaries
- [ ] Completion-fraud detector: compare what an agent claimed it did against
      what its trace shows it did (claimed coverage of forty targets, trace
      contains eleven). A counting problem, not a judgement call, so it belongs
      in `detectors.py`. The detector to protect if anything gets cut.
- [ ] Token-spend anomaly: spend per actor against that actor's own baseline,
      the same shape as the existing `rate_anomaly` detector and able to reuse
      its window handling.

The investigation assistant explains alerts and never creates them. Both
detectors above are pure functions of the actor's trace and the policy.

---

## Version 0.6

Evidence integrity and ingest.

- [ ] Tamper-evident append-only event log: hash-chained entries, so the event
      store can be shown not to have been edited after the fact. This is what
      turns the alert history into something an auditor or assessor will accept.
- [ ] Findings-envelope ingest: accept the envelope defined in
      `findings-envelope.md` from `maltriage` and `claude-recon-agent`.
      Envelope findings become alerts without Shadowfax knowing anything about
      the emitter.
- [ ] Weight `info` at 0 in risk scoring. The shared severity ladder carries
      five levels and Shadowfax currently defines four; this is the only change
      the shared ladder forces.

---

## Version 1.0

- [ ] Electron desktop application
- [ ] PostgreSQL support
- [ ] Multi-user support
- [ ] Docker images
- [ ] SIEM integrations
- [ ] Production deployment
