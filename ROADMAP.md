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
- [x] WebSocket or SSE push, replacing the poll loop (SSE: `GET /stream`)
- [x] Restrict CORS to the dashboard origin

---

## Version 0.4

- [x] MITRE ATT&CK mapping. Technique ids come verbatim from a shared registry
      (`attack_registry.json`) consumed across the portfolio; `attack.py` maps
      alert categories (and per-rule destructive actions) to ids and enriches
      from the registry. Nothing generates a technique id. Shipped in the
      `v0.4.6` snapshot.
- [x] Alert correlation. `correlate.py` groups an actor's alerts into incidents
      by a policy time-window; `GET /incidents`. Shipped in `v0.4.7`.
- [ ] Threat intelligence feeds
- [x] Incident reports. Deterministic markdown report per incident
      (`GET /incidents/{id}`), shown in the dashboard's Incidents view. `v0.4.7`.

---

## Version 0.4.5

Agent traces as events. The current event schema describes what an actor did
to a system; an AI agent produces a different shape, and this release ingests
it.

- [x] Agent-trace event type: `event_type: "tool_call"` carrying tool,
      arguments, exit status, duration (and optional host/port/url) in metadata,
      emitted by a harness or parsed from a session log. No schema change.
- [x] Destructive-action detectors: recursive delete, database drop, credential
      write, disk wipe, system shutdown, rule-based via
      `policy.destructive_action_rules`.
- [x] Engagement scope as a policy object (`policy.engagement_scope`): allowed
      domains, IP ranges, ports; an out-of-scope destination fires
      `out_of_scope_action`. Scope lives in policy because
      `detectors.run_for_actor` is a pure function of history and policy.
- [x] Settled the rescan-cost strategy: accepted the linear cost deliberately
      (the stateful detectors need full history, so a recompute-window cap would
      break them) and recorded it in `architecture.md` and `CHANGELOG.md`. The
      real fix, when volume demands it, is incremental detector state.

---

## Version 0.5

- [x] AI investigation assistant. `assistant.py` explains an alert or a
      correlated incident to an analyst from a deterministic evidence brief;
      `GET /alerts/{id}/explain` and `GET /incidents/{id}/explain` are read-only.
      The LLM explains, never creates or decides, and has no tools. Falls back to
      a deterministic narrative when no API key is set. Shipped in `v0.5.1`.
- [x] Natural language search: `assistant.translate_query()` turns a
      plain-English query into a validated alert filter (`POST /search`); the
      model only translates, every value is validated against known enums, and
      detection stays deterministic. Deterministic keyword fallback with no key.
      Shipped in `v0.5.2`.
- [x] Threat summaries: the incident explanation is a plain-English threat
      summary of a correlated burst of alerts. Shipped in `v0.5.1`.
- [x] Completion-fraud detector: `completion_claim` events are checked against
      the trace's actual coverage; fires `completion_fraud` when delivery falls
      short of the claim beyond `completion_claim_tolerance`. Shipped in the
      `v0.5` snapshot.
- [x] Token-spend anomaly: `token_spend_anomaly` on `metadata.tokens` per actor
      against the actor's own baseline, same window shape as `rate_anomaly`.
      Shipped in `v0.5`.

The investigation assistant explains alerts and never creates them. Both
detectors above are pure functions of the actor's trace and the policy.

---

## Version 0.6

Attack-chain correlation, then evidence integrity and ingest.

- [x] Attack-chain (kill-chain) correlation: an incident whose alerts advance in
      order through the MITRE ATT&CK tactics is flagged as a chain and, when it
      reaches a terminal tactic (lateral movement, collection, C2, exfiltration,
      impact), escalated to critical. Deterministic — the longest
      strictly-increasing tactic-rank subsequence of the incident's alerts, in
      `correlate.py`; threshold `attack_chain_min_stages`. Shipped in `v0.6.0`.
- [x] Tamper-evident append-only event log: hash-chained entries, so the event
      store can be shown not to have been edited after the fact. This is what
      turns the alert history into something an auditor or assessor will accept.
      `ledger.py`: `entry_hash = sha256(prev_hash | canonical_json(content))`
      over insertion order, plus a `ledger_head` record so truncation is visible
      too. Verification locates the *first* break and distinguishes edit from
      deletion from truncation. `GET /ledger/verify`, `GET /ledger/head`,
      `shadowfax verify`, and a dashboard integrity badge. Tamper-evident, not
      tamper-proof — anchoring the head off-box is left to the operator.
      Shipped in `v0.9.0`.
- [x] Findings-envelope ingest: accept the envelope defined in
      `findings-envelope.md` from `maltriage` and `claude-recon-agent`.
      Envelope findings become alerts without Shadowfax knowing anything about
      the emitter. `envelope.py` validates strictly and translates findings into
      **events**, so a detector produces the alerts and the "alerts are a pure
      function of (events, policy)" invariant holds -- which also means an
      ingested finding composes with correlation and can form the first stage of
      a kill chain Shadowfax completes itself. `POST /findings`, and
      `shadowfax ingest` detects an envelope rather than taking a flag.
      Shipped in `v0.11.0`.
- [x] Weight `info` at 0 in risk scoring. The shared severity ladder carries
      five levels and Shadowfax currently defines four; this is the only change
      the shared ladder forces. Applied to risk scoring, incident scoring and the
      triage digest: informational findings are context, and a hundred of them
      must not out-score one critical. Shipped in `v0.11.0`.

---

## Version 0.7

- [x] Command-line interface: `cli.py`, stdlib-only, over the HTTP API (never
      the database, so auth and RBAC still apply). `--json` everywhere and
      meaningful exit codes; `shadowfax check` exits non-zero when alerts match,
      so a harness can gate its own run. Shipped in `v0.7.0`.
- [x] Triage digest: `digest.py` ranks the open incidents (those with
      unacknowledged alerts) into a "these N need you" queue. The ranking is
      deterministic — severity, completed attack chains, unacknowledged volume,
      age — and every item carries the reasons behind its position; the
      assistant only writes a covering narrative and cannot re-order it.
      `GET /digest`, `shadowfax digest`, and a dashboard view. An incident
      leaves the queue only when a human acknowledges its alerts. Shipped in
      `v0.8.0`.

---

## Version 0.10

Harden the platform's own front door, then point the engine at it.

- [x] Sign-in throttling and lockout: `throttle.py`, a pure function of
      `(failure timestamps, now, settings)`. Backoff (2s, 4s, 8s … capped) then
      lockout; nothing sleeps, so a flood cannot exhaust the server through its
      own defence. Hard lockout is scoped to a (username, source) pair so it
      cannot be used to lock a user out of their own account; a looser
      source-wide scope catches password spraying and deliberately slows without
      ever locking, because a source address is shared. `GET /auth/lockouts`,
      `DELETE /auth/lockouts/{username}`, `shadowfax lockouts`, and a "Front
      door" drawer. Shipped in `v0.10.0`.
- [x] Close the user-enumeration oracle: the throttle runs before the username
      lookup, failures are recorded whether or not the account exists, and
      `auth.dummy_verify()` spends the same PBKDF2 work when it does not — the
      old early return made response time a reliable signal for which accounts
      were real. Shipped in `v0.10.0`.
- [x] Platform self-monitoring: failed sign-ins and lockouts against Shadowfax
      become ordinary events under the `shadowfax-auth` actor, in the same
      hash-chained ledger, and raise `brute_force_auth` (T1110) through the
      existing detector with no special-casing in the engine. The attempted
      username is metadata, never the actor id. `dormancy_exempt_actors` keeps a
      quiet front door from raising `dormant_reappearance`. Shipped in
      `v0.10.0`.
- [ ] Users and API keys management UI. The endpoints exist and are admin-only;
      the dashboard still makes you reach for `curl`.
- [ ] Second factor (TOTP) for admin accounts. Throttling slows guessing; it
      does not stop a leaked password.

---

## Version 0.11

- [x] The two v0.6 items above, closing that version's list.
- [x] Alert provenance: `source_tool`, `validated` and `evidence` on ingested
      alerts, with the emitter's id deriving (never becoming) the Shadowfax alert
      id, so re-ingest is idempotent and analyst state follows the finding while
      a crafted id cannot inherit a native alert's acknowledgement. Shipped in
      `v0.11.0`.
- [ ] Emit the envelope as well as ingest it. Shadowfax's own alerts are already
      a near-exact fit for a finding; `GET /findings` would let the portfolio's
      tools consume Shadowfax the way Shadowfax consumes them.
- [ ] Subject pages. A `file:` or `host:` actor is an actor only by convention,
      and the actor drawer shows it an event timeline when what it wants is a
      findings report grouped by emitter.

---

## Version 0.12

Make it runnable. Everything above is invisible to anyone who gives up during
setup, and setup was two processes, two package managers and a CORS allowlist.

- [x] One-command packaging: a two-stage `Dockerfile` (Node builds the
      dashboard, Python runs the API and serves it from its own origin) and a
      `docker-compose.yml` with a named volume for the event store. Non-root
      user; Node does not survive into the final image. `GET /healthz` and
      `SHADOWFAX_DB` exist for the same reason. Shipped in `v0.12.0`.
- [x] Scripted attack replay: `demo.py` drives a compromise through a running
      instance in three acts -- a kill chain forming from separate alerts, an
      external tool's findings attaching to the same actor over the shared
      envelope, and an attack on Shadowfax itself raising an ordinary alert.
      The attack's clock and the replay's pacing are deliberately separate, and
      the replay honours the server's `Retry-After` so it demonstrates the
      detection as well as the throttle. Shipped in `v0.12.0`.
- [ ] Publish the image, so `docker run ghcr.io/jh-infosec/shadowfax` needs no
      clone at all.
- [ ] A recorded terminal/dashboard capture of the replay in the README, for
      people who will not run anything.

---

## Version 1.0

- [ ] Electron desktop application
- [ ] PostgreSQL support
- [ ] Multi-user support
- [x] Docker images -- shipped in `v0.12.0` (building locally; publishing one is still open above).
- [ ] SIEM integrations
- [ ] Production deployment
