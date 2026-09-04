# Changelog

## Version 0.4.7

Alert correlation and incident reports (the rest of the roadmap's v0.4).
Detectors say *what* fired; correlation says *these fired together*, collapsing
a stream of alerts into the smaller set of incidents an analyst actually works.

### Added

- **`correlate.py`** groups an actor's alerts into **incidents** by temporal
  proximity: a new incident starts whenever the gap to the previous alert
  exceeds `policy.correlation_window_minutes` (default 30). Pure function of
  `(alerts, window)` -- no I/O, no LLM, deterministic like detection. Each
  incident carries its window, alert count, severity breakdown, unioned
  categories and ATT&CK techniques, a risk score, and a one-line summary.
  Incident ids are deterministic (actor + first alert id).
- **Deterministic incident reports.** `render_report()` produces a factual
  markdown report -- summary, ATT&CK techniques, and a timeline table -- from
  the incident's own data. (The v0.5 investigation assistant is where an LLM
  gets to *explain*; here we only summarise what is already known.)
- `GET /incidents` (correlated list) and `GET /incidents/{id}` (with member
  alerts and the markdown report), computed on read from stored alerts, so
  there is no new table or migration.
- **Incidents view in the dashboard.** An Incidents drawer lists incidents and
  shows the selected one's summary, ATT&CK badges, timeline, and a
  "Copy report" button.

### Changed

- `DEFAULT_POLICY` gains `correlation_window_minutes` (30).
- Backend version is now `0.4.7`.

## Version 0.4.6

MITRE ATT&CK mapping (the roadmap's v0.4 item). Every alert now carries the
ATT&CK technique(s) it corresponds to, so analysts see intent in a shared
vocabulary.

### Added

- **Shared technique registry** (`attack_registry.json`): id -> name, tactic,
  URL. It is the single source of technique metadata for the whole portfolio
  (Shadowfax, claude-recon-agent, maltriage) -- one place a technique id is
  corrected. Technique ids are used verbatim from it; nothing generates one.
- **`attack.py`** maps Shadowfax's alert categories to technique ids and
  enriches them from the registry. `enrich()` silently drops any id the
  registry doesn't know, so a typo shows up as a missing badge, never an
  invented technique. `validate()` (enforced by a test) asserts every id the
  category map and the default policy reference exists in the registry.
- **Per-rule techniques for destructive actions.** Each `destructive_action`
  rule in policy declares its own `attack` id, because `rm -rf` (T1485 Data
  Destruction) and a system shutdown (T1529) are both destructive but different
  techniques. Fixed detectors use the category mapping; unmapped categories
  (policy controls, pure anomalies) carry no technique, which is honest.
- Alerts now include an `attack` array (`[{id, name, tactic, url}]`) on
  `/alerts` and `/actors/{id}`, and the dashboard shows a linked technique
  badge (e.g. `T1485`) on each alert. `GET /attack` returns the registry.

### Changed

- `alerts` gains an `attack` column (JSON). A pre-v0.4 alerts table without it
  is dropped and rebuilt on startup (alerts are derived; `alert_state` is
  keyed by id and preserved).
- Backend version is now `0.4.6`.

## Version 0.4.5

Agent traces as events. Shadowfax now watches an AI agent's tool calls, not just
human-style activity. No schema change: a tool call is an event with
`event_type: "tool_call"` and its shape (`tool`, `arguments`, `exit_status`,
`duration_ms`, optional `host`/`port`/`url`) in `metadata`.

### Added

- **Destructive-action detection.** A new `destructive_action` category fires
  when a tool call matches a policy pattern -- recursive delete, database drop,
  credential write, disk wipe, system shutdown. Rules live in
  `policy.destructive_action_rules` (label + severity + case-insensitive
  substrings), so the patterns are governed by policy and reachable by tests,
  and detection stays deterministic. First matching rule wins; one alert per
  call.
- **Engagement scope.** `policy.engagement_scope` (allowed domains, IP ranges,
  ports) defines the rules of engagement. A tool call whose destination host,
  IP or port falls outside it fires `out_of_scope_action`. IP ranges are
  matched with the stdlib `ipaddress` module; only calls with a real network
  destination are checked, so filesystem and symbolic targets are left alone.
- Sample agent traces in the seed data (an offensive-security agent that runs
  in-scope, out-of-scope and destructive tool calls), visible after `/reset`.

Detectors remain a pure function of `(actor history, policy)`; both new
categories are just rules in `detectors.py`. The dashboard needed no change --
the new categories flow through the existing table and category filter.

### Note on rescan cost

A recon session is one actor with potentially hundreds of tool calls, and a
rescan replays an actor's full history (linear in its length). This is accepted
deliberately for now rather than bounded: the stateful detectors
(capability resurrection, privilege tracking) need the whole history, so a
naive recompute-window cap would break them. When trace volume makes this hurt,
the fix is incremental detector state, not a shorter replay -- recorded here so
it is a decision, not a surprise in v0.5.

## Version 0.3.2

Live updates over Server-Sent Events, replacing the poll loop.

- **The poll loop is gone.** The dashboard opens one `EventSource` to
  `GET /stream` and refreshes on demand instead of fetching every five seconds.
  Ingesting an event, editing policy, resetting, or acknowledging an alert now
  reaches every open dashboard in well under a second (measured ~0.3s), and the
  browser holds one long-lived connection rather than a request every 5s.
- A small in-process bus (`bus.py`) fans a `change` signal to each subscriber;
  the stream carries only the signal, so each client re-queries with its own
  server-side filters. `publish()` is safe to call from the sync endpoints.
- The stream authenticates by `?token=` (the browser `EventSource` cannot set
  an `Authorization` header) or a Bearer header for non-browser clients; a
  15-second keepalive comment holds the connection open. Service API keys
  cannot stream. The connection indicator now reflects the live stream.
- Backend version is now `0.3.2`.

## Version 0.3.1

Authentication, roles and API keys.

- **Sign-in with user accounts.** `POST /auth/login` issues an opaque bearer
  token; `POST /auth/logout` revokes it; `GET /auth/me` returns the current
  user. Sessions expire after 12 hours. Passwords are hashed with PBKDF2 and a
  per-user salt; only token and API-key fingerprints are stored, never the
  secrets themselves. Stdlib only -- no new dependencies.
- **Roles.** `admin` > `analyst` > `viewer`. Reads need `viewer`; acknowledge,
  assign and policy edits need `analyst`; reset, user management and API-key
  management need `admin`. Every previously open endpoint is now protected.
- **API keys for ingest.** Agents and harnesses push events with an
  `X-API-Key` header. `POST /api-keys` (admin) returns the key once; it is
  ingest-only and cannot read alerts.
- **`acknowledged_by` is server-set** from the session, so an acknowledgement
  always records who really made it -- the request body can no longer spoof it.
- **First admin** is created on a fresh database from
  `SHADOWFAX_ADMIN_USERNAME` / `SHADOWFAX_ADMIN_PASSWORD`; with none set, a
  default `admin`/`admin` is created and a loud console warning is printed.
- **CORS is locked down** to the dashboard origin (default
  `http://localhost:5173`, override with `SHADOWFAX_CORS_ORIGINS`) instead of
  being open to all origins.
- **Dashboard login.** A sign-in screen gates the console; the token is kept in
  `localStorage` so a reload stays signed in, and a 401 drops back to login.
  The top bar shows the current user and role with a sign-out button, and the
  UI hides actions a role cannot perform (a viewer sees state read-only).
- Backend version is now `0.3.1`.

## Version 0.3.0

Stable alert identity and the analyst state it unblocks. First backend change
since v0.1.

### Added

- Deterministic alert ids. An alert's id is now
  `sha256("shadowfax|{actor}|{category}|{event_id}")[:16]` rather than an
  autoincrement integer, so recomputing the same alert from the same input
  yields the same id. `detectors.alert_identity` is the single source of the
  rule, and it follows the shared findings-envelope id form (actor as subject,
  `category` as the machine-stable key, event as the discriminator).
- `alert_state` table holding per-alert acknowledgement, assignment and notes,
  keyed on the deterministic id. It is deliberately not foreign-keyed to
  `alerts`, so a rescan's delete-and-reinsert leaves it untouched and the state
  re-attaches to the same alert when it is rebuilt.
- `PATCH /alerts/{id}/state` to acknowledge, assign or annotate an alert.
  Unknown ids 404. Alert responses (`/alerts`, `/actors/{id}`) now carry
  `acknowledged`, `acknowledged_by`, `assigned_to` and `note`.
- Startup rebuilds alerts when events exist but the alerts table is empty
  (after a restart or the schema migration below).

### Changed

- `alerts.id` is now `TEXT PRIMARY KEY`. A pre-v0.3 database with an integer
  `alerts.id` is migrated on startup by dropping the alerts table (alerts are
  derived data) and rebuilding it with deterministic ids; `alert_state` is
  keyed by id and is preserved.
- Backend version is now `0.3.0`.

### Why message is excluded from the id

The roadmap and `architecture.md` originally described the id as a hash of
"actor, event, category and message". Including the human-readable message
would mean that editing a detector's wording silently changed every historical
alert's id and destroyed any acknowledgement attached to it -- the exact
failure the findings envelope warns against for titles. The id therefore hashes
the machine-stable `category` (the envelope's "key") and excludes `message`.

### Dashboard

- The alert table has a Status column with per-row **Acknowledge** and
  **Assign** controls, wired to `PATCH /alerts/{id}/state` through the single
  `api.js` client. Acknowledged rows are dimmed and show who acknowledged them;
  assignment shows an `@user` tag. Updates are optimistic and reconciled on the
  next poll.
- Acting analyst is a placeholder (`CURRENT_USER` in `constants.js`) until
  authentication lands; it fills `acknowledged_by` / `assigned_to`.
- Because ids are now stable, `AlertTable` and `ActorDrawer` update rows in
  place instead of tearing them down each poll.

## Version 0.2.1

Defect-clearing pass over the v0.2 dashboard and backend. No new features.

### Fixed

- Unticking every severity or actor type now shows no alerts instead of all.
  An empty selection short-circuits the alert request rather than sending no
  parameter, which the API reads as unfiltered.
- The search box is debounced (300 ms), so typing fires one request after it
  settles instead of one per keystroke. The input stays responsive; only the
  settled value drives a fetch.
- Category filtering is wired to the sidebar. "Categories seen" is now a set
  of checkboxes that filter server-side via the `category` parameter `/alerts`
  already supported. The list is accumulated from alerts ever seen, so options
  don't vanish when a category filter narrows the view. Empty selection means
  all categories (opt-in narrowing, since the category set is discovered, not
  fixed).

### Changed

- Backend startup migrated from the deprecated `@app.on_event("startup")` to a
  `lifespan` context manager.
- `app.py` type hints aligned to the `str | None` style used elsewhere;
  dropped the `Optional` import.

### Notes

Alert identity is still keyed on `alerts.id`, which changes on every rescan.
That is the v0.3 stable-alert-identity item, not part of this pass.

## Version 0.2.0

Dashboard release. The backend is unchanged.

### Added

- React dashboard under `frontend/`, built with Vite
- Live alert table, sortable by severity, category, actor or time
- Actor timeline drawer, showing an actor's full event history with alerts
  attached to the events that produced them
- Risk composition bar, breaking an actor's risk score down by severity
- Filtering by severity, actor type and free-text search, applied server-side
- Policy editor, editing the live policy as JSON and triggering a full rescan
  on save
- Connection status indicator, reflecting whether the last poll succeeded
- Severity counts in the top bar, refreshed on every poll

### Notes

The dashboard polls `/stats` and `/alerts` every five seconds. This is a
deliberate choice for v0.2: it needs no backend changes, no connection
lifecycle handling and no reconnect logic, and a five second delay is
invisible to an analyst reading a screen. WebSocket or SSE push is a v0.3
item.

`frontend/src/api.js` is the only file in the dashboard that calls `fetch`,
which is what makes the dashboard-talks-only-to-the-API rule enforceable by
reading one file.

The dashboard holds no detection logic. Severity colours and sort order are
presentation only.

Alert identity is still not stable. Rows are keyed on `alerts.id`, which
changes on every rescan, so the table re-renders rather than updates. This
matters more now than it did in v0.1.0 and is the blocker for any per-alert
analyst state. See Known Constraints in `architecture.md`.

Neither the API nor the dashboard has authentication. Both are v0.3.
