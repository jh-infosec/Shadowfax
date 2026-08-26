# Changelog

## Version 0.3.0

Stable alert identity and the analyst state it unblocks, plus authentication,
roles and API keys. First backend change since v0.1.

### Authentication & access control

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

### Added

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
