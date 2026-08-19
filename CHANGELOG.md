# Changelog

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
