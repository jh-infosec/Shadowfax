# Changelog

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
