# Shadowfax Dashboard

React frontend for Shadowfax. See the repository root for the project
README, the roadmap and `architecture.md`, which is the source of truth for
how this fits together.

## Running it

The backend has to be running first, from the repository root:

```bash
uvicorn app:app --reload --port 8000
```

Then, from this directory:

```bash
npm install
npm run dev
```

Open `http://localhost:5173`.

`VITE_API_BASE` sets the backend URL, defaulting to `http://127.0.0.1:8000`.
Put it in `.env` here if the backend runs elsewhere.

## Layout

```
index.html
vite.config.js
package.json
src/
  main.jsx              entry point
  App.jsx               top-level state, poll loop, wiring
  api.js                the only file that calls fetch
  constants.js          severity colours and ordering
  styles.css            all styling, palette defined as CSS variables
  components/
    TopBar.jsx          branding, connection status, severity counts
    Sidebar.jsx         filters and the policy button
    AlertTable.jsx      sortable alert table
    ActorDrawer.jsx     actor timeline and risk composition
    PolicyEditor.jsx    JSON policy editor
```

## Two rules worth keeping

**`api.js` is the only file that calls `fetch`.** That is what makes the
dashboard-talks-only-to-the-API rule checkable by reading one file. A
component that fetches directly breaks it quietly.

**No detection logic lives here.** The dashboard decides how an alert looks,
never whether it exists. Severity colours and sort order in `constants.js`
are presentation. Anything that decides whether something is worth alerting
on belongs in `detectors.py`, where the policy governs it and tests reach it.

## Why polling

`POLL_INTERVAL_MS` in `App.jsx` refreshes `/stats` and `/alerts` every five
seconds. That is a deliberate v0.2 choice: no backend changes, no connection
lifecycle, no reconnect logic, and five seconds is invisible to someone
reading a screen.

WebSocket or SSE push is on the roadmap for v0.3, worth doing when event
volume or alert-to-response time demands it and not before.

## Known issues

The v0.2.1 filter and search defects are now fixed (see the root
`CHANGELOG.md`). One known issue remains, tracked for v0.3:

- Rows are keyed on `alert.id`, which changes on every rescan, so the table
  rebuilds rather than updates on each poll. This is the stable-alert-identity
  work and blocks per-alert analyst state.

## Not built yet

- No authentication, matching the backend, both v0.3
- No UI for ingesting events, though `api.ingestEvents` is already wired up
- No automated tests
- Electron wrapper is v1.0. This is a standard Vite app, so it amounts to
  pointing Electron at the built `dist/` output
