import React, { useCallback, useEffect, useRef, useState } from "react";
import TopBar from "./components/TopBar.jsx";
import Sidebar from "./components/Sidebar.jsx";
import AlertTable from "./components/AlertTable.jsx";
import ActorDrawer from "./components/ActorDrawer.jsx";
import PolicyEditor from "./components/PolicyEditor.jsx";
import IncidentsDrawer from "./components/IncidentsDrawer.jsx";
import ExplanationModal from "./components/ExplanationModal.jsx";
import Login from "./components/Login.jsx";
import { SEVERITIES, ACTOR_TYPES } from "./constants.js";
import * as api from "./api.js";

// How long to wait after the last keystroke before searching, so typing
// fires a single request instead of one per character.
const SEARCH_DEBOUNCE_MS = 300;

// Coalesce a burst of stream events (e.g. a batch ingest) into one refetch.
const STREAM_REFRESH_DEBOUNCE_MS = 200;

export default function App() {
  // Auth: `user` is the signed-in {username, role}, or null when logged out.
  // `authChecked` guards the first render until we know whether a stored token
  // is still valid.
  const [user, setUser] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);

  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [connected, setConnected] = useState(true);
  const [error, setError] = useState(null);

  const [filters, setFilters] = useState({
    severity: new Set(SEVERITIES),
    actorType: new Set(ACTOR_TYPES),
    // Categories are discovered from alerts, not a fixed list, so this is an
    // opt-in narrowing filter: empty means "all categories", ticking some
    // narrows to those. (Severity and actor type use the opposite rule below,
    // where empty means "none", because their full set is known up front.)
    category: new Set(),
    search: "",
  });

  // The search box updates filters.search on every keystroke so typing stays
  // responsive, but the API call uses this debounced copy.
  const [debouncedSearch, setDebouncedSearch] = useState("");

  // Categories ever seen, accumulated so the checkboxes don't vanish when a
  // category filter narrows the alerts the list is derived from.
  const [knownCategories, setKnownCategories] = useState([]);

  const [selectedActorId, setSelectedActorId] = useState(null);
  const [actorDetail, setActorDetail] = useState(null);

  const [policyOpen, setPolicyOpen] = useState(false);
  const [policy, setPolicy] = useState(null);
  const [incidentsOpen, setIncidentsOpen] = useState(false);
  // The alert whose explanation modal is open, or null.
  const [explainAlert, setExplainAlert] = useState(null);

  // Role helpers. admin > analyst > viewer.
  const canAnalyst = user && (user.role === "analyst" || user.role === "admin");
  const canAdmin = user && user.role === "admin";

  // A 401 anywhere (an expired or revoked session) drops us back to login.
  useEffect(() => {
    api.setUnauthorizedHandler(() => setUser(null));
  }, []);

  // On load, if a token is stored, confirm it still identifies a user.
  useEffect(() => {
    if (!api.getToken()) {
      setAuthChecked(true);
      return;
    }
    api
      .getMe()
      .then(setUser)
      .catch(() => setUser(null))
      .finally(() => setAuthChecked(true));
  }, []);

  const refresh = useCallback(async () => {
    // An empty severity or actor-type selection means nothing matches, so
    // skip the alerts request entirely rather than send no parameter, which
    // the API would read as "unfiltered" and return everything.
    const hasMatchableFilter =
      filters.severity.size > 0 && filters.actorType.size > 0;
    try {
      const [statsResult, alertsResult] = await Promise.all([
        api.getStats(),
        hasMatchableFilter
          ? api.getAlerts({
              severity: [...filters.severity],
              actorType: [...filters.actorType],
              category: [...filters.category],
              search: debouncedSearch,
            })
          : Promise.resolve([]),
      ]);
      setStats(statsResult);
      setAlerts(alertsResult);
      setConnected(true);
      setError(null);
    } catch (err) {
      setConnected(false);
      setError(err.message);
    }
  }, [filters.severity, filters.actorType, filters.category, debouncedSearch]);

  // Keep a live handle to the latest refresh so the stream can call it without
  // re-subscribing every time the filters (and thus refresh) change.
  const refreshRef = useRef(refresh);
  useEffect(() => {
    refreshRef.current = refresh;
  }, [refresh]);

  // Debounce the search text: only the settled value drives a fetch.
  useEffect(() => {
    const id = setTimeout(() => setDebouncedSearch(filters.search), SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(id);
  }, [filters.search]);

  // Fetch on sign-in and whenever the filters change.
  useEffect(() => {
    if (!user) return;
    refresh();
  }, [refresh, user]);

  // Live updates over Server-Sent Events, replacing the old poll loop. The
  // stream carries a lightweight "change" signal; the dashboard re-queries with
  // its own filters, so per-client filtering stays server-side.
  useEffect(() => {
    if (!user) return;
    let debounce;
    const onChange = () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => refreshRef.current(), STREAM_REFRESH_DEBOUNCE_MS);
    };
    const es = new EventSource(api.streamUrl());
    es.onopen = () => setConnected(true);
    es.addEventListener("change", onChange);
    es.onerror = () => setConnected(false); // EventSource auto-reconnects
    return () => {
      clearTimeout(debounce);
      es.close();
    };
  }, [user]);

  // Load the full timeline whenever an actor is selected from the table.
  useEffect(() => {
    if (!selectedActorId) {
      setActorDetail(null);
      return;
    }
    api.getActorDetail(selectedActorId).then(setActorDetail).catch((err) => setError(err.message));
  }, [selectedActorId]);

  // Accumulate the set of categories ever seen. Only grows, so the category
  // checkboxes stay put even when a category filter shrinks the alert list.
  useEffect(() => {
    if (alerts.length === 0) return;
    setKnownCategories((prev) => {
      const merged = new Set(prev);
      for (const a of alerts) merged.add(a.category);
      return merged.size === prev.length ? prev : [...merged].sort();
    });
  }, [alerts]);

  const handleLogout = async () => {
    await api.logout();
    setUser(null);
  };

  const handleReset = async () => {
    await api.resetData();
    refresh();
  };

  const handleOpenPolicy = async () => {
    const current = await api.getPolicy();
    setPolicy(current);
    setPolicyOpen(true);
  };

  const handleSavePolicy = async (updated) => {
    await api.updatePolicy(updated);
    setPolicyOpen(false);
    refresh();
  };

  // Write analyst state for one alert. Optimistically patch the row so the UI
  // responds instantly, then persist and reconcile on the next refresh. The
  // alert id is stable, so the change survives the rescans that rebuild alerts.
  const handleSetAlertState = useCallback(async (alertId, patch) => {
    setAlerts((prev) => prev.map((a) => (a.id === alertId ? { ...a, ...patch } : a)));
    if (actorDetail) {
      setActorDetail((prev) =>
        prev ? { ...prev, alerts: prev.alerts.map((a) => (a.id === alertId ? { ...a, ...patch } : a)) } : prev
      );
    }
    try {
      await api.setAlertState(alertId, patch);
    } catch (err) {
      setError(err.message);
    } finally {
      refresh();
    }
  }, [refresh, actorDetail]);

  // acknowledged_by is set server-side from the session, so the client only
  // needs the optimistic label; the server's value wins on the next refresh.
  const acknowledgeAlert = (alertId, acknowledged) =>
    handleSetAlertState(
      alertId,
      acknowledged
        ? { acknowledged: true, acknowledged_by: user?.username }
        : { acknowledged: false }
    );

  const assignAlertToMe = (alertId) =>
    handleSetAlertState(alertId, { assigned_to: user?.username });

  if (!authChecked) {
    return (
      <div className="app">
        <div className="empty-state">Connecting…</div>
      </div>
    );
  }

  if (!user) {
    return <Login onAuthenticated={setUser} />;
  }

  return (
    <div className="app">
      <TopBar
        stats={stats}
        connected={connected}
        onReset={handleReset}
        canReset={canAdmin}
        user={user}
        onLogout={handleLogout}
      />
      {error && <div className="error-banner">{error}</div>}

      <div className="body">
        <Sidebar
          filters={filters}
          onFiltersChange={setFilters}
          categories={knownCategories}
          onOpenPolicy={handleOpenPolicy}
          canEditPolicy={canAnalyst}
          onOpenIncidents={() => setIncidentsOpen(true)}
        />
        <div className="main">
          <div className="table-wrap">
            <AlertTable
              alerts={alerts}
              onSelectActor={setSelectedActorId}
              onAcknowledge={acknowledgeAlert}
              onAssign={assignAlertToMe}
              onExplain={setExplainAlert}
              canAct={canAnalyst}
            />
          </div>
        </div>
      </div>

      {actorDetail && (
        <ActorDrawer detail={actorDetail} onClose={() => setSelectedActorId(null)} />
      )}

      {incidentsOpen && <IncidentsDrawer onClose={() => setIncidentsOpen(false)} />}

      {explainAlert && (
        <ExplanationModal alert={explainAlert} onClose={() => setExplainAlert(null)} />
      )}

      {policyOpen && policy && (
        <PolicyEditor
          policy={policy}
          onSave={handleSavePolicy}
          onClose={() => setPolicyOpen(false)}
        />
      )}
    </div>
  );
}
