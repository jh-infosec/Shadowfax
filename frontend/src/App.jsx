import React, { useCallback, useEffect, useState } from "react";
import TopBar from "./components/TopBar.jsx";
import Sidebar from "./components/Sidebar.jsx";
import AlertTable from "./components/AlertTable.jsx";
import ActorDrawer from "./components/ActorDrawer.jsx";
import PolicyEditor from "./components/PolicyEditor.jsx";
import { SEVERITIES, ACTOR_TYPES } from "./constants.js";
import * as api from "./api.js";

// How often the dashboard polls the API for fresh alerts and stats.
// A real "live" feel without needing a websocket for v0.2.
const POLL_INTERVAL_MS = 5000;

// How long to wait after the last keystroke before searching, so typing
// fires a single request instead of one per character.
const SEARCH_DEBOUNCE_MS = 300;

export default function App() {
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

  // Debounce the search text: only the settled value drives a fetch.
  useEffect(() => {
    const id = setTimeout(() => setDebouncedSearch(filters.search), SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(id);
  }, [filters.search]);

  // Poll on an interval, and immediately whenever filters change.
  useEffect(() => {
    refresh();
    const id = setInterval(refresh, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [refresh]);

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

  return (
    <div className="app">
      <TopBar stats={stats} connected={connected} onReset={handleReset} />
      {error && <div className="error-banner">{error}</div>}

      <div className="body">
        <Sidebar
          filters={filters}
          onFiltersChange={setFilters}
          categories={knownCategories}
          onOpenPolicy={handleOpenPolicy}
        />
        <div className="main">
          <div className="table-wrap">
            <AlertTable alerts={alerts} onSelectActor={setSelectedActorId} />
          </div>
        </div>
      </div>

      {actorDetail && (
        <ActorDrawer detail={actorDetail} onClose={() => setSelectedActorId(null)} />
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
