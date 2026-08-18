import React, { useCallback, useEffect, useMemo, useState } from "react";
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

export default function App() {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [connected, setConnected] = useState(true);
  const [error, setError] = useState(null);

  const [filters, setFilters] = useState({
    severity: new Set(SEVERITIES),
    actorType: new Set(ACTOR_TYPES),
    search: "",
  });

  const [selectedActorId, setSelectedActorId] = useState(null);
  const [actorDetail, setActorDetail] = useState(null);

  const [policyOpen, setPolicyOpen] = useState(false);
  const [policy, setPolicy] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const [statsResult, alertsResult] = await Promise.all([
        api.getStats(),
        api.getAlerts({
          severity: [...filters.severity],
          actorType: [...filters.actorType],
          search: filters.search,
        }),
      ]);
      setStats(statsResult);
      setAlerts(alertsResult);
      setConnected(true);
      setError(null);
    } catch (err) {
      setConnected(false);
      setError(err.message);
    }
  }, [filters]);

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

  const categories = useMemo(() => [...new Set(alerts.map((a) => a.category))].sort(), [alerts]);

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
          categories={categories}
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
