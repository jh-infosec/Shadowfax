import React, { useCallback, useEffect, useRef, useState } from "react";
import TopBar from "./components/TopBar.jsx";
import Sidebar from "./components/Sidebar.jsx";
import AlertTable from "./components/AlertTable.jsx";
import ActorDrawer from "./components/ActorDrawer.jsx";
import PolicyEditor from "./components/PolicyEditor.jsx";
import PasswordModal from "./components/PasswordModal.jsx";
import IncidentsDrawer from "./components/IncidentsDrawer.jsx";
import DigestDrawer from "./components/DigestDrawer.jsx";
import LockoutsDrawer from "./components/LockoutsDrawer.jsx";
import AccountsDrawer from "./components/AccountsDrawer.jsx";
import TwoFactorModal from "./components/TwoFactorModal.jsx";
import SubjectsDrawer from "./components/SubjectsDrawer.jsx";
import ExplanationModal from "./components/ExplanationModal.jsx";
import NLSearch from "./components/NLSearch.jsx";
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
  const [passwordOpen, setPasswordOpen] = useState(false);
  // After an admin reset the server refuses everything but a password change
  // (v0.19), so the dashboard does not try to load anything until it is done.
  const ready = Boolean(user) && !user.must_change_password;
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
  const [digestOpen, setDigestOpen] = useState(false);
  const [lockoutsOpen, setLockoutsOpen] = useState(false);
  const [accountsOpen, setAccountsOpen] = useState(false);
  const [twoFactorOpen, setTwoFactorOpen] = useState(false);
  const [subjectsOpen, setSubjectsOpen] = useState(false);
  // The alert whose explanation modal is open, or null.
  const [explainAlert, setExplainAlert] = useState(null);
  // Active natural-language search result (snapshot), or null for the normal
  // filtered list. When set, the table shows these alerts with an interpretation
  // banner; Clear returns to the live filtered view.
  const [nlResult, setNlResult] = useState(null);

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
    if (!ready) return;
    refresh();
  }, [refresh, ready]);

  // Live updates over Server-Sent Events, replacing the old poll loop. The
  // stream carries a lightweight "change" signal; the dashboard re-queries with
  // its own filters, so per-client filtering stays server-side.
  //
  // Reconnection is done here rather than left to EventSource (v0.17.1): its
  // built-in retry would reuse the same URL, and the ticket in that URL is
  // single-use. Each attempt asks for a fresh ticket, backing off to 30s.
  useEffect(() => {
    if (!ready) return;
    let debounce;
    let retry;
    let es = null;
    let stopped = false;
    let delay = 1000;
    let opened = false;
    const onChange = () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => refreshRef.current(), STREAM_REFRESH_DEBOUNCE_MS);
    };
    const schedule = () => {
      if (stopped) return;
      retry = setTimeout(connect, delay);
      delay = Math.min(delay * 2, 30000);
    };
    const connect = async () => {
      let url;
      try {
        url = await api.streamUrl();
      } catch (err) {
        setConnected(false);
        // A 401 means the session is gone; request() has already signed out.
        if (err.status !== 401) schedule();
        return;
      }
      if (stopped) return;
      es = new EventSource(url);
      es.onopen = () => {
        setConnected(true);
        delay = 1000;
        // Anything that changed while disconnected was never signalled.
        if (opened) refreshRef.current();
        opened = true;
      };
      es.addEventListener("change", onChange);
      const drop = () => {
        setConnected(false);
        es.close();
        schedule();
      };
      es.onerror = drop;
      es.addEventListener("goodbye", drop); // the session ended server-side
    };
    connect();
    return () => {
      stopped = true;
      clearTimeout(debounce);
      clearTimeout(retry);
      if (es) es.close();
    };
  }, [ready]);

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

  // Escape closes the topmost drawer or modal (v0.22) -- one layer per press,
  // so a drawer opened over another goes first. The policy editor and the
  // password form are left alone: both hold typed input, and a stray keypress
  // should not throw an unsaved policy away.
  useEffect(() => {
    const onKey = (e) => {
      if (e.key !== "Escape" || e.defaultPrevented) return;
      if (passwordOpen || policyOpen || twoFactorOpen) return;
      if (explainAlert) setExplainAlert(null);
      else if (accountsOpen) setAccountsOpen(false);
      else if (subjectsOpen) setSubjectsOpen(false);
      else if (lockoutsOpen) setLockoutsOpen(false);
      else if (digestOpen) setDigestOpen(false);
      else if (incidentsOpen) setIncidentsOpen(false);
      else if (selectedActorId) setSelectedActorId(null);
      else return;
      e.preventDefault();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [passwordOpen, policyOpen, twoFactorOpen, explainAlert, accountsOpen, subjectsOpen, lockoutsOpen, digestOpen,
      incidentsOpen, selectedActorId]);

  const handleLogout = async () => {
    await api.logout();
    setUser(null);
  };

  const handleReset = async () => {
    await api.resetData();
    setNlResult(null);
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
    setNlResult((prev) =>
      prev ? { ...prev, alerts: prev.alerts.map((a) => (a.id === alertId ? { ...a, ...patch } : a)) } : prev
    );
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

  if (user.must_change_password) {
    return (
      <PasswordModal
        forced
        user={user}
        onDone={() => setUser({ ...user, must_change_password: false })}
        onLogout={handleLogout}
      />
    );
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
        onChangePassword={() => setPasswordOpen(true)}
        onTwoFactor={() => setTwoFactorOpen(true)}
      />
      {twoFactorOpen && <TwoFactorModal onClose={() => setTwoFactorOpen(false)} />}
      {passwordOpen && (
        <PasswordModal
          user={user}
          onDone={() => setPasswordOpen(false)}
          onCancel={() => setPasswordOpen(false)}
        />
      )}
      {error && <div className="error-banner">{error}</div>}

      <div className="body">
        <Sidebar
          filters={filters}
          onFiltersChange={setFilters}
          categories={knownCategories}
          onOpenPolicy={handleOpenPolicy}
          canEditPolicy={canAnalyst}
          onOpenIncidents={() => setIncidentsOpen(true)}
          onOpenDigest={() => setDigestOpen(true)}
          onOpenSubjects={() => setSubjectsOpen(true)}
          onOpenLockouts={() => setLockoutsOpen(true)}
          onOpenAccounts={() => setAccountsOpen(true)}
          canSeeLockouts={canAdmin}
        />
        <div className="main">
          <NLSearch
            result={nlResult}
            onResult={setNlResult}
            onClear={() => setNlResult(null)}
          />
          <div className="table-wrap">
            <AlertTable
              alerts={nlResult ? nlResult.alerts : alerts}
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

      {digestOpen && (
        <DigestDrawer
          onClose={() => setDigestOpen(false)}
          onSelectActor={(a) => { setDigestOpen(false); setSelectedActorId(a); }}
        />
      )}

      {lockoutsOpen && <LockoutsDrawer onClose={() => setLockoutsOpen(false)} />}

      {subjectsOpen && (
        <SubjectsDrawer
          onClose={() => setSubjectsOpen(false)}
          onSelectActor={(a) => { setSubjectsOpen(false); setSelectedActorId(a); }}
        />
      )}

      {accountsOpen && (
        <AccountsDrawer me={user.username} onClose={() => setAccountsOpen(false)} />
      )}

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
