// API client for the Shadowfax backend.
//
// Every function here is a thin wrapper around fetch. The dashboard never
// talks to SQLite directly -- it only ever calls this API, matching the
// "dashboard communicates only with the API" rule in architecture.md.

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";
const TOKEN_KEY = "shadowfax_token";

// The bearer token, mirrored to localStorage so a reload keeps the session.
let authToken = null;
try {
  authToken = localStorage.getItem(TOKEN_KEY);
} catch {
  authToken = null;
}

// Called when the API reports 401 on a non-login request, i.e. the session is
// no longer valid. App registers this to drop back to the login screen.
let onUnauthorized = null;

export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn;
}

export function getToken() {
  return authToken;
}

export function setToken(token) {
  authToken = token || null;
  try {
    if (authToken) localStorage.setItem(TOKEN_KEY, authToken);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage may be unavailable; the in-memory token still works */
  }
}

async function request(path, { headers: extraHeaders, ...options } = {}) {
  const headers = { "Content-Type": "application/json", ...(extraHeaders || {}) };
  if (authToken) headers.Authorization = `Bearer ${authToken}`;
  const res = await fetch(`${API_BASE}${path}`, { headers, ...options });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    const err = new Error(`${options.method || "GET"} ${path} failed: ${res.status} ${body}`);
    err.status = res.status;
    // A 401 on anything other than the login attempt means the session died.
    if (res.status === 401 && path !== "/auth/login") {
      setToken(null);
      if (onUnauthorized) onUnauthorized();
    }
    throw err;
  }
  return res.json();
}

// Authentication

export async function login(username, password) {
  const data = await request("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  setToken(data.token);
  return data.user; // { username, role }
}

export async function logout() {
  try {
    await request("/auth/logout", { method: "POST" });
  } catch {
    /* even if the call fails, drop the local token */
  }
  setToken(null);
}

export function getMe() {
  return request("/auth/me");
}

// URL for the Server-Sent Events stream. The browser EventSource can't set
// headers, so the token rides as a query parameter.
export function streamUrl() {
  const qs = authToken ? `?token=${encodeURIComponent(authToken)}` : "";
  return `${API_BASE}/stream${qs}`;
}

export function getStats() {
  return request("/stats");
}

export function getActors() {
  return request("/actors");
}

export function getActorDetail(actorId) {
  return request(`/actors/${encodeURIComponent(actorId)}`);
}

export function getAlerts(filters = {}) {
  const params = new URLSearchParams();
  (filters.severity || []).forEach((s) => params.append("severity", s));
  (filters.actorType || []).forEach((t) => params.append("actor_type", t));
  (filters.category || []).forEach((c) => params.append("category", c));
  if (filters.search) params.append("search", filters.search);
  const qs = params.toString();
  return request(`/alerts${qs ? `?${qs}` : ""}`);
}

export function getIncidents() {
  return request("/incidents");
}

export function getIncident(id) {
  return request(`/incidents/${encodeURIComponent(id)}`);
}

export function getPolicy() {
  return request("/policy");
}

export function updatePolicy(policy) {
  return request("/policy", { method: "PUT", body: JSON.stringify(policy) });
}

export function resetData() {
  return request("/reset", { method: "POST" });
}

export function ingestEvents(events) {
  return request("/events", { method: "POST", body: JSON.stringify(events) });
}

// Acknowledge, assign or annotate an alert. `patch` may carry any of
// { acknowledged, acknowledged_by, assigned_to, note }; only the fields
// present are changed. The alert's id is stable, so this state persists
// across the rescans that rebuild the alert.
export function setAlertState(alertId, patch) {
  return request(`/alerts/${encodeURIComponent(alertId)}/state`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

export { API_BASE };
