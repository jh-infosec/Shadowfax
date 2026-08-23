// API client for the Shadowfax backend.
//
// Every function here is a thin wrapper around fetch. The dashboard never
// talks to SQLite directly -- it only ever calls this API, matching the
// "dashboard communicates only with the API" rule in architecture.md.

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`${options.method || "GET"} ${path} failed: ${res.status} ${body}`);
  }
  return res.json();
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
