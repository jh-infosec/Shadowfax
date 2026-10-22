// API client for the Shadowfax backend.
//
// Every function here is a thin wrapper around fetch. The dashboard never
// talks to SQLite directly -- it only ever calls this API, matching the
// "dashboard communicates only with the API" rule in architecture.md.

// Where the backend lives.
//
// `??`, not `||`: an explicitly empty VITE_API_BASE is a real answer, not a
// missing one. It means "same origin as this page", which is how the packaged
// container serves things -- one process, one port, and no CORS to configure.
// Unset (the dev server, where Vite is on :5173 and uvicorn on :8000) still
// falls back to the local backend.
const API_BASE = import.meta.env.VITE_API_BASE ?? "http://127.0.0.1:8000";
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
    // Keep the server's structured reason, so a refusal that lists its problems
    // can be shown as a list rather than as a line of JSON.
    try {
      err.detail = JSON.parse(body).detail;
    } catch {
      err.detail = undefined;
    }
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

// `second` is {totp_code} or {recovery_code} (v0.25). Without one, an account
// with two-factor on throws with err.detail.mfa_required.
export async function login(username, password, second = {}) {
  const data = await request("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password, ...second }),
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

// v0.19. Throws with `err.detail.problems` when the new password is refused.
export function changePassword(currentPassword, newPassword) {
  return request("/auth/password", {
    method: "POST",
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
}

// URL for the Server-Sent Events stream (v0.17.1). The browser EventSource
// can't set headers, so something has to go in the URL -- and URLs are what
// access logs record. Not the session token, then: a single-use ticket that
// expires in 30 seconds, asked for with the token in a header. Each connection
// needs a fresh one, so this is called on every (re)connect.
export async function streamUrl() {
  const { ticket } = await request("/stream/ticket", { method: "POST" });
  return `${API_BASE}/stream?ticket=${encodeURIComponent(ticket)}`;
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

// Investigation assistant (v0.5). These are read-only: the assistant explains
// a finding, it never creates or changes one. `source` in the reply is "llm",
// "deterministic" (no model configured) or "deterministic_fallback" (a model
// call was attempted and failed).
export function explainAlert(id) {
  return request(`/alerts/${encodeURIComponent(id)}/explain`);
}

export function explainIncident(id) {
  return request(`/incidents/${encodeURIComponent(id)}/explain`);
}

export function getAssistantStatus() {
  return request("/assistant/status");
}

// Natural-language alert search (v0.5.2). The assistant translates `query`
// into a validated filter and returns the matching alerts plus how it read the
// query: { query, filters, interpretation, source, count, alerts }.
export function nlSearch(query) {
  return request("/search", { method: "POST", body: JSON.stringify({ query }) });
}

// Triage digest (v0.8). Read-only: the ranking is computed server-side and
// deterministically; the assistant only writes the covering narrative.
export function getDigest(limit) {
  const qs = limit ? `?limit=${encodeURIComponent(limit)}` : "";
  return request(`/digest${qs}`);
}

// Tamper-evident ledger (v0.9). Both are read-only. `verifyLedger` recomputes
// the whole hash chain server-side and returns
// { ok, entries, verified, head, broken_at, reason, summary, recorded_head };
// `getLedgerHead` returns just { entry_count, head_hash, updated_at } so the
// head can be exported and anchored outside the database's own trust boundary.
export function verifyLedger() {
  return request("/ledger/verify");
}

export function getLedgerHead() {
  return request("/ledger/head");
}

// Sign-in lockouts (v0.10). Admin-only. `getLockouts` returns the scopes with
// failures in the window plus the settings in force; `clearLockout` releases a
// username and is itself recorded as an event.
export function getLockouts() {
  return request("/auth/lockouts");
}

export function clearLockout(username) {
  return request(`/auth/lockouts/${encodeURIComponent(username)}`, { method: "DELETE" });
}

// Accounts (v0.23). Admin-only. Passwords and keys come back exactly once, in
// the response to the call that made them; nothing here can read one later.
export function listUsers() {
  return request("/users");
}

export function createUser(username, role) {
  return request("/users", {
    method: "POST",
    body: JSON.stringify({ username, role, generate: true }),
  });
}

export function resetUserPassword(username) {
  return request(`/users/${encodeURIComponent(username)}/password`, {
    method: "POST",
    body: JSON.stringify({ generate: true }),
  });
}

// v0.24: {role} and/or {disabled}. Refused for your own account, and for the
// last enabled admin.
export function updateUser(username, patch) {
  return request(`/users/${encodeURIComponent(username)}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

// Two-factor (v0.25).
export function getTotp() {
  return request("/auth/totp");
}

export function startTotp(currentPassword) {
  return request("/auth/totp/setup", {
    method: "POST",
    body: JSON.stringify({ current_password: currentPassword }),
  });
}

export function confirmTotp(code) {
  return request("/auth/totp/confirm", { method: "POST", body: JSON.stringify({ code }) });
}

export function disableTotp(currentPassword, code) {
  const second = code.includes("-") ? { recovery_code: code } : { code };
  return request("/auth/totp/disable", {
    method: "POST",
    body: JSON.stringify({ current_password: currentPassword, ...second }),
  });
}

export function resetUserTotp(username) {
  return request(`/users/${encodeURIComponent(username)}/totp/reset`, { method: "POST" });
}

export function listApiKeys() {
  return request("/api-keys");
}

export function createApiKey(label) {
  return request("/api-keys", { method: "POST", body: JSON.stringify({ label: label || null }) });
}

export function revokeApiKey(id) {
  return request(`/api-keys/${encodeURIComponent(id)}`, { method: "DELETE" });
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
