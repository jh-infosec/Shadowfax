// Is there a Shadowfax at this address, and is it serving the dashboard?
//
// Asked before the app loads anything from a server, so a typo, a server
// that's down, or something that isn't Shadowfax at all gets a sentence that
// says which, instead of a blank window.

"use strict";

async function fetchWithTimeout(url, ms, fetchImpl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetchImpl(url, { signal: controller.signal, redirect: "manual",
                                  headers: { Accept: "application/json, text/html" } });
  } finally {
    clearTimeout(timer);
  }
}

// { ok: true, version } or { ok: false, error }.
async function checkServer(origin, { timeoutMs = 6000, fetchImpl = fetch } = {}) {
  let health;
  try {
    const res = await fetchWithTimeout(`${origin}/healthz`, timeoutMs, fetchImpl);
    if (res.status !== 200) {
      return { ok: false, error: `Something answered at ${origin}, but not like Shadowfax (it said ${res.status}).` };
    }
    health = await res.json();
  } catch (err) {
    if (err && err.name === "AbortError") {
      return { ok: false, error: `${origin} didn't answer within ${Math.round(timeoutMs / 1000)} seconds.` };
    }
    const code = err && err.cause && err.cause.code;
    if (code === "CERT_HAS_EXPIRED" || /CERT|SSL|TLS/i.test(String(code || err.message))) {
      return { ok: false, error: `${origin} has an HTTPS certificate this computer doesn't trust, so it wasn't opened.` };
    }
    return { ok: false, error: `Couldn't reach ${origin}. Is Shadowfax running, and is the address right?` };
  }
  if (!health || health.status !== "ok" || !/shadowfax/i.test(String(health.service || ""))) {
    return { ok: false, error: `Something answered at ${origin}, but it isn't Shadowfax.` };
  }
  try {
    const page = await fetchWithTimeout(`${origin}/`, timeoutMs, fetchImpl);
    const html = page.status === 200 ? await page.text() : "";
    if (!html.includes('id="root"')) {
      return { ok: false, error: `Shadowfax ${health.version} is running at ${origin}, but it isn't serving the ` +
        "dashboard. The Docker image always does; from source, build it first with npm run build in the frontend folder." };
    }
  } catch {
    return { ok: false, error: `Shadowfax answered at ${origin}, but its dashboard didn't load.` };
  }
  return { ok: true, version: String(health.version || "") };
}

module.exports = { checkServer };
