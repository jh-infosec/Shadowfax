// The desktop app's rules about what it will load, open and show (v0.38).
//
// Pure functions, no Electron: everything here is unit-tested with plain
// `node --test`, and main.js only wires these answers to Electron's events.
//
// The app shows one thing, a Shadowfax server's own dashboard, so the rules are
// short. The window may only ever show that server's origin. Links elsewhere
// open in the system browser, and only if they're ordinary web links. The page
// gets three narrow functions from the app (notify, set the badge, hear about a
// notification being clicked), and only while it is that server's page.

"use strict";

const SEVERITIES = new Set(["critical", "high"]);
const ALERT_ID = /^[0-9a-f]{16}$/;
const MAX_TITLE = 120;
const MAX_BODY = 300;

// A server address as typed, turned into the origin the app will load, or an
// error message. Only http and https; no user name or password in the URL
// (they would be sent with every request and saved in the settings file); any
// path is dropped, because the dashboard lives at the root.
function normaliseServerUrl(input) {
  let text = String(input || "").trim();
  if (!text) return { error: "Type the address of your Shadowfax server." };
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) text = `http://${text}`;
  let url;
  try {
    url = new URL(text);
  } catch {
    return { error: "That isn't a web address. It should look like http://localhost:8000" };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { error: "Only http:// and https:// addresses can be opened." };
  }
  if (url.username || url.password) {
    return { error: "Leave the user name and password out of the address; you sign in on the next screen." };
  }
  if (!url.hostname) return { error: "That address has no server name in it." };
  return { origin: url.origin, local: isLocalHost(url.hostname), secure: url.protocol === "https:" };
}

function isLocalHost(hostname) {
  const h = String(hostname).toLowerCase().replace(/^\[|\]$/g, "");
  return h === "localhost" || h.endsWith(".localhost") || h === "::1" || /^127\./.test(h);
}

// Whether the window may show this URL: the server's own origin, nothing else.
// A dashboard link that leads anywhere else is handed to the system browser.
function isSameOrigin(url, origin) {
  try {
    return new URL(url).origin === origin;
  } catch {
    return false;
  }
}

// Whether a link may be handed to the system browser: plain web links only.
// file:, javascript:, custom protocol handlers and the like could start
// programs on this computer, which no alert in a dashboard should be able to.
function isSafeExternal(url) {
  try {
    const u = new URL(url);
    return (u.protocol === "https:" || u.protocol === "http:") && !u.username && !u.password;
  } catch {
    return false;
  }
}

function clean(text, max) {
  // Control characters out, whitespace squeezed, length capped. The text comes
  // from alerts, which quote whatever an attacker put in an event.
  const s = String(text == null ? "" : text)
    .replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/g, " ")
    .replace(/[\u{E0000}-\u{E007F}]/gu, "")
    .replace(/\s+/g, " ")
    .trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

// A notification request from the dashboard, checked and cleaned, or null.
function validateNotification(payload) {
  if (!payload || typeof payload !== "object") return null;
  const { id, severity, title, body } = payload;
  if (typeof id !== "string" || !ALERT_ID.test(id)) return null;
  if (!SEVERITIES.has(severity)) return null;
  const t = clean(title, MAX_TITLE);
  if (!t) return null;
  return { id, severity, title: t, body: clean(body, MAX_BODY) };
}

function validateBadge(count) {
  return Number.isInteger(count) && count >= 0 && count <= 100000 ? count : null;
}

// Notifications are rate-limited: a burst of new alerts shows the first few
// and then one summary, rather than forty pop-ups. `now` is passed in so tests
// don't have to wait.
class NotificationGate {
  constructor({ perWindow = 3, windowMs = 10000 } = {}) {
    this.perWindow = perWindow;
    this.windowMs = windowMs;
    this.shown = [];
    this.held = 0;
    this.seen = new Set();
  }

  // "show" this one, "hold" it for the summary, or "skip" it (seen before).
  offer(id, now) {
    if (this.seen.has(id)) return "skip";
    this.seen.add(id);
    if (this.seen.size > 5000) this.seen = new Set([...this.seen].slice(-2500));
    this.shown = this.shown.filter((t) => now - t < this.windowMs);
    if (this.shown.length < this.perWindow) {
      this.shown.push(now);
      return "show";
    }
    this.held += 1;
    return "hold";
  }

  // How many were held back since the last summary, resetting the count.
  takeHeld() {
    const n = this.held;
    this.held = 0;
    return n;
  }
}

module.exports = {
  normaliseServerUrl,
  isLocalHost,
  isSameOrigin,
  isSafeExternal,
  validateNotification,
  validateBadge,
  NotificationGate,
  clean,
};
