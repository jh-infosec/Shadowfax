// The desktop app's settings: which servers you've used and a couple of
// preferences. A small JSON file in the app's own data folder.
//
// Nothing secret is kept here. The sign-in lives in the dashboard page's own
// storage for that server, exactly as it would in a browser, so this file can
// be read by anyone without giving anything away.

"use strict";

const fs = require("fs");
const path = require("path");
const { normaliseServerUrl } = require("./security");

const MAX_RECENT = 8;
const DEFAULTS = { servers: [], lastServer: null, closeToTray: true };

function sanitise(raw) {
  const out = { ...DEFAULTS };
  if (!raw || typeof raw !== "object") return out;
  const servers = Array.isArray(raw.servers) ? raw.servers : [];
  out.servers = [];
  for (const s of servers) {
    const n = normaliseServerUrl(s);
    if (n.origin && !out.servers.includes(n.origin)) out.servers.push(n.origin);
    if (out.servers.length >= MAX_RECENT) break;
  }
  const last = normaliseServerUrl(raw.lastServer);
  out.lastServer = last.origin && out.servers.includes(last.origin) ? last.origin : null;
  out.closeToTray = raw.closeToTray !== false;
  return out;
}

class Settings {
  constructor(dir) {
    this.file = path.join(dir, "shadowfax-desktop.json");
    this.data = { ...DEFAULTS };
  }

  load() {
    try {
      this.data = sanitise(JSON.parse(fs.readFileSync(this.file, "utf8")));
    } catch {
      // Missing or damaged: start fresh rather than refuse to open.
      this.data = { ...DEFAULTS };
    }
    return this.data;
  }

  save() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2));
    fs.renameSync(tmp, this.file);
  }

  // Most recent first, no duplicates, at most MAX_RECENT.
  remember(origin) {
    this.data.servers = [origin, ...this.data.servers.filter((s) => s !== origin)].slice(0, MAX_RECENT);
    this.data.lastServer = origin;
    this.save();
  }

  forget(origin) {
    this.data.servers = this.data.servers.filter((s) => s !== origin);
    if (this.data.lastServer === origin) this.data.lastServer = null;
    this.save();
  }
}

module.exports = { Settings, sanitise, MAX_RECENT };
