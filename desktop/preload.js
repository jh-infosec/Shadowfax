// The dashboard window's only link to the app (v0.38).
//
// Sandboxed: it can't reach Node.js or the file system. It offers the page
// three functions and nothing else, and only when the page is the Shadowfax
// server this window was opened for. main.js checks every call again.

"use strict";

const { contextBridge, ipcRenderer } = require("electron");

const arg = process.argv.find((a) => a.startsWith("--sfx-origin="));
const expected = arg ? arg.slice("--sfx-origin=".length) : null;
const ALERT_ID = /^[0-9a-f]{16}$/;

if (expected && window.location.origin === expected) {
  let opener = null;
  ipcRenderer.on("sfx:open-alert", (_e, id) => {
    if (typeof id === "string" && ALERT_ID.test(id) && opener) opener(id);
  });
  contextBridge.exposeInMainWorld("shadowfaxDesktop", Object.freeze({
    notify: (alert) => {
      if (!alert || typeof alert !== "object") return;
      ipcRenderer.send("sfx:notify", {
        id: String(alert.id), severity: String(alert.severity),
        title: String(alert.title), body: String(alert.body),
      });
    },
    setBadge: (count) => ipcRenderer.send("sfx:badge", Number(count)),
    onOpenAlert: (fn) => { opener = typeof fn === "function" ? fn : null; },
  }));
}
