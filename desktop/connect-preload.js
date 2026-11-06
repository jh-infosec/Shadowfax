// The connect window's link to the app (v0.38). The page asks; main.js decides.

"use strict";

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("shadowfaxConnect", Object.freeze({
  recent: () => ipcRenderer.invoke("connect:recent"),
  check: (address) => ipcRenderer.invoke("connect:check", String(address)),
  open: (address) => ipcRenderer.invoke("connect:open", String(address)),
  forget: (address) => ipcRenderer.invoke("connect:forget", String(address)),
  onMessage: (fn) => ipcRenderer.on("connect:message", (_e, text) => fn(String(text))),
}));
