// Shadowfax Desktop (v0.38): the dashboard in its own window, with desktop
// notifications for new critical and high alerts and a tray icon.
//
// The app doesn't carry its own copy of the dashboard. It opens the one your
// Shadowfax server serves, so the two can never be different versions, and it
// works with the server on this computer, in Docker, or anywhere you can reach.
//
// It is built like a browser that can only visit one site:
//
// * Every page is sandboxed, with no Node.js and context isolation on.
// * The dashboard window may only show its server's origin. Links elsewhere
//   open in the system browser, and only if they are ordinary web links.
// * The dashboard gets three functions from the app (notify, badge, and hear
//   that a notification was clicked) and every call is checked: it must come
//   from that server's page, and the content is validated and cleaned.
// * No permission prompts are granted except copying to the clipboard, which
//   the dashboard uses for one-time secrets like a new API key.
// * Certificate errors are never overridden.

"use strict";

const path = require("path");
const { pathToFileURL } = require("url");
const {
  app, BrowserWindow, Menu, Notification, Tray, dialog, ipcMain, nativeImage, session, shell,
} = require("electron");
const sec = require("./security");
const { Settings } = require("./settings");
const { checkServer } = require("./server-check");

const TEST = process.env.SHADOWFAX_DESKTOP_TEST === "1";
if (process.env.SHADOWFAX_DESKTOP_USER_DATA) {
  app.setPath("userData", process.env.SHADOWFAX_DESKTOP_USER_DATA);
}
app.setAppUserModelId("io.github.jhinfosec.shadowfax");  // Windows notifications need it
// Every renderer in the operating system's sandbox. Skipped only when the app
// was started with --no-sandbox, which the end-to-end tests need on CI machines
// that can't create one; pages are still sandboxed by their own settings below.
if (!process.argv.includes("--no-sandbox")) app.enableSandbox();

const CONNECT_URL = pathToFileURL(path.join(__dirname, "connect.html")).href;
const ICON = path.join(__dirname, "build", "icon.png");
const TRAY_ICON = path.join(__dirname, "build", "tray.png");
const BADGE_ICON = path.join(__dirname, "build", "badge.png");

// In test mode, what the app would have shown or opened is recorded here
// instead, so the end-to-end tests can check it without real pop-ups.
const record = { notifications: [], external: [], blocked: [], badge: null };
if (TEST) global.__sfxTest = record;

let settings = null;
let tray = null;
let connectWin = null;
let dashboard = null;
let origin = null;
let quitting = false;
let critical = 0;
let gate = new sec.NotificationGate();
let summaryTimer = null;
const checked = new Map();     // origin -> time it last passed checkServer
const live = new Set();        // notifications kept alive until clicked or closed

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", () => showMain());
}

// -- windows -------------------------------------------------------------------

const BASE_PREFS = {
  contextIsolation: true,
  sandbox: true,
  nodeIntegration: false,
  nodeIntegrationInSubFrames: false,
  webviewTag: false,
  spellcheck: false,
  safeDialogs: true,
};

function openConnect(message) {
  // The connect window opens before the dashboard closes: for a moment with no
  // window at all, the app would count as closed and quit.
  const old = dashboard;
  dashboard = null;
  origin = null;
  if (connectWin) {
    connectWin.show();
    connectWin.focus();
    if (message) connectWin.webContents.send("connect:message", String(message));
  } else {
    connectWin = new BrowserWindow({
      width: 560, height: 540, resizable: false, show: false, title: "Shadowfax",
      backgroundColor: "#0b0f17", icon: ICON, autoHideMenuBar: true,
      webPreferences: { ...BASE_PREFS, preload: path.join(__dirname, "connect-preload.js") },
    });
    const win = connectWin;
    win.loadURL(message ? `${CONNECT_URL}?message=${encodeURIComponent(message)}` : CONNECT_URL);
    win.once("ready-to-show", () => win.show());
    win.on("closed", () => {
      if (win === connectWin) connectWin = null;
      if (!dashboard && !quitting && !tray) app.quit();
    });
  }
  if (old) old.destroy();
  return connectWin;
}

function openDashboard(serverOrigin) {
  origin = serverOrigin;
  gate = new sec.NotificationGate();
  critical = 0;
  settings.remember(serverOrigin);
  dashboard = new BrowserWindow({
    width: 1440, height: 900, minWidth: 960, minHeight: 600, show: false,
    backgroundColor: "#0b0f17", icon: ICON, title: "Shadowfax",
    webPreferences: {
      ...BASE_PREFS,
      preload: path.join(__dirname, "preload.js"),
      // The preload only offers the bridge to this exact origin.
      additionalArguments: [`--sfx-origin=${serverOrigin}`],
    },
  });
  const win = dashboard;
  win.loadURL(`${serverOrigin}/`);
  win.once("ready-to-show", () => {
    win.show();
    if (connectWin) connectWin.close();
  });
  win.webContents.on("did-fail-load", (_e, code, desc, url, isMain) => {
    if (isMain && win === dashboard) openConnect(`Couldn't load ${serverOrigin} (${desc || code}).`);
  });
  win.on("page-title-updated", (e) => {
    e.preventDefault();
    updateTitle();
  });
  win.on("close", (e) => {
    if (!quitting && tray && settings.data.closeToTray && win === dashboard) {
      e.preventDefault();
      win.hide();
    }
  });
  win.on("closed", () => {
    if (win === dashboard) {
      dashboard = null;
      origin = null;
      if (!quitting && !connectWin) app.quit();
    }
  });
  updateTitle();
  return win;
}

function showMain() {
  const w = dashboard || connectWin || openConnect();
  if (w.isMinimized()) w.restore();
  w.show();
  w.focus();
}

function updateTitle() {
  if (!dashboard) return;
  let host = origin;
  try {
    host = new URL(origin).host;
  } catch { /* keep the origin */ }
  const suffix = critical ? ` (${critical} critical)` : "";
  dashboard.setTitle(`Shadowfax · ${host}${suffix}`);
}

// -- what pages may do ------------------------------------------------------------

function allowedUrl(contents, url) {
  if (dashboard && contents === dashboard.webContents) return sec.isSameOrigin(url, origin);
  if (connectWin && contents === connectWin.webContents) return url.split("?")[0] === CONNECT_URL;
  return false;
}

function openExternal(url) {
  if (!sec.isSafeExternal(url)) {
    record.blocked.push(url);
    return;
  }
  if (TEST) record.external.push(url);
  else shell.openExternal(url);
}

app.on("web-contents-created", (_e, contents) => {
  contents.on("will-attach-webview", (e) => e.preventDefault());
  contents.setWindowOpenHandler(({ url }) => {
    openExternal(url);
    return { action: "deny" };
  });
  const guard = (e, url) => {
    if (!allowedUrl(contents, url)) {
      e.preventDefault();
      openExternal(url);
    }
  };
  contents.on("will-navigate", guard);
  contents.on("will-redirect", guard);
});

function installSessionGuards() {
  const ses = session.defaultSession;
  const clipboardOk = (wc, requestingUrl) => Boolean(
    dashboard && wc === dashboard.webContents && requestingUrl && sec.isSameOrigin(requestingUrl, origin));
  ses.setPermissionRequestHandler((wc, permission, callback, details) => {
    callback(permission === "clipboard-sanitized-write" && clipboardOk(wc, details && details.requestingUrl));
  });
  ses.setPermissionCheckHandler((wc, permission, requestingOrigin) =>
    permission === "clipboard-sanitized-write" && clipboardOk(wc, requestingOrigin));
}

function fromDashboard(e) {
  return Boolean(dashboard && origin && e.sender === dashboard.webContents && e.senderFrame
    && e.senderFrame === e.sender.mainFrame && sec.isSameOrigin(e.senderFrame.url, origin));
}

function fromConnect(e) {
  return Boolean(connectWin && e.sender === connectWin.webContents && e.senderFrame
    && e.senderFrame.url.split("?")[0] === CONNECT_URL);
}

// -- the connect window's requests ----------------------------------------------

ipcMain.handle("connect:recent", (e) => (fromConnect(e) ? settings.data.servers.slice() : []));

ipcMain.handle("connect:check", async (e, input) => {
  if (!fromConnect(e)) return { ok: false, error: "not allowed" };
  const n = sec.normaliseServerUrl(input);
  if (n.error) return { ok: false, error: n.error };
  const result = await checkServer(n.origin);
  if (result.ok) checked.set(n.origin, Date.now());
  // Plain http to another computer sends your password across the network
  // unencrypted. Allowed, because a lab network may have nothing else, but said.
  return { ...result, origin: n.origin, plainRemote: !n.secure && !n.local };
});

ipcMain.handle("connect:open", (e, input) => {
  if (!fromConnect(e)) return false;
  const n = sec.normaliseServerUrl(input);
  // Only an address that just passed the check: the page can't skip it.
  if (n.error || !checked.has(n.origin) || Date.now() - checked.get(n.origin) > 120000) return false;
  openDashboard(n.origin);
  return true;
});

ipcMain.handle("connect:forget", (e, input) => {
  if (!fromConnect(e)) return [];
  const n = sec.normaliseServerUrl(input);
  if (n.origin) settings.forget(n.origin);
  return settings.data.servers.slice();
});

// -- the dashboard's requests ---------------------------------------------------

ipcMain.on("sfx:notify", (e, payload) => {
  if (!fromDashboard(e)) return;
  const n = sec.validateNotification(payload);
  if (!n) return;
  const verdict = gate.offer(n.id, Date.now());
  if (verdict === "show") showNotification(n);
  else if (verdict === "hold" && !summaryTimer) {
    summaryTimer = setTimeout(() => {
      summaryTimer = null;
      const more = gate.takeHeld();
      if (more) {
        showNotification({ id: null, severity: "high",
          title: `${more} more new alert${more === 1 ? "" : "s"}`, body: "Open Shadowfax to see them." });
      }
    }, gate.windowMs);
  }
});

ipcMain.on("sfx:badge", (e, count) => {
  if (!fromDashboard(e)) return;
  const c = sec.validateBadge(count);
  if (c === null) return;
  critical = c;
  record.badge = c;
  updateTitle();
  try {
    app.setBadgeCount(c);
  } catch { /* not every desktop has a badge */ }
  if (dashboard && process.platform === "win32") {
    dashboard.setOverlayIcon(c ? nativeImage.createFromPath(BADGE_ICON) : null,
                             c ? `${c} open critical alerts` : "");
  }
  if (tray) tray.setToolTip(c ? `Shadowfax: ${c} open critical alert${c === 1 ? "" : "s"}` : "Shadowfax");
});

function showNotification(n) {
  if (TEST) {
    record.notifications.push(n);
    return;
  }
  if (!Notification.isSupported()) return;
  const note = new Notification({ title: n.title, body: n.body, silent: n.severity !== "critical",
                                  icon: ICON });
  live.add(note);
  const done = () => live.delete(note);
  note.on("click", () => {
    done();
    showMain();
    if (n.id && dashboard) dashboard.webContents.send("sfx:open-alert", n.id);
  });
  note.on("close", done);
  note.show();
}

// -- menus and tray ----------------------------------------------------------------

function buildMenu() {
  const template = [
    ...(process.platform === "darwin" ? [{ role: "appMenu" }] : []),
    { label: "File", submenu: [
      { label: "Switch server…", accelerator: "CmdOrCtrl+Shift+S", click: () => openConnect() },
      { type: "separator" },
      { label: "Quit", accelerator: "CmdOrCtrl+Q", click: () => { quitting = true; app.quit(); } },
    ] },
    { role: "editMenu" },
    { label: "View", submenu: [
      { role: "reload" }, { type: "separator" },
      { role: "resetZoom" }, { role: "zoomIn" }, { role: "zoomOut" }, { type: "separator" },
      { role: "togglefullscreen" }, { role: "toggleDevTools" },
    ] },
    { label: "Help", submenu: [
      { label: "Shadowfax on GitHub", click: () => openExternal("https://github.com/jh-infosec/Shadowfax") },
      { label: "About Shadowfax Desktop", click: () => dialog.showMessageBox({
        type: "info", title: "Shadowfax Desktop", icon: ICON,
        message: `Shadowfax Desktop ${app.getVersion()}`,
        detail: `Electron ${process.versions.electron}, Chromium ${process.versions.chrome}` +
          (origin ? `\nConnected to ${origin}` : ""),
      }) },
    ] },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

function createTray() {
  try {
    tray = new Tray(nativeImage.createFromPath(TRAY_ICON));
  } catch {
    tray = null;   // a desktop without a tray: closing the window quits
    return;
  }
  tray.setToolTip("Shadowfax");
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: "Open Shadowfax", click: () => showMain() },
    { label: "Switch server…", click: () => { openConnect(); } },
    { type: "separator" },
    { label: "Quit", click: () => { quitting = true; app.quit(); } },
  ]));
  tray.on("click", () => showMain());
}

// -- start -----------------------------------------------------------------------

function startingServer() {
  const arg = process.argv.find((a) => a.startsWith("--server="));
  return (arg && arg.slice("--server=".length)) || process.env.SHADOWFAX_DESKTOP_SERVER
    || settings.data.lastServer;
}

app.on("before-quit", () => { quitting = true; });
app.on("activate", () => showMain());
app.on("window-all-closed", () => {
  if (!tray || quitting) app.quit();
});

app.whenReady().then(async () => {
  settings = new Settings(app.getPath("userData"));
  settings.load();
  installSessionGuards();
  buildMenu();
  if (!TEST || process.env.SHADOWFAX_DESKTOP_TRAY === "1") createTray();
  const start = startingServer();
  if (!start) {
    openConnect();
    return;
  }
  const n = sec.normaliseServerUrl(start);
  if (n.error) {
    openConnect(n.error);
    return;
  }
  const result = await checkServer(n.origin);
  if (result.ok) openDashboard(n.origin);
  else openConnect(result.error);
});
