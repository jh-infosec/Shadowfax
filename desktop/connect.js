// The connect page (v0.38). Plain script, no framework: it asks main.js to
// check an address and open it. Everything shown is set with textContent, so
// nothing a server or a settings file says can become markup.

"use strict";

const api = window.shadowfaxConnect;
const $ = (id) => document.getElementById(id);
const form = $("form");
const input = $("address");
const button = $("connect");
const statusBox = $("status");
const warning = $("warning");
let pending = null;   // an address waiting for "Connect anyway"

function say(text, kind) {
  statusBox.hidden = !text;
  statusBox.textContent = text || "";
  statusBox.className = `status ${kind || ""}`;
}

function busy(on) {
  button.disabled = on;
  input.disabled = on;
  button.textContent = on ? "Checking…" : "Connect";
}

async function connect(address, confirmed) {
  warning.hidden = true;
  busy(true);
  say("Checking…", "");
  let result;
  try {
    result = await api.check(address);
  } catch {
    result = { ok: false, error: "Something went wrong checking that address." };
  }
  busy(false);
  if (!result.ok) {
    say(result.error, "error");
    input.focus();
    return;
  }
  if (result.plainRemote && !confirmed) {
    say("", "");
    pending = result.origin;
    warning.hidden = false;
    $("anyway").focus();
    return;
  }
  say(`Shadowfax ${result.version} found. Opening…`, "ok");
  const opened = await api.open(result.origin);
  if (!opened) say("Couldn't open it. Try again.", "error");
}

function renderRecent(servers) {
  const list = $("recent");
  list.replaceChildren();
  $("recent-box").hidden = servers.length === 0;
  for (const origin of servers) {
    const li = document.createElement("li");
    const go = document.createElement("button");
    go.type = "button";
    go.className = "server";
    go.textContent = origin;
    go.addEventListener("click", () => {
      input.value = origin;
      connect(origin, false);
    });
    const forget = document.createElement("button");
    forget.type = "button";
    forget.className = "forget";
    forget.title = `Forget ${origin}`;
    forget.setAttribute("aria-label", `Forget ${origin}`);
    forget.textContent = "×";
    forget.addEventListener("click", async () => renderRecent(await api.forget(origin)));
    li.append(go, forget);
    list.append(li);
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  connect(input.value, false);
});
$("anyway").addEventListener("click", () => {
  if (pending) connect(pending, true);
});
api.onMessage((text) => say(text, "error"));

(async () => {
  const message = new URLSearchParams(window.location.search).get("message");
  if (message) say(message, "error");
  const servers = await api.recent();
  renderRecent(servers);
  if (servers.length) input.value = servers[0];
  input.focus();
  input.select();
})();
