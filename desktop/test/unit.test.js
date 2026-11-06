// Unit tests for the desktop app's rules (v0.38). Plain Node, no Electron:
//
//     cd desktop && npm test

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const sec = require("../security");
const { Settings, sanitise, MAX_RECENT } = require("../settings");
const { checkServer } = require("../server-check");

test("server addresses become origins; the scheme defaults to http", () => {
  assert.deepEqual(sec.normaliseServerUrl("localhost:8000"),
    { origin: "http://localhost:8000", local: true, secure: false });
  assert.equal(sec.normaliseServerUrl("https://sfx.example.com/some/page?x=1#y").origin,
    "https://sfx.example.com");
  assert.equal(sec.normaliseServerUrl("  http://127.0.0.1:8000/  ").origin, "http://127.0.0.1:8000");
  assert.equal(sec.normaliseServerUrl("http://[::1]:8000").local, true);
  assert.equal(sec.normaliseServerUrl("http://10.0.0.5:8000").local, false);
});

test("addresses the app won't open are refused with a reason", () => {
  for (const bad of ["", "   ", "file:///etc/passwd", "javascript:alert(1)", "ftp://x.example",
                     "http://admin:hunter2@sfx.example", "http://", "not a url at all"]) {
    const r = sec.normaliseServerUrl(bad);
    assert.ok(r.error && !r.origin, `should refuse ${JSON.stringify(bad)}`);
  }
  assert.match(sec.normaliseServerUrl("http://a:b@x.example").error, /password/);
});

test("the window may only show its server's origin", () => {
  const o = "http://localhost:8000";
  assert.ok(sec.isSameOrigin("http://localhost:8000/", o));
  assert.ok(sec.isSameOrigin("http://localhost:8000/docs#x", o));
  assert.ok(!sec.isSameOrigin("http://localhost:8001/", o));
  assert.ok(!sec.isSameOrigin("https://localhost:8000/", o));
  assert.ok(!sec.isSameOrigin("http://localhost:8000.evil.example/", o));
  assert.ok(!sec.isSameOrigin("not a url", o));
});

test("only ordinary web links are handed to the system browser", () => {
  assert.ok(sec.isSafeExternal("https://atlas.mitre.org/techniques/AML.T0051.001"));
  assert.ok(sec.isSafeExternal("http://example.com/"));
  for (const bad of ["file:///C:/Windows/System32/calc.exe", "javascript:alert(1)", "ms-msdt:/id x",
                     "smb://host/share", "vscode://x", "https://u:p@x.example/", "", "\\\\host\\share"]) {
    assert.ok(!sec.isSafeExternal(bad), `should refuse ${bad}`);
  }
});

test("notifications are validated and their text cleaned", () => {
  const ok = sec.validateNotification({ id: "0123456789abcdef", severity: "critical",
    title: "CRITICAL · injection_followed", body: "called Bash with\n'https://x'\u0007\u202e" });
  assert.equal(ok.body, "called Bash with 'https://x'");
  assert.equal(sec.validateNotification({ id: "nope", severity: "critical", title: "t" }), null);
  assert.equal(sec.validateNotification({ id: "0123456789abcdef", severity: "low", title: "t" }), null);
  assert.equal(sec.validateNotification({ id: "0123456789abcdef", severity: "high", title: "  " }), null);
  assert.equal(sec.validateNotification(null), null);
  const long = sec.validateNotification({ id: "0123456789abcdef", severity: "high", title: "x".repeat(500),
    body: "y".repeat(5000) });
  assert.ok(long.title.length <= 120 && long.body.length <= 300);
  const hidden = String.fromCodePoint(...[..."ignore"].map((c) => 0xE0000 + c.charCodeAt(0)));
  assert.equal(sec.validateNotification({ id: "0123456789abcdef", severity: "high", title: `a${hidden}b` }).title,
    "ab");
});

test("the badge only takes a sensible count", () => {
  assert.equal(sec.validateBadge(3), 3);
  assert.equal(sec.validateBadge(0), 0);
  for (const bad of [-1, 1.5, "3", NaN, null, 1e9]) assert.equal(sec.validateBadge(bad), null);
});

test("a burst of alerts shows a few, then holds the rest for one summary", () => {
  const gate = new sec.NotificationGate({ perWindow: 3, windowMs: 10000 });
  const ids = [...Array(8)].map((_, i) => i.toString(16).padStart(16, "0"));
  const verdicts = ids.map((id) => gate.offer(id, 1000));
  assert.deepEqual(verdicts, ["show", "show", "show", "hold", "hold", "hold", "hold", "hold"]);
  assert.equal(gate.offer(ids[0], 1000), "skip");
  assert.equal(gate.takeHeld(), 5);
  assert.equal(gate.takeHeld(), 0);
  assert.equal(gate.offer("ffffffffffffffff", 12000), "show");
});

test("settings keep recent servers, most recent first, and survive a damaged file", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sfx-desktop-"));
  const s = new Settings(dir);
  s.load();
  s.remember("http://localhost:8000");
  s.remember("https://sfx.example.com");
  s.remember("http://localhost:8000");
  const again = new Settings(dir);
  assert.deepEqual(again.load().servers, ["http://localhost:8000", "https://sfx.example.com"]);
  assert.equal(again.data.lastServer, "http://localhost:8000");
  again.forget("http://localhost:8000");
  assert.equal(new Settings(dir).load().lastServer, null);
  fs.writeFileSync(path.join(dir, "shadowfax-desktop.json"), "{ not json");
  assert.deepEqual(new Settings(dir).load().servers, []);
  for (let i = 0; i < 20; i++) s.remember(`http://host${i}.example`);
  assert.equal(s.data.servers.length, MAX_RECENT);
});

test("a hand-edited settings file can't smuggle in a bad address", () => {
  const data = sanitise({ servers: ["javascript:alert(1)", "http://ok.example/x", "file:///etc"],
                          lastServer: "file:///etc", closeToTray: "no" });
  assert.deepEqual(data.servers, ["http://ok.example"]);
  assert.equal(data.lastServer, null);
  assert.equal(data.closeToTray, true);
});

function serve(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, "127.0.0.1", () => resolve({ srv, origin: `http://127.0.0.1:${srv.address().port}` }));
  });
}

test("the server check knows Shadowfax from something else", async () => {
  const shadowfax = await serve((req, res) => {
    if (req.url === "/healthz") {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ status: "ok", service: "Shadowfax API", version: "0.38.0" }));
    } else res.end('<!doctype html><div id="root"></div>');
  });
  const apiOnly = await serve((req, res) => {
    if (req.url === "/healthz") res.end(JSON.stringify({ status: "ok", service: "Shadowfax API", version: "0.38.0" }));
    else { res.statusCode = 404; res.end("{}"); }
  });
  const other = await serve((req, res) => res.end(JSON.stringify({ hello: "world" })));
  const slow = await serve(() => { /* never answers */ });
  try {
    assert.deepEqual(await checkServer(shadowfax.origin), { ok: true, version: "0.38.0" });
    assert.match((await checkServer(apiOnly.origin)).error, /isn't serving the dashboard/);
    assert.match((await checkServer(other.origin)).error, /isn't Shadowfax/);
    assert.match((await checkServer(slow.origin, { timeoutMs: 300 })).error, /didn't answer/);
    assert.match((await checkServer("http://127.0.0.1:9")).error, /Couldn't reach/);
  } finally {
    for (const s of [shadowfax, apiOnly, other, slow]) s.srv.closeAllConnections?.(), s.srv.close();
  }
});
