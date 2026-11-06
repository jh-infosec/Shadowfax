// Checks on the packaged app, the thing people install (v0.38).
//
//     node test/packaged.js dist/linux-unpacked/shadowfax-desktop
//
// The end-to-end tests drive the app through Node's inspector, which the
// packaged app deliberately switches off (Electron "fuses"), so they can't run
// against it. This checks the build from outside instead: it starts, it opens
// the dashboard from its packaged files, and the switches that would let
// someone run code inside it are really off.

"use strict";

const { spawn, spawnSync } = require("child_process");
const fs = require("fs");
const net = require("net");
const os = require("os");
const path = require("path");
const { chromium } = require("playwright-core");

const exe = path.resolve(process.argv[2] || "dist/linux-unpacked/shadowfax-desktop");
const URL_ = (process.env.SHADOWFAX_URL || "http://127.0.0.1:8000").replace(/\/$/, "");
const NO_SANDBOX = process.env.SFX_NO_SANDBOX === "1" ? ["--no-sandbox"] : [];
let passed = 0;

function check(label, ok) {
  console.log(`[${ok ? "PASS" : "FAIL"}] ${label}`);
  if (!ok) {
    process.exitCode = 1;
    throw new Error(`failed: ${label}`);
  }
  passed += 1;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function portOpen(port) {
  return new Promise((resolve) => {
    const s = net.connect(port, "127.0.0.1");
    s.once("connect", () => { s.destroy(); resolve(true); });
    s.once("error", () => resolve(false));
  });
}

async function main() {
  check("the packaged app exists", fs.existsSync(exe));

  // ELECTRON_RUN_AS_NODE would turn the app into a plain Node.js that runs
  // whatever script it's given, signed installer and all.
  const asNode = spawnSync(exe, [...NO_SANDBOX, "-e", "console.log('ran-as-node')"],
    { env: { ...process.env, ELECTRON_RUN_AS_NODE: "1" }, timeout: 8000, encoding: "utf8" });
  check("it can't be used as a Node.js interpreter (ELECTRON_RUN_AS_NODE is off)",
    !String(asNode.stdout).includes("ran-as-node"));

  const userData = fs.mkdtempSync(path.join(os.tmpdir(), "sfx-packaged-"));
  const child = spawn(exe, [...NO_SANDBOX, "--remote-debugging-port=9334", "--inspect=9335"], {
    env: { ...process.env, SHADOWFAX_DESKTOP_SERVER: URL_, SHADOWFAX_DESKTOP_USER_DATA: userData },
    stdio: "ignore",
  });
  try {
    let browser = null;
    for (let i = 0; i < 40 && !browser; i++) {
      await sleep(500);
      browser = await chromium.connectOverCDP("http://127.0.0.1:9334").catch(() => null);
    }
    check("it starts", Boolean(browser));
    let page = null;
    for (let i = 0; i < 40 && !page; i++) {
      await sleep(500);
      page = browser.contexts().flatMap((c) => c.pages()).find((p) => p.url().startsWith(`${URL_}/`)) || null;
    }
    check("and opens the server's dashboard from its packaged files", Boolean(page));
    await page.waitForSelector('input[autocomplete="username"]', { timeout: 15000 });
    const bridge = await page.evaluate(() => ({ require: typeof window.require,
      api: window.shadowfaxDesktop ? Object.keys(window.shadowfaxDesktop).sort().join(",") : null }));
    check("with the same narrow bridge and no Node.js in the page",
      bridge.require === "undefined" && bridge.api === "notify,onOpenAlert,setBadge");
    check("Node's inspector can't be switched on to take over the app (--inspect is off)",
      !(await portOpen(9335)));
    await browser.close().catch(() => {});
  } finally {
    child.kill();
  }
  console.log(`\nAll ${passed} packaged-app checks passed.`);
}

main().catch((err) => {
  if (!process.exitCode) {
    console.error(err);
    process.exitCode = 1;
  }
  process.exit(process.exitCode);
});
