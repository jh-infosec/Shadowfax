// Inside Shadowfax Desktop (v0.38): desktop notifications for new critical and
// high alerts, and the count of open critical alerts on the window and tray.
//
// In a browser `window.shadowfaxDesktop` doesn't exist and none of this runs.
// The app provides it only to the dashboard of the server it opened.
//
// What counts as new is decided here, from alerts the dashboard can already
// read: the first check only learns what is there (opening the app must not
// replay every alert ever raised), and each later check notifies the ones it
// hasn't seen. The app rate-limits what it shows.

const NOTIFY = ["critical", "high"];
const MAX_PER_CHECK = 20;

export function desktopBridge() {
  return typeof window !== "undefined" && window.shadowfaxDesktop ? window.shadowfaxDesktop : null;
}

export function createAlertWatcher({ bridge, fetchAlerts, onOpen }) {
  const seen = new Set();
  const actors = new Map();   // alert id -> actor id, for opening one from a notification
  let primed = false;
  let running = false;
  let again = false;

  bridge.onOpenAlert((id) => {
    const actor = actors.get(id);
    if (actor) onOpen(actor, id);
  });

  async function once() {
    let alerts;
    try {
      alerts = await fetchAlerts({ severity: NOTIFY });
    } catch {
      return; // signed out or offline; the next change tries again
    }
    const fresh = [];
    for (const a of alerts) {
      actors.set(a.id, a.actor_id);
      if (!seen.has(a.id)) {
        seen.add(a.id);
        if (primed && !a.acknowledged) fresh.push(a);
      }
    }
    primed = true;
    // Oldest first, so the notifications arrive in the order things happened.
    fresh.sort((x, y) => String(x.timestamp).localeCompare(String(y.timestamp)));
    for (const a of fresh.slice(-MAX_PER_CHECK)) {
      bridge.notify({
        id: a.id,
        severity: a.severity,
        title: `${a.severity.toUpperCase()} · ${a.category} · ${a.actor_id}`,
        body: a.message,
      });
    }
    bridge.setBadge(alerts.filter((a) => a.severity === "critical" && !a.acknowledged).length);
  }

  // One check at a time. A change that arrives during a check is not dropped:
  // it runs one more check when the current one finishes.
  async function check() {
    if (running) {
      again = true;
      return;
    }
    running = true;
    try {
      do {
        again = false;
        await once();
      } while (again);
    } finally {
      running = false;
    }
  }

  return { check };
}
