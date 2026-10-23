import React, { useCallback, useEffect, useState } from "react";
import * as api from "../api.js";

// Front door (v0.10): who is failing to sign in to Shadowfax itself.
//
// Shadowfax has always been able to detect brute-force authentication. From
// this version its own login is one of the things it watches, and the failures
// land in the ordinary event log where the ordinary detectors see them — so the
// alerts show up in the main table with no special casing. This drawer is the
// operational half of that: what is locked right now, and the one button an
// admin needs when a colleague is locked out and wants back in.
//
// Admin-only, because releasing a lockout is a security decision and ought to
// be attributable. The release is written into the tamper-evident ledger for
// the same reason: "the lockout went away" is exactly the kind of thing whose
// absence from an audit trail would be suspicious.

function relative(iso) {
  if (!iso) return "—";
  const then = new Date(iso + (iso.endsWith("Z") ? "" : "Z"));
  const secs = Math.max(0, Math.round((Date.now() - then.getTime()) / 1000));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  return `${Math.round(secs / 3600)}h ago`;
}

export default function LockoutsDrawer({ onClose }) {
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(null);

  const load = useCallback(() => {
    api.getLockouts().then((r) => { setReport(r); setError(null); })
      .catch((e) => setError(e.message));
  }, []);

  useEffect(() => { load(); }, [load]);

  const unlock = async (username) => {
    setBusy(username);
    try {
      await api.clearLockout(username);
      load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(null);
    }
  };

  const settings = report?.settings;
  const locked = (report?.scopes || []).filter((s) => s.locked);

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <div className="drawer lockouts-drawer">
        <div className="drawer-head">
          <div className="drawer-actor">Front door</div>
          <button className="drawer-close" onClick={onClose}>&times;</button>
        </div>

        {error && <div className="error-banner">{error}</div>}
        {report === null && !error && <div className="empty-state">Loading…</div>}

        {report && (
          <>
            <div className="lockout-rule">
              Locks a username from one source after <b>{settings.max_failures}</b>{" "}
              failures in <b>{settings.window_minutes} min</b>, for{" "}
              <b>{settings.lockout_minutes} min</b>. Backoff starts at{" "}
              <b>{settings.backoff_after}</b>.
            </div>

            {report.scopes.length === 0 ? (
              <div className="empty-state">
                No failed sign-ins in the window. The front door is quiet.
              </div>
            ) : (
              <>
                <div className="lockout-count">
                  {locked.length} locked · {report.scopes.length - locked.length} backing off
                </div>
                <table className="lockout-table">
                  <thead>
                    <tr>
                      <th>Username</th>
                      <th>Source</th>
                      <th>Fails</th>
                      <th>State</th>
                      <th>Last</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {report.scopes.map((s) => (
                      <tr key={`${s.username}|${s.source}`} className={s.locked ? "locked" : ""}>
                        {/* The attempted username is whatever the caller typed,
                            so it is rendered as plain text and nothing else. */}
                        <td className="mono">{s.username}</td>
                        <td className="mono">{s.source}</td>
                        <td className="mono">{s.failures}</td>
                        <td>
                          {s.locked ? (
                            <span className="lockout-state locked">
                              locked {s.retry_after_seconds}s
                            </span>
                          ) : s.retry_after_seconds ? (
                            <span className="lockout-state backoff">
                              backoff {s.retry_after_seconds}s
                            </span>
                          ) : (
                            <span className="lockout-state">—</span>
                          )}
                        </td>
                        <td className="mono">{relative(s.last_failure)}</td>
                        <td>
                          <button
                            className="btn"
                            disabled={busy === s.username}
                            onClick={() => unlock(s.username)}
                            title="clear this username's recorded failures"
                          >
                            {busy === s.username ? "…" : "Release"}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}

            <div className="lockout-foot">
              A source address is shared — an office, a VPN, a NAT gateway — so
              spraying many usernames from one address only ever slows it down.
              Hard lockout applies to a username-and-source pair, where it cannot
              be used to lock a colleague out of their own account.
              <br />
              <br />
              Failed sign-ins here are ordinary events in Shadowfax's own log:
              they raise <code>brute_force_auth</code> through the same detector,
              with the same ATT&amp;CK mapping, as an attack on anything else it
              watches.
            </div>
          </>
        )}
      </div>
    </>
  );
}
