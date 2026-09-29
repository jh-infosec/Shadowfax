import React, { useCallback, useEffect, useState } from "react";
import * as api from "../api.js";

// Evidence-integrity badge (v0.9).
//
// Shadowfax's findings are only worth as much as the event log they are derived
// from, so the log's integrity belongs on screen next to the alert counts rather
// than buried in a CLI. The badge re-verifies whenever the event count changes
// (the parent passes `stats`, which the SSE stream keeps current), so a break
// shows up on its own instead of waiting to be asked for.
//
// Verification is read-only and recomputed server-side from the stored chain;
// nothing here is cached or trusted from a previous answer.
export default function LedgerBadge({ eventCount }) {
  const [report, setReport] = useState(null);
  const [checking, setChecking] = useState(false);
  const [open, setOpen] = useState(false);
  const [failed, setFailed] = useState(null);

  const verify = useCallback(async () => {
    setChecking(true);
    try {
      setReport(await api.verifyLedger());
      setFailed(null);
    } catch (err) {
      // Couldn't reach the check. That is not the same as a broken ledger, and
      // the badge must not imply it is.
      setReport(null);
      setFailed(err.message);
    } finally {
      setChecking(false);
    }
  }, []);

  // Re-verify on mount and whenever the log grows or shrinks.
  useEffect(() => {
    verify();
  }, [verify, eventCount]);

  const state = failed ? "unknown" : report ? (report.ok ? "ok" : "broken") : "unknown";
  const label =
    state === "ok"
      ? `ledger verified · ${report.entries}`
      : state === "broken"
      ? "LEDGER BROKEN"
      : checking
      ? "verifying ledger…"
      : "ledger unverified";

  return (
    <div className="ledger-badge-wrap">
      <button
        className={`ledger-badge ${state}`}
        onClick={() => setOpen((v) => !v)}
        title="Evidence integrity — click for detail"
      >
        <span className="ledger-icon" aria-hidden="true">
          {state === "ok" ? "⛓" : state === "broken" ? "✕" : "…"}
        </span>
        {label}
      </button>

      {open && (
        <div className="ledger-pop">
          <div className="ledger-pop-title">Evidence integrity</div>

          {state === "ok" && (
            <>
              <p className="ledger-pop-line good">{report.summary}</p>
              <p className="ledger-pop-note">
                Every event is hash-chained to the one before it. All{" "}
                {report.entries} links were recomputed and matched, so no event
                has been edited, deleted or reordered since it was recorded.
              </p>
              <div className="ledger-pop-label">Head hash</div>
              <code className="ledger-hash">{report.head}</code>
              <p className="ledger-pop-note">
                Tamper-<em>evident</em>, not tamper-proof: anyone who can rewrite
                the database can rewrite the chain with it. Export this head
                somewhere outside that reach and a third party can check it too.
              </p>
            </>
          )}

          {state === "broken" && (
            <>
              <p className="ledger-pop-line bad">{report.summary}</p>
              {report.broken_at && (
                <div className="ledger-break">
                  <div>
                    <span className="ledger-pop-label">Position</span>{" "}
                    {report.broken_at.position}
                  </div>
                  <div>
                    <span className="ledger-pop-label">Event id</span>{" "}
                    {report.broken_at.event_id}
                  </div>
                  <div>
                    <span className="ledger-pop-label">Actor</span>{" "}
                    {report.broken_at.actor_id}
                  </div>
                  <div>
                    <span className="ledger-pop-label">Recorded</span>{" "}
                    {report.broken_at.timestamp}
                  </div>
                </div>
              )}
              <p className="ledger-pop-note">
                Treat findings derived from this log as unverified until the break
                is explained. The {report.verified} entries before it still
                verify cleanly.
              </p>
            </>
          )}

          {state === "unknown" && (
            <p className="ledger-pop-note">
              {failed
                ? `The integrity check could not be reached: ${failed}. This says nothing about the log itself.`
                : "Verifying the chain…"}
            </p>
          )}

          <button className="btn" onClick={verify} disabled={checking}>
            {checking ? "Verifying…" : "Verify again"}
          </button>
        </div>
      )}
    </div>
  );
}
