import React, { useEffect, useState } from "react";
import * as api from "../api.js";
import { SEVERITY_COLOUR } from "../constants.js";

// Everything other tools have reported findings about (v0.26): files, hosts,
// workspaces and actors, worst first. Choosing one opens its drawer, which
// leads with the findings report.

export default function SubjectsDrawer({ onClose, onSelectActor }) {
  const [rows, setRows] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.getSubjects().then(setRows).catch((e) => setError(e.message));
  }, []);

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <div className="drawer subjects-drawer">
        <div className="drawer-head">
          <div className="drawer-actor">Subjects</div>
          <button className="drawer-close" onClick={onClose}>&times;</button>
        </div>
        <div className="drawer-sub">What other tools have reported findings about</div>
        {error && <div className="error-banner">{error}</div>}
        {rows === null && !error && <div className="empty-state">Loading…</div>}
        {rows && rows.length === 0 && (
          <div className="empty-state">
            No findings have been ingested yet. Tools report them through
            POST /findings (see findings-envelope.md).
          </div>
        )}
        {rows && rows.length > 0 && (
          <table className="lockout-table subjects-table">
            <thead>
              <tr><th>Subject</th><th>Worst</th><th>Findings</th><th>Tools</th><th>Last</th></tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.actor_id} className="subject-row" onClick={() => onSelectActor(r.actor_id)}>
                  <td>
                    <span className="subject-kind">{r.subject.kind}</span>{" "}
                    <span className="mono">{r.subject.label || r.subject.id}</span>
                  </td>
                  <td className="mono" style={{ color: SEVERITY_COLOUR[r.worst] }}>{r.worst}</td>
                  <td className="mono">
                    {r.finding_count}{r.open ? ` (${r.open} open)` : ""}
                  </td>
                  <td>
                    {r.tools.join(", ")}
                    {r.corroborated ? <span className="subject-state"> {r.corroborated} agreed</span> : null}
                  </td>
                  <td className="mono">{r.last_reported.replace("T", " ").slice(0, 16)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
