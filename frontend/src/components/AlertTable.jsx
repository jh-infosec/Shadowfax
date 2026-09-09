import React, { useMemo, useState } from "react";
import { SEVERITY_COLOUR, SEVERITY_ORDER } from "../constants.js";

export default function AlertTable({ alerts, onSelectActor, onAcknowledge, onAssign, onExplain, canAct }) {
  const [sortKey, setSortKey] = useState("timestamp");
  const [sortDir, setSortDir] = useState("desc");

  const sorted = useMemo(() => {
    const copy = [...alerts];
    copy.sort((a, b) => {
      let cmp = 0;
      if (sortKey === "severity") cmp = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
      else if (sortKey === "actor_id") cmp = a.actor_id.localeCompare(b.actor_id);
      else if (sortKey === "category") cmp = a.category.localeCompare(b.category);
      else cmp = new Date(a.timestamp) - new Date(b.timestamp);
      return sortDir === "asc" ? cmp : -cmp;
    });
    return copy;
  }, [alerts, sortKey, sortDir]);

  const handleSort = (key) => {
    if (sortKey === key) setSortDir(sortDir === "asc" ? "desc" : "asc");
    else { setSortKey(key); setSortDir("asc"); }
  };

  if (!sorted.length) {
    return <div className="empty-state">No alerts match the current filters.</div>;
  }

  return (
    <table className="alert-table">
      <thead>
        <tr>
          <th onClick={() => handleSort("severity")}>Severity</th>
          <th onClick={() => handleSort("category")}>Category</th>
          <th onClick={() => handleSort("actor_id")}>Actor</th>
          <th onClick={() => handleSort("timestamp")}>Time</th>
          <th>Target</th>
          <th>Detail</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {sorted.map((a) => (
          <tr
            key={a.id}
            className={a.acknowledged ? "acknowledged" : undefined}
            onClick={() => onSelectActor(a.actor_id)}
          >
            <td>
              <div className="sev-cell" style={{ color: SEVERITY_COLOUR[a.severity] }}>
                <span className="dot" style={{ background: SEVERITY_COLOUR[a.severity] }} />
                {a.severity}
              </div>
            </td>
            <td className="cat-badge">{a.category}</td>
            <td className="actor-cell">
              {a.actor_id}
              <span className="actor-type-badge">{a.actor_type}</span>
            </td>
            <td className="time-cell">{a.timestamp.replace("T", " ").slice(0, 16)}</td>
            <td className="target-cell">{a.target}</td>
            <td className="msg-cell">
              <button
                className="explain-link"
                title="Explain this alert"
                onClick={(e) => { e.stopPropagation(); onExplain(a); }}
              >
                ✦ explain
              </button>
              {a.message}
              {a.attack && a.attack.length > 0 && (
                <span className="attack-badges">
                  {a.attack.map((t) => (
                    <a
                      key={t.id}
                      className="attack-badge"
                      href={t.url}
                      target="_blank"
                      rel="noreferrer"
                      title={`${t.id} · ${t.name} (${t.tactic})`}
                      onClick={(e) => e.stopPropagation()}
                    >
                      {t.id}
                    </a>
                  ))}
                </span>
              )}
            </td>
            {/* Analyst state. stopPropagation keeps these clicks from opening
                the actor drawer that the row click triggers. Viewers see the
                same state read-only, without the action buttons. */}
            <td className="status-cell" onClick={(e) => e.stopPropagation()}>
              {a.acknowledged ? (
                canAct ? (
                  <button
                    className="ack-badge"
                    title={a.acknowledged_by ? `acknowledged by ${a.acknowledged_by} — click to undo` : "click to undo"}
                    onClick={() => onAcknowledge(a.id, false)}
                  >
                    ✓ ack{a.acknowledged_by ? ` · ${a.acknowledged_by}` : ""}
                  </button>
                ) : (
                  <span className="ack-badge static" title={a.acknowledged_by ? `acknowledged by ${a.acknowledged_by}` : "acknowledged"}>
                    ✓ ack{a.acknowledged_by ? ` · ${a.acknowledged_by}` : ""}
                  </span>
                )
              ) : (
                canAct && (
                  <button className="ack-btn" onClick={() => onAcknowledge(a.id, true)}>
                    Ack
                  </button>
                )
              )}
              {a.assigned_to ? (
                <span className="assigned-tag" title={`assigned to ${a.assigned_to}`}>
                  @{a.assigned_to}
                </span>
              ) : (
                canAct && (
                  <button className="assign-btn" onClick={() => onAssign(a.id)}>
                    Assign
                  </button>
                )
              )}
              {!canAct && !a.acknowledged && !a.assigned_to && (
                <span className="status-none">—</span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
