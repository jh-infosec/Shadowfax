import React, { useEffect, useState } from "react";
import { SEVERITY_COLOUR } from "../constants.js";
import * as api from "../api.js";

// Triage digest (v0.8): the open incidents that most need an analyst, ranked.
//
// The ranking is computed server-side and deterministically — every item shows
// the reasons that produced its position, so the queue can be interrogated
// rather than taken on trust. The assistant writes only the covering narrative
// and cannot re-order anything. Nothing here closes or acts on an incident: an
// item leaves the queue when a human acknowledges its alerts.

const SOURCE_LABEL = {
  llm: "summary written by a model",
  deterministic: "summary generated from the ranking (no model)",
  deterministic_fallback: "summary generated from the ranking (model unavailable)",
};

export default function DigestDrawer({ onClose, onSelectActor }) {
  const [digest, setDigest] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.getDigest().then(setDigest).catch((e) => setError(e.message));
  }, []);

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <div className="drawer digest-drawer">
        <div className="drawer-head">
          <div className="drawer-actor">Triage digest</div>
          <button className="drawer-close" onClick={onClose}>&times;</button>
        </div>
        {error && <div className="error-banner">{error}</div>}
        {digest === null && !error && <div className="empty-state">Loading…</div>}

        {digest && (
          <>
            <div className="digest-sub">
              {digest.open_incidents} open incident
              {digest.open_incidents !== 1 ? "s" : ""} ·{" "}
              {digest.unacknowledged_alerts} unacknowledged alert
              {digest.unacknowledged_alerts !== 1 ? "s" : ""} ·{" "}
              generated {digest.generated_at.replace("T", " ").slice(0, 16)}
            </div>

            {digest.narrative && (
              <div className="digest-narrative">
                <div className="digest-narrative-badge">
                  {SOURCE_LABEL[digest.source] || digest.source}
                </div>
                <div className="digest-narrative-text">{digest.narrative}</div>
              </div>
            )}

            {digest.items.length === 0 ? (
              <div className="empty-state">
                Nothing open — every incident's alerts have been acknowledged.
              </div>
            ) : (
              digest.items.map((item, idx) => (
                <div key={item.incident_id} className="digest-item">
                  <div className="digest-item-head">
                    <span className="digest-rank">{idx + 1}</span>
                    <span
                      className="digest-sev"
                      style={{ color: SEVERITY_COLOUR[item.severity] }}
                    >
                      {item.severity.toUpperCase()}
                    </span>
                    <button
                      className="digest-actor"
                      onClick={() => onSelectActor && onSelectActor(item.actor_id)}
                      title="open this actor's timeline"
                    >
                      {item.actor_id}
                    </button>
                    <span className="digest-unacked">
                      {item.unacknowledged} unacknowledged
                    </span>
                    <span className="digest-priority" title="deterministic priority score">
                      priority {item.priority}
                    </span>
                  </div>

                  {item.chain && item.chain.escalated && (
                    <div className="digest-chain">
                      ⛓ {item.chain.stages.join(" → ")}
                    </div>
                  )}

                  <ul className="digest-reasons">
                    {item.reasons.map((r) => (
                      <li key={r}>{r}</li>
                    ))}
                  </ul>
                </div>
              ))
            )}

            <div className="digest-foot">
              Ranked by severity, completed attack chains, unacknowledged volume
              and age — all computed deterministically. Shadowfax ranks the
              queue; the decisions are yours. An incident leaves this list when
              its alerts are acknowledged.
            </div>
          </>
        )}
      </div>
    </>
  );
}
