import React from "react";
import { SEVERITY_COLOUR, SEVERITY_ORDER } from "../constants.js";

export default function ActorDrawer({ detail, onClose }) {
  if (!detail) return null;
  const { actor_id, events, alerts, risk } = detail;

  const flaggedByEvent = {};
  alerts.forEach((a) => {
    flaggedByEvent[a.event_id] = flaggedByEvent[a.event_id] || [];
    flaggedByEvent[a.event_id].push(a);
  });

  const total = (risk.critical || 0) + (risk.high || 0) + (risk.medium || 0) + (risk.low || 0) || 1;
  const seg = (n, colour) => (n ? <div className="risk-seg" style={{ width: `${(n / total) * 100}%`, background: colour }} /> : null);

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <div className="drawer">
        <div className="drawer-head">
          <div className="drawer-actor">{actor_id}</div>
          <button className="drawer-close" onClick={onClose}>&times;</button>
        </div>
        <div className="drawer-sub">
          {events[0]?.actor_type} &middot; {events.length} events &middot; risk score {risk.score}
        </div>

        <div className="risk-label">Alert composition</div>
        <div className="risk-bar">
          {seg(risk.critical, SEVERITY_COLOUR.critical)}
          {seg(risk.high, SEVERITY_COLOUR.high)}
          {seg(risk.medium, SEVERITY_COLOUR.medium)}
          {seg(risk.low, SEVERITY_COLOUR.low)}
        </div>
        <div className="risk-note">
          {risk.critical || 0} critical &middot; {risk.high || 0} high &middot; {risk.medium || 0} medium &middot; {risk.low || 0} low
        </div>

        <div className="timeline-title">Full activity timeline</div>
        {events.map((e) => {
          const flags = (flaggedByEvent[e.id] || []).sort(
            (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
          );
          const worst = flags[0];
          return (
            <div
              key={e.id}
              className={`tl-item ${flags.length ? "flagged" : ""}`}
              style={worst ? { "--sevcolor": SEVERITY_COLOUR[worst.severity] } : undefined}
            >
              <div className="tl-time">{e.timestamp.replace("T", " ").slice(0, 16)}</div>
              <div className="tl-event">{e.event_type} &rarr; {e.target}</div>
              {flags.map((f) => (
                <div key={f.id} className="tl-flag" style={{ color: SEVERITY_COLOUR[f.severity] }}>
                  {f.severity.toUpperCase()} &middot; {f.category}: {f.message}
                </div>
              ))}
            </div>
          );
        })}
      </div>
    </>
  );
}
