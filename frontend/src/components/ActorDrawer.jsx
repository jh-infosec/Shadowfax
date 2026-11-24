import React from "react";
import { SEVERITY_COLOUR, SEVERITY_ORDER } from "../constants.js";
import PermissionsPanel from "./PermissionsPanel.jsx";
import CapabilitiesPanel from "./CapabilitiesPanel.jsx";
import SubjectReport from "./SubjectReport.jsx";

export default function ActorDrawer({ detail, onClose, onDraftProfile, onSelectActor }) {
  if (!detail) return null;
  const { actor_id, events, alerts, risk, permissions, manifest, subject_report } = detail;

  const flaggedByEvent = {};
  alerts.forEach((a) => {
    flaggedByEvent[a.event_id] = flaggedByEvent[a.event_id] || [];
    flaggedByEvent[a.event_id].push(a);
  });

  const total = (risk.critical || 0) + (risk.high || 0) + (risk.medium || 0) + (risk.low || 0) + (risk.info || 0) || 1;
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
          {seg(risk.info, SEVERITY_COLOUR.info)}
        </div>
        <div className="risk-note">
          {risk.critical || 0} critical &middot; {risk.high || 0} high &middot; {risk.medium || 0} medium &middot; {risk.low || 0} low &middot; {risk.info || 0} info
        </div>

        <PermissionsPanel permissions={permissions} actorType={events[0]?.actor_type} />
        {onDraftProfile && events[0]?.actor_type === "ai_agent" && (
          <button className="btn draft-btn" onClick={() => onDraftProfile(actor_id)}>
            Draft a profile from what it did
          </button>
        )}
        <CapabilitiesPanel manifest={manifest} />
        <SubjectReport report={subject_report} />

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
              {/* v0.46: hand-offs link to the other agent, and a received
                  hand-off that carries an injection says so. */}
              {e.event_type === "agent_handoff" || e.event_type === "handoff_received" ? (
                <div className="tl-event tl-handoff">
                  {e.event_type === "agent_handoff" ? "handed work to " : "work handed over by "}
                  {onSelectActor ? (
                    <button className="link-btn tl-agent-link" onClick={() => onSelectActor(e.target)}>
                      {e.target}
                    </button>
                  ) : e.target}
                  {e.metadata?.taint && (
                    <span className="taint-badge"
                          title={`carries what an injection planted in ${e.metadata.taint.source}`}>
                      tainted
                    </span>
                  )}
                  {e.metadata?.message && <div className="tl-handoff-msg">{e.metadata.message}</div>}
                </div>
              ) : (
                <div className="tl-event">{e.event_type} &rarr; {e.target}</div>
              )}
              {flags.map((f) => (
                <div key={f.id} className={`tl-flag${f.suppressed_by ? " muted" : ""}`}
                     style={{ color: SEVERITY_COLOUR[f.severity] }}>
                  {/* v0.42: muted alerts stay on the timeline, marked. */}
                  {f.suppressed_by ? <span className="muted-badge">muted · rule {f.suppressed_by}</span> : null}
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
