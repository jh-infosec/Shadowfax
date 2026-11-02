import React from "react";
import CaseNotes from "./CaseNotes.jsx";
import { SEVERITY_COLOUR } from "../constants.js";

// One alert's case notes, opened from the alert table (v0.35).
export default function NotesModal({ alert, canWrite, onClose }) {
  if (!alert) return null;
  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <div className="explain-modal notes-modal">
        <div className="drawer-head">
          <div className="drawer-actor" style={{ color: SEVERITY_COLOUR[alert.severity] }}>
            {alert.severity.toUpperCase()} · {alert.category}
          </div>
          <button className="drawer-close" onClick={onClose}>&times;</button>
        </div>
        <div className="explain-modal-sub">
          {alert.actor_id} · {alert.target} · {alert.timestamp.replace("T", " ").slice(0, 16)}
        </div>
        <p className="explain-modal-msg">{alert.message}</p>
        <CaseNotes kind="alert" id={alert.id} canWrite={canWrite} />
      </div>
    </>
  );
}
