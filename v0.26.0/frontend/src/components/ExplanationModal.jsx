import React from "react";
import Explanation from "./Explanation.jsx";
import * as api from "../api.js";
import { SEVERITY_COLOUR } from "../constants.js";

// A small modal that explains a single alert. Opened from the alert table so an
// analyst can ask "what is this?" without leaving the list. Read-only: it only
// calls the explain endpoint.

export default function ExplanationModal({ alert, onClose }) {
  if (!alert) return null;
  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <div className="explain-modal">
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
        <Explanation
          fetcher={() => api.explainAlert(alert.id)}
          label="Explain this alert"
        />
      </div>
    </>
  );
}
