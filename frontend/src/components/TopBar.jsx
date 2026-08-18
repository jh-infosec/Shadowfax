import React from "react";

export default function TopBar({ stats, connected, onReset }) {
  return (
    <div className="topbar">
      <div className="brand">
        <div className="radar">
          <div className="radar-ring" />
          <div className="radar-sweep" />
          <div className="radar-dot" />
        </div>
        <div>
          <div className="brand-name">SHADOWFAX</div>
          <div className="brand-sub">actor-agnostic intrusion detection</div>
        </div>
      </div>

      <div className="conn-status">
        <span className={`conn-dot ${connected ? "live" : "down"}`} />
        {connected ? "connected to API" : "API unreachable"}
      </div>

      <button className="btn" onClick={onReset}>
        Reset to sample data
      </button>

      <div className="stats">
        <div className="stat crit">CRIT <b>{stats?.alert_counts?.critical ?? 0}</b></div>
        <div className="stat high">HIGH <b>{stats?.alert_counts?.high ?? 0}</b></div>
        <div className="stat med">MED <b>{stats?.alert_counts?.medium ?? 0}</b></div>
        <div className="stat low">LOW <b>{stats?.alert_counts?.low ?? 0}</b></div>
      </div>
    </div>
  );
}
