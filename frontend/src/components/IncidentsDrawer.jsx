import React, { useEffect, useState } from "react";
import { SEVERITY_COLOUR } from "../constants.js";
import Explanation from "./Explanation.jsx";
import * as api from "../api.js";

export default function IncidentsDrawer({ onClose }) {
  const [incidents, setIncidents] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    api.getIncidents().then((list) => {
      setIncidents(list);
      if (list.length) setSelectedId(list[0].id);
    }).catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    if (!selectedId) return;
    setDetail(null);
    setCopied(false);
    api.getIncident(selectedId).then(setDetail).catch((e) => setError(e.message));
  }, [selectedId]);

  const copyReport = async () => {
    if (!detail) return;
    try {
      await navigator.clipboard.writeText(detail.report);
      setCopied(true);
    } catch {
      /* clipboard may be unavailable */
    }
  };

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <div className="drawer incidents-drawer">
        <div className="drawer-head">
          <div className="drawer-actor">Incidents</div>
          <button className="drawer-close" onClick={onClose}>&times;</button>
        </div>
        {error && <div className="error-banner">{error}</div>}

        <div className="incidents-layout">
          <div className="incident-list">
            {incidents === null && <div className="empty-state">Loading…</div>}
            {incidents && incidents.length === 0 && (
              <div className="empty-state">No incidents.</div>
            )}
            {incidents && incidents.map((i) => (
              <button
                key={i.id}
                className={`incident-row ${i.id === selectedId ? "active" : ""}`}
                onClick={() => setSelectedId(i.id)}
              >
                <span className="dot" style={{ background: SEVERITY_COLOUR[i.severity] }} />
                <span className="incident-actor">{i.actor_id}</span>
                <span className="incident-meta">
                  {i.alert_count} alert{i.alert_count !== 1 ? "s" : ""} · {i.start.slice(5, 16).replace("T", " ")}
                </span>
              </button>
            ))}
          </div>

          <div className="incident-detail">
            {detail && (
              <>
                <div className="incident-title" style={{ color: SEVERITY_COLOUR[detail.severity] }}>
                  {detail.severity.toUpperCase()} · {detail.actor_id}
                  <span className="actor-type-badge">{detail.actor_type}</span>
                </div>
                <div className="incident-sub">
                  {detail.start.replace("T", " ").slice(0, 16)} → {detail.end.replace("T", " ").slice(0, 16)}
                  {" · "}{detail.duration_minutes} min · risk {detail.risk_score}
                </div>
                <p className="incident-summary">{detail.summary}</p>

                <Explanation
                  key={selectedId}
                  fetcher={() => api.explainIncident(selectedId)}
                  label="Explain this incident"
                />

                {detail.techniques.length > 0 && (
                  <div className="incident-tech">
                    {detail.techniques.map((t) => (
                      <a key={t.id} className="attack-badge" href={t.url} target="_blank"
                         rel="noreferrer" title={`${t.name} (${t.tactic})`}>{t.id}</a>
                    ))}
                  </div>
                )}

                <div className="incident-timeline-title">Timeline</div>
                <table className="incident-timeline">
                  <tbody>
                    {detail.alerts.map((a) => (
                      <tr key={a.id}>
                        <td className="time-cell">{a.timestamp.replace("T", " ").slice(11, 16)}</td>
                        <td style={{ color: SEVERITY_COLOUR[a.severity], fontWeight: 700 }}>{a.severity}</td>
                        <td className="cat-badge">{a.category}</td>
                        <td className="msg-cell">{a.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                <button className="btn" style={{ marginTop: 16 }} onClick={copyReport}>
                  {copied ? "Report copied ✓" : "Copy report (Markdown)"}
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
