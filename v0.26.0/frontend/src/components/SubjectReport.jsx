import React from "react";
import { SEVERITY_COLOUR } from "../constants.js";

// What other tools have reported about this subject (v0.26), grouped by the
// tool that reported it -- the view a file, a host or a workspace needs, where
// a timeline of "events" is the wrong shape. Built server-side by subjects.py;
// this only lays it out.

const LEVELS = ["critical", "high", "medium", "low", "info"];

function when(ts) {
  return ts ? ts.replace("T", " ").slice(0, 16) : "—";
}

export default function SubjectReport({ report }) {
  if (!report) return null;
  const { subject, totals, finding_count, unvalidated, open, not_raised, emitters, corroborated } = report;

  return (
    <div className="subject-report">
      <div className="risk-label">Findings report</div>
      <div className="subject-head">
        <span className="subject-kind">{subject.kind}</span>
        <span className="subject-id mono">{subject.label || subject.id}</span>
      </div>
      <div className="subject-summary">
        {finding_count} finding{finding_count === 1 ? "" : "s"} from {emitters.length} tool
        {emitters.length === 1 ? "" : "s"}
        {" · "}{open} open
        {unvalidated ? ` · ${unvalidated} unvalidated` : ""}
        {not_raised ? ` · ${not_raised} not raised` : ""}
      </div>
      <div className="subject-levels">
        {LEVELS.filter((l) => totals[l]).map((l) => (
          <span key={l} className="subject-level" style={{ color: SEVERITY_COLOUR[l], borderColor: SEVERITY_COLOUR[l] }}>
            {totals[l]} {l}
          </span>
        ))}
      </div>

      {corroborated.length > 0 && (
        <div className="subject-corroborated">
          <div className="subject-section-title">Reported by more than one tool</div>
          {corroborated.map((c) => (
            <div key={c.key} className="subject-corr-row">
              <span className="mono" style={{ color: SEVERITY_COLOUR[c.worst] }}>{c.key}</span>
              <span className="subject-tools"> — {c.tools.join(", ")}</span>
            </div>
          ))}
        </div>
      )}

      {emitters.map((em) => (
        <div key={em.tool} className="subject-emitter">
          <div className="subject-emitter-head">
            <span className="src-badge subject-tool">via {em.tool}</span>
            <span className="subject-emitter-meta">
              {em.versions.join(", ")}
              {em.runs.length ? ` · ${em.runs.length} run${em.runs.length === 1 ? "" : "s"}` : ""}
              {" · "}last {when(em.last_reported)}
            </span>
          </div>
          {em.findings.map((f) => (
            <div key={`${f.finding_id}-${f.reported_at}`}
                 className={`subject-finding${f.acknowledged ? " acked" : ""}`}
                 style={{ "--sevcolor": SEVERITY_COLOUR[f.severity] }}>
              <div className="subject-finding-title">
                <span className="subject-sev" style={{ color: SEVERITY_COLOUR[f.severity] }}>
                  {(f.severity || "").toUpperCase()}
                </span>
                {f.title}
                {f.validated === false && <span className="src-badge unvalidated">unvalidated</span>}
                {f.acknowledged && <span className="subject-state">acknowledged</span>}
                {f.assigned_to && <span className="subject-state">→ {f.assigned_to}</span>}
                {!f.raised && <span className="subject-state warn">not raised</span>}
              </div>
              {f.evidence && <div className="subject-evidence">{f.evidence}</div>}
              {(f.mitre || f.recommendation) && (
                <div className="subject-extra">
                  {f.mitre && <span className="mono">{f.mitre}</span>}
                  {f.recommendation && <span> · {f.recommendation}</span>}
                </div>
              )}
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}
