import React, { useEffect, useState } from "react";
import * as api from "../api.js";

// A first draft of an agent's permission profile (v0.29), from what it has
// done -- not from its manifest; see profile_draft.py for why. Nothing is saved
// here: "Open in policy editor" puts the draft into the policy text, where the
// analyst edits it and saves it like any other policy change.

export default function ProfileDraftModal({ agentId, onClose, onOpenInEditor }) {
  const [draft, setDraft] = useState(null);
  const [key, setKey] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.getProfileDraft(agentId)
      .then((d) => { setDraft(d); setKey(d.existing_profile && d.keys.includes(d.existing_profile)
        ? d.existing_profile : d.keys[0]); })  // the narrower key by default
      .catch((e) => setError(typeof e.detail === "string" ? e.detail : e.message));
  }, [agentId]);

  const flagged = draft?.would_flag || [];
  const bySeverity = flagged.reduce((acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }), {});

  return (
    <div className="policy-modal-overlay" onClick={onClose}>
      <div className="policy-modal draft-modal" onClick={(e) => e.stopPropagation()}>
        <div className="policy-modal-head">
          <div className="policy-modal-title">Draft a profile — {agentId}</div>
          <button className="drawer-close" onClick={onClose}>&times;</button>
        </div>
        <div className="draft-body">
          {error && <div className="policy-error">{error}</div>}
          {!draft && !error && <div className="empty-state">Drafting…</div>}
          {draft && (
            <>
              <p className="draft-lead">
                Built from the <b>{draft.evidence.tool_calls}</b> tool call(s) this agent made,
                not from what it was configured with. Review it before saving.
              </p>
              <div className="draft-used">
                {draft.evidence.used.map((u) => (
                  <span key={u.tool} className={`perm-chip ${u.risky ? "deny" : "allow"}`}
                        title={u.risky ? "denied in the draft: a shell or raw socket" : "granted in the draft"}>
                    {u.tool} ×{u.calls}
                  </span>
                ))}
                {draft.evidence.never_called.map((t) => (
                  <span key={`n-${t}`} className="perm-chip excess" title="configured, never called: not granted">
                    {t} (unused)
                  </span>
                ))}
              </div>
              <ul className="draft-notes">
                {draft.notes.map((n) => <li key={n}>{n}</li>)}
              </ul>
              <div className={`draft-flagged${flagged.length ? " warn" : ""}`}>
                {flagged.length === 0
                  ? "Applied to this agent's history, the draft would have flagged nothing."
                  : `Applied to this agent's history, the draft would have flagged ${flagged.length} event(s): `
                    + Object.entries(bySeverity).map(([s, n]) => `${n} ${s}`).join(", ") + "."}
              </div>
              <div className="draft-keys">
                Save under:
                {draft.keys.map((k) => (
                  <label key={k} className="draft-key">
                    <input type="radio" name="draft-key" checked={key === k} onChange={() => setKey(k)} />
                    <code>{k}</code>
                    {k === draft.existing_profile && <span className="draft-replaces"> replaces the existing profile</span>}
                  </label>
                ))}
              </div>
              <pre className="draft-json">{JSON.stringify({ [key]: draft.profile }, null, 2)}</pre>
            </>
          )}
        </div>
        <div className="policy-modal-foot">
          <button className="btn" onClick={onClose}>Close</button>
          <button className="btn primary" disabled={!draft || !key}
                  onClick={() => onOpenInEditor(key, draft.profile)}>
            Open in policy editor
          </button>
        </div>
      </div>
    </div>
  );
}
