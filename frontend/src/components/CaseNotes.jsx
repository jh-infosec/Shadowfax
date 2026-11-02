import React, { useCallback, useEffect, useState } from "react";
import * as api from "../api.js";

// The case timeline for an alert or an incident (v0.35): notes people wrote and
// the triage changes they made, oldest first. Notes are append-only -- there is
// no edit or delete -- so a correction is simply another note. Everything here
// is rendered as plain text; nothing a note says is ever treated as markup.

const MAX_CHARS = 4000;

function when(ts) {
  return (ts || "").replace("T", " ").slice(0, 16);
}

export default function CaseNotes({ kind, id, canWrite }) {
  const [entries, setEntries] = useState(null);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const load = useCallback(() => {
    api.getNotes(kind, id).then(setEntries).catch((e) => setError(e.message));
  }, [kind, id]);

  useEffect(() => { setEntries(null); load(); }, [load]);

  // A note written by someone else while this is open.
  useEffect(() => {
    const onNote = (e) => {
      if (kind === "incident" || e.detail === `${kind}:${id}`) load();
    };
    window.addEventListener("shadowfax-note", onNote);
    return () => window.removeEventListener("shadowfax-note", onNote);
  }, [kind, id, load]);

  // Escape must not throw away a half-written note: while there is a draft,
  // mark the keypress handled before the dashboard's own Escape handler sees it.
  useEffect(() => {
    if (!draft.trim()) return undefined;
    const hold = (e) => { if (e.key === "Escape") e.preventDefault(); };
    window.addEventListener("keydown", hold, true);
    return () => window.removeEventListener("keydown", hold, true);
  }, [draft]);

  const submit = async () => {
    if (!draft.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.addNote(kind, id, draft);
      setDraft("");
      load();
    } catch (e) {
      setError(typeof e.detail === "string" ? e.detail : e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="case-notes">
      <div className="case-notes-title">Case notes</div>
      {error && <div className="policy-error">{error}</div>}
      {entries === null && <div className="empty-state">Loading…</div>}
      {entries && entries.length === 0 && (
        <div className="case-empty">No notes yet.{canWrite ? " Write down what you checked and what you think." : ""}</div>
      )}
      {entries && entries.length > 0 && (
        <ol className="case-timeline">
          {entries.map((n) => (
            <li key={n.id} className={`case-entry ${n.kind}`}>
              <div className="case-entry-head">
                <span className="case-author">{n.author}</span>
                <span className="case-time">{when(n.at)}</span>
                {n.on && <span className="case-on">on {n.on}</span>}
              </div>
              {n.kind === "note" ? (
                <div className="case-body">{n.body}</div>
              ) : (
                <div className="case-change">{(n.changes || []).join(", ")}</div>
              )}
            </li>
          ))}
        </ol>
      )}
      {canWrite && (
        <div className="case-compose">
          <textarea
            className="case-input"
            placeholder="Add a note. Notes can't be edited or deleted afterwards. Ctrl+Enter to add."
            value={draft}
            maxLength={MAX_CHARS}
            rows={3}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) submit(); }}
          />
          <div className="case-compose-foot">
            <span className="case-count">{draft.length}/{MAX_CHARS}</span>
            <button className="btn primary" disabled={!draft.trim() || busy} onClick={submit}>
              {busy ? "Adding…" : "Add note"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
