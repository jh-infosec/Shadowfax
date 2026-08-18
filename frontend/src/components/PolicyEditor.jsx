import React, { useState } from "react";

export default function PolicyEditor({ policy, onSave, onClose }) {
  const [text, setText] = useState(JSON.stringify(policy, null, 2));
  const [error, setError] = useState(null);
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      setError(`Invalid JSON: ${err.message}`);
      return;
    }
    setError(null);
    setSaving(true);
    try {
      await onSave(parsed);
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="policy-modal-overlay" onClick={onClose}>
      <div className="policy-modal" onClick={(e) => e.stopPropagation()}>
        <div className="policy-modal-head">
          <div className="policy-modal-title">Edit policy</div>
          <button className="drawer-close" onClick={onClose}>&times;</button>
        </div>
        <textarea
          className="policy-textarea"
          value={text}
          onChange={(e) => setText(e.target.value)}
          spellCheck={false}
        />
        {error && <div className="policy-error">{error}</div>}
        <div className="policy-modal-foot">
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" onClick={handleSave} disabled={saving}>
            {saving ? "Saving…" : "Save and rescan"}
          </button>
        </div>
      </div>
    </div>
  );
}
