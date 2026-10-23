import React, { useState } from "react";

// Shared "explain this finding" panel, used for both incidents and single
// alerts. It takes a `fetcher` that returns the assistant's reply
// ({ narrative, source, model }) and renders a generate button, a loading
// state, and the narrative with an honest badge saying whether a model wrote
// it or it was generated deterministically.
//
// The assistant explains; it never decides. The copy here reflects that: it is
// an explanation for an analyst, not a verdict or an instruction.

const SOURCE_LABEL = {
  llm: (model) => `Written by ${model || "a language model"}`,
  deterministic: () => "Generated from alert data (no model configured)",
  deterministic_fallback: () => "Generated from alert data (model unavailable)",
};

export default function Explanation({ fetcher, label = "Explain this finding" }) {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const run = async () => {
    setLoading(true);
    setError(null);
    try {
      setResult(await fetcher());
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="explanation">
      {!result && (
        <button className="btn explain-btn" onClick={run} disabled={loading}>
          {loading ? "Thinking…" : `✦ ${label}`}
        </button>
      )}
      {error && <div className="error-banner">{error}</div>}
      {result && (
        <div className="explanation-body">
          <div className="explanation-head">
            <span className="explanation-badge">
              {(SOURCE_LABEL[result.source] || (() => result.source))(result.model)}
            </span>
            <button className="explain-regenerate" onClick={run} disabled={loading}>
              {loading ? "…" : "↻ regenerate"}
            </button>
          </div>
          <div className="explanation-text">{result.narrative}</div>
          <div className="explanation-foot">
            The assistant explains findings for an analyst. It never creates,
            closes or acts on an alert — you decide what to do.
          </div>
        </div>
      )}
    </div>
  );
}
