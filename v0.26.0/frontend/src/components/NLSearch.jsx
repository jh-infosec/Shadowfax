import React, { useState } from "react";
import * as api from "../api.js";

// Natural-language alert search (v0.5.2). The analyst types a plain-English
// request; the backend's assistant translates it into a validated filter and
// returns the matching alerts. This component owns the query box and the
// interpretation banner; the parent renders the returned alerts and clears the
// search. The banner shows exactly how the query was read — and whether a model
// or the offline keyword parser read it — so the translation stays inspectable.

const SOURCE_LABEL = {
  llm: (m) => `interpreted by ${m || "a model"}`,
  deterministic: () => "interpreted by keyword match (no model)",
  deterministic_fallback: () => "interpreted by keyword match (model unavailable)",
};

export default function NLSearch({ result, onResult, onClear }) {
  const [q, setQ] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const run = async (e) => {
    e.preventDefault();
    const query = q.trim();
    if (!query) return;
    setLoading(true);
    setError(null);
    try {
      onResult(await api.nlSearch(query));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const clear = () => {
    setQ("");
    setError(null);
    onClear();
  };

  return (
    <div className="nlsearch">
      <form className="nlsearch-form" onSubmit={run}>
        <span className="nlsearch-spark">✦</span>
        <input
          className="nlsearch-input"
          placeholder="Ask in plain English — e.g. critical destructive actions by AI agents last week"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <button className="btn" type="submit" disabled={loading}>
          {loading ? "Searching…" : "Search"}
        </button>
        {result && (
          <button className="btn" type="button" onClick={clear}>
            Clear
          </button>
        )}
      </form>

      {error && <div className="error-banner">{error}</div>}

      {result && (
        <div className="nlsearch-banner">
          <span className="nlsearch-count">{result.count} match{result.count !== 1 ? "es" : ""}</span>
          <span className="nlsearch-interp">
            read “{result.query}” as <strong>{result.interpretation}</strong>
          </span>
          <span className="nlsearch-source">
            {(SOURCE_LABEL[result.source] || (() => result.source))(result.model)}
          </span>
        </div>
      )}
    </div>
  );
}
