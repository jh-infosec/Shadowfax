import React from "react";
import { SEVERITIES, ACTOR_TYPES, SEVERITY_COLOUR } from "../constants.js";

export default function Sidebar({ filters, onFiltersChange, categories, onOpenPolicy }) {
  const toggle = (group, value) => {
    const set = new Set(filters[group]);
    set.has(value) ? set.delete(value) : set.add(value);
    onFiltersChange({ ...filters, [group]: set });
  };

  const resetFilters = () => {
    onFiltersChange({
      severity: new Set(SEVERITIES),
      actorType: new Set(ACTOR_TYPES),
      search: "",
    });
  };

  return (
    <div className="sidebar">
      <div className="filter-group">
        <div className="filter-title">Severity</div>
        {SEVERITIES.map((s) => (
          <label className="check-row" key={s}>
            <input
              type="checkbox"
              checked={filters.severity.has(s)}
              onChange={() => toggle("severity", s)}
            />
            <span className="dot" style={{ background: SEVERITY_COLOUR[s] }} />
            {s}
          </label>
        ))}
      </div>

      <div className="filter-group">
        <div className="filter-title">Actor type</div>
        {ACTOR_TYPES.map((t) => (
          <label className="check-row" key={t}>
            <input
              type="checkbox"
              checked={filters.actorType.has(t)}
              onChange={() => toggle("actorType", t)}
            />
            {t.replace("_", " ")}
          </label>
        ))}
      </div>

      <div className="filter-group">
        <div className="filter-title">Search</div>
        <input
          className="search"
          type="text"
          placeholder="actor, target, category…"
          value={filters.search}
          onChange={(e) => onFiltersChange({ ...filters, search: e.target.value })}
        />
      </div>

      <div className="filter-group">
        <div className="filter-title">Categories seen</div>
        <div style={{ fontSize: 11, color: "var(--muted-2)", fontFamily: "var(--mono)", lineHeight: 1.7 }}>
          {categories.length ? categories.join(", ") : "none"}
        </div>
      </div>

      <button className="clear-link" onClick={resetFilters}>Reset filters</button>

      <div className="filter-group" style={{ marginTop: 24 }}>
        <button className="btn" style={{ width: "100%" }} onClick={onOpenPolicy}>
          Edit policy
        </button>
      </div>
    </div>
  );
}
