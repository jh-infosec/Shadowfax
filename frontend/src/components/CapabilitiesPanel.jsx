import React from "react";

// What the agent is configured with (v0.18), from its latest capability
// manifest, each tool marked against its permission profile. Sits under the
// declared permissions: one says what the agent may do, this says what it can.

const STATUS = {
  granted: { label: "granted", kind: "allow" },
  denied: { label: "denied by profile", kind: "deny" },
  not_granted: { label: "not granted", kind: "excess" },
  unprofiled: { label: "no profile", kind: "plain" },
};

export default function CapabilitiesPanel({ manifest }) {
  if (!manifest) return null;
  const { tools, count, received_at, manifests_seen, added, removed, mcp_servers } = manifest;
  const excess = tools.filter((t) => t.severity);
  const order = { denied: 0, not_granted: 1, unprofiled: 2, granted: 3 };
  const sorted = [...tools].sort((a, b) => order[a.status] - order[b.status] || a.tool.localeCompare(b.tool));

  return (
    <div className="caps-panel">
      <div className="risk-label">Declared capabilities</div>
      <div className="caps-summary">
        {count} tool{count === 1 ? "" : "s"} in the latest manifest
        {mcp_servers?.length ? ` · MCP: ${mcp_servers.join(", ")}` : ""}
        {" · "}received {received_at.replace("T", " ").slice(0, 16)}
        {manifests_seen > 1 ? ` · ${manifests_seen} manifests seen` : ""}
      </div>
      {excess.length > 0 && (
        <div className="caps-warning">
          {excess.length} configured tool{excess.length === 1 ? "" : "s"} outside the
          profile — removable before the agent ever uses {excess.length === 1 ? "it" : "them"}.
        </div>
      )}
      <div className="perm-values caps-tools">
        {sorted.map((t) => (
          <span key={t.tool} className={`perm-chip ${STATUS[t.status].kind}`}
                title={STATUS[t.status].label}>
            {t.tool}
          </span>
        ))}
      </div>
      {(added.length > 0 || removed.length > 0) && (
        <div className="caps-drift">
          since the previous manifest:
          {added.length > 0 && <> added <b>{added.join(", ")}</b></>}
          {added.length > 0 && removed.length > 0 && ";"}
          {removed.length > 0 && <> removed {removed.join(", ")}</>}
        </div>
      )}
    </div>
  );
}
