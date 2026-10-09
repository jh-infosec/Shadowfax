import React from "react";

// The permission profile that governs an actor (v0.16), shown beside what the
// actor actually did. An alert that says "outside declared permissions" is only
// half an answer until you can see what was declared.

const ROWS = [
  ["allowed_tools", "Allowed tools"],
  ["denied_tools", "Denied tools"],
  ["allowed_targets", "Allowed targets"],
  ["denied_targets", "Denied targets"],
];

function Grant({ label, values, kind }) {
  // A missing grant and an empty one mean different things, so they read
  // differently: "not restricted" versus "none granted".
  let body;
  if (values == null) {
    body = <span className="perm-open">not restricted</span>;
  } else if (values.length === 0) {
    body = <span className="perm-none">none granted</span>;
  } else {
    body = values.map((v) => (
      <span key={v} className={`perm-chip ${kind}`}>{v}</span>
    ));
  }
  return (
    <div className="perm-row">
      <div className="perm-key">{label}</div>
      <div className="perm-values">{body}</div>
    </div>
  );
}

export default function PermissionsPanel({ permissions, actorType }) {
  if (!permissions) return null;
  const { enabled, profile, matched_by, description, grants, unprofiled_agents } = permissions;

  let content;
  if (!enabled) {
    content = <div className="perm-note">Permission profiles are switched off in the policy.</div>;
  } else if (!profile) {
    const flagged = actorType === "ai_agent" && unprofiled_agents === "alert";
    content = (
      <div className={`perm-note ${flagged ? "perm-undeclared" : ""}`}>
        No permission profile is declared for this actor
        {flagged ? " — as an AI agent, that is itself flagged." : "."}
      </div>
    );
  } else {
    content = (
      <>
        <div className="perm-profile">
          <code>{profile}</code>
          <span className="perm-match">
            {matched_by === "exact" ? "declared for this actor" : "matched by pattern"}
          </span>
        </div>
        {description && <div className="perm-desc">{description}</div>}
        {ROWS.map(([key, label]) => (
          <Grant key={key} label={label} values={grants?.[key]}
                 kind={key.startsWith("denied") ? "deny" : "allow"} />
        ))}
      </>
    );
  }

  return (
    <div className="perm-panel">
      <div className="risk-label">Declared permissions</div>
      {content}
    </div>
  );
}
