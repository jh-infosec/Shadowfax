// Shared constants for severity presentation, used by every component that
// renders an alert.

// Five levels, shared across the portfolio by findings-envelope.md. Shadowfax's
// own detectors emit the top four; `info` arrives over the findings envelope.
export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

// `external` covers subjects that are not people, agents or service accounts --
// a file, a host, a log workspace named by an ingested findings envelope.
export const ACTOR_TYPES = ["human", "ai_agent", "service_account", "external"];

export const SEVERITY_COLOUR = {
  critical: "var(--crit)",
  high: "var(--high)",
  medium: "var(--med)",
  low: "var(--low)",
  info: "var(--info)",
};

export const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
