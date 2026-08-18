// Shared constants for severity presentation, used by every component that
// renders an alert.

export const SEVERITIES = ["critical", "high", "medium", "low"];
export const ACTOR_TYPES = ["human", "ai_agent", "service_account"];

export const SEVERITY_COLOUR = {
  critical: "var(--crit)",
  high: "var(--high)",
  medium: "var(--med)",
  low: "var(--low)",
};

export const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
