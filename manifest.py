"""
Agent capability manifests (v0.18).

v0.16 gave each agent a permission profile: what it is *allowed* to do. An agent
framework already knows something else about it: what it is *able* to do --
the tools in its tool list, the MCP servers it is connected to. Nobody compared
the two. An agent configured with `bash` whose profile never granted `bash` is a
permission violation waiting for its first call, and until v0.18 the only way to
find out was to wait for that call.

A manifest is that tool list, posted to Shadowfax (`POST /agents/{id}/manifest`)
by whatever starts the agent. Shadowfax then reports three things:

* **excess_capability** -- the agent is configured with tools its profile does
  not grant. Raised when the manifest arrives, before any of them is used: high
  if the profile explicitly denies one, medium if it merely never granted it.
  Least privilege says the tool should not be there at all.
* **capability_drift** -- a later manifest adds tools the previous one did not
  have. An agent quietly gaining an MCP server between runs is exactly what a
  supply-chain or configuration attack looks like from the outside. Low on its
  own; anything it adds outside the profile is excess_capability as well.
* **unlisted_tool_call** -- the agent called a tool that is not in its latest
  manifest. Either the manifest is wrong, or the agent got a tool from somewhere
  its configuration does not account for -- an injected server, a tool smuggled
  in at runtime. Medium.

**Accepted shapes**, because there is no single standard and an integration
should not need a converter. A manifest is a JSON object with any of:

    {
      "tools": [
        "read_file",                                           # a bare name
        {"name": "search", "input_schema": {...}},             # Anthropic / MCP
        {"type": "function", "function": {"name": "query"}}    # OpenAI
      ],
      "mcp_servers": {
        "github": {"tools": [{"name": "create_issue", ...}]}   # an MCP tools/list result
      },
      "observed_at": "2026-10-11T09:00:00Z"
    }

MCP tools are namespaced `mcp__<server>__<tool>`, the convention Claude Code
uses, so `mcp__github__create_issue` and a profile pattern `mcp__github__*` line
up. Only names are kept -- descriptions and schemas are dropped, because the
comparison needs nothing else and a schema is where a long injected instruction
would hide.

Validation is strict, as for the findings envelope: an item that is not one of
those shapes rejects the whole manifest, naming the path. Taking the tools we
recognise and dropping the rest would turn "we could not parse this" into "the
agent does not have this", which is the one mistake a capability inventory
cannot make.

A manifest is stored as an event, like a finding, so alerts stay a pure
function of (events, policy): change a profile and every manifest the agent ever
sent is re-judged against it.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import permissions

EVENT_TYPE = "capability_manifest"

MAX_TOOLS = 1000
MAX_NAME_LENGTH = 200
SERVER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
TOP_LEVEL_KEYS = frozenset({"tools", "mcp_servers", "observed_at"})

# How many tool names an alert message spells out before saying "+N more".
SHOWN_IN_MESSAGE = 6


class ManifestError(ValueError):
    def __init__(self, message: str, path: str = ""):
        super().__init__(message)
        self.message = message
        self.path = path

    def describe(self) -> str:
        return f"{self.path}: {self.message}" if self.path else self.message


@dataclass(frozen=True)
class Manifest:
    tools: tuple[str, ...]          # sorted, unique
    servers: tuple[str, ...]        # MCP servers named, sorted
    observed_at: str | None

    @property
    def digest(self) -> str:
        """Identifies the tool set, so an unchanged manifest is recognised."""
        return hashlib.sha256("\n".join(self.tools).encode()).hexdigest()[:16]


# -- parsing ---------------------------------------------------------------------

def _tool_name(item: Any, path: str) -> str:
    if isinstance(item, str):
        name = item
    elif isinstance(item, dict) and item.get("type") == "function" and isinstance(item.get("function"), dict):
        name = item["function"].get("name")
        path = f"{path}.function.name"
    elif isinstance(item, dict) and "name" in item:
        name = item["name"]
        path = f"{path}.name"
    else:
        raise ManifestError("not a tool: expected a name, an object with \"name\", "
                            "or an OpenAI {\"type\": \"function\", \"function\": {...}}", path)
    if not isinstance(name, str) or not name.strip():
        raise ManifestError("a tool name must be a non-empty string", path)
    name = name.strip()
    if len(name) > MAX_NAME_LENGTH:
        raise ManifestError(f"a tool name may be at most {MAX_NAME_LENGTH} characters", path)
    if any(ch.isspace() or ord(ch) < 32 for ch in name):
        raise ManifestError("a tool name may not contain whitespace or control characters", path)
    return name


def _tool_list(value: Any, path: str) -> list[Any]:
    # Accept a tools/list result ({"tools": [...]}) or the bare array.
    if isinstance(value, dict) and set(value) <= {"tools", "nextCursor"} and "tools" in value:
        value, path = value["tools"], f"{path}.tools"
    if not isinstance(value, list):
        raise ManifestError("must be an array of tools", path)
    return value


def parse(doc: Any) -> Manifest:
    """A manifest from any accepted shape, or `ManifestError` naming the path."""
    if not isinstance(doc, dict):
        raise ManifestError("a manifest must be a JSON object")
    unknown = sorted(set(doc) - TOP_LEVEL_KEYS)
    if unknown:
        raise ManifestError(f"unknown key {unknown[0]!r}; expected tools, mcp_servers, observed_at")
    if "tools" not in doc and "mcp_servers" not in doc:
        raise ManifestError("needs \"tools\", \"mcp_servers\", or both (either may be empty)")

    names: set[str] = set()
    for i, item in enumerate(_tool_list(doc.get("tools", []), "tools")):
        names.add(_tool_name(item, f"tools[{i}]"))

    servers = doc.get("mcp_servers", {})
    if not isinstance(servers, dict):
        raise ManifestError("must be an object keyed by server name", "mcp_servers")
    for server, listing in servers.items():
        where = f"mcp_servers[{server!r}]"
        if not isinstance(server, str) or not SERVER_NAME.match(server) or "__" in server:
            raise ManifestError("a server name must be 1-64 letters, digits, '.', '-' or "
                                "'_', and may not contain '__' (the namespace separator)", where)
        for i, item in enumerate(_tool_list(listing, where)):
            names.add(f"mcp__{server}__{_tool_name(item, f'{where}[{i}]')}")

    if len(names) > MAX_TOOLS:
        raise ManifestError(f"{len(names):,} tools; a manifest may list at most {MAX_TOOLS:,}")

    observed = doc.get("observed_at")
    if observed is not None:
        if not isinstance(observed, str):
            raise ManifestError("must be an ISO 8601 timestamp", "observed_at")
        try:
            datetime.fromisoformat(observed.replace("Z", "+00:00"))
        except ValueError:
            raise ManifestError("must be an ISO 8601 timestamp", "observed_at")

    return Manifest(tuple(sorted(names)), tuple(sorted(servers)), observed)


def to_event(manifest: Manifest, actor_id: str, actor_type: str,
             now: datetime | None = None) -> dict[str, Any]:
    """The manifest as an event. Timestamped by `observed_at` if given, so a
    manifest captured at agent start-up sorts before the calls that followed."""
    if manifest.observed_at:
        ts = datetime.fromisoformat(manifest.observed_at.replace("Z", "+00:00"))
        if ts.tzinfo is not None:
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    else:
        ts = (now or datetime.now(timezone.utc)).replace(tzinfo=None)
    return {
        "timestamp": ts.replace(microsecond=0).isoformat(),
        "actor_id": actor_id,
        "actor_type": actor_type,
        "task": None,
        "event_type": EVENT_TYPE,
        # Read on the timeline as "capability_manifest -> 4 configured tools".
        "target": f"{len(manifest.tools)} configured tool{'' if len(manifest.tools) == 1 else 's'}",
        "metadata": {"tools": list(manifest.tools), "mcp_servers": list(manifest.servers),
                     "digest": manifest.digest},
    }


def tools_of(event: dict[str, Any]) -> tuple[str, ...] | None:
    """The tool set a stored manifest event declares, or None if it is malformed.
    Every manifest arrives through `parse()`; this is for reading it back."""
    tools = (event.get("metadata") or {}).get("tools")
    if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
        return None
    return tuple(sorted(set(tools)))


# -- judging -----------------------------------------------------------------------

def tool_status(tool: str, profile: dict[str, Any] | None) -> tuple[str, str | None]:
    """("granted" | "denied" | "not_granted" | "unprofiled", severity or None).

    Uses the permission profile's own evaluation, so a tool is "denied" here
    exactly when calling it would raise a critical permission_violation.
    """
    if profile is None:
        return "unprofiled", None
    breaches = permissions.evaluate({"event_type": "tool_call", "target": "",
                                     "metadata": {"tool": tool}},
                                    profile, check_tool=True, check_target=False)
    if not breaches:
        return "granted", None
    if permissions.worst(breaches) == permissions.SEVERITY_DENIED:
        return "denied", "high"
    return "not_granted", "medium"


def listing(names: list[str]) -> str:
    shown = ", ".join(names[:SHOWN_IN_MESSAGE])
    more = len(names) - SHOWN_IN_MESSAGE
    return shown + (f" (+{more} more)" if more > 0 else "")


def is_listed(tool: str, tools: tuple[str, ...]) -> bool:
    """Whether a called tool is in the manifest. Case-insensitive, and the bare
    name of an MCP tool counts (agents often call `create_issue`, not
    `mcp__github__create_issue`)."""
    t = tool.strip().lower()
    for declared in tools:
        d = declared.lower()
        if t == d or (d.startswith("mcp__") and d.rsplit("__", 1)[-1] == t):
            return True
    return False


def assess(tools: tuple[str, ...], profile: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Each declared tool with its standing under the profile, for the dashboard."""
    out = []
    for tool in tools:
        status, severity = tool_status(tool, profile)
        out.append({"tool": tool, "status": status, "severity": severity})
    return out


def describe(events: list[dict[str, Any]], policy: dict[str, Any]) -> dict[str, Any] | None:
    """The latest manifest of one actor's (time-ordered) events, assessed against
    its profile, plus what changed from the one before. None if it has none."""
    manifests = [e for e in events if e.get("event_type") == EVENT_TYPE and tools_of(e) is not None]
    if not manifests:
        return None
    latest = manifests[-1]
    tools = tools_of(latest)
    previous = tools_of(manifests[-2]) if len(manifests) > 1 else None
    resolution = permissions.resolve(latest["actor_id"], policy)
    return {
        "received_at": latest["timestamp"],
        "count": len(tools),
        "manifests_seen": len(manifests),
        "mcp_servers": (latest.get("metadata") or {}).get("mcp_servers", []),
        "profile": resolution.name,
        "tools": assess(tools, resolution.profile),
        "added": sorted(set(tools) - set(previous)) if previous is not None else [],
        "removed": sorted(set(previous) - set(tools)) if previous is not None else [],
    }
