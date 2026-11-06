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

v0.36 keeps two things about them, still never the text itself: a fingerprint
of each tool's description and schema, so a tool that keeps its name but is
quietly rewritten is caught (`tool_definition_changed`, tool poisoning); and
the names of any prompt-injection markers found in them (see injection.py).

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

import injection
import permissions

EVENT_TYPE = "capability_manifest"

MAX_TOOLS = 1000
MAX_NAME_LENGTH = 200
SERVER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
TOP_LEVEL_KEYS = frozenset({"tools", "mcp_servers", "observed_at", "partial"})

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
    # v0.36: tool name -> fingerprint of its description and schema, for tools
    # that have either; and tools whose definitions carry injection markers.
    definitions: tuple[tuple[str, str], ...] = ()
    poisoned: tuple[tuple[str, tuple[str, ...]], ...] = ()
    # v0.37: a partial manifest updates only the MCP servers it names (what a
    # proxy in front of one server can see); `complete` says whether the merged
    # result is known to be the agent's whole tool list.
    partial: bool = False
    complete: bool = True

    @property
    def digest(self) -> str:
        """Identifies the tool set and its definitions, so an unchanged manifest
        is recognised and a rewritten tool is not."""
        parts = list(self.tools) + [f"{n}={fp}" for n, fp in self.definitions]
        return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


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


def _tool_definition(item: Any) -> tuple[str, Any]:
    """(description, schema) for a tool object; ("", None) for a bare name."""
    if not isinstance(item, dict):
        return "", None
    if item.get("type") == "function" and isinstance(item.get("function"), dict):
        fn = item["function"]
        return str(fn.get("description") or ""), fn.get("parameters")
    return (str(item.get("description") or ""),
            item.get("input_schema", item.get("inputSchema")))


def _definition_facts(name: str, item: Any, fingerprints: dict[str, str],
                      poisoned: dict[str, tuple[str, ...]]) -> None:
    description, schema = _tool_definition(item)
    if not description and schema is None:
        return
    canonical = json.dumps({"description": description, "schema": schema},
                           sort_keys=True, default=str)
    fingerprints[name] = hashlib.sha256(canonical.encode()).hexdigest()[:16]
    found = injection.scan(description + "\n" + json.dumps(schema, default=str))
    if found:
        poisoned[name] = tuple(f["marker"] for f in found)


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
    partial = doc.get("partial", False)
    if not isinstance(partial, bool):
        raise ManifestError("must be true or false", "partial")
    if partial and ("tools" in doc or not doc.get("mcp_servers")):
        # A partial manifest replaces named servers' tools and nothing else, so
        # it can only name servers: a bare tool belongs to no server it could
        # replace.
        raise ManifestError("a partial manifest updates named MCP servers only: give "
                            "\"mcp_servers\" and no \"tools\"", "partial")

    names: set[str] = set()
    fingerprints: dict[str, str] = {}
    poisoned: dict[str, tuple[str, ...]] = {}
    for i, item in enumerate(_tool_list(doc.get("tools", []), "tools")):
        name = _tool_name(item, f"tools[{i}]")
        names.add(name)
        _definition_facts(name, item, fingerprints, poisoned)

    servers = doc.get("mcp_servers", {})
    if not isinstance(servers, dict):
        raise ManifestError("must be an object keyed by server name", "mcp_servers")
    for server, listing in servers.items():
        where = f"mcp_servers[{server!r}]"
        if not isinstance(server, str) or not SERVER_NAME.match(server) or "__" in server:
            raise ManifestError("a server name must be 1-64 letters, digits, '.', '-' or "
                                "'_', and may not contain '__' (the namespace separator)", where)
        for i, item in enumerate(_tool_list(listing, where)):
            name = f"mcp__{server}__{_tool_name(item, f'{where}[{i}]')}"
            names.add(name)
            _definition_facts(name, item, fingerprints, poisoned)

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

    return Manifest(tuple(sorted(names)), tuple(sorted(servers)), observed,
                    tuple(sorted(fingerprints.items())), tuple(sorted(poisoned.items())),
                    partial=partial, complete=not partial)


def _server_of(tool: str) -> str | None:
    if tool.startswith("mcp__"):
        parts = tool.split("__")
        if len(parts) >= 3:
            return parts[1]
    return None


def merge(previous: dict[str, Any] | None, update: Manifest) -> Manifest:
    """A partial manifest folded into the agent's previous manifest (v0.37).

    The servers the update names are replaced; every other tool, server and
    definition is carried over. The result is complete only if the previous
    one was: two proxies each reporting their own server still don't add up to
    the agent's whole configuration. A full manifest is returned unchanged.
    """
    if not update.partial:
        return update
    replaced = set(update.servers)
    prev_tools = tools_of(previous) if previous is not None else None
    if prev_tools is None:
        prev_tools = ()
    meta = (previous or {}).get("metadata") or {}
    prev_complete = previous is not None and meta.get("complete", True) is not False
    keep = lambda name: _server_of(name) not in replaced
    tools = {t for t in prev_tools if keep(t)} | set(update.tools)
    servers = {s for s in meta.get("mcp_servers", []) if isinstance(s, str)} | replaced
    definitions = {n: fp for n, fp in definitions_of(previous or {}).items() if keep(n)}
    definitions.update(dict(update.definitions))
    poisoned = {n: tuple(m) for n, m in poisoned_of(previous or {}).items() if keep(n)}
    poisoned.update(dict(update.poisoned))
    return Manifest(tuple(sorted(tools)), tuple(sorted(servers)), update.observed_at,
                    tuple(sorted(definitions.items())), tuple(sorted(poisoned.items())),
                    partial=True, complete=prev_complete)


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
                     "digest": manifest.digest,
                     # v0.36: fingerprints and marker names only, never the text.
                     "definitions": dict(manifest.definitions),
                     "poisoned": {name: list(m) for name, m in manifest.poisoned},
                     # v0.37: false when built only from partial manifests, so
                     # tools outside the servers it names are not "unlisted".
                     "complete": manifest.complete},
    }


def definitions_of(event: dict[str, Any]) -> dict[str, str]:
    """Tool name -> definition fingerprint, from a stored manifest event."""
    defs = (event.get("metadata") or {}).get("definitions")
    return {k: v for k, v in defs.items() if isinstance(k, str) and isinstance(v, str)} \
        if isinstance(defs, dict) else {}


def poisoned_of(event: dict[str, Any]) -> dict[str, list[str]]:
    """Tool name -> injection markers found in its definition."""
    found = (event.get("metadata") or {}).get("poisoned")
    return {k: [str(m) for m in v] for k, v in found.items() if isinstance(v, list)} \
        if isinstance(found, dict) else {}


def is_complete(event: dict[str, Any]) -> bool:
    """Whether a stored manifest is the agent's whole tool list. Manifests from
    before v0.37 were always whole."""
    return (event.get("metadata") or {}).get("complete", True) is not False


def covers(tool: str, servers: tuple[str, ...]) -> bool:
    """Whether a called tool belongs to one of these MCP servers, by its
    namespaced name."""
    server = _server_of(tool.strip())
    return server is not None and server in servers


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
