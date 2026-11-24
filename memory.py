"""
Poisoned memory: an injection that comes back in a later session (v0.48).

An injection normally lasts as long as the conversation that read it. Agents
with memory change that. Claude Code loads CLAUDE.md into every session in a
project; Cursor, Copilot, Gemini and others have their own instruction files;
and memory servers and tools keep notes an agent reads back next time. If an
agent that has just read a poisoned page writes what it was told into one of
those, the injection is no longer in a web page it might never read again. It
is in the agent's own instructions, loaded at the start of every session from
then on, by that agent and by any other agent working in the same place. That
is MITRE ATLAS AML.T0080.000, AI Agent Context Poisoning: Memory.

How Shadowfax sees it:

* **The write.** A tool call that writes into a memory location: a file whose
  name or path matches the policy's `memory_files` (CLAUDE.md, AGENTS.md,
  .cursorrules and the rest by default), or a call to a tool matching
  `memory_tools` (memory servers' and memory tools' names). Claude Code's
  Write and Edit, MultiEdit, a filesystem MCP server's write and edit, and a
  shell redirect (`echo ... >> CLAUDE.md`) all count. If what was written
  contains instructions aimed at an AI, or something an injection the agent
  read in the last hour planted (a URL, host, address or path), it raises
  `memory_poisoned`.
* **The load.** The connector's `InstructionsLoaded` hook reports each memory
  file Claude Code loads, with its contents, as a `memory_loaded` event. That
  is content like any tool result: instructions aimed at an AI in it raise
  `prompt_injection`, and the agent then using something planted there raises
  `injection_followed`. Before v0.48 Shadowfax never saw these files at all,
  because Claude Code reads them itself, not through a tool.
* **Remembered.** An agent that poisoned a memory location is held to it: when
  it loads or reads that location again, days later, what it planted there
  counts as planted, even if the instruction was rewritten in plain words that
  no longer look like an injection. Writing the location again clean clears it.

Pure: no I/O.
"""

from __future__ import annotations

import fnmatch
import json
import re
from typing import Any

LOADED = "memory_loaded"
MAX_CONTENT = 50_000

# Files agents load as standing instructions or memory. Bare names match the
# file's name anywhere; patterns with a "/" match the end of the path.
DEFAULT_FILES = [
    "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENT.md", "GEMINI.md", "MEMORY.md",
    ".cursorrules", ".windsurfrules", ".clinerules", "copilot-instructions.md",
    ".claude/rules/*", ".claude/memory/*", ".claude/agents/*", ".claude/commands/*",
    ".claude/skills/*/SKILL.md", ".cursor/rules/*", ".github/instructions/*",
]
# Tools that keep memory: Claude's memory tool, memory MCP servers
# (mcp__memory__create_entities, add_observations), and anything named for it.
DEFAULT_TOOLS = ["memory", "mcp__memory__*", "*_memory", "*memory_*", "remember*", "add_observations"]

# What a write tool puts into the file, by argument name.
_TEXT_KEYS = ("content", "new_string", "new_str", "file_text", "text", "insert_text", "newText", "new_text")
_REDIRECT = re.compile(r"(?:>>?|\btee\s+(?:-a\s+)?)\s*([\"']?)([^\s;|&<>\"']+)\1")


def files(policy: dict[str, Any]) -> list[str]:
    configured = policy.get("memory_files")
    return [str(p) for p in configured] if isinstance(configured, list) else DEFAULT_FILES


def tools(policy: dict[str, Any]) -> list[str]:
    configured = policy.get("memory_tools")
    return [str(p) for p in configured] if isinstance(configured, list) else DEFAULT_TOOLS


def normal(path: str) -> str:
    """A path as compared: forward slashes, lower case, no trailing slash."""
    return str(path or "").strip().strip("\"'").replace("\\", "/").rstrip("/").lower()


def is_memory_file(path: str, policy: dict[str, Any]) -> bool:
    p = normal(path)
    if not p:
        return False
    name = p.rsplit("/", 1)[-1]
    for pattern in files(policy):
        pat = normal(pattern)
        if "/" not in pat:
            if fnmatch.fnmatchcase(name, pat):
                return True
        elif fnmatch.fnmatchcase(p, pat) or fnmatch.fnmatchcase(p, "*/" + pat):
            return True
    return False


def is_memory_tool(tool: str, policy: dict[str, Any]) -> bool:
    t = str(tool or "").lower()
    return bool(t) and any(fnmatch.fnmatchcase(t, p.lower()) for p in tools(policy))


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def writes(event: dict[str, Any], policy: dict[str, Any]) -> list[tuple[str, str, bool]]:
    """The memory locations a tool call writes, as (location, what it wrote,
    whether that replaced the whole thing). Empty for a call that writes no
    memory. Only a whole new file can clear an earlier poisoning: an edit
    elsewhere in the file leaves the planted text where it was."""
    if event.get("event_type") != "tool_call":
        return []
    meta = event.get("metadata") or {}
    tool = str(meta.get("tool") or "")
    args = meta.get("arguments")
    if isinstance(args, str):
        # The connector shortens arguments too long to send, which leaves them
        # as text that no longer parses: keep the text, and take the path from
        # the field it lifted out before shortening.
        try:
            args = json.loads(args)
        except ValueError:
            args = {"content": args}
            if isinstance(meta.get("path"), str):
                args["file_path"] = meta["path"]
    args = args if isinstance(args, dict) else {}

    if is_memory_tool(tool, policy):
        return [(tool, _text(args)[:MAX_CONTENT], False)]

    out: list[tuple[str, str, bool]] = []
    path = next((args[k] for k in ("file_path", "path", "notebook_path") if isinstance(args.get(k), str)), None)
    if path and is_memory_file(path, policy):
        parts = [args[k] for k in _TEXT_KEYS if isinstance(args.get(k), str)]
        for edit in args.get("edits") or []:
            if isinstance(edit, dict):
                parts += [edit[k] for k in _TEXT_KEYS if isinstance(edit.get(k), str)]
        if parts:
            whole = any(isinstance(args.get(k), str) for k in ("content", "file_text")) and not args.get("edits")
            out.append((path, "\n".join(parts)[:MAX_CONTENT], whole))

    command = args.get("command") if isinstance(args.get("command"), str) else meta.get("command")
    if isinstance(command, str):
        for _quote, target in _REDIRECT.findall(command):
            if is_memory_file(target, policy) and not any(normal(target) == normal(p) for p, _, _ in out):
                out.append((target, command[:MAX_CONTENT], False))
    return out


def loaded_location(event: dict[str, Any]) -> str | None:
    """Where content an agent was given came from, when that's a place it could
    have written: a memory file Claude Code loaded, or a file a tool read."""
    meta = event.get("metadata") or {}
    if event.get("event_type") == LOADED:
        return str(meta.get("file_path") or event.get("target") or "") or None
    if event.get("event_type") == "tool_result":
        return str(meta.get("source") or event.get("target") or "") or None
    return None


def is_memory_content(event: dict[str, Any], policy: dict[str, Any]) -> bool:
    """Whether what an agent was given came out of memory: a memory file Claude
    Code loaded, or one a tool read. Scanned with injection.MEMORY_MARKERS."""
    if event.get("event_type") == LOADED:
        return True
    loc = loaded_location(event) if event.get("event_type") == "tool_result" else None
    return bool(loc) and is_memory_file(loc, policy)


def validate(policy: dict[str, Any]) -> list[str]:
    """Problems with the policy's memory settings. Both are optional: left out,
    the defaults above apply; an empty list turns that half off."""
    problems = []
    for key in ("memory_files", "memory_tools"):
        value = policy.get(key)
        if value is None:
            continue
        if not isinstance(value, list) or not all(isinstance(p, str) and p.strip() for p in value):
            problems.append(f"{key} must be a list of names or patterns")
    return problems
