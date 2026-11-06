"""
Connect real AI agents to Shadowfax (v0.37).

Until v0.37 an agent's activity reached Shadowfax only if somebody wrote code
to post it. This file is that code, written once, so the agent you already run
reports what it does without being changed:

* **Claude Code** (and anything built on the Claude Agent SDK) through hooks.
  Every tool the agent uses is reported as a `tool_call`, and what the tool gave
  back as a `tool_result`, so prompt injection in a fetched page or a read file
  is caught (see injection.py).
* **Any MCP client** through a small proxy that sits between the client and an
  MCP server. It reports the server's tool list as a manifest (so a tool that is
  quietly rewritten raises `tool_definition_changed`), every call, and every
  result. Claude Desktop, Cursor and the rest all speak MCP.
* **Your own Python agent** through `Reporter`, with a decorator for tools.

One file, standard library only, Python 3.9 or newer, so it can be copied onto
whatever machine runs the agent. Quick start:

    python shadowfax_agent.py configure --url http://shadowfax:8000 --api-key sk_shadowfax_...
    python shadowfax_agent.py claude-code --write ~/.claude/settings.json
    python shadowfax_agent.py mcp-proxy --server github -- npx -y @modelcontextprotocol/server-github

Three rules hold everywhere:

* **It never gets in the agent's way.** Shadowfax watches; it doesn't block. A
  hook always exits 0 and prints nothing; the proxy forwards every byte
  unchanged before it looks at it. If Shadowfax is down, events wait in a local
  spool and go when it is back.
* **The API key stays out of the agent's environment.** It is read from
  ~/.shadowfax/agent.json (or SHADOWFAX_API_KEY), never put into the settings
  the agent's own shell inherits.
* **It sends what the tools did, not what the model thought.** Prompts and the
  model's replies are not reported.
"""

from __future__ import annotations

import argparse
import functools
import inspect
import json
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

VERSION = "0.38.0"
DEFAULT_URL = "http://127.0.0.1:8000"
ACTOR_TYPE = "ai_agent"

# Shadowfax's own limits (limits.py), with room to spare.
MAX_TARGET = 2048
METADATA_BUDGET = 15_000      # the server's default cap is 16 KiB
BATCH_SIZE = 100
# The spool holds events while Shadowfax can't be reached. Bounded, so an agent
# left running against a dead server doesn't fill the disk.
SPOOL_MAX_BYTES = 20_000_000
FLUSH_PER_HOOK = 500          # spooled events one hook run will try to send

# What to name a call by, in order, when a tool's input has several fields.
TARGET_KEYS = ("url", "uri", "file_path", "notebook_path", "path", "command",
               "query", "pattern", "prompt", "description")
# Fields of a tool's response that are never content (binary payloads).
SKIP_KEYS = frozenset({"data", "base64", "blob", "signature", "image"})
_URL = re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>`)\]}|;]+", re.I)
_SERVER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


# -- configuration -------------------------------------------------------------

def config_path() -> Path:
    return Path(os.environ.get("SHADOWFAX_AGENT_CONFIG") or
                Path.home() / ".shadowfax" / "agent.json")


def default_agent_id() -> str:
    """ai-agent-<this computer's name>. The same default for the hook, the proxy
    and the library, so everything one machine's agent does lands on one actor."""
    host = re.sub(r"[^a-z0-9.-]+", "-", socket.gethostname().lower()).strip("-.") or "host"
    return f"ai-agent-{host}"


class Config:
    """Where Shadowfax is and who this agent is. Environment variables win over
    the config file, so one machine can run several agents under different ids."""

    def __init__(self, url: str = DEFAULT_URL, api_key: str | None = None,
                 agent_id: str | None = None, task: str | None = None,
                 timeout: float = 3.0, spool_dir: str | Path | None = None):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.agent_id = agent_id or default_agent_id()
        self.task = task or None
        self.timeout = timeout
        self.spool_dir = Path(spool_dir) if spool_dir else Path.home() / ".shadowfax" / "spool"

    @classmethod
    def load(cls) -> "Config":
        stored: dict[str, Any] = {}
        try:
            stored = json.loads(config_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        env = os.environ.get
        key = env("SHADOWFAX_API_KEY") or stored.get("api_key")
        key_file = env("SHADOWFAX_API_KEY_FILE")
        if key_file:
            try:
                key = Path(key_file).read_text(encoding="utf-8").strip()
            except OSError:
                pass
        try:
            timeout = float(env("SHADOWFAX_TIMEOUT") or stored.get("timeout") or 3.0)
        except ValueError:
            timeout = 3.0
        return cls(url=env("SHADOWFAX_URL") or stored.get("url") or DEFAULT_URL,
                   api_key=key,
                   agent_id=env("SHADOWFAX_AGENT_ID") or stored.get("agent_id"),
                   task=env("SHADOWFAX_TASK") or stored.get("task"),
                   timeout=timeout,
                   spool_dir=env("SHADOWFAX_SPOOL_DIR") or stored.get("spool_dir"))


def check_agent_id(agent_id: str) -> str | None:
    """Why an agent id would be refused, or None."""
    if not agent_id or len(agent_id) > 256:
        return "an agent id must be 1-256 characters"
    if agent_id.lower().startswith("shadowfax-"):
        return "ids starting with 'shadowfax-' are Shadowfax's own accounts"
    return None


# -- talking to Shadowfax --------------------------------------------------------

class HttpTransport:
    """POSTs JSON with the API key. Returns (status, body); status 0 means the
    server could not be reached at all."""

    def __init__(self, config: Config):
        self.config = config

    def post(self, path: str, body: Any) -> tuple[int, Any]:
        return self.request("POST", path, body)

    def request(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        headers = {"User-Agent": f"shadowfax-agent/{VERSION}", "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body, default=str).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.config.api_key:
            headers["X-API-Key"] = self.config.api_key
        req = urllib.request.Request(self.config.url + path, data=data, headers=headers,
                                     method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                raw = resp.read()
                return resp.status, _json_or_none(raw)
        except urllib.error.HTTPError as err:
            return err.code, _json_or_none(err.read())
        except (urllib.error.URLError, OSError, ValueError):
            return 0, None


def _json_or_none(raw: bytes) -> Any:
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return None


def _retryable(status: int) -> bool:
    # Unreachable, rate-limited, a server error, or a key that may yet be fixed:
    # keep the events. Anything else is a request the server will never accept.
    return status == 0 or status in (401, 403, 408, 429) or status >= 500


# -- the spool ---------------------------------------------------------------------

class Spool:
    """Events waiting for Shadowfax, one JSON line each.

    Several hooks can run at once (an agent calls tools in parallel), so a run
    that wants to send the spool first renames it to a file of its own: only one
    rename can win, and nothing is sent twice.
    """

    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.file = self.dir / "pending.jsonl"

    def add(self, items: Iterable[tuple[str, Any]]) -> None:
        lines = [json.dumps({"path": p, "body": b}, default=str) for p, b in items]
        if not lines:
            return
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self.dir, 0o700)
            except OSError:
                pass
            with open(self.file, "a", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            if self.file.stat().st_size > SPOOL_MAX_BYTES:
                self._trim()
        except OSError:
            pass

    def _trim(self) -> None:
        # Keep the newest half: the oldest events are the least likely to matter
        # by the time the server is back, and the count of what was dropped is
        # written down so the gap is visible.
        try:
            lines = self.file.read_text(encoding="utf-8").splitlines()
            keep = lines[len(lines) // 2:]
            self.file.write_text("\n".join(keep) + "\n", encoding="utf-8")
            self.note(f"spool over {SPOOL_MAX_BYTES:,} bytes; dropped the oldest "
                      f"{len(lines) - len(keep):,} events")
        except OSError:
            pass

    def take(self) -> list[tuple[str, Any]]:
        claimed = []
        try:
            mine = self.dir / f"sending-{os.getpid()}-{time.time_ns()}.jsonl"
            os.replace(self.file, mine)
            claimed.append(mine)
        except OSError:
            pass
        # A run that crashed mid-send leaves its claim behind; pick those up
        # once they are clearly abandoned.
        try:
            for stale in self.dir.glob("sending-*.jsonl"):
                if stale not in claimed and time.time() - stale.stat().st_mtime > 300:
                    mine = self.dir / f"sending-{os.getpid()}-{time.time_ns()}.jsonl"
                    os.replace(stale, mine)
                    claimed.append(mine)
        except OSError:
            pass
        items: list[tuple[str, Any]] = []
        for path in claimed:
            try:
                for line in path.read_text(encoding="utf-8").splitlines():
                    try:
                        rec = json.loads(line)
                        items.append((rec["path"], rec["body"]))
                    except (ValueError, KeyError, TypeError):
                        continue
                path.unlink()
            except OSError:
                pass
        return items

    def note(self, message: str) -> None:
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            with open(self.dir / "errors.log", "a", encoding="utf-8") as f:
                f.write(f"{now_iso()} {message}\n")
        except OSError:
            pass


# -- events ----------------------------------------------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _plain(value: Any) -> Any:
    """`value` as plain JSON data; anything else becomes its string form."""
    try:
        return json.loads(json.dumps(value, default=str))
    except (TypeError, ValueError):
        return str(value)


def text_of(value: Any, _depth: int = 0) -> str:
    """The readable text in a tool's response, whatever shape it came in: a
    string, Claude Code's per-tool objects, or MCP content blocks."""
    if _depth > 12 or value is None or isinstance(value, bool):
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return ""
    if isinstance(value, (list, tuple)):
        return "\n".join(t for t in (text_of(v, _depth + 1) for v in value) if t)
    if isinstance(value, dict):
        kind = value.get("type")
        if kind in ("image", "audio") and "text" not in value:
            return f"[{kind}]"
        parts = []
        for k, v in value.items():
            if k in SKIP_KEYS or k == "type":
                continue
            t = text_of(v, _depth + 1)
            if t:
                parts.append(t)
        return "\n".join(parts)
    return str(value)


def shorten(text: str, limit: int) -> str:
    """`text` cut to about `limit` characters, keeping its start and its end
    (an instruction hidden at the bottom of a page is still seen) and saying how
    much went."""
    if len(text) <= limit:
        return text
    limit = max(limit, 120)
    head = int(limit * 0.7)
    tail = limit - head
    cut = len(text) - head - tail
    return f"{text[:head]}\n[... {cut:,} characters cut by shadowfax_agent ...]\n{text[-tail:]}"


def _size(meta: dict[str, Any]) -> int:
    # Measured the way the server measures it (limits.metadata_size).
    return len(json.dumps(meta, separators=(",", ":"), default=str).encode())


def fit(meta: dict[str, Any], budget: int = METADATA_BUDGET) -> dict[str, Any]:
    """Metadata trimmed to fit Shadowfax's size limit, longest field first, so
    an event is shortened rather than refused."""
    for _ in range(30):
        size = _size(meta)
        if size <= budget:
            return meta
        candidates = [(len(json.dumps(meta[k], default=str)), k)
                      for k in ("output", "arguments", "error", "command", "source")
                      if k in meta and meta[k]]
        if not candidates:
            break
        length, key = max(candidates)
        value = meta[key] if isinstance(meta[key], str) else json.dumps(meta[key], default=str)
        meta[key] = shorten(value, max(120, int(len(value) * budget / size * 0.85)))
        meta["truncated"] = True
    return meta


def target_for(tool: str, args: Any) -> str:
    """What a call was aimed at: the URL, file, command or query it was given."""
    if isinstance(args, str) and args.strip():
        return args[:MAX_TARGET]
    if isinstance(args, dict):
        for key in TARGET_KEYS:
            value = args.get(key)
            if isinstance(value, str) and value.strip():
                return value[:MAX_TARGET]
        for value in args.values():
            if isinstance(value, str) and value.strip():
                return value[:MAX_TARGET]
    return tool[:MAX_TARGET]


def call_details(args: Any) -> dict[str, Any]:
    """Fields Shadowfax's detectors look for by name (url, path, command), lifted
    out of a tool's input. A URL inside a shell command counts, so `curl` to a
    host outside the engagement scope is checked like a web fetch."""
    out: dict[str, Any] = {}
    if not isinstance(args, dict):
        return out
    for key in ("url", "uri"):
        if isinstance(args.get(key), str):
            out["url"] = args[key]
            break
    for key in ("file_path", "notebook_path", "path"):
        if isinstance(args.get(key), str):
            out["path"] = args[key]
            break
    if isinstance(args.get("command"), str):
        out["command"] = args["command"]
        if "url" not in out:
            m = _URL.search(args["command"])
            if m:
                out["url"] = m.group(0).rstrip(".,;:!?")
    return out


def make_event(agent_id: str, event_type: str, target: str, metadata: dict[str, Any],
               task: str | None = None, timestamp: str | None = None) -> dict[str, Any]:
    return {"timestamp": timestamp or now_iso(), "actor_id": agent_id,
            "actor_type": ACTOR_TYPE, "task": task, "event_type": event_type,
            "target": (target or "")[:MAX_TARGET], "metadata": fit(metadata)}


def call_event(agent_id: str, tool: str, args: Any, *, task: str | None = None,
               extra: dict[str, Any] | None = None, timestamp: str | None = None) -> dict[str, Any]:
    meta = {"tool": tool, "arguments": _plain(args) if args is not None else {}}
    meta.update(call_details(args))
    meta.update(extra or {})
    meta["reported_by"] = f"shadowfax_agent/{VERSION}"
    return make_event(agent_id, "tool_call", target_for(tool, args), meta, task, timestamp)


def result_event(agent_id: str, tool: str, args: Any, output: Any, *,
                 task: str | None = None, extra: dict[str, Any] | None = None,
                 timestamp: str | None = None) -> dict[str, Any]:
    details = call_details(args)
    target = target_for(tool, args)
    meta = {"tool": tool, "source": details.get("url") or details.get("path") or target,
            "output": text_of(output)}
    meta.update(extra or {})
    meta["reported_by"] = f"shadowfax_agent/{VERSION}"
    return make_event(agent_id, "tool_result", target, meta, task, timestamp)


# -- the reporter ------------------------------------------------------------------

class Reporter:
    """Sends events to Shadowfax, never raising into the agent.

    With `background=True` (the default for libraries and the proxy) events are
    queued and sent in batches from a thread, so a tool call never waits on the
    network. With `background=False` (the Claude Code hook, which runs once per
    tool call) each `flush()` sends straight away.

        sfx = Reporter("research-agent-1")

        @sfx.tool
        def fetch(url: str) -> str:
            ...

    Whatever can't be delivered goes to the spool and is sent next time.
    """

    def __init__(self, agent_id: str | None = None, *, config: Config | None = None,
                 transport: Any = None, background: bool = True, task: str | None = None,
                 spool: Spool | None = None):
        self.config = config or Config.load()
        if agent_id:
            self.config.agent_id = agent_id
        if task:
            self.config.task = task
        problem = check_agent_id(self.config.agent_id)
        if problem:
            raise ValueError(problem)
        self.transport = transport or HttpTransport(self.config)
        self.spool = spool or Spool(self.config.spool_dir)
        self.sent = 0
        self.dropped = 0
        self._pending: list[tuple[str, Any]] = []
        self._lock = threading.Lock()
        self._queue: "queue.Queue[tuple[str, Any] | None]" | None = None
        self._thread: threading.Thread | None = None
        if background:
            self._queue = queue.Queue()
            self._thread = threading.Thread(target=self._run, name="shadowfax-reporter",
                                            daemon=True)
            self._thread.start()

    @property
    def agent_id(self) -> str:
        return self.config.agent_id

    # what agents call

    def send(self, event: dict[str, Any]) -> None:
        self._enqueue(("/events", event))

    def tool_call(self, tool: str, arguments: Any = None, **extra: Any) -> dict[str, Any]:
        event = call_event(self.agent_id, tool, arguments, task=self.config.task, extra=extra)
        self.send(event)
        return event

    def tool_result(self, tool: str, output: Any, arguments: Any = None,
                    **extra: Any) -> dict[str, Any]:
        event = result_event(self.agent_id, tool, arguments, output, task=self.config.task,
                             extra=extra)
        self.send(event)
        return event

    def manifest(self, tools: list[Any] | None = None,
                 mcp_servers: dict[str, Any] | None = None, *, partial: bool = False) -> None:
        """The tools the agent is configured with. `partial=True` updates only
        the named MCP servers and leaves the rest of the agent's list alone."""
        doc: dict[str, Any] = {"observed_at": now_iso()}
        if tools is not None:
            doc["tools"] = tools
        if mcp_servers is not None:
            doc["mcp_servers"] = mcp_servers
        if partial:
            doc["partial"] = True
        self._enqueue((f"/agents/{urllib.parse.quote(self.agent_id, safe='')}/manifest", doc))

    def tool(self, fn: Callable | None = None, *, name: str | None = None,
             results: bool = True) -> Callable:
        """Decorator: report each call of a tool function, and what it returned."""
        def wrap(f: Callable) -> Callable:
            tool_name = name or f.__name__
            signature = inspect.signature(f)

            def bound(args: tuple, kwargs: dict) -> dict[str, Any]:
                try:
                    b = signature.bind_partial(*args, **kwargs)
                    return {k: v for k, v in b.arguments.items() if k not in ("self", "cls")}
                except TypeError:
                    return {"args": list(args), **kwargs}

            if inspect.iscoroutinefunction(f):
                @functools.wraps(f)
                async def inner_async(*args: Any, **kwargs: Any) -> Any:
                    call_args = bound(args, kwargs)
                    self.tool_call(tool_name, call_args)
                    out = await f(*args, **kwargs)
                    if results:
                        self.tool_result(tool_name, out, call_args)
                    return out
                return inner_async

            @functools.wraps(f)
            def inner(*args: Any, **kwargs: Any) -> Any:
                call_args = bound(args, kwargs)
                self.tool_call(tool_name, call_args)
                out = f(*args, **kwargs)
                if results:
                    self.tool_result(tool_name, out, call_args)
                return out
            return inner

        return wrap(fn) if fn is not None else wrap

    def flush(self, timeout: float = 5.0) -> None:
        """Send everything queued so far (or spool it)."""
        if self._queue is not None:
            done = threading.Event()
            self._queue.put(("__flush__", done))
            done.wait(timeout)
        else:
            self._deliver(include_spool=True)

    def close(self, timeout: float = 5.0) -> None:
        if self._queue is not None and self._thread is not None:
            self._queue.put(None)
            self._thread.join(timeout)
            self._queue = None
        else:
            self._deliver(include_spool=True)

    # inside

    def _enqueue(self, item: tuple[str, Any]) -> None:
        if self._queue is not None:
            self._queue.put(item)
        else:
            with self._lock:
                self._pending.append(item)

    def _run(self) -> None:
        assert self._queue is not None
        first = True
        while True:
            try:
                item = self._queue.get(timeout=0.5)
            except queue.Empty:
                item = "idle"
            stop = item is None
            waiter = None
            if isinstance(item, tuple) and item[0] == "__flush__":
                waiter = item[1]
            elif isinstance(item, tuple):
                self._pending.append(item)
            if self._pending or waiter or stop or first:
                # Gather whatever else is already queued, so a burst goes in one
                # request rather than one request per event.
                while True:
                    try:
                        more = self._queue.get_nowait()
                    except queue.Empty:
                        break
                    if more is None:
                        stop = True
                    elif more[0] == "__flush__":
                        waiter = waiter or more[1]
                    else:
                        self._pending.append(more)
                self._deliver(include_spool=first)
                first = False
            if waiter is not None:
                waiter.set()
            if stop:
                return

    def _deliver(self, include_spool: bool) -> None:
        with self._lock:
            items, self._pending = self._pending, []
        if include_spool:
            waiting = self.spool.take()
            if len(waiting) > FLUSH_PER_HOOK:
                # A long backlog goes a slice at a time, so one hook run stays
                # well inside Claude Code's timeout. Events carry their own
                # timestamps, so arriving late doesn't reorder them.
                self.spool.add(waiting[FLUSH_PER_HOOK:])
                waiting = waiting[:FLUSH_PER_HOOK]
            items = waiting + items
        if not items:
            return
        failed: list[tuple[str, Any]] = []
        i = 0
        while i < len(items):
            path, body = items[i]
            if failed:
                # Once the server is unreachable, don't try every batch: keep
                # them in order for next time.
                failed.extend(items[i:])
                break
            if path == "/events":
                batch = [body]
                while (i + len(batch) < len(items) and len(batch) < BATCH_SIZE
                       and items[i + len(batch)][0] == "/events"):
                    batch.append(items[i + len(batch)][1])
                status, reply = self._post(path, batch)
                if status == 200:
                    self.sent += len(batch)
                elif _retryable(status):
                    failed.extend(("/events", e) for e in batch)
                else:
                    self.dropped += len(batch)
                    self.spool.note(f"Shadowfax refused {len(batch)} event(s) with {status}: "
                                    f"{_detail(reply)}")
                i += len(batch)
            else:
                status, reply = self._post(path, body)
                if status == 200:
                    self.sent += 1
                elif _retryable(status):
                    failed.append((path, body))
                else:
                    self.dropped += 1
                    self.spool.note(f"Shadowfax refused a manifest with {status}: {_detail(reply)}")
                i += 1
        if failed:
            self.spool.add(failed)

    def _post(self, path: str, body: Any) -> tuple[int, Any]:
        try:
            return self.transport.post(path, body)
        except Exception as exc:  # never into the agent
            self.spool.note(f"sending failed: {exc!r}")
            return 0, None


def _detail(reply: Any) -> str:
    if isinstance(reply, dict) and "detail" in reply:
        return str(reply["detail"])[:300]
    return str(reply)[:300]


# -- Claude Code hooks -------------------------------------------------------------

HOOK_EVENTS = ("PostToolUse", "PostToolUseFailure")


def hook_events(payload: dict[str, Any], agent_id: str, task: str | None = None,
                skip_mcp: bool = False) -> list[dict[str, Any]]:
    """Shadowfax events for one Claude Code hook call.

    PostToolUse gives both halves at once: the call (what the tool was asked
    to do) and the result (what came back). They share a timestamp and go in
    that order, so the result is never seen before its call. PostToolUseFailure
    is the call alone, marked failed.
    """
    name = payload.get("hook_event_name")
    tool = payload.get("tool_name")
    if name not in HOOK_EVENTS or not isinstance(tool, str) or not tool:
        return []
    if skip_mcp and tool.startswith("mcp__"):
        return []
    args = payload.get("tool_input")
    common: dict[str, Any] = {"session_id": payload.get("session_id"),
                              "tool_use_id": payload.get("tool_use_id")}
    if payload.get("agent_type"):
        common["subagent"] = payload["agent_type"]
    if payload.get("duration_ms") is not None:
        common["duration_ms"] = payload["duration_ms"]
    server = payload.get("mcp_server")
    if isinstance(server, dict) and server.get("name"):
        common["mcp_server"] = server.get("name")
    common = {k: v for k, v in common.items() if v is not None}
    ts = now_iso()
    if name == "PostToolUse":
        call = call_event(agent_id, tool, args, task=task, timestamp=ts,
                          extra={**common, "exit_status": "ok"})
        result = result_event(agent_id, tool, args, payload.get("tool_response"), task=task,
                              timestamp=ts, extra=common)
        return [call, result]
    failure = {**common, "exit_status": "interrupted" if payload.get("is_interrupt") else "error",
               "error": str(payload.get("error") or "")}
    return [call_event(agent_id, tool, args, task=task, timestamp=ts, extra=failure)]


def run_hook(stdin: Any = None, config: Config | None = None, transport: Any = None) -> int:
    """Entry point for `shadowfax_agent.py hook`. Always 0, prints nothing:
    stdout and a non-zero exit both mean something to Claude Code, and a
    monitor must not."""
    try:
        config = config or Config.load()
        raw = (stdin or sys.stdin).read()
        payload = json.loads(raw) if raw.strip() else {}
        if not isinstance(payload, dict):
            return 0
        events = hook_events(payload, config.agent_id, config.task,
                             skip_mcp=os.environ.get("SHADOWFAX_HOOK_SKIP_MCP") == "1")
        reporter = Reporter(config=config, transport=transport, background=False)
        for e in events:
            reporter.send(e)
        reporter.flush()
    except Exception as exc:
        try:
            Spool((config or Config()).spool_dir).note(f"hook failed: {exc!r}")
        except Exception:
            pass
    return 0


def claude_code_settings(python: str | None = None, script: str | None = None) -> dict[str, Any]:
    """The hooks block for Claude Code's settings.json.

    Exec form (`command` plus `args`), so no shell parses the paths: the same
    block works from bash, zsh and PowerShell, and with spaces in a path.
    """
    entry = {"type": "command", "command": python or sys.executable,
             "args": [script or str(Path(__file__).resolve()), "hook"], "timeout": 15}
    return {"hooks": {name: [{"matcher": "*", "hooks": [entry]}] for name in HOOK_EVENTS}}


def _is_ours(hook: Any) -> bool:
    text = json.dumps(hook)
    return "shadowfax_agent" in text and "hook" in text


def merge_settings(existing: dict[str, Any], ours: dict[str, Any]) -> dict[str, Any]:
    """`ours` added to a settings object, replacing an earlier copy of our hook
    and leaving every other setting and hook as it was."""
    merged = json.loads(json.dumps(existing))
    hooks = merged.setdefault("hooks", {})
    for event, groups in ours["hooks"].items():
        current = [g for g in hooks.get(event, [])
                   if not any(_is_ours(h) for h in (g.get("hooks") or []))]
        hooks[event] = current + groups
    return merged


# -- the MCP proxy -------------------------------------------------------------------

class McpObserver:
    """Watches one MCP server's JSON-RPC traffic and turns it into events.

    It is handed copies of messages that have already been forwarded; nothing
    it does (or fails to do) can change what the client and server see.
    """

    def __init__(self, server: str, reporter: Reporter, report_calls: bool = True):
        self.server = server
        self.reporter = reporter
        self.report_calls = report_calls
        self.pending: dict[str, tuple[str, Any, Any]] = {}
        self.listing: dict[str, Any] = {}
        self.lock = threading.Lock()

    @staticmethod
    def _messages(line: bytes) -> list[dict[str, Any]]:
        try:
            msg = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            return []
        items = msg if isinstance(msg, list) else [msg]
        return [m for m in items if isinstance(m, dict)]

    def from_client(self, line: bytes) -> None:
        for msg in self._messages(line):
            if "id" not in msg or not isinstance(msg.get("method"), str):
                continue
            key = json.dumps(msg["id"])
            params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
            if msg["method"] == "tools/call":
                tool = f"mcp__{self.server}__{params.get('name')}"
                args = params.get("arguments")
                with self.lock:
                    self.pending[key] = ("call", tool, args)
                if self.report_calls:
                    self.reporter.send(call_event(self.reporter.agent_id, tool, args,
                                                  task=self.reporter.config.task,
                                                  extra={"mcp_server": self.server}))
            elif msg["method"] == "tools/list":
                with self.lock:
                    self.pending[key] = ("list", None, bool(params.get("cursor")))

    def from_server(self, line: bytes) -> None:
        for msg in self._messages(line):
            if "id" not in msg or ("result" not in msg and "error" not in msg):
                continue
            with self.lock:
                entry = self.pending.pop(json.dumps(msg["id"]), None)
            if entry is None:
                continue
            kind, tool, detail = entry
            result = msg.get("result")
            if kind == "call" and self.report_calls and isinstance(result, dict):
                meta = {"mcp_server": self.server}
                if result.get("isError"):
                    meta["is_error"] = True
                content = result.get("content")
                if result.get("structuredContent") is not None and not content:
                    content = result.get("structuredContent")
                self.reporter.send(result_event(self.reporter.agent_id, tool, detail, content,
                                                task=self.reporter.config.task, extra=meta))
            elif kind == "list" and isinstance(result, dict):
                tools = result.get("tools")
                if not isinstance(tools, list):
                    continue
                if not detail:  # a fresh listing, not the next page of one
                    self.listing = {}
                for t in tools:
                    if isinstance(t, dict) and isinstance(t.get("name"), str):
                        self.listing[t["name"]] = t
                if not result.get("nextCursor"):
                    self.reporter.manifest(mcp_servers={self.server: list(self.listing.values())},
                                           partial=True)


def run_proxy(server: str, command: list[str], reporter: Reporter, report_calls: bool = True,
              stdin: Any = None, stdout: Any = None) -> int:
    """Run an MCP server as a child process and relay stdio between it and the
    client, unchanged, reporting as it goes. Returns the server's exit code."""
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    exe = shutil.which(command[0]) or command[0]
    child = subprocess.Popen([exe] + command[1:], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, bufsize=0)
    observer = McpObserver(server, reporter, report_calls)

    def watch(fn: Callable[[bytes], None], line: bytes) -> None:
        try:
            fn(line)
        except Exception as exc:  # a parsing bug must never stop the relay
            reporter.spool.note(f"proxy could not read a message: {exc!r}")

    def client_to_server() -> None:
        try:
            for line in iter(stdin.readline, b""):
                # Observed first, so a request is known before its response can
                # possibly arrive; forwarded unchanged either way.
                watch(observer.from_client, line)
                child.stdin.write(line)
                child.stdin.flush()
        except (OSError, ValueError):
            pass
        finally:
            try:
                child.stdin.close()
            except OSError:
                pass

    def server_to_client() -> None:
        try:
            for line in iter(child.stdout.readline, b""):
                stdout.write(line)
                stdout.flush()
                watch(observer.from_server, line)
        except (OSError, ValueError):
            pass

    up = threading.Thread(target=client_to_server, daemon=True)
    down = threading.Thread(target=server_to_client, daemon=True)
    up.start()
    down.start()
    try:
        code = child.wait()
    except KeyboardInterrupt:
        child.terminate()
        code = child.wait()
    down.join(5)
    reporter.close()
    return code


# -- command line ---------------------------------------------------------------------

def _write_private(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def check_connection(config: Config, transport: Any = None, out: Any = None) -> int:
    """Whether the URL and key work, without sending an event: the ledger head
    is the one thing an API key may read."""
    out = out or sys.stdout
    transport = transport or HttpTransport(config)
    status, body = transport.request("GET", "/ledger/head")
    if status == 200:
        print(f"Connected to {config.url} as agent '{config.agent_id}'. "
              f"The ledger has {body.get('entry_count', '?') if isinstance(body, dict) else '?'} entries.",
              file=out)
        return 0
    if status == 0:
        print(f"Can't reach Shadowfax at {config.url}. Is it running, and is the URL right?",
              file=out)
    elif status in (401, 403):
        print("Shadowfax is there but refused the API key. An admin can make a new one: "
              "open Accounts on the dashboard and click New API key.", file=out)
    else:
        print(f"Shadowfax answered {status}: {_detail(body)}", file=out)
    return 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="shadowfax_agent.py",
                                description="Connect AI agents to Shadowfax.")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("configure", help="save the Shadowfax URL and API key on this machine")
    c.add_argument("--url", required=True)
    c.add_argument("--api-key", required=True)
    c.add_argument("--agent-id", help=f"defaults to {default_agent_id()}")

    sub.add_parser("check", help="test the connection without sending anything")

    cc = sub.add_parser("claude-code", help="print (or add) the Claude Code hooks")
    cc.add_argument("--write", metavar="SETTINGS_JSON",
                    help="add the hooks to this settings file, keeping everything else")

    sub.add_parser("hook", help="run as a Claude Code hook (Claude Code calls this)")

    mp = sub.add_parser("mcp-proxy", help="run an MCP server behind a reporting proxy")
    mp.add_argument("--server", required=True, help="the server's name, e.g. github")
    mp.add_argument("--manifest-only", action="store_true",
                    help="report the tool list but not calls (when Claude Code hooks already "
                         "report the calls)")
    mp.add_argument("command", nargs=argparse.REMAINDER,
                    help="-- then the command that starts the MCP server")

    sub.add_parser("flush", help="send anything waiting in the spool now")

    args = p.parse_args(argv)

    if args.cmd == "hook":
        return run_hook()

    if args.cmd == "configure":
        config = Config.load()
        agent_id = args.agent_id or config.agent_id
        problem = check_agent_id(agent_id)
        if problem:
            print(problem, file=sys.stderr)
            return 2
        _write_private(config_path(), {"url": args.url.rstrip("/"), "api_key": args.api_key,
                                       "agent_id": agent_id})
        print(f"Saved to {config_path()} (readable only by you).")
        return check_connection(Config.load())

    if args.cmd == "check":
        return check_connection(Config.load())

    if args.cmd == "claude-code":
        ours = claude_code_settings()
        if not args.write:
            print(json.dumps(ours, indent=2))
            return 0
        path = Path(args.write).expanduser()
        existing: dict[str, Any] = {}
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8") or "{}")
            except ValueError:
                print(f"{path} isn't valid JSON, so it was left alone. Fix it or add this "
                      f"by hand:\n{json.dumps(ours, indent=2)}", file=sys.stderr)
                return 1
            shutil.copy2(path, path.with_name(path.name + ".bak"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(merge_settings(existing, ours), indent=2) + "\n",
                        encoding="utf-8")
        print(f"Added the Shadowfax hooks to {path}" +
              (f" (the old file is {path.name}.bak)" if existing else "") +
              ". Restart Claude Code to pick them up.")
        return 0

    if args.cmd == "mcp-proxy":
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        if not command:
            print("give the MCP server's command after --", file=sys.stderr)
            return 2
        if not _SERVER_NAME.match(args.server) or "__" in args.server:
            print("a server name is 1-64 letters, digits, '.', '-' or '_' (no '__')",
                  file=sys.stderr)
            return 2
        reporter = Reporter(background=True)
        return run_proxy(args.server, command, reporter, report_calls=not args.manifest_only)

    if args.cmd == "flush":
        reporter = Reporter(background=False)
        reporter.flush()
        waiting = 0
        try:
            waiting = len(reporter.spool.file.read_text(encoding="utf-8").splitlines())
        except OSError:
            pass
        print(f"sent {reporter.sent}, still waiting {waiting}")
        return 0 if waiting == 0 else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
