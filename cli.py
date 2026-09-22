#!/usr/bin/env python3
"""
Shadowfax command-line interface (v0.7).

Shadowfax watches AI agents, and AI agents are most at home in a terminal: they
reach for tools they can invoke and output they can parse. This CLI is that
surface. Everything the dashboard does, a harness or an agent can do from a
shell -- ingest a trace, query alerts, read an incident, ask for an explanation,
gate a run on whether anything fired.

Two rules shape it:

* **It goes through the HTTP API, never the database.** The CLI is just another
  client. Authentication, roles and every policy check apply exactly as they do
  to the dashboard -- a convenience tool must not become a way around the
  security model of a security tool.
* **It is scriptable.** Every command takes `--json` for machine consumption,
  writes errors to stderr, and returns a meaningful exit code. `shadowfax check`
  exits non-zero when alerts match, so a CI job or an agent harness can fail a
  run the moment its own behaviour trips a detector.

Configuration follows the same "a config file or a flag" convention: settings
live in ~/.shadowfax/config.json, and every one is overridable by environment
variable or flag.

Usage:

    python cli.py status
    python cli.py login -u admin
    cat trace.json | python cli.py ingest -
    python cli.py alerts --severity critical --json
    python cli.py incidents --json
    python cli.py explain incident <id>
    python cli.py search "critical destructive actions by ai agents"
    python cli.py check --severity critical      # exit 1 if any match

Exit codes:
    0  success (and, for `check`, nothing matched)
    1  matches found (`check`) or the command failed
    2  usage error
    3  authentication / authorisation failure
    4  could not reach the API
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_AUTH = 3
EXIT_UNREACHABLE = 4

DEFAULT_URL = "http://127.0.0.1:8000"
CONFIG_PATH = Path(os.environ.get("SHADOWFAX_CONFIG",
                                  Path.home() / ".shadowfax" / "config.json"))


# --- configuration ---------------------------------------------------------

def load_config() -> dict[str, Any]:
    """Stored settings, or an empty dict. A missing or unreadable config is not
    an error -- flags and environment variables can supply everything."""
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_config(cfg: dict[str, Any]) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    try:
        # The file holds a session token; keep it to the owner.
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


def resolve_settings(args: argparse.Namespace) -> dict[str, Any]:
    """Flag > environment > config file > default, for each setting."""
    cfg = load_config()
    url = (getattr(args, "url", None) or os.environ.get("SHADOWFAX_URL")
           or cfg.get("url") or DEFAULT_URL)
    token = (getattr(args, "token", None) or os.environ.get("SHADOWFAX_TOKEN")
             or cfg.get("token"))
    api_key = (getattr(args, "api_key", None) or os.environ.get("SHADOWFAX_API_KEY")
               or cfg.get("api_key"))
    return {"url": url.rstrip("/"), "token": token, "api_key": api_key}


# --- transport -------------------------------------------------------------
#
# One seam for every request the CLI makes. The default speaks HTTP over the
# stdlib; the test suite injects a transport backed by the API's own test client
# so the CLI is exercised end to end without a live server.

class ApiError(Exception):
    def __init__(self, message: str, code: int = EXIT_FAIL):
        super().__init__(message)
        self.code = code


class HttpTransport:
    """urllib-backed transport. No third-party HTTP dependency."""

    def __init__(self, base_url: str, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def request(self, method: str, path: str, params: dict | None = None,
                body: Any = None, headers: dict | None = None) -> tuple[int, Any]:
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params, doseq=True)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={"content-type": "application/json", **(headers or {})},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                return resp.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            try:
                payload = json.loads(raw)
            except ValueError:
                payload = {"detail": raw}
            return exc.code, payload
        except (urllib.error.URLError, OSError) as exc:
            raise ApiError(f"cannot reach Shadowfax at {self.base_url}: {exc}",
                           EXIT_UNREACHABLE) from exc


class Client:
    """Thin request helper that applies credentials and turns HTTP failures into
    ApiError with a meaningful exit code."""

    def __init__(self, transport, token: str | None = None, api_key: str | None = None):
        self.transport = transport
        self.token = token
        self.api_key = api_key

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if self.api_key:
            h["X-API-Key"] = self.api_key
        return h

    def call(self, method: str, path: str, params: dict | None = None,
             body: Any = None) -> Any:
        status, payload = self.transport.request(method, path, params, body, self._headers())
        if status in (401, 403):
            detail = _detail(payload)
            raise ApiError(
                f"{detail} (run `shadowfax login`, or set SHADOWFAX_TOKEN / "
                f"SHADOWFAX_API_KEY)", EXIT_AUTH)
        if status >= 400:
            raise ApiError(f"{method} {path} failed ({status}): {_detail(payload)}")
        return payload


def _detail(payload: Any) -> str:
    if isinstance(payload, dict):
        d = payload.get("detail", payload)
        return d if isinstance(d, str) else json.dumps(d)
    return str(payload)


# --- output ----------------------------------------------------------------

def emit(out, value: Any, as_json: bool, human) -> None:
    """Print machine-readable JSON, or the human rendering. Agents pass --json;
    people get the table."""
    if as_json:
        print(json.dumps(value, indent=2), file=out)
    else:
        human(out, value)


def _col(s: Any, width: int) -> str:
    text = "" if s is None else str(s)
    if len(text) > width:
        return text[: width - 1] + "…"
    return text.ljust(width)


def _short_time(ts: str | None) -> str:
    return (ts or "").replace("T", " ")[:16]


def human_alerts(out, alerts: list[dict]) -> None:
    if not alerts:
        print("no alerts match.", file=out)
        return
    print(f"{_col('SEVERITY', 9)} {_col('CATEGORY', 22)} {_col('ACTOR', 16)} "
          f"{_col('TIME', 17)} DETAIL", file=out)
    for a in alerts:
        print(f"{_col(a.get('severity'), 9)} {_col(a.get('category'), 22)} "
              f"{_col(a.get('actor_id'), 16)} {_col(_short_time(a.get('timestamp')), 17)} "
              f"{a.get('message', '')}", file=out)
    print(f"\n{len(alerts)} alert{'s' if len(alerts) != 1 else ''}.", file=out)


def human_incidents(out, incidents: list[dict]) -> None:
    if not incidents:
        print("no incidents.", file=out)
        return
    print(f"{_col('ID', 18)} {_col('SEVERITY', 9)} {_col('ACTOR', 16)} "
          f"{_col('ALERTS', 7)} {_col('START', 17)} CHAIN", file=out)
    for i in incidents:
        chain = i.get("chain") or {}
        chain_text = ""
        if chain:
            chain_text = " → ".join(s["tactic"] for s in chain.get("stages", []))
            if chain.get("escalated"):
                chain_text = "[escalated] " + chain_text
        print(f"{_col(i.get('id'), 18)} {_col(i.get('severity'), 9)} "
              f"{_col(i.get('actor_id'), 16)} {_col(i.get('alert_count'), 7)} "
              f"{_col(_short_time(i.get('start')), 17)} {chain_text}", file=out)
    print(f"\n{len(incidents)} incident{'s' if len(incidents) != 1 else ''}.", file=out)


def human_actors(out, actors: list[dict]) -> None:
    if not actors:
        print("no actors.", file=out)
        return
    print(f"{_col('ACTOR', 20)} {_col('TYPE', 16)} {_col('EVENTS', 7)} {_col('RISK', 6)}",
          file=out)
    for a in actors:
        print(f"{_col(a.get('actor_id'), 20)} {_col(a.get('actor_type'), 16)} "
              f"{_col(a.get('event_count'), 7)} {_col(a.get('risk_score'), 6)}", file=out)


def human_stats(out, stats: dict) -> None:
    counts = stats.get("alert_counts", {})
    print(f"events {stats.get('event_count', 0)} · actors {stats.get('actor_count', 0)}",
          file=out)
    print("alerts: " + "  ".join(f"{k} {v}" for k, v in counts.items()), file=out)


# --- commands --------------------------------------------------------------

def _alert_filter_params(args: argparse.Namespace) -> dict:
    params: dict[str, Any] = {}
    if getattr(args, "severity", None):
        params["severity"] = args.severity
    if getattr(args, "actor_type", None):
        params["actor_type"] = args.actor_type
    if getattr(args, "category", None):
        params["category"] = args.category
    if getattr(args, "actor", None):
        params["actor_id"] = args.actor
    if getattr(args, "search", None):
        params["search"] = args.search
    if getattr(args, "since", None):
        params["since"] = args.since
    if getattr(args, "until", None):
        params["until"] = args.until
    if getattr(args, "limit", None):
        params["limit"] = args.limit
    return params


def cmd_status(client: Client, args, out) -> int:
    info = client.call("GET", "/stats")
    assistant = {}
    try:
        assistant = client.call("GET", "/assistant/status") or {}
    except ApiError:
        pass  # a viewer-level key may not reach it; the core status still stands
    payload = {"reachable": True, "stats": info, "assistant": assistant}
    def human(o, v):
        human_stats(o, v["stats"])
        a = v.get("assistant") or {}
        if a:
            print(f"assistant: {'model ' + str(a.get('model')) if a.get('configured') else 'deterministic (no model configured)'}",
                  file=o)
    emit(out, payload, args.json, human)
    return EXIT_OK


def cmd_login(client: Client, args, out) -> int:
    import getpass
    username = args.username or input("username: ")
    password = args.password or os.environ.get("SHADOWFAX_PASSWORD") or getpass.getpass("password: ")
    payload = client.call("POST", "/auth/login",
                          body={"username": username, "password": password})
    cfg = load_config()
    cfg["url"] = args.resolved_url
    cfg["token"] = payload["token"]
    save_config(cfg)
    emit(out, {"user": payload.get("user"), "expires_at": payload.get("expires_at"),
               "config": str(CONFIG_PATH)}, args.json,
         lambda o, v: print(f"signed in as {v['user']['username']} "
                            f"({v['user']['role']}); token saved to {v['config']}", file=o))
    return EXIT_OK


def cmd_ingest(client: Client, args, out) -> int:
    """Read events as JSON (a list, or one object) from a file or stdin. This is
    the integration point for a harness or agent emitting its own trace."""
    raw = sys.stdin.read() if args.source == "-" else Path(args.source).read_text(encoding="utf-8")
    try:
        events = json.loads(raw)
    except ValueError as exc:
        raise ApiError(f"input is not valid JSON: {exc}", EXIT_USAGE)
    if isinstance(events, dict):
        events = [events]
    if not isinstance(events, list) or not events:
        raise ApiError("expected a non-empty JSON array of events", EXIT_USAGE)
    result = client.call("POST", "/events", body=events)
    emit(out, result, args.json,
         lambda o, v: print(f"ingested {v.get('ingested', 0)} event(s); "
                            f"{len(v.get('alerts', []))} alert(s) for "
                            f"{', '.join(v.get('affected_actors', []))}", file=o))
    return EXIT_OK


def cmd_alerts(client: Client, args, out) -> int:
    alerts = client.call("GET", "/alerts", params=_alert_filter_params(args))
    emit(out, alerts, args.json, human_alerts)
    return EXIT_OK


def cmd_check(client: Client, args, out) -> int:
    """Exit non-zero when alerts match. Lets a harness gate its own run:
    `shadowfax check --severity critical || fail_the_build`."""
    alerts = client.call("GET", "/alerts", params=_alert_filter_params(args))
    emit(out, {"matched": len(alerts), "alerts": alerts if args.json else []}, args.json,
         lambda o, v: print(
             f"{v['matched']} alert(s) matched." if v["matched"] else "no alerts matched.",
             file=o))
    return EXIT_FAIL if alerts else EXIT_OK


def cmd_incidents(client: Client, args, out) -> int:
    if args.incident_id:
        detail = client.call("GET", f"/incidents/{args.incident_id}")
        if args.report:
            print(detail.get("report", ""), file=out)
            return EXIT_OK
        emit(out, detail, args.json,
             lambda o, v: (human_incidents(o, [v]), print("\n" + v.get("summary", ""), file=o)))
        return EXIT_OK
    incidents = client.call("GET", "/incidents")
    emit(out, incidents, args.json, human_incidents)
    return EXIT_OK


def cmd_explain(client: Client, args, out) -> int:
    path = (f"/alerts/{args.target_id}/explain" if args.kind == "alert"
            else f"/incidents/{args.target_id}/explain")
    result = client.call("GET", path)
    emit(out, result, args.json,
         lambda o, v: print(f"[{v.get('source')}]\n{v.get('narrative', '')}", file=o))
    return EXIT_OK


def cmd_search(client: Client, args, out) -> int:
    result = client.call("POST", "/search", body={"query": args.query})
    def human(o, v):
        print(f"read “{v.get('query')}” as {v.get('interpretation')} "
              f"[{v.get('source')}]\n", file=o)
        human_alerts(o, v.get("alerts", []))
    emit(out, result, args.json, human)
    return EXIT_OK


def cmd_actors(client: Client, args, out) -> int:
    actors = client.call("GET", "/actors")
    emit(out, actors, args.json, human_actors)
    return EXIT_OK


def cmd_stats(client: Client, args, out) -> int:
    stats = client.call("GET", "/stats")
    emit(out, stats, args.json, human_stats)
    return EXIT_OK


def cmd_policy(client: Client, args, out) -> int:
    """The active policy is Shadowfax's config file; read it and write it back."""
    if args.action == "get":
        policy = client.call("GET", "/policy")
        print(json.dumps(policy, indent=2), file=out)
        return EXIT_OK
    raw = sys.stdin.read() if args.file == "-" else Path(args.file).read_text(encoding="utf-8")
    try:
        policy = json.loads(raw)
    except ValueError as exc:
        raise ApiError(f"policy is not valid JSON: {exc}", EXIT_USAGE)
    result = client.call("PUT", "/policy", body=policy)
    emit(out, result, args.json, lambda o, v: print(v.get("status", "policy updated"), file=o))
    return EXIT_OK


# --- argument parsing ------------------------------------------------------

def _common_flags() -> argparse.ArgumentParser:
    """Connection and output flags, shared by the top level and every
    subcommand, so both `shadowfax --json stats` and the far more natural
    `shadowfax stats --json` work. SUPPRESS keeps an absent flag on the
    subparser from clobbering one given before the subcommand."""
    c = argparse.ArgumentParser(add_help=False)
    c.add_argument("--url", default=argparse.SUPPRESS,
                   help=f"API base URL (default {DEFAULT_URL})")
    c.add_argument("--token", default=argparse.SUPPRESS,
                   help="bearer token (overrides the stored one)")
    c.add_argument("--api-key", dest="api_key", default=argparse.SUPPRESS,
                   help="service API key, for ingest")
    c.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                   help="machine-readable JSON output")
    return c


def build_parser() -> argparse.ArgumentParser:
    common = _common_flags()
    p = argparse.ArgumentParser(
        prog="shadowfax", parents=[common],
        description="Shadowfax CLI — query and feed the AI-agent security platform.")
    sub = p.add_subparsers(dest="command", required=True)
    _orig_add_parser = sub.add_parser

    def add_parser(name, **kw):
        kw.setdefault("parents", []).append(common)
        return _orig_add_parser(name, **kw)

    sub.add_parser = add_parser  # every subcommand inherits the common flags

    def add_filters(sp):
        sp.add_argument("--severity", action="append",
                        choices=["critical", "high", "medium", "low"])
        sp.add_argument("--actor-type", dest="actor_type", action="append",
                        choices=["human", "ai_agent", "service_account"])
        sp.add_argument("--category", action="append")
        sp.add_argument("--actor")
        sp.add_argument("--search")
        sp.add_argument("--since", help="ISO timestamp lower bound")
        sp.add_argument("--until", help="ISO timestamp upper bound")
        sp.add_argument("--limit", type=int)

    sub.add_parser("status", help="API reachability, counts and assistant mode")

    sp = sub.add_parser("login", help="sign in and store a session token")
    sp.add_argument("-u", "--username")
    sp.add_argument("-p", "--password", help="prompted for if omitted")

    sp = sub.add_parser("ingest", help="ingest events from a JSON file or '-' for stdin")
    sp.add_argument("source")

    add_filters(sub.add_parser("alerts", help="list alerts"))
    add_filters(sub.add_parser("check", help="exit non-zero if any alert matches"))

    sp = sub.add_parser("incidents", help="list incidents, or show one")
    sp.add_argument("incident_id", nargs="?")
    sp.add_argument("--report", action="store_true", help="print the markdown report")

    sp = sub.add_parser("explain", help="explain an alert or an incident")
    sp.add_argument("kind", choices=["alert", "incident"])
    sp.add_argument("target_id")

    sp = sub.add_parser("search", help="natural-language alert search")
    sp.add_argument("query")

    sub.add_parser("actors", help="list actors with risk scores")
    sub.add_parser("stats", help="alert and event counts")

    sp = sub.add_parser("policy", help="read or replace the active policy")
    sp.add_argument("action", choices=["get", "set"])
    sp.add_argument("file", nargs="?", default="-",
                    help="policy JSON file for 'set' ('-' for stdin)")

    return p


COMMANDS = {
    "status": cmd_status, "login": cmd_login, "ingest": cmd_ingest,
    "alerts": cmd_alerts, "check": cmd_check, "incidents": cmd_incidents,
    "explain": cmd_explain, "search": cmd_search, "actors": cmd_actors,
    "stats": cmd_stats, "policy": cmd_policy,
}


def run(argv: list[str] | None = None, transport=None, out=None, err=None) -> int:
    """Entry point. `transport` is injectable so the CLI can be driven against a
    test client; `out`/`err` likewise, which keeps it testable end to end."""
    out = out or sys.stdout
    err = err or sys.stderr
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse already printed the message
        return int(exc.code or EXIT_USAGE)

    # Flags use SUPPRESS so they can appear on either side of the subcommand;
    # fill in the defaults for anything that was never given.
    args.json = getattr(args, "json", False)

    settings = resolve_settings(args)
    args.resolved_url = settings["url"]
    transport = transport or HttpTransport(settings["url"])
    client = Client(transport, settings["token"], settings["api_key"])

    try:
        return COMMANDS[args.command](client, args, out)
    except ApiError as exc:
        print(f"error: {exc}", file=err)
        return exc.code
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=err)
        return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(run())
