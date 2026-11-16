"""
Threat intelligence feeds (v0.39).

Lists of known-bad infrastructure (botnet command servers, malware download
links, hijacked networks, your own team's watchlist) checked against what agents
actually reach. An agent that curls a URL a feed lists as a malware download, or
calls out to an address a feed lists as a botnet server, raises
`threat_intel_match`.

Three rules decide everything here:

* **An indicator is never forgotten.** Feeds drop entries all the time (a
  command server goes offline, a URL is cleaned up). When that happens the
  indicator is marked retired, not deleted. An event matches an indicator if it
  happened while the indicator was listed, or before it was listed at all, which
  is the case that matters most: the agent reached it before anyone knew it was
  bad. Alerts stay a pure function of (events, policy, indicators), so a feed
  dropping an entry never makes an old alert vanish.
* **Fetching is fenced.** An admin can add a feed from the dashboard, which
  means the server fetches a URL someone typed. That is how servers get turned
  against their own network (SSRF), so feeds must be https, must resolve to
  public addresses only, and the connection goes to the address that was
  checked. Redirects aren't followed, downloads are capped, and an account key
  is written into the URL as `{env:SHADOWFAX_INTEL_...}` so it comes from the
  server's environment, is never stored, and can't be any other variable.
* **A feed can't flag everything.** Entries that would match huge swathes of
  the internet (a /0 network) or your own internal network (10.0.0.0/8,
  localhost) are dropped and counted, so a broken or poisoned feed can't bury
  the alert table.

Parsing, classifying and matching are pure. Fetching is here too, behind one
function that tests replace.
"""

from __future__ import annotations

import csv
import http.client
import io
import ipaddress
import json
import os
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

CATEGORY = "threat_intel_match"
FORMATS = ("text", "csv", "json")
SEVERITIES = ("medium", "high", "critical")
SEVERITY_RANK = {"medium": 1, "high": 2, "critical": 3}
MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024
MAX_INDICATORS = 250_000
FETCH_TIMEOUT = 30
MIN_REFRESH_MINUTES = 15
DEFAULT_REFRESH_MINUTES = 360
# The narrowest networks a feed may list: anything wider would match a
# continent's worth of addresses.
MIN_PREFIX = {4: 8, 6: 32}
ENV_PLACEHOLDER = re.compile(r"\{env:([A-Za-z0-9_]+)\}")
ENV_ALLOWED = re.compile(r"^SHADOWFAX_INTEL_[A-Z0-9_]{1,64}$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")


class IntelError(Exception):
    """Something about a feed, said in words an admin can act on."""


# -- presets -----------------------------------------------------------------------
#
# Well-known free feeds, as their providers published them in November 2026.
# Providers do change their addresses and terms (abuse.ch started requiring a
# free account key for most downloads in October 2026); a preset that stops
# working says so in its status rather than silently matching nothing.

PRESETS: dict[str, dict[str, Any]] = {
    "feodo": {
        "name": "Feodo Tracker: botnet command servers",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "format": "text", "field": None, "severity": "critical", "attack": ["T1071"],
        "description": "abuse.ch's list of active botnet command-and-control servers. "
                       "An agent talking to one is a strong sign it has been taken over.",
    },
    "spamhaus-drop": {
        "name": "Spamhaus DROP: hijacked networks",
        "url": "https://www.spamhaus.org/drop/drop_v4.json",
        "format": "json", "field": "cidr", "severity": "high", "attack": ["T1071"],
        "description": "Networks Spamhaus says are run entirely by criminals. Nothing "
                       "legitimate should need to reach them.",
    },
    "urlhaus": {
        "name": "URLhaus: malware download links",
        "url": "https://urlhaus-api.abuse.ch/v2/files/exports/{env:SHADOWFAX_INTEL_ABUSECH_KEY}/recent.csv",
        "format": "csv", "field": "2", "severity": "high", "attack": ["T1105"],
        "description": "abuse.ch's recent malware download URLs. Needs a free abuse.ch "
                       "account key in SHADOWFAX_INTEL_ABUSECH_KEY on the server.",
    },
}


# -- parsing ----------------------------------------------------------------------

def _comment(line: str) -> bool:
    s = line.lstrip()
    return not s or s.startswith(("#", ";", "//"))


def parse(body: bytes, fmt: str, field: str | None) -> list[str]:
    """The raw entries in a feed download. Raises IntelError if the format or
    field is wrong for it."""
    text = body.decode("utf-8", errors="replace")
    if fmt == "text":
        out = []
        for line in text.splitlines():
            if _comment(line):
                continue
            token = re.split(r"[\s;,]+", line.strip(), maxsplit=1)[0]
            if token:
                out.append(token)
        return out
    if fmt == "csv":
        rows = [r for r in csv.reader(line for line in text.splitlines() if not _comment(line)) if r]
        if not rows:
            return []
        if field is not None and str(field).isdigit():
            idx = int(field)
            start = 0
        else:
            header = [h.strip().lower() for h in rows[0]]
            if not field or field.lower() not in header:
                raise IntelError(f"the CSV has no column called {field!r} (its columns are "
                                 f"{', '.join(header[:12])}); give a column name or a number from 0")
            idx = header.index(field.lower())
            start = 1
        return [r[idx].strip() for r in rows[start:] if len(r) > idx and r[idx].strip()]
    if fmt == "json":
        items: list[Any]
        try:
            loaded = json.loads(text)
            items = loaded if isinstance(loaded, list) else [loaded]
        except ValueError:
            items = []
            for line in text.splitlines():
                if line.strip():
                    try:
                        items.append(json.loads(line))
                    except ValueError:
                        continue
        out = []
        for item in items:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict) and field and isinstance(item.get(field), str):
                out.append(item[field])
        if items and not out:
            raise IntelError(f"none of the JSON entries has a text field called {field!r}")
        return out
    raise IntelError(f"unknown format {fmt!r}; use one of {', '.join(FORMATS)}")


# -- what an entry is ------------------------------------------------------------

# Addresses that belong to a network's inside: private ranges, carrier NAT,
# loopback, link-local (cloud metadata lives there), multicast and reserved
# space. Spelled out rather than ipaddress's is_private, which also counts the
# documentation ranges that examples and tests use.
_INTERNAL = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10",
    "ff00::/8")]


def _public_ip(ip: ipaddress._BaseAddress) -> bool:
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return not any(ip.version == n.version and ip in n for n in _INTERNAL)


def classify(raw: str) -> tuple[str, str] | None:
    """(kind, normalised value) for one entry: "ip", "cidr", "domain" or "url".
    None for anything else, and for entries that would match internal
    addresses or far too much of the internet."""
    v = str(raw).strip().strip("\"'").strip()
    if not v or len(v) > 2048 or any(ch.isspace() for ch in v):
        return None
    if "://" in v:
        try:
            u = urlsplit(v)
            host = (u.hostname or "").rstrip(".").lower()
            port = u.port
        except ValueError:
            return None
        if u.scheme.lower() not in ("http", "https", "ftp", "ws", "wss") or not host:
            return None
        if _host_kind(host) is None:
            return None
        netloc = host if port is None else f"{host}:{port}"
        path = u.path or "/"
        return "url", f"{u.scheme.lower()}://{netloc}{path}" + (f"?{u.query}" if u.query else "")
    try:
        if "/" in v:
            net = ipaddress.ip_network(v, strict=False)
            if net.prefixlen < MIN_PREFIX[net.version] or not _public_ip(net.network_address):
                return None
            if net.prefixlen == net.max_prefixlen:
                return "ip", str(net.network_address)
            return "cidr", str(net)
        ip = ipaddress.ip_address(v)
        return ("ip", str(ip)) if _public_ip(ip) else None
    except ValueError:
        pass
    host = v.lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    return ("domain", host) if _DOMAIN.match(host) else None


def _host_kind(host: str) -> str | None:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return "ip" if _public_ip(ip) else None
    except ValueError:
        return "domain" if _DOMAIN.match(host) else None


def classify_all(entries: Iterable[str]) -> tuple[dict[str, str], int]:
    """{normalised value: kind} for a feed's entries, and how many were dropped."""
    out: dict[str, str] = {}
    dropped = 0
    for raw in entries:
        c = classify(raw)
        if c is None:
            dropped += 1
            continue
        out[c[1]] = c[0]
        if len(out) > MAX_INDICATORS:
            raise IntelError(f"more than {MAX_INDICATORS:,} entries; that's not a feed this "
                             f"server should hold in memory")
    return out, dropped


# -- matching ---------------------------------------------------------------------

@dataclass(frozen=True)
class Listing:
    feed_id: int
    feed: str
    severity: str
    attack: tuple[str, ...]
    kind: str
    value: str
    first_listed: str
    retired_at: str | None


@dataclass(frozen=True)
class Match:
    observed: str        # what the event reached
    listing: Listing


def _ts(text: str | None) -> datetime | None:
    if not text:
        return None
    return datetime.fromisoformat(str(text).replace("Z", "+00:00")).replace(tzinfo=None)


class Index:
    """Every listed indicator of every enabled feed, ready to look things up."""

    def __init__(self, listings: Iterable[Listing]):
        self.exact: dict[tuple[str, str], list[Listing]] = {}
        self.nets: dict[int, dict[tuple[int, int], list[Listing]]] = {}
        self.size = 0
        for li in listings:
            self.size += 1
            if li.kind == "cidr":
                net = ipaddress.ip_network(li.value)
                key = (net.version, int(net.network_address))
                self.nets.setdefault(net.prefixlen, {}).setdefault(key, []).append(li)
            else:
                self.exact.setdefault((li.kind, li.value), []).append(li)

    def __len__(self) -> int:
        return self.size

    def _ip_hits(self, ip: ipaddress._BaseAddress) -> list[Listing]:
        hits = list(self.exact.get(("ip", str(ip)), []))
        n = int(ip)
        bits = ip.max_prefixlen
        for prefix, table in self.nets.items():
            if prefix > bits:
                continue
            mask = ((1 << prefix) - 1) << (bits - prefix)
            hits.extend(table.get((ip.version, n & mask), []))
        return hits

    def _host_hits(self, host: str) -> list[Listing]:
        try:
            return self._ip_hits(ipaddress.ip_address(host.strip("[]")))
        except ValueError:
            pass
        hits: list[Listing] = []
        parts = host.split(".")
        # The host itself and each parent domain, but not the bare top level.
        for i in range(len(parts) - 1):
            hits.extend(self.exact.get(("domain", ".".join(parts[i:])), []))
        return hits

    def match(self, observed: Iterable[str], at: datetime) -> list[Match]:
        """What in `observed` (URLs, hosts, IPs the event reached) is listed, and
        was listed when the event happened or only later."""
        if not self.size:
            return []
        found: list[Match] = []
        for raw in observed:
            c = classify(raw) if "://" in str(raw) else None
            candidates: list[tuple[str, Listing]] = []
            if c and c[0] == "url":
                candidates += [(c[1], li) for li in self.exact.get(("url", c[1]), [])]
                host = (urlsplit(c[1]).hostname or "")
            else:
                host = str(raw).strip().lower().rstrip(".")
            if host:
                candidates += [(host, li) for li in self._host_hits(host)]
            for shown, li in candidates:
                retired = _ts(li.retired_at)
                if retired is None or at <= retired:
                    found.append(Match(shown, li))
        return found


def listing_from_row(row: Any) -> Listing:
    attack = ()
    try:
        attack = tuple(json.loads(row["attack"] or "[]"))
    except (ValueError, TypeError):
        pass
    return Listing(int(row["feed_id"]), row["feed_name"], row["severity"], attack, row["kind"],
                   row["value"], row["first_listed"], row["retired_at"])


# -- fetching ---------------------------------------------------------------------

def resolve_url(template: str, environ: dict[str, str] | None = None) -> str:
    """The URL with `{env:NAME}` placeholders filled in from the server's
    environment. Only SHADOWFAX_INTEL_* variables, so a feed URL can't be used
    to read the database password out of the environment."""
    environ = os.environ if environ is None else environ

    def fill(m: re.Match) -> str:
        name = m.group(1)
        if not ENV_ALLOWED.match(name):
            raise IntelError(f"{{env:{name}}} isn't allowed: only variables named "
                             f"SHADOWFAX_INTEL_something can go in a feed URL")
        value = environ.get(name)
        if not value:
            raise IntelError(f"the server has no {name} set; add it to the server's environment "
                             f"(for Docker, an -e option or the .env file) and restart it")
        return value

    return ENV_PLACEHOLDER.sub(fill, template)


def check_template(template: str, allow_private: bool = False) -> None:
    """Refuse a feed URL that could never be fetched safely, before it's saved."""
    for name in ENV_PLACEHOLDER.findall(template):
        if not ENV_ALLOWED.match(name):
            raise IntelError(f"{{env:{name}}} isn't allowed: only variables named "
                             f"SHADOWFAX_INTEL_something can go in a feed URL")
    probe = ENV_PLACEHOLDER.sub("KEY", template)
    try:
        u = urlsplit(probe)
    except ValueError:
        raise IntelError("that isn't a URL")
    if u.scheme not in (("https", "http") if allow_private else ("https",)):
        raise IntelError("feeds must be https:// so nobody on the network can change what they say")
    if not u.hostname or u.username or u.password:
        raise IntelError("give a plain https:// URL with a server name and no user name or password in it")


def _public_addresses(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addrs = [info[4][0] for info in infos]
    if not addrs:
        raise IntelError(f"{host} doesn't resolve to any address")
    for a in addrs:
        if not _public_ip(ipaddress.ip_address(a.split("%")[0])):
            raise IntelError(f"{host} resolves to {a}, which is not a public address; feeds are "
                             f"never fetched from inside your own network")
    return addrs


class _PinnedHTTPS(http.client.HTTPSConnection):
    """An HTTPS connection to an address that was already checked, with the
    certificate still verified against the real host name."""

    def __init__(self, host: str, address: str, port: int, timeout: float):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._address = address

    def connect(self) -> None:
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def fetch(url: str, allow_private: bool = False, timeout: float = FETCH_TIMEOUT) -> bytes:
    """Download a feed. Raises IntelError with a plain reason. Never mentions the
    resolved URL, which may hold a key."""
    u = urlsplit(url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    try:
        if allow_private:
            conn: http.client.HTTPConnection = (
                http.client.HTTPSConnection(host, port, timeout=timeout) if u.scheme == "https"
                else http.client.HTTPConnection(host, port, timeout=timeout))
        else:
            if u.scheme != "https":
                raise IntelError("feeds must be https://")
            conn = _PinnedHTTPS(host, _public_addresses(host, port)[0], port, timeout)
        conn.request("GET", path, headers={"User-Agent": "Shadowfax threat intel",
                                           "Accept": "text/plain, text/csv, application/json, */*"})
        resp = conn.getresponse()
        if resp.status in (301, 302, 303, 307, 308):
            raise IntelError(f"the feed answered with a redirect ({resp.status}); give the final "
                             f"address instead, since redirects aren't followed")
        if resp.status in (401, 403, 410):
            raise IntelError(f"the feed refused the download ({resp.status}). It may now need an "
                             f"account key: check the provider's page")
        if resp.status != 200:
            raise IntelError(f"the feed answered {resp.status}")
        body = resp.read(MAX_DOWNLOAD_BYTES + 1)
        if len(body) > MAX_DOWNLOAD_BYTES:
            raise IntelError(f"the download is over {MAX_DOWNLOAD_BYTES // (1024 * 1024)} MB")
        return body
    except IntelError:
        raise
    except ssl.SSLError:
        raise IntelError("the feed's HTTPS certificate couldn't be verified")
    except socket.timeout:
        raise IntelError(f"the feed didn't answer within {timeout:.0f} seconds")
    except (OSError, http.client.HTTPException) as exc:
        raise IntelError(f"couldn't download the feed ({type(exc).__name__})")


Fetcher = Callable[[str], bytes]
