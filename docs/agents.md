# Connecting agents and declaring what they're for

How real agents report to Shadowfax, and how to tell it what each agent is allowed to do. Back to the [README](../README.md).

## Connecting your agents

Shadowfax can only watch what it's told about. `shadowfax_agent.py` is a single
file that reports what a real agent does, without you changing the agent. It
only needs Python 3.9 or newer, nothing to install, so copy it onto whatever
machine runs the agent.

First, make an API key for the agent: sign in as an admin, open **Accounts**,
and click **New API key**. Then save the key on the agent's machine and check
it works:

```bash
python shadowfax_agent.py configure --url http://your-shadowfax:8000 --api-key sk_shadowfax_...
```

```
Saved to /home/you/.shadowfax/agent.json (readable only by you).
Connected to http://your-shadowfax:8000 as agent 'ai-agent-laptop'. The ledger has 69 entries.
```

The agent is named after the computer unless you pass `--agent-id`. Give it a
[permission profile](#agent-permissions) under that name to say what it's for.

### Claude Code

```bash
python shadowfax_agent.py claude-code --write ~/.claude/settings.json
```

That adds two hooks to Claude Code's settings and leaves everything else in
the file alone (the old file is kept as `settings.json.bak`). Restart Claude
Code. From then on, every tool it uses is reported as a `tool_call`, and what
the tool gave back as a `tool_result`, so a poisoned web page or file is caught
the moment Claude reads it. Leave out `--write` to just print the settings.
The same hooks work for agents built on the Claude Agent SDK.

![A Claude Code session reading a poisoned changelog and then running the curl it asked for, as alerts in Shadowfax](screenshots/claude-code.png)

### Any MCP client

Claude Desktop, Cursor and most other agent tools connect to MCP servers. Put
the proxy in front of a server by changing the command that starts it. For
example, in Claude Desktop's `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "github": {
      "command": "python",
      "args": ["C:\\tools\\shadowfax_agent.py", "mcp-proxy", "--server", "github", "--",
               "npx", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

The proxy passes every message through unchanged and reports the server's tool
list, each call and each result. Because it sees the tool list, it also catches
a server that rewrites one of its tools between runs (`tool_definition_changed`)
or hides instructions in a tool's description. If Claude Code hooks are already
reporting the calls, add `--manifest-only` so they aren't counted twice.

### Your own Python agent

```python
from shadowfax_agent import Reporter

sfx = Reporter("research-agent-1")

@sfx.tool
def fetch(url: str) -> str:
    ...
```

Each call to a decorated tool is reported with its arguments, and what it
returned is scanned like any other result. `sfx.tool_call(...)`,
`sfx.tool_result(...)` and `sfx.manifest(...)` are there for anything the
decorator doesn't fit.

### What it promises

- **It never gets in the agent's way.** Shadowfax watches, it doesn't block. The
  hook always exits cleanly and prints nothing, and the proxy forwards every
  message before it looks at it.
- **Nothing is lost when Shadowfax is down.** Events wait in
  `~/.shadowfax/spool` and are sent next time, oldest first.
- **The key stays out of the agent's reach, as far as it can.** It's read from
  `~/.shadowfax/agent.json` (readable only by you), never put into the settings
  the agent's own shell inherits. An agent running as you could still read that
  file, so give each agent its own key. A key can only send events, and each
  one has an ingest budget.
- **It sends what the tools did, not what you asked.** Your prompts and the
  model's replies are not reported.
- **Large results are cut to fit.** A result over about 15 KB keeps its start
  and its end, so an instruction hidden at the bottom of a long page is still
  seen. Something hidden in the middle of a very long page can be cut out.

`python shadowfax_agent.py check` tests the connection without sending
anything, and `python shadowfax_agent.py flush` sends whatever is waiting.

## Agents that hand work to each other

More and more agent systems are teams: a planner hands a task to a coder, a
researcher passes what it found to a writer, an orchestrator fans work out to
helpers. That's also how an attack moves between them. An injection doesn't
have to be acted on by the agent that read it; it can be passed on, in a
perfectly ordinary-looking hand-off, to another agent that has the tools to
act on it.

When one of your agents hands work to another, report it:

```python
from shadowfax_agent import Reporter

reporter = Reporter("planner-1")
reporter.handoff("coder-2", "Fix the export bug in issue 88: " + issue_text)
```

Anything else that posts events can send the same thing: an event of type
`agent_handoff` whose target is the receiving agent's id, with what was passed
on in `metadata.message`.

Shadowfax writes the other half itself: a `handoff_received` event in the
receiving agent's timeline, saying who it came from. Nobody can post one of
those directly. On the dashboard, each side of a hand-off links to the other
agent.

What it watches for:

- **An injection passed on.** If the sender read injected content in the last
  hour, and its hand-off passes on something planted there (a URL, a host, an
  address or a path it hadn't used before reading it), the received hand-off
  is marked **tainted**, with where the injection came from. If the receiving
  agent then uses that thing, it raises `injection_spread` (critical), naming
  every agent it passed through: `planner-1 → coder-2 → deployer-3`. It
  follows chains of any length.
- **Instructions in the hand-off itself.** The message is read like any other
  content, so instructions aimed at an AI in it raise `prompt_injection`.
- **A confused deputy.** If the receiving agent does something its own profile
  allows but the sender's profile doesn't, within an hour of the hand-off, it
  raises `delegated_escalation`: the sender may be getting round its limits
  through this agent. It's only judged when the sender has a profile.
- **Who may delegate to whom.** A profile can list `allowed_delegates`, the
  agents it may hand work to (patterns allowed). Handing work to anyone else
  is a `permission_violation`. Delegation a profile plans for this way is also
  never reported as escalation: an orchestrator can't do its workers' jobs by
  design.

```json
"planner-*": {
  "description": "Reads the issue tracker and hands tasks to the coding agents.",
  "allowed_tools": ["fetch_issue"],
  "allowed_delegates": ["dev-agent-*"]
}
```

An orchestrator handing work to many agents at once isn't counted as lateral
movement. Claude Code's own subagents run under the same agent id as the
session that started them; their events carry a `subagent` field.


## Agent permissions

Most detectors decide something is wrong because it's unusual: more targets than
normal, faster than its baseline, more data than a threshold. None of them know
what the agent was actually meant to do. A permission profile tells Shadowfax
exactly that.

```json
"agent_permissions": {
  "unprofiled_agents": "alert",
  "profiles": {
    "recon-agent-*": {
      "description": "Authorised recon for engagement alpha: scan and fetch, never a shell.",
      "allowed_tools":  ["nmap", "curl", "dig", "nikto"],
      "denied_tools":   ["nc", "ncat", "netcat", "bash", "sh", "powershell"],
      "denied_targets": ["~/.ssh/*", "/etc/*", "*.pem"]
    }
  }
}
```

Anything outside the profile raises `permission_violation`. It's **critical** if
the tool or target was explicitly denied and **high** if it just wasn't granted.
No baseline is needed, so an agent's very first action can trigger it. With
`"unprofiled_agents": "alert"`, an AI agent that nobody wrote a profile for
raises one `undeclared_agent` alert.

I designed the rules so a profile can't quietly fail open:

| Rule | Why |
|---|---|
| Leaving out a list means unrestricted, an empty list means nothing | They're two different statements |
| Deny beats allow | If you wrote it down as forbidden, it stays forbidden |
| A deny matches any spelling of a tool (`/usr/bin/nc`, `NC`, `nc.exe`) | Renaming the binary shouldn't get around it |
| An allow only matches as written, against the resolved path | `/repo/../etc/shadow` isn't inside `/repo/*` |
| A tool call with no tool name, or an event with no target, isn't granted | Missing information isn't permission |
| Broken profiles are rejected by `PUT /policy` with every problem listed | `"allowed_tools": "nmap"` would otherwise grant `n`, `m`, `a` and `p` |
| One alert per distinct breach | Forty retries of the same denied tool is one finding |
| `allowed_delegates` limits which agents it may hand work to | See [Agents that hand work to each other](#agents-that-hand-work-to-each-other) |

Deny lists are a backstop. The allow list is the real control. A relative path
like `../../etc/passwd` can't be resolved without knowing the agent's working
directory, so a deny pattern won't reliably catch it, but an allow list will
because it was never granted.

Profiles are matched by exact actor id first, then by the most specific pattern
(`build-prod-*` beats `build-*`, which beats `*`). Because a profile is part of
the policy, adding one rescans history, so every action an agent already took is
judged against it.

You can also ask in advance. `GET /actors/{id}/permissions?tool=nc&target=...`
(or `cli.py permissions`) tells you whether an action would be reported, using
the same logic the detector uses afterwards. An agent runtime could use that to
refuse a call before making it. Shadowfax itself still only observes, because a
monitor that's also the gate becomes the first thing an attacker wants to take
down.

### Capability manifests

A profile says what an agent is allowed to do. The framework running it knows
what it can do: its tool list and its MCP servers. A manifest is that list,
posted by whatever starts the agent:

```bash
curl -X POST http://localhost:8000/agents/build-agent-2/manifest \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"tools": ["read_file", "run_tests", "bash"],
       "mcp_servers": {"github": {"tools": [{"name": "create_issue"}]}}}'
```

It accepts plain names, Anthropic and MCP tool objects, OpenAI function tools
and MCP `tools/list` results. MCP tools are named like
`mcp__github__create_issue`. Only the names are stored. Descriptions and schemas
are dropped on arrival, since that's where an injected instruction would hide.
If any part of a manifest can't be read, the whole thing is rejected rather than
silently missing a tool.

| Alert | Severity | Meaning |
|---|---|---|
| `excess_capability` | high if denied, otherwise medium | configured with a tool the profile doesn't grant, caught before it's used |
| `capability_drift` | low | a later manifest added tools |
| `unlisted_tool_call` | medium | the agent called a tool its own manifest doesn't list |

The last one is the interesting case. An agent calling a tool that isn't in its
configuration either has a wrong manifest or got the tool from somewhere else,
like an injected MCP server.

### Drafting a profile

Writing a profile by hand means knowing every tool the agent needs. The **Draft
a profile** button in an agent's drawer (also `GET /agents/{id}/profile-draft`
and `cli.py permissions <agent> --draft`) builds a first draft from the agent's
actual tool calls. It deliberately doesn't copy the manifest, because a profile
copied from the configuration would just grant whatever the agent was given,
which is exactly what `excess_capability` is meant to question.

- Tools it called are allowed, except shells and raw sockets (`bash`, `sh`,
  `powershell`, `nc` and so on), which are denied wherever they appear.
- Configured tools it never called aren't granted. Once the profile is saved
  they show up as `excess_capability`, which makes them candidates to remove.
- The usual secret locations (`~/.ssh/*`, `~/.aws/*`, `/etc/*`, `*.pem`) are
  denied. No target allow list is guessed.
- It shows every past event the draft would have flagged.

Nothing is saved automatically. **Open in policy editor** puts the draft into the
policy under the agent's id or its family pattern (like `recon-agent-*`), and it
only takes effect when an analyst saves it.
