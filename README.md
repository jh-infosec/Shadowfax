# Shadowfax

[![CI](https://github.com/jh-infosec/Shadowfax/actions/workflows/ci.yml/badge.svg)](https://github.com/jh-infosec/Shadowfax/actions/workflows/ci.yml)

> A security operations platform for monitoring autonomous AI agents.

![Shadowfax's dashboard during the scripted attack: alerts arriving live as an agent goes rogue, a second agent follows instructions hidden in a web page, and the separate alerts come together as one kill chain](docs/demo.gif)

*The scripted attack playing out on the live dashboard (36 seconds, sped up).*

## Why I built this

AI agents are being trusted with more and more: writing code, running tools,
calling APIs and making decisions with very little supervision. Most security
tooling was built to watch people, service accounts and servers. It doesn't
really have a concept of an agent that decides for itself what to do next.

Shadowfax is my attempt at what a security operations platform could look like
if AI agents were treated as identities in their own right. I'm building it
alongside my studies in offensive security and AI, and it's the main project in
my portfolio. It tries to answer three questions about any agent: what is it
doing, why is it doing it, and should that be trusted?

It watches, explains and alerts. It isn't a security boundary and doesn't
block anything.

## What it does

- **Watches real agents.** One dependency-free file reports what Claude Code,
  any MCP client or your own Python tools actually do, without changing the
  agent, and keeps events in a local spool while Shadowfax is down.
- **Knows what each agent is for.** Permission profiles say which tools and
  targets an agent was given, so its first step outside them is reported with
  no baseline needed. Shadowfax can draft a profile from what an agent did.
- **Catches what matters for agents.** 37 deterministic detectors, including
  prompt injection and an agent acting on it, destructive commands, data
  leaving, credentials being touched, and threat intelligence feeds checked
  against everything agents reach, even before an entry was listed.
- **Follows work between agents.** When one agent hands work to another,
  Shadowfax follows it: an injection one agent read and passed on is caught
  when another acts on it, and so is a restricted agent getting a
  better-equipped one to do what it can't. Claude Code's subagents are
  followed this way automatically.
- **Notices poisoned memory.** An agent writing an injection into CLAUDE.md or
  another memory file, where every later session would load it, is caught as
  it happens, and again if it comes back days later.
- **Puts it in context.** Every alert is mapped to MITRE ATT&CK or ATLAS,
  related alerts become incidents, and an attack that moves through the kill
  chain in order is flagged.
- **Stays quiet on ordinary work,** and lets analysts mute a false positive
  with a reason and an end date, on the record.
- **Keeps evidence that can be checked.** Every event is hash-chained, so an
  edit, a deletion or a reordering is detectable, and old events can be
  archived without breaking the chain.
- **Works for a team.** Live dashboard, case notes, an optional assistant that
  explains alerts in plain English, roles, two-factor sign-in, a desktop app,
  a command line, and alerts sent on to a SIEM.
- **Runs anywhere.** SQLite with no setup or PostgreSQL, a signed image on
  ghcr.io, and a one-command production setup with HTTPS.

## How well it works

- **Noise:** on two weeks of ordinary work (about 12,900 events from coding
  agents, their subagents and the memory files they load, the planner handing
  them work, a research agent, a CI runner, an ops agent, a nightly backup and
  three people) it raises **0.93 alerts per 1,000 events** with the policy it
  ships with, and **0.39** once each agent has a profile, while catching all
  18 attacks in the same run (20 with profiles). CI fails if either number gets
  worse. [How that's measured](docs/detection.md#how-noisy-is-it).
- **Speed:** recording an event takes about 10 ms whether the agent has 1,000
  events of history or 50,000. [The benchmark](docs/evidence.md#recording-stays-fast).
- **Tests:** every push runs 1,238 API checks on SQLite and again on
  PostgreSQL, 93 checks in a real browser, the desktop app's own tests, the
  scripted attack against the built image, and vulnerability and code
  scanning. [What CI checks](docs/development.md#continuous-integration).

## Try it

**Look around without setting anything up.** Demo mode adds a "Look around as
a visitor" button, replays the scripted attack every hour, and lets visitors
read everything and change nothing:

```bash
docker run -p 8000:8000 -e SHADOWFAX_DEMO=1 ghcr.io/jh-infosec/shadowfax
```

Then open `http://localhost:8000`. [Running a public demo](docs/public-demo.md)
covers hosting one for other people.

**Run your own:**

```bash
docker run -d --name shadowfax -p 8000:8000 -v shadowfax-data:/data \
  ghcr.io/jh-infosec/shadowfax
docker logs shadowfax        # shows the admin password generated on first start
python demo.py --password <that password>     # replay the scripted attack
```

**Watch your own Claude Code:**

```bash
python shadowfax_agent.py configure --url http://localhost:8000 --api-key <a key from Accounts>
python shadowfax_agent.py claude-code --write ~/.claude/settings.json
```

[Getting started](docs/getting-started.md) has the other ways to run it, and
[Connecting agents](docs/agents.md) covers MCP clients and Python agents.

## A look around

**The alert table,** worst first, each alert tagged with its ATT&CK or ATLAS
technique.

![The Shadowfax dashboard after the scripted attack, with alerts sorted worst first and each tagged with its ATT&CK technique](docs/screenshots/dashboard.png)

**An incident and the kill chain it completed,** escalated to critical because
it reached exfiltration.

![Incident drawer showing a completed kill chain from reconnaissance to exfiltration](docs/screenshots/incident-kill-chain.png)

There's more in [the tour](docs/tour.md).

## Documentation

| Guide | What's in it |
| --- | --- |
| [Getting started](docs/getting-started.md) | Every way to run it, PostgreSQL, the command line, the desktop app, all settings |
| [Connecting agents](docs/agents.md) | Claude Code, MCP clients, Python agents, agents handing work to each other, permission profiles, capability manifests |
| [Detection](docs/detection.md) | How noisy it is, prompt injection, threat intelligence, muting false positives, other tools' findings, SIEMs |
| [Investigating](docs/investigation.md) | Case notes and the investigation assistant |
| [Evidence and history](docs/evidence.md) | The hash-chained ledger, speed on long histories, archiving |
| [Securing Shadowfax](docs/security.md) | Sign-in, two-factor, lockouts, Shadowfax watching itself, the security model |
| [Deployment](docs/deployment.md) | PostgreSQL and HTTPS on a server, backups, upgrades |
| [Running a public demo](docs/public-demo.md) | Demo mode and hosting it |
| [Developing and testing](docs/development.md) | The test suites, CI, releasing, screenshots |
| [Architecture](architecture.md) | How it's built and why |
| [Security policy](SECURITY.md) | Reporting a vulnerability |
| [Code signing policy](CODE_SIGNING.md) | What's signed, by whom, and the desktop app's privacy statement |

## Architecture

```
                 Browser
                    │
                    ▼
            Dashboard (React)
                    │
                    ▼
              Shadowfax API
                    │
         ┌──────────┴──────────┐
         ▼                     ▼
 SQLite or PostgreSQL    Detection engine
```

Every event comes in through the API. The detection engine checks the actor's
behaviour against the current policy and produces alerts. The dashboard only
talks to the API, so it decides how an alert looks but never whether it exists.

**Stack:** Python, FastAPI, SQLite or PostgreSQL, React and Vite, Electron,
Docker.

## Philosophy

Shadowfax is meant to help analysts, not replace them.

Detection is deterministic and driven by policy. Every rule is written out in
one file, where the policy controls it and the tests can check it.

Language models are only used to explain and summarise. They're never the
security boundary.

## Roadmap

Everything on the original list for 1.0 is done, apart from code-signing the
Windows installer. The history is in [CHANGELOG.md](CHANGELOG.md) and the plan
in [ROADMAP.md](ROADMAP.md). The most recent versions:

| Version | Added |
| --- | --- |
| 0.40 | MIT licence, security policy, pinned dependencies, vulnerability and code scanning |
| 0.41 | Recording stays fast as history grows, archiving old events |
| 0.42 | Muting false positives, with a reason and an end date |
| 0.43 | Noise measured on two weeks of ordinary work and held down in CI |
| 0.44 | A public demo mode, and this shorter README |
| 0.45 | One-click hosting for the demo on Render, and code signing through SignPath |
| 0.46 | Following work between agents: injections that spread, and confused deputies |
| 0.47 | Claude Code subagents followed automatically, as hand-offs |
| 0.48 | Poisoned memory: injections written into CLAUDE.md and other memory files |

## Licence

Shadowfax is released under the [MIT licence](LICENSE): use it, change it and
share it, as long as the copyright notice comes along.
