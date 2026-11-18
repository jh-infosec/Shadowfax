# Security policy

Shadowfax is a security tool, so a hole in it matters more than most. Thank
you for taking the time to report one.

## Reporting a vulnerability

Please report it privately, not in a public issue:

1. Open the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe what you found, how to reproduce it, and what an attacker could
   do with it.

Only the maintainer can read the report. This is a one-person project, so I
can't promise a fixed timetable, but I aim to reply within a week and to fix
anything serious in the next release. I'm happy to credit you in the
changelog, or to leave your name out if you'd rather.

## What's in scope

The latest release, and `main`:

- the server (`app.py` and the modules it uses) and the Docker image
- the dashboard
- the desktop app and its installers
- the agent connector, `shadowfax_agent.py`

Things I especially want to hear about: a way to sign in without the right
password or second factor, to read or change data your role shouldn't reach,
to alter the evidence ledger without `/ledger/verify` noticing, to make the
server fetch something inside its own network, to run code in the desktop app,
or to make an attack go undetected that the README says is detected.

## What's not

- The demo's well-known `admin/admin` login when you run it from source on
  purpose. The published image generates a password.
- Attacks that need someone who is already an admin on your Shadowfax.
- Advisories in build-only tools (Vite, electron-builder and their
  dependencies) that never reach users. `supply_chain.py` explains the line
  between what ships and what doesn't.

## How dependencies are kept honest

- The server's Python packages are pinned, with hashes, in `requirements.lock`.
  The Docker image installs exactly those and refuses anything else.
- Every push, and once a week even when nothing has changed, CI runs
  `supply_chain.py`, which checks the Python packages, the dashboard's
  JavaScript and the Electron inside the desktop app against the public
  vulnerability databases. A known high or critical vulnerability in anything
  that ships fails the run, and GitHub emails the maintainer.
- CodeQL scans the Python and JavaScript code on the same schedule, and its
  findings appear in the Security tab.
