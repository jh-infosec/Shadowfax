# Running a public demo

How to put Shadowfax somewhere anyone can look at it, without giving anyone
the ability to change it. Back to the [README](../README.md).

## What demo mode does

Start the server with `SHADOWFAX_DEMO=1`:

```bash
docker run -d --name shadowfax-demo -p 8000:8000 -e SHADOWFAX_DEMO=1 \
  ghcr.io/jh-infosec/shadowfax
```

Then:

- **Anyone can look around.** The sign-in page gets a **Look around as a
  visitor** button. It signs in to a shared account called `visitor` with the
  viewer role, so a visitor can see every alert, incident, timeline and the
  ledger, and change nothing. The server enforces that on every endpoint, not
  just by hiding buttons.
- **The shared account can't be taken over.** Its password and two-factor
  can't be changed by anyone signed in as it, because either would lock every
  other visitor out. Pressing the button again and again can't fill the
  database either: only the newest 500 visitor sessions are kept.
- **It's never empty and never stale.** When the server starts, and then every
  hour, it resets its data and replays the scripted attack from `demo.py`
  against itself, so there's always a fresh kill chain, a prompt injection and
  a brute force against its own sign-in page to look at. A banner tells
  visitors when the next reset is.
- **A replay that goes wrong is logged.** It runs with the same checks as
  `demo.py --assert`. If a reset doesn't raise everything the script says it
  should, a line starting `[demo]` goes into the server log.
- **No model calls on a stranger's behalf.** The investigation assistant uses
  its built-in explanations in demo mode, even if `ANTHROPIC_API_KEY` is set,
  so visitors clicking **explain** can't spend your credit. Set
  `SHADOWFAX_DEMO_ALLOW_MODEL=1` if you want the model anyway.

Your own admin account works as normal. The replay signs in as a separate
admin account, `demo-operator`, whose password is made up fresh every time
the server starts and never leaves the process.

## Settings

| Setting | What it does |
| --- | --- |
| `SHADOWFAX_DEMO` | `1` turns demo mode on |
| `SHADOWFAX_DEMO_RESET_MINUTES` | how often the data resets (default 60, at least 1) |
| `SHADOWFAX_DEMO_SELF_URL` | where the replay reaches the server (default `http://127.0.0.1:8000`, the port the image listens on) |
| `SHADOWFAX_DEMO_ALLOW_MODEL` | `1` lets visitors' explanations use a model |

## Hosting it

Any service that runs a Docker image and gives it a public HTTPS address will
do. It's one process with a SQLite file, and nothing has to persist: the data
is rebuilt on every start.

### On Render's free plan

The repository has a `render.yaml` that sets this up. You need a Render
account (free, no card), signed in with GitHub.

1. In Render, choose **New**, then **Blueprint**.
2. Pick the Shadowfax repository. Render reads `render.yaml` and shows one web
   service, `shadowfax-demo`, on the free plan, with `SHADOWFAX_DEMO=1`.
3. Choose **Apply**. Render builds the Dockerfile (a few minutes the first
   time) and gives the service an address ending in `.onrender.com`.
4. Open it. You should see the **Look around as a visitor** button.

What the free plan means for a demo:

- It goes to sleep after 15 minutes with no visitors, and the next visitor
  waits about a minute while it wakes. The sample data is there straight
  away, and the scripted attack replays a few seconds after that.
- It has 512 MB of memory and a small share of a CPU, which is enough for
  this but makes the first replay slower than on your own machine.
- Every push to `main` rebuilds and redeploys it, so the demo always runs the
  latest code.
- The admin password is printed once in Render's log for the service, as
  usual. You don't need it for the demo.

### Anywhere else

Point the service at the Dockerfile (or at `ghcr.io/jh-infosec/shadowfax`, once
a release with demo mode is published), set `SHADOWFAX_DEMO=1`, and send
traffic to port 8000.

Some things to know before you share the link:

- **Use a fresh instance.** Don't turn demo mode on for a Shadowfax that holds
  real data: visitors can read everything on it, and the hourly reset replaces
  it with the sample data.
- **Run one copy.** Each copy replays the attack on its own schedule, so two
  copies behind one address would show different data from one page load to
  the next.
- **The admin password is still printed once** in the log on first start, as
  usual. Keep it, or set `SHADOWFAX_ADMIN_PASSWORD` as a secret on the host.

On every push, CI starts the image it builds in demo mode and checks it the
way a stranger would see it: the visitor button, the data, the banner, and a
visitor being refused when they try to reset the data.
