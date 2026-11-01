# Deploying Shadowfax

This guide takes Shadowfax from "running on my laptop" to running on a server
that other people can use: PostgreSQL for storage, HTTPS in front, backups,
and a copy of the evidence ledger kept somewhere safe.

Everything here uses `docker-compose.postgres.yml` and the `Caddyfile` from
the repository. CI starts the PostgreSQL setup on every push and runs the
scripted attack against it.

## What you need

- A Linux server or VM with Docker and Docker Compose. 2 GB of memory is
  plenty.
- For HTTPS, a domain name pointing at the server, with ports 80 and 443 open.
- A copy of this repository on the server (`git clone https://github.com/jh-infosec/Shadowfax`).

Docker Desktop on Windows or macOS works fine for trying all of this out. You
only need a real server for the HTTPS part.

## 1. Start it

From the repository folder:

```bash
docker compose -f docker-compose.postgres.yml up -d --build
docker compose -f docker-compose.postgres.yml logs shadowfax
```

The log shows the admin password, once:

```
  SHADOWFAX: created the first admin account with a generated password
    username: admin
    password: 3kq0N2...
```

Open `http://localhost:8000` on the server and sign in. If the server is
somewhere else, an SSH tunnel from your own computer works until HTTPS is set
up:

```bash
ssh -L 8000:localhost:8000 you@your-server
```

Three containers start:

| Container | What it does |
| --- | --- |
| `secrets` | Creates a random database password on the first start, then exits |
| `db` | PostgreSQL 16. Not reachable from outside these containers |
| `shadowfax` | The API and dashboard, on port 8000 of the server itself only |

You never have to choose or type the database password. It lives in a Docker
volume that only the database and Shadowfax can read, and it never appears in
an environment variable or in `docker inspect`.

## 2. Save your settings in a .env file

Rather than typing `-f docker-compose.postgres.yml` every time, create a file
called `.env` next to it:

```
COMPOSE_FILE=docker-compose.postgres.yml
COMPOSE_PROFILES=https
SHADOWFAX_DOMAIN=shadowfax.example.com
```

Docker Compose reads this file on its own, so from now on the commands are
just `docker compose ...`. The rest of this guide assumes you've done this.
`.env` is in `.gitignore`, so it won't end up in a commit.

## 3. Turn on HTTPS

1. Point your domain's DNS record (an `A` record) at the server's IP address.
2. Make sure ports 80 and 443 are open in the server's firewall.
3. Run:

```bash
docker compose up -d --build
```

This adds a fourth container, Caddy, which gets a certificate for your domain
from Let's Encrypt and renews it by itself. Give it a minute, then open
`https://shadowfax.example.com`.

A few things Caddy is set up to do:

- The live stream (Server-Sent Events) is passed straight through, so the
  dashboard still updates the moment something changes.
- It tells Shadowfax each visitor's real IP address. Shadowfax only believes
  that from Caddy, so the sign-in throttle can't be dodged by sending a fake
  `X-Forwarded-For` header.
- It adds HSTS and a few other security headers.

Shadowfax itself is still only listening on the server's own port 8000, so
everyone else has to come in through HTTPS.

## 4. Lock it down

- **Change the admin password** with **Change password** in the top bar.
- **Turn on two-factor** for your account with the **Two-factor** button. Then
  make it mandatory for every admin by adding this line to `.env` and running
  `docker compose up -d`:

  ```
  SHADOWFAX_REQUIRE_ADMIN_2FA=1
  ```

- **Give everyone their own account** from the **Accounts** drawer, with the
  lowest role that does the job: `viewer` to look, `analyst` to triage,
  `admin` only for people who manage accounts.
- **Give agents API keys**, not user accounts. A key can send events and run
  the ledger checks in section 6, but can't read alerts or change anything.
- **Close everything else** in the firewall apart from 80, 443 and SSH.

## 5. Back up the database

```bash
docker compose exec db pg_dump -U shadowfax -d shadowfax --clean --if-exists -f /backups/shadowfax.sql
```

The file appears in the `backups` folder next to the compose file. These
commands work the same in PowerShell, Command Prompt and bash, because the file
is written inside the container rather than through your shell.

To take one every night at 02:15 on Linux, add this with `crontab -e` (the `%`
signs need a backslash in a crontab):

```
15 2 * * * cd /opt/Shadowfax && docker compose exec -T db pg_dump -U shadowfax -d shadowfax --clean --if-exists -f /backups/shadowfax-$(date +\%F).sql
```

Copy the backups to another machine as well. A backup on the same disk doesn't
help when the disk dies.

**Treat backups as secret.** They contain everything Shadowfax knows,
including password hashes and two-factor secrets. `backups/` is in
`.gitignore` so it can't be committed by accident.

### Restoring

```bash
docker compose stop shadowfax
docker compose exec -T db psql -U shadowfax -d shadowfax -v ON_ERROR_STOP=1 -f /backups/shadowfax.sql
docker compose start shadowfax
```

Because the backup was taken with `--clean`, it replaces what's in the
database rather than adding to it. Afterwards, check the ledger still holds
together:

```bash
python cli.py --url https://shadowfax.example.com login -u admin
python cli.py --url https://shadowfax.example.com verify
```

## 6. Keep a copy of the ledger head somewhere else

The event ledger is hash-chained, so editing or deleting an event breaks the
chain. Someone with full control of the database could still rewrite the
events and recompute the whole chain, though, and then `verify` would pass. The
defence is a copy of the chain's head that they can't reach.

Create an API key for this in the **Accounts** drawer (label it something like
"ledger anchor"). Then, from a **different machine**, save the head every hour:

```
0 * * * * curl -fsS -H "X-API-Key: sk_shadowfax_..." https://shadowfax.example.com/ledger/head >> /var/log/shadowfax-ledger-heads.log
```

Each line looks like this:

```
{"entry_count":63,"head_hash":"3936aa3c2acd81b0...","updated_at":"..."}
```

To check a saved line later, ask for the head as it was at that entry count:

```bash
curl -fsS -H "X-API-Key: sk_shadowfax_..." "https://shadowfax.example.com/ledger/head?at=63"
```

The `head_hash` has to match the one you saved. If it doesn't, something
before entry 63 has been changed, even if `verify` says the ledger is intact.

The same key can run the full check on a schedule:

```bash
curl -fsS -H "X-API-Key: sk_shadowfax_..." https://shadowfax.example.com/ledger/verify | grep -q '"ok":true' || echo "LEDGER BROKEN"
```

## 7. Upgrading

Take a backup first, then:

```bash
git pull
docker compose up -d --build
```

Database changes are applied automatically when Shadowfax starts. Read the
[changelog](../CHANGELOG.md) for anything that affects you. For example,
upgrading to v0.33 signs everyone out once.

## 8. Other settings

These can all go in `.env`:

| Setting | What it does |
| --- | --- |
| `SHADOWFAX_REQUIRE_ADMIN_2FA` | `1` makes two-factor mandatory for admins |
| `SHADOWFAX_FORWARD_WEBHOOK_URL` and `SHADOWFAX_FORWARD_WEBHOOK_SECRET` | send alerts to a SIEM over a signed webhook |
| `SHADOWFAX_FORWARD_SYSLOG` | send alerts over syslog, e.g. `tcp://siem.example.com:6514` |
| `ANTHROPIC_API_KEY` | lets the investigation assistant use a model |
| `SHADOWFAX_PORT` | the server-local port for Shadowfax (default 8000) |

The README's [configuration table](../README.md#configuration) lists
everything else. To use one of those, add it to the `environment` section of
`docker-compose.postgres.yml`.

To check on it: `docker compose ps` shows each container's health, and
`GET /healthz` answers without signing in, for an uptime monitor.

## What this setup doesn't do

- **It's one server.** If the server goes down, Shadowfax goes down with it.
  Backups (section 5) are how you recover.
- **Two-factor secrets are stored readable** in the database, because they're
  needed to check codes. Keep the database, its volume and its backups private.
- **Docker's logs grow** until you limit them. Docker's documentation on the
  `json-file` logging driver explains how.

## Removing it

`docker compose down` stops everything and keeps your data.
`docker compose down -v` deletes the database **and** its password together.
Never delete one of those two volumes without the other, because the database
only accepts the password it was created with.
