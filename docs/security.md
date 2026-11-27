# Securing Shadowfax itself

Sign-in, two-factor, lockouts, how Shadowfax watches its own front door, and the security model. Back to the [README](../README.md).

## The sign-in page

Shadowfax has had a `brute_force_auth` detector since v0.1, but until v0.10 its
own sign-in page would have let an attacker guess forever. That didn't sit right
with me, so the login is now properly protected.

- **Backoff, then lockout.** After a few failures the caller has to wait longer
  and longer between attempts (2s, 4s, 8s, up to a cap), then the scope is
  locked. Someone who mistyped won't notice, but a password list slows to a
  crawl. Nothing sleeps on the server: it replies straight away with `429` and a
  `Retry-After`, so a flood can't tie up connections.
- **Lockout is per username and source, never per account.** Locking an account
  after N failures would let anyone who knows a username lock its owner out. A
  looser limit per source address catches password spraying, but it only slows
  things down and never locks, because a whole office or VPN can share one
  address.
- **No username enumeration.** Failures are counted the same way whether or not
  the account exists, and a check for a missing user does the same argon2 work
  as a real one, so response times don't give anything away.

```
sign-in throttle: lock after 5 failures in 15 min, for 15 min (backoff from 3)

USERNAME       SOURCE       FAILS  STATE     LAST FAILURE
j.bartlett     127.0.0.1    5      LOCKED    2026-09-30T12:02:11
```

`X-Forwarded-For` is only believed from a proxy you name. The client sets that
header, so if Shadowfax trusted it from anyone, an attacker could just make up a
new address for every guess. The Docker image trusts nobody's by default. Behind
a reverse proxy, set `FORWARDED_ALLOW_IPS` to the proxy's address so Shadowfax
sees each visitor's real address; the PostgreSQL compose file does this for its
Caddy. (If you run uvicorn yourself, note that it trusts `127.0.0.1` unless you
set `FORWARDED_ALLOW_IPS` too.)

This slows guessing down. It won't stop an attacker with lots of addresses, and
it's not a replacement for good passwords and two-factor.

### Shadowfax watches itself

Failed sign-ins and lockouts are stored as ordinary events under the actor
`shadowfax-auth`, in the same ledger as everything else. The normal
`brute_force_auth` detector fires on them and they show up in the normal alert
table. There's no separate audit log to keep in sync.

The username someone tried is stored in the event's metadata, not as the actor,
because it's attacker-controlled text. Otherwise anyone could "sign in" as a
real actor and inject events into their timeline.

Set `SHADOWFAX_SELF_MONITOR=0` to turn this off.

### Locked out of your own Shadowfax

If the only admin password is lost, reset it from the machine Shadowfax runs on:

```bash
docker exec -it shadowfax python recover.py admin               # published image
docker exec -it shadowfax python recover.py admin --remove-2fa  # lost phone too
docker compose exec shadowfax python recover.py admin           # docker compose
python recover.py admin                                          # from source
```

It asks you to type the username again and then prints a new password once. You
have to change it at the next sign-in, all of the account's sessions are ended
and its sign-in failures are cleared. It works directly on the database, so it
can't be reached over the network. It isn't silent either: the reset goes into
the ledger and raises a high `console_recovery` alert naming the account and the
OS user, even with self-monitoring off. None of your events are touched.

## Security

Found a vulnerability? Please report it privately, as [SECURITY.md](../SECURITY.md)
explains, rather than in a public issue.

Every endpoint needs authentication. People sign in for a bearer token and
agents send events with an API key. There are three roles: `viewer` can read,
`analyst` can acknowledge, assign and edit the policy, and `admin` manages
users, keys and resets. Tokens and keys are only stored as fingerprints, never
in a usable form.

On a fresh database the first admin comes from `SHADOWFAX_ADMIN_USERNAME` and
`SHADOWFAX_ADMIN_PASSWORD`. If they aren't set, running from source creates
`admin` / `admin` with a warning, and the Docker image generates a random
password and prints it once. Set real credentials before exposing it anywhere.

**Passwords.** At least 12 characters, not the username and not one of the
obvious ones. They're hashed with argon2id using the settings OWASP recommends,
which makes guessing them on a GPU far more expensive than the PBKDF2 hashing
Shadowfax used before v0.33. Accounts from older versions are moved over the
next time they sign in, so nobody has to reset anything. Changing your password
needs the current one (throttled like sign-in) and signs out your other
sessions. When an admin resets someone's password, that person has to choose a
new one before they can do anything else. Changes and resets go into the
ledger.

**Sessions.** A sign-in lasts up to 12 hours, but the token itself only lasts 30
minutes. The dashboard swaps it for a new one in the background every 10
minutes, and the CLI does the same before a command, so a copied token is only
useful for a short time. If a token that has already been swapped is ever used
to refresh again, someone else must have a copy of it. Shadowfax can't tell
which side is the real user, so it ends the session for both and raises a high
`session_token_reuse` alert (T1550). Leave the dashboard closed for more than
half an hour, or the CLI unused, and you'll need to sign in again. Both times
can be changed (see Configuration).

**Accounts.** Admins manage users and API keys from the **Accounts** drawer. New
users get a generated password they must change on first sign-in, and API keys
are shown once. Creating a new admin raises `admin_account_created` (T1136) and
promoting someone to admin raises `admin_role_granted` (T1098), since an extra
admin account is a classic way to keep access. Disabling an account signs it out
everywhere without deleting anything it did. Admins can't change their own role
or disable themselves, and the last enabled admin can't be demoted or disabled.

**Two-factor sign-in.** Any account can turn on TOTP from the **Two-factor**
button by scanning a QR code into an authenticator app. Each code works once,
one 30 second step of clock drift is allowed, and wrong codes count towards the
same lockout as wrong passwords. Ten recovery codes cover a lost phone. Turning
it off needs the password and a code. An admin can remove it from someone
else's account, which raises `mfa_removed` (T1556). Set
`SHADOWFAX_REQUIRE_ADMIN_2FA=1` to make it mandatory for admins: an admin
without it can only reach the enrolment screen until it's set up.

**Other protections.**

- Session tokens never appear in URLs. The live stream uses a single-use ticket
  that expires after 30 seconds.
- Requests are limited before they're parsed: 2 MiB per body, 1,000 events per
  request and 16 KiB of metadata per event.
- Each credential can send 6,000 events a minute by default. Going over is
  refused with `429` and raises an `ingest_flood` alert.
- Timestamps must be ISO 8601 and are stored in UTC.
- Because alerts are rebuilt from the whole history, a new event dated in the
  past can make old alerts disappear. When that happens Shadowfax records which
  alerts went and who sent the event, and raises `history_rewritten`. An alert
  that only moves onto the earlier event, saying the same thing (an agent's
  first action arriving late, for example), isn't counted: nothing it
  concluded changed.
- Nobody can send events as Shadowfax's own actors.
- The CLI only sends a saved token to the server it was saved for, and doesn't
  follow redirects.

For a shared deployment, follow [docs/deployment.md](deployment.md):
PostgreSQL, HTTPS in front, and the database and its backups kept private. The
two-factor secrets have to be stored in a readable form, so anyone who can read
the database can read them.
