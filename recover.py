"""
Recover a locked-out account from the server's own console (v0.22).

    python recover.py admin                      # from source
    docker exec -it shadowfax python recover.py admin

Everything else in Shadowfax goes through the API, and the API wants a signed-in
admin. If the only admin's password is lost -- or the generated one scrolled out
of the container log -- there was no way back in short of discarding the volume,
and with it every event the ledger holds.

This is that way back in, and it is deliberately narrow:

* It runs **where the database is**: on the host, or inside the container. Being
  able to run it already means being able to read and rewrite the database file,
  so it grants nothing an attacker in that position does not already have. It is
  not reachable over the network.
* It **generates** the new password and prints it once, to this terminal only --
  not to the server log, and nothing is read from the command line, where shell
  history would keep it.
* The password is marked **must-change**, every session the account had is
  ended, and its sign-in failures are cleared, so a lockout does not outlive the
  reset.
* It is **written into the ledger** as `console_password_reset` under
  Shadowfax's own `shadowfax-auth` actor, and the detector raises
  `console_recovery` (high). A reset that bypassed every authentication check is
  exactly what an analyst should see -- whether it was the owner on a bad day or
  someone with a shell on the server. This happens even when self-monitoring is
  switched off: the recovery is its own audit trail, or it is a back door.

The running server picks the change up on its next request; the dashboard shows
the new alert on its next refresh rather than live, because the push channel
lives inside the server process.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from datetime import datetime, timezone

import auth
import db

EVENT_TYPE = "console_password_reset"


def _os_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # no passwd entry for the uid, as in some containers
        return "unknown"


def recover(username: str, *, now: datetime | None = None) -> dict:
    """Reset `username`'s password from the console. Returns what was done,
    including the new password. Raises LookupError for an unknown user and
    FileNotFoundError when there is no database to recover."""
    # Imported here so `--help` works without the server's dependencies, and so
    # a missing database is reported before anything creates one.
    if not db.DB_PATH.exists():
        raise FileNotFoundError(
            f"no database at {db.DB_PATH} -- set SHADOWFAX_DB to the file the server uses")
    import app

    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    password = auth.generate_password()
    with db.get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        user = db.get_user_by_username(conn, username)
        if user is None:
            admins = [u["username"] for u in db.list_users(conn) if u["role"] == "admin"]
            conn.rollback()
            raise LookupError(f"no user '{username}'"
                              + (f"; admins are: {', '.join(admins)}" if admins else ""))
        pw_hash, salt = auth.hash_password(password)
        db.set_password(conn, user["id"], pw_hash, salt, must_change=True)
        ended = db.delete_sessions_for_user(conn, user["id"])
        cleared = db.clear_login_failures(conn, username)
        # A recovery that left the account switched off would not recover it
        # (v0.24); the event says it was re-enabled.
        re_enabled = bool(user.get("disabled"))
        if re_enabled:
            db.set_disabled(conn, user["id"], False)
        db.insert_event(conn, {
            "timestamp": now.isoformat(),
            "actor_id": app.SELF_ACTOR_ID,
            "actor_type": app.SELF_ACTOR_TYPE,
            "task": "platform_authentication",
            "event_type": EVENT_TYPE,
            "target": app.SELF_TARGET,
            "metadata": {"attempted_username": username, "role": user["role"],
                         "source": "console", "os_user": _os_user(),
                         "sessions_ended": ended, "failures_cleared": cleared,
                         "re_enabled": re_enabled},
        })
        app._rescan_actor(conn, app.SELF_ACTOR_ID)
        conn.commit()
    return {"username": username, "role": user["role"], "password": password,
            "sessions_ended": ended, "failures_cleared": cleared, "re_enabled": re_enabled}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="recover.py",
        description="Reset an account's password from the server console. The new "
                    "password is generated, shown once, and must be changed at the "
                    "next sign-in. Recorded in the ledger; raises console_recovery.")
    p.add_argument("username", help="the account to recover, e.g. admin")
    p.add_argument("--yes", action="store_true",
                   help="do not ask for confirmation (for scripts)")
    args = p.parse_args(argv)

    if not args.yes:
        print(f"This resets the password for '{args.username}', signs out all of its "
              f"sessions and raises a high alert (console_recovery).")
        try:
            answer = input("Type the username again to continue: ")
        except EOFError:
            answer = ""
        if answer.strip() != args.username:
            print("Not confirmed; nothing changed.", file=sys.stderr)
            return 1
    try:
        r = recover(args.username)
    except (LookupError, FileNotFoundError) as exc:
        print(f"error: {exc.args[0]}", file=sys.stderr)
        return 1

    print()
    print(f"  Password for '{r['username']}' ({r['role']}) reset.")
    print(f"  New password:  {r['password']}")
    print()
    print("  Shown once. It must be changed at the next sign-in.")
    if r["re_enabled"]:
        print("  The account was disabled; it has been re-enabled.")
    print(f"  Sessions ended: {r['sessions_ended']}; "
          f"sign-in failures cleared: {r['failures_cleared']}.")
    print("  Recorded in the ledger; a console_recovery alert has been raised.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
