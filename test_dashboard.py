"""
Dashboard browser tests (v0.14).

CI has built the dashboard since v0.13 and could not tell a built bundle from a
working one. Vite exits 0 on a page that renders nothing: a component throwing
on mount, an API field quietly renamed, a filter that drops every row — all of
these ship green. The one part of Shadowfax a person actually looks at was the
one part nothing checked.

These are the assertions a human makes when they glance at the dashboard and
believe it. Each one is about *what the engine found arriving on screen*, not
about markup: that alerts the API returned are rendered as rows, that an
ingested finding says who reported it, that a kill chain Shadowfax correlated
is drawn, that the ledger badge reflects the real chain. A test that only
asserted "a table element exists" would pass on an empty table, which is the
failure it most needs to catch.

Run against a Shadowfax that already has data -- `demo.py` is what puts it
there, so in CI this runs straight after the replay:

    python demo.py --fast --assert
    python test_dashboard.py

    python test_dashboard.py --url http://127.0.0.1:8000 --headed

Playwright is a developer dependency, not a runtime one. `requirements-dev.txt`
carries it; the shipped container has neither it nor a browser.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8000"

passed = 0
failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    global passed
    if condition:
        passed += 1
        print(f"[PASS] {label}")
    else:
        failures.append(f"{label}{(' — ' + detail) if detail else ''}")
        print(f"[FAIL] {label}{(' — ' + detail) if detail else ''}")


def seed_if_empty(url: str) -> bool:
    """Make sure there is something to look at.

    The tests assert that findings *reach the screen*, so they need a populated
    instance. In CI the replay has already run; locally it may not have, and a
    test that silently passes against an empty dashboard would be worthless.
    """
    try:
        req = urllib.request.Request(
            f"{url}/auth/login",
            data=json.dumps({"username": "admin", "password": "admin"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            token = json.loads(resp.read())["token"]
        req = urllib.request.Request(f"{url}/stats",
                                     headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            counts = json.loads(resp.read())["alert_counts"]
        return sum(counts.values()) > 0
    except (urllib.error.URLError, urllib.error.HTTPError, KeyError):
        return False


def run(url: str, headed: bool) -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("The dashboard tests need Playwright:\n"
              "    pip install -r requirements-dev.txt\n"
              "    python -m playwright install chromium")
        return 2

    if not seed_if_empty(url):
        print(f"No alerts at {url} — run `python demo.py --fast` first, or check "
              f"that Shadowfax is up.\nThese tests assert that findings reach the "
              f"screen, so an empty instance would make them meaningless.")
        return 2

    print(f"\n== dashboard, in a real browser ({url}) ==")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not headed)
        page = browser.new_page(viewport={"width": 1500, "height": 950})

        # A dashboard that renders but logs errors is a dashboard mid-failure.
        console_errors: list[str] = []
        page.on("console", lambda m: console_errors.append(m.text)
                if m.type == "error" else None)
        # Only the message: a React stack is a page of minified frames and the
        # first line is the part that names what went wrong.
        page.on("pageerror",
                lambda e: console_errors.append(str(e).strip().splitlines()[0]))

        try:
            _run_checks(page, url)
        except Exception as exc:
            # A component that throws on mount takes the whole page with it, and
            # the first thing to notice is a selector that never appears. Report
            # that as a finding rather than a traceback: CI fails either way, but
            # only one of them tells you what broke.
            first_line = str(exc).strip().splitlines()[0]
            check("the dashboard rendered far enough to finish the checks",
                  False, f"{type(exc).__name__}: {first_line}")
        finally:
            # Reported whatever else happened: an exception during the checks is
            # often downstream of an error the page already logged.
            # De-duplicated: React reports the same mount failure several times
            # over, and three copies of one error reads as three problems.
            unique = list(dict.fromkeys(e.strip().splitlines()[0]
                                        for e in console_errors))
            check("the dashboard logged no console errors",
                  not unique, "; ".join(unique[:3]))
            browser.close()

    print()
    if failures:
        print(f"{len(failures)} dashboard check(s) failed:")
        for f in failures:
            print(f"  ✗ {f}")
        return 1
    print(f"All {passed} dashboard checks passed.")
    return 0


def _run_checks(page, url: str) -> None:
    page.goto(url, wait_until="networkidle")

    # -- sign-in ------------------------------------------------------------
    check("the sign-in form is served", page.locator('input[type="password"]').count() == 1)
    page.fill('input[type="text"]', "admin")
    page.fill('input[type="password"]', "admin")
    page.click('button[type="submit"]')

    # Waiting for the ledger badge means waiting for the app shell *and* a
    # successful authenticated API call, which is a better signal than any
    # arbitrary sleep.
    page.wait_for_selector(".ledger-badge", timeout=20000)
    page.wait_for_timeout(1500)
    check("signing in reaches the dashboard", page.locator(".topbar").count() == 1)

    # -- the alert table actually has alerts in it --------------------------
    # The assertion that matters. A table element exists on an empty dashboard
    # too; rows are what prove the API's alerts reached the screen.
    rows = page.locator(".table-wrap tbody tr")
    check("the alert table renders rows", rows.count() > 0,
          f"{rows.count()} rows")

    table_text = page.inner_text(".table-wrap")
    check("rows carry a severity", any(s in table_text.lower()
                                       for s in ("critical", "high", "medium")))
    check("rows carry an ATT&CK technique", "T1" in table_text)

    # The counts in the top bar and the rows below come from different calls.
    # If they disagree, one of them is lying.
    stats_text = page.inner_text(".stats")
    check("the top bar shows severity counts", "CRIT" in stats_text and "HIGH" in stats_text)
    check("the top bar's counts are not all zero",
          any(ch.isdigit() and ch != "0" for ch in stats_text))

    # -- provenance from an ingested finding --------------------------------
    # v0.11's whole point: an alert that came from another tool says so.
    check("an ingested finding names the tool that reported it",
          page.locator(".src-badge").count() > 0)

    # -- the evidence integrity badge ---------------------------------------
    badge = page.inner_text(".ledger-badge")
    check("the ledger badge reports the chain verified", "verified" in badge.lower(),
          badge.replace("\n", " "))

    # -- the kill chain is drawn, not just computed -------------------------
    page.click("text=Incidents")
    page.wait_for_selector(".drawer", timeout=10000)
    page.wait_for_timeout(1200)
    drawer = page.inner_text(".drawer")
    # `or len(drawer) > 50` used to be the escape hatch here, which made this
    # pass on any drawer with some text in it -- including an empty one with a
    # heading. By this file's own standard that is worse than no check. What
    # proves the drawer *opened with incidents in it* is that it lists them:
    # every row reads "<actor> · N alerts".
    check("the incidents drawer lists incidents", "alert" in drawer.lower(),
          drawer[:100].replace("\n", " ") or "(drawer was empty)")

    chained = page.locator(".drawer").get_by_text("chain", exact=False)
    check("an incident is flagged as a kill chain", chained.count() > 0)

    # Click the chained incident and confirm the stages render.
    rows_in_drawer = page.locator(".drawer li, .incident-row, .drawer tr")
    for i in range(min(rows_in_drawer.count(), 12)):
        row = rows_in_drawer.nth(i)
        if "chain" in (row.inner_text() or "").lower():
            row.click()
            break
    page.wait_for_timeout(1200)
    detail = page.inner_text(".drawer")
    check("the kill chain's tactics are on screen",
          "Exfiltration" in detail and ("Lateral Movement" in detail
                                        or "Credential Access" in detail),
          detail[:120].replace("\n", " "))
    # Asserted on the chain's own state, not on the "escalated high -> critical"
    # caption. That caption only appears when escalation *changed* the severity,
    # and since v0.16 the replayed agent's incident is critical before the chain
    # completes (its first breach of its permission profile is critical). The
    # text check then failed on a chain that was escalated -- it was testing the
    # severity history, not the claim in its name.
    check("a completed chain is marked as escalated",
          page.locator(".drawer .kill-chain.escalated").count() > 0
          and "reaches Exfiltration" in detail,
          detail[:120].replace("\n", " "))

    # -- filtering still filters --------------------------------------------
    # A filter that silently matches everything looks identical to a working one
    # until you count.
    # Closed with its own button. This used to press Escape, which the dashboard
    # does not handle: the drawer stayed open over the table, and the filter
    # checks only passed because typing into the search box needs no click.
    # The first check that had to click a row (v0.16) found the overlay in the
    # way.
    page.click(".drawer-close")
    page.wait_for_timeout(600)
    before = page.locator(".table-wrap tbody tr").count()
    search = page.locator('input[placeholder*="actor"]')
    # Guarded on `before`: with no rows to begin with, "the filter emptied the
    # table" and "the rows came back" would both pass on a dashboard that was
    # already broken. A check that cannot fail is worse than no check.
    if search.count() and before > 0:
        search.fill("no-such-actor-anywhere")
        page.wait_for_timeout(1500)
        after = page.locator(".table-wrap tbody tr").count()
        check("a search that matches nothing empties the table",
              after == 0, f"{before} rows before, {after} after")
        search.fill("")
        page.wait_for_timeout(1500)
        restored = page.locator(".table-wrap tbody tr").count()
        check("clearing the search brings the rows back",
              restored == before, f"{before} before, {restored} after clearing")
    else:
        check("the filter checks had rows to work with", False,
              "no rows were rendered, so filtering could not be tested")

    # -- declared permissions, beside what the agent did (v0.16) ------------
    # An alert reading "outside declared permissions" is half an answer until
    # the declaration is on screen next to it. recon-agent-3 is in the bundled
    # sample data, so this holds whether or not the replay has run.
    if search.count():
        search.fill("recon-agent-3")
        page.wait_for_timeout(1500)
        recon_rows = page.locator(".table-wrap tbody tr")
        if recon_rows.count():
            recon_rows.first.click()
            page.wait_for_selector(".perm-panel", timeout=10000)
            panel = page.inner_text(".perm-panel")
            check("the actor drawer shows the profile that governs the agent",
                  "recon-agent-*" in panel, panel[:120].replace("\n", " "))
            check("denied grants are shown as denied",
                  page.locator(".perm-panel .perm-chip.deny").count() > 0)
            check("a breach of the profile is on the agent's timeline",
                  "permission_violation" in page.inner_text(".drawer"))
        else:
            check("the sample agent's alerts could be found to open its drawer",
                  False, "no rows for recon-agent-3")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check the Shadowfax dashboard in a real browser.")
    parser.add_argument("--url", default=DEFAULT_URL,
                        help=f"a running Shadowfax (default {DEFAULT_URL})")
    parser.add_argument("--headed", action="store_true",
                        help="show the browser, for watching or debugging")
    args = parser.parse_args(argv)
    return run(args.url, args.headed)


if __name__ == "__main__":
    raise SystemExit(main())
