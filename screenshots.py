"""
Regenerate the README's screenshots (v0.30).

    python demo.py --fast                 # put a realistic history on screen
    python screenshots.py                 # writes docs/screenshots/*.png

Every image in the README comes from this script, run against a real server
after the scripted attack, so the pictures are of the product as it is -- not
mock-ups that drift out of date. Re-run it after a UI change and commit the
images that changed. It adds a small amount of data of its own (two scanners
reporting on one host, a throwaway user with two-factor on) so that every
screen it shows has something on it; run it against a throwaway instance, not
one that holds real evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import urllib.request
from pathlib import Path

DEFAULT_URL = "http://127.0.0.1:8000"
OUT = Path(__file__).parent / "docs" / "screenshots"
VIEWPORT = {"width": 1440, "height": 900}


def _api(url: str, method: str, path: str, body=None, token: str | None = None):
    req = urllib.request.Request(
        f"{url}{path}", data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json",
                 **({"Authorization": f"Bearer {token}"} if token else {})},
        method=method)
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _seed_extras(url: str, token: str) -> str:
    """Two scanners on one host, so the subject page has a story to tell."""
    host = {"kind": "host", "id": "10.20.30.40", "label": "build-runner-7"}
    for tool, version, run, findings in (
        ("portscout", "1.2.0", "weekly-42", [
            {"id": "ps-ssh", "key": "open_admin_port", "severity": "high",
             "title": "SSH reachable from the internet", "evidence": "22/tcp open to 0.0.0.0/0",
             "validated": True, "recommendation": "restrict 22/tcp to the VPN range"},
            {"id": "ps-cert", "key": "self_signed_cert", "severity": "low",
             "title": "Self-signed certificate on 443",
             "evidence": "CN=build-runner-7 (as the certificate states)", "validated": False}]),
        ("vulnscan", "0.9.1", "nightly", [
            {"id": "vs-ssh", "key": "open_admin_port", "severity": "critical",
             "title": "Admin service reachable without MFA", "evidence": "sshd 7.2 answered externally",
             "validated": True, "mitre": "T1133 - External Remote Services"},
            {"id": "vs-kern", "key": "outdated_kernel", "severity": "medium",
             "title": "Kernel 5.4 is end-of-life", "evidence": "uname -r: 5.4.0-42",
             "validated": True}])):
        _api(url, "POST", "/findings", {
            "envelope_version": "1.0", "generated": "2026-10-19T09:00:00Z",
            "source": {"tool": tool, "version": version, "run_id": run},
            "subject": host, "findings": findings}, token)
    return f"{host['kind']}:{host['id']}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--url", default=DEFAULT_URL)
    p.add_argument("--username", default=os.environ.get("SHADOWFAX_ADMIN_USERNAME") or "admin")
    p.add_argument("--password", default=os.environ.get("SHADOWFAX_ADMIN_PASSWORD") or "admin")
    args = p.parse_args(argv)

    from playwright.sync_api import sync_playwright
    import totp

    token = _api(args.url, "POST", "/auth/login",
                 {"username": args.username, "password": args.password})["token"]
    if not _api(args.url, "GET", "/alerts", None, token):
        print("No alerts yet -- run `python demo.py --fast` first.", file=sys.stderr)
        return 2
    subject = _seed_extras(args.url, token)
    # A few accounts and a key, so the Accounts drawer is not empty.
    existing = {u["username"] for u in _api(args.url, "GET", "/users", None, token)}
    for name, role in (("m.okafor", "analyst"), ("r.singh", "viewer"), ("t.vance", "admin")):
        if name not in existing:
            _api(args.url, "POST", "/users", {"username": name, "role": role, "generate": True}, token)
    if not _api(args.url, "GET", "/api-keys", None, token):
        _api(args.url, "POST", "/api-keys", {"label": "ci-harness"}, token)
        _api(args.url, "POST", "/api-keys", {"label": "recon-agent fleet"}, token)
    OUT.mkdir(parents=True, exist_ok=True)
    shots: list[str] = []

    def save(target, name: str) -> None:
        path = OUT / f"{name}.png"
        target.screenshot(path=str(path))
        shots.append(path.name)

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport=VIEWPORT, device_scale_factor=1)
        page.goto(args.url, wait_until="networkidle")
        page.fill('input[autocomplete="username"]', args.username)
        page.fill('input[type="password"]', args.password)
        page.click('button[type="submit"]')
        page.wait_for_selector(".table-wrap tbody tr", timeout=15000)
        page.click("th:has-text('Severity')")          # worst first for the overview
        page.wait_for_timeout(1200)
        save(page, "dashboard")

        page.click("text=Incidents")
        page.wait_for_selector(".drawer .kill-chain", timeout=10000)
        page.locator(".drawer li, .incident-row, .drawer tr").first.click()
        page.wait_for_timeout(800)
        save(page, "incident-kill-chain")
        page.click(".drawer-close")

        search = page.locator('input[placeholder*="actor"]')
        search.fill("recon-agent-3")
        page.wait_for_timeout(1200)
        page.locator(".table-wrap tbody tr").first.click()
        page.wait_for_selector(".caps-panel", timeout=10000)
        page.wait_for_timeout(500)
        save(page, "agent-permissions")
        page.click("button:has-text('Draft a profile')")
        page.wait_for_selector(".draft-modal .draft-json", timeout=10000)
        page.wait_for_timeout(400)
        save(page.locator(".draft-modal"), "profile-draft")
        page.keyboard.press("Escape")
        page.keyboard.press("Escape")
        search.fill("")
        page.wait_for_timeout(800)

        page.get_by_role("button", name="Subjects", exact=True).click()
        page.wait_for_selector(".subjects-table", timeout=10000)
        page.locator(".subjects-table tr", has_text="build-runner-7").click()
        page.wait_for_selector(".subject-report", timeout=10000)
        page.wait_for_timeout(500)
        save(page, "subject-report")
        page.keyboard.press("Escape")

        page.get_by_role("button", name="Accounts", exact=True).click()
        page.wait_for_selector(".accounts-keys", timeout=10000)
        page.wait_for_timeout(500)
        box = page.locator(".accounts-drawer").bounding_box()
        bottom = page.locator(".accounts-drawer .lockout-foot").last.bounding_box()
        page.screenshot(path=str(OUT / "accounts.png"), clip={
            "x": box["x"], "y": box["y"], "width": box["width"],
            "height": bottom["y"] + bottom["height"] + 24 - box["y"]})
        shots.append("accounts.png")
        page.keyboard.press("Escape")
        browser.close()

        # Two-factor sign-in, as a throwaway user on this throwaway instance.
        name, pw_ = f"analyst-{secrets.token_hex(2)}", "screenshot-pass-123"
        _api(args.url, "POST", "/users", {"username": name, "password": pw_, "role": "analyst"}, token)
        user_token = _api(args.url, "POST", "/auth/login", {"username": name, "password": pw_})["token"]
        secret = _api(args.url, "POST", "/auth/totp/setup", {"current_password": pw_}, user_token)["secret"]
        _api(args.url, "POST", "/auth/totp/confirm",
             {"code": totp.code_at(secret, totp.current_step())}, user_token)
        browser = pw.chromium.launch()
        page = browser.new_page(viewport={"width": 900, "height": 640})
        page.goto(args.url, wait_until="networkidle")
        page.fill('input[autocomplete="username"]', name)
        page.fill('input[type="password"]', pw_)
        page.click('button[type="submit"]')
        page.wait_for_selector(".login-code", timeout=10000)
        page.wait_for_timeout(300)
        save(page, "two-factor-sign-in")
        browser.close()

    print(f"wrote {len(shots)} screenshots to {OUT}: {', '.join(shots)}")
    print(f"(the subject page shows {subject})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
