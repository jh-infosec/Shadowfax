"""
Known vulnerabilities in what Shadowfax ships (v0.40).

    python supply_chain.py              # run every check CI runs
    python supply_chain.py --npm-only   # just the JavaScript side

Two package managers, and two kinds of dependency in each:

* **Shipped:** code that ends up in front of users. The server's Python
  packages (requirements.lock, installed into the Docker image), the
  dashboard's runtime JavaScript (React), and Electron itself, which is inside
  every desktop installer. A known high or critical vulnerability in any of
  these fails the build.
* **Build-only:** tools that run on the build machine and never ship: Vite,
  electron-builder and their dependencies. Their advisories are listed so
  they're seen, but don't fail the build, because they only process files
  this repository wrote. (In November 2026 that list includes a picomatch ReDoS
  advisory with no fixed version; electron-builder pulls it in.)

The judging is a pure function, `judge`, so the rule itself is tested.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
FAILING = ("high", "critical")
# Desktop packages that ship inside the installer even though npm lists them
# as devDependencies (electron-builder requires that).
DESKTOP_SHIPPED = ("electron",)


def judge(audit: dict, shipped: tuple[str, ...] | None) -> tuple[list[str], list[str]]:
    """(failures, notes) from `npm audit --json` output.

    `shipped` names the packages that end up in front of users; None means
    every package in the audit does (an audit already run with --omit=dev).
    """
    failures, notes = [], []
    for name, vuln in sorted((audit.get("vulnerabilities") or {}).items()):
        severity = str(vuln.get("severity", "")).lower()
        via = [v.get("title") for v in vuln.get("via", []) if isinstance(v, dict) and v.get("title")]
        line = f"{name} ({severity})" + (f": {via[0]}" if via else "")
        if (shipped is None or name in shipped) and severity in FAILING:
            failures.append(line)
        else:
            notes.append(line)
    return failures, notes


def _npm_audit(folder: Path, omit_dev: bool) -> dict:
    npm = shutil.which("npm")
    if npm is None:
        raise SystemExit("npm isn't installed")
    cmd = [npm, "audit", "--json"] + (["--omit=dev"] if omit_dev else [])
    out = subprocess.run(cmd, cwd=folder, capture_output=True, text=True).stdout
    try:
        return json.loads(out or "{}")
    except ValueError:
        raise SystemExit(f"npm audit in {folder.name} didn't return JSON:\n{out[:500]}")


def _pip_audit() -> list[str]:
    exe = shutil.which("pip-audit")
    if exe is None:
        raise SystemExit("pip-audit isn't installed (pip install -r requirements-dev.txt)")
    r = subprocess.run([exe, "--strict", "--progress-spinner", "off", "-r", str(ROOT / "requirements.lock")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return [line for line in (r.stdout + r.stderr).splitlines() if line.strip()]
    return []


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--npm-only", action="store_true")
    args = p.parse_args(argv)
    failed = False

    if not args.npm_only:
        problems = _pip_audit()
        print("Python (requirements.lock): " + ("no known vulnerabilities" if not problems else "VULNERABLE"))
        for line in problems:
            print(f"  {line}")
        failed |= bool(problems)

    checks = [("dashboard runtime", ROOT / "frontend", True, None),
              ("dashboard build tools", ROOT / "frontend", False, ()),
              ("desktop app", ROOT / "desktop", False, DESKTOP_SHIPPED)]
    for label, folder, omit_dev, shipped in checks:
        failures, notes = judge(_npm_audit(folder, omit_dev), shipped)
        print(f"{label}: " + (f"{len(failures)} shipped package(s) with a known high or critical vulnerability"
                              if failures else "nothing shipped is affected"))
        for line in failures:
            print(f"  FAIL {line}")
        for line in notes:
            print(f"  note (build-only) {line}")
        failed |= bool(failures)

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
