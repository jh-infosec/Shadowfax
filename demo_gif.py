"""
Record the README's demo GIF (v0.36).

    python demo_gif.py                    # against http://127.0.0.1:8000
    python demo_gif.py --url ... --password ...

Signs in to the dashboard in a real browser, runs the scripted attack
(`demo.py`) against the same server, and captures the dashboard while the
alerts arrive. A caption shows which act and step is playing, taken live from
the demo's own output, so the GIF tells the story without sound or a narrator.
It ends on the Incidents drawer showing the kill chain. Frames are stitched
into docs/demo.gif with ffmpeg.

Like screenshots.py, run it against a throwaway instance: the demo resets the
data to the bundled sample first.
"""

from __future__ import annotations

import argparse
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

DEFAULT_URL = "http://127.0.0.1:8000"
OUT = Path(__file__).parent / "docs" / "demo.gif"
VIEWPORT = {"width": 1280, "height": 760}
FPS = 4
WIDTH = 960

_CAPTION_JS = """(text) => {
  let el = document.getElementById('sfx-demo-caption');
  if (!el) {
    el = document.createElement('div');
    el.id = 'sfx-demo-caption';
    el.style.cssText = 'position:fixed;left:50%;bottom:22px;transform:translateX(-50%);' +
      'z-index:9999;max-width:80%;padding:10px 18px;border-radius:8px;' +
      'background:rgba(8,12,20,0.92);border:1px solid #38bdf8;color:#e2e8f0;' +
      'font:600 15px/1.4 system-ui,sans-serif;box-shadow:0 8px 30px rgba(0,0,0,0.6);' +
      'text-align:center;pointer-events:none;white-space:pre-line';
    document.body.appendChild(el);
  }
  el.textContent = text;
  el.style.display = text ? 'block' : 'none';
}"""

_ACT = re.compile(r"ACT (\d+) · (.+?)\s*$")
_STEP = re.compile(r"^\s+\d+\.\s+(.+)$")


def _reader(stream, lines: "queue.Queue[str]") -> None:
    for line in iter(stream.readline, ""):
        lines.put(line.rstrip("\n"))
    stream.close()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--url", default=DEFAULT_URL)
    p.add_argument("--username", default=os.environ.get("SHADOWFAX_ADMIN_USERNAME") or "admin")
    p.add_argument("--password", default=os.environ.get("SHADOWFAX_ADMIN_PASSWORD") or "admin")
    p.add_argument("--speed", type=float, default=0.55, help="demo pacing (lower is faster)")
    args = p.parse_args(argv)

    if not shutil.which("ffmpeg"):
        print("demo_gif.py needs ffmpeg on the PATH.", file=sys.stderr)
        return 2
    from playwright.sync_api import sync_playwright

    frames = Path(tempfile.mkdtemp(prefix="shadowfax-gif-"))
    count = 0

    def grab(page) -> None:
        nonlocal count
        page.screenshot(path=str(frames / f"f{count:05d}.png"))
        count += 1

    def hold(page, seconds: float) -> None:
        for _ in range(int(seconds * FPS)):
            started = time.monotonic()
            grab(page)
            time.sleep(max(0.0, 1 / FPS - (time.monotonic() - started)))

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport=VIEWPORT, device_scale_factor=1)
        page.goto(args.url, wait_until="networkidle")
        page.fill('input[autocomplete="username"]', args.username)
        page.fill('input[type="password"]', args.password)
        page.click('button[type="submit"]')
        page.wait_for_selector(".table-wrap tbody tr", timeout=15000)
        page.evaluate(_CAPTION_JS, "Shadowfax · watching AI agents live")
        hold(page, 2)

        demo = subprocess.Popen(
            [sys.executable, str(Path(__file__).parent / "demo.py"), "--url", args.url,
             "--username", args.username, "--password", args.password,
             "--speed", str(args.speed), "--no-colour"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        lines: "queue.Queue[str]" = queue.Queue()
        threading.Thread(target=_reader, args=(demo.stdout, lines), daemon=True).start()

        act = ""
        while demo.poll() is None or not lines.empty():
            started = time.monotonic()
            while not lines.empty():
                line = lines.get()
                if m := _ACT.search(line):
                    act = f"Act {m.group(1)} · {m.group(2)}"
                    page.evaluate(_CAPTION_JS, act)
                elif (m := _STEP.match(line)) and act:
                    page.evaluate(_CAPTION_JS, f"{act}\n{m.group(1)}")
            grab(page)
            time.sleep(max(0.0, 1 / FPS - (time.monotonic() - started)))
        if demo.returncode != 0:
            print(f"the demo exited with {demo.returncode}; recording kept anyway", file=sys.stderr)

        page.evaluate(_CAPTION_JS, "Separate alerts, one incident: the kill chain")
        hold(page, 1.5)
        page.click("text=Incidents")
        page.wait_for_selector(".drawer .incident-row", timeout=10000)
        page.locator(".incident-row", has_text="demo-agent-1").first.click()
        page.wait_for_selector(".drawer .kill-chain", timeout=10000)
        hold(page, 5)
        browser.close()

    OUT.parent.mkdir(parents=True, exist_ok=True)
    palette = (f"fps={FPS},scale={WIDTH}:-1:flags=lanczos,split[a][b];"
               f"[a]palettegen=max_colors=128:stats_mode=diff[p];"
               f"[b][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle")
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(FPS),
                    "-i", str(frames / "f%05d.png"), "-vf", palette, "-loop", "0", str(OUT)],
                   check=True)
    if os.environ.get("SHADOWFAX_GIF_KEEP_FRAMES"):
        print(f"frames kept in {frames}")
    else:
        shutil.rmtree(frames, ignore_errors=True)
    print(f"wrote {OUT} ({OUT.stat().st_size / 1_000_000:.1f} MB, {count} frames, "
          f"{count / FPS:.0f} s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
