"""
Draw Shadowfax Desktop's icons (v0.38).

    python desktop/make_icons.py

The radar mark from the dashboard's top bar, as an SVG rendered by the same
headless browser the screenshots use, so the icons are regenerated rather than
hand-edited. Writes desktop/build/icon.png (512 px; electron-builder makes the
Windows .ico from it), tray.png and badge.png.
"""

from pathlib import Path

OUT = Path(__file__).parent / "build"

ICON_SVG = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="{size}" height="{size}">
  <defs>
    <radialGradient id="bg" cx="50%" cy="40%" r="75%">
      <stop offset="0" stop-color="#13213a"/><stop offset="1" stop-color="#070b13"/>
    </radialGradient>
    <linearGradient id="sweep" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#38bdf8" stop-opacity="0.85"/>
      <stop offset="1" stop-color="#38bdf8" stop-opacity="0"/>
    </linearGradient>
  </defs>
  {background}
  <circle cx="256" cy="256" r="176" fill="none" stroke="#38bdf8" stroke-opacity="0.55" stroke-width="{ring}"/>
  <circle cx="256" cy="256" r="112" fill="none" stroke="#38bdf8" stroke-opacity="0.38" stroke-width="{ring}"/>
  <circle cx="256" cy="256" r="48" fill="none" stroke="#38bdf8" stroke-opacity="0.3" stroke-width="{ring}"/>
  <path d="M256 256 L256 80 A176 176 0 0 1 408.4 168 Z" fill="url(#sweep)"/>
  <line x1="256" y1="256" x2="256" y2="80" stroke="#7dd3fc" stroke-width="{ring}"/>
  <circle cx="338" cy="150" r="{dot}" fill="#e0f2fe"/>
  <circle cx="338" cy="150" r="{glow}" fill="#38bdf8" fill-opacity="0.35"/>
</svg>
"""

BADGE_SVG = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16">
  <circle cx="8" cy="8" r="7" fill="#ef4444" stroke="#0b0f17" stroke-width="1.5"/>
</svg>
"""


def main() -> None:
    from playwright.sync_api import sync_playwright

    OUT.mkdir(parents=True, exist_ok=True)
    shapes = {
        "icon.png": (512, ICON_SVG.format(
            size=512, ring=6, dot=16, glow=30,
            background='<rect x="16" y="16" width="480" height="480" rx="112" fill="url(#bg)"/>')),
        # The tray icon has no tile behind it and thicker lines, so it reads at
        # 16 to 32 pixels on a light or a dark taskbar.
        "tray.png": (32, ICON_SVG.format(
            size=32, ring=26, dot=40, glow=0,
            background='<circle cx="256" cy="256" r="236" fill="#0b0f17"/>')),
        "badge.png": (16, BADGE_SVG),
    }
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for name, (size, svg) in shapes.items():
            page = browser.new_page(viewport={"width": size, "height": size})
            page.set_content(f'<html><body style="margin:0;background:transparent">{svg}</body></html>')
            page.locator("svg").screenshot(path=str(OUT / name), omit_background=True)
            page.close()
        browser.close()
    print("wrote " + ", ".join(str(OUT / n) for n in shapes))


if __name__ == "__main__":
    main()
