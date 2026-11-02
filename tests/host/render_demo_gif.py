#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Render assets/sweep-demo.gif from a real 56-PoC sweep capture.

The lines shown are the actual output of a real run (see the capture header
in the log); this is a terminal *rendering* of that output, not a simulation
of it. Reads the capture file given as the first argument (default:
sweep_capture.log at the repository root), writes assets/sweep-demo.gif.

Capture a fresh 56-PoC simulator sweep from the repo root first, e.g.:

    { echo "=== SELFTEST ==="; python3 simulator/flatsat_sim.py --selftest;
      echo "=== SWEEP $(date -u +%Y-%m-%dT%H:%M:%SZ) ===";
      for f in poc/v0*.py poc/v1*.py; do
        if python3 "$f" --quiet --no-save > poc_out.log 2>&1; then
          tail -1 poc_out.log | sed "s/^/PASS $(basename "$f" .py) | /"
        else echo "FAIL $(basename "$f" .py)"; fi
      done; echo "=== END ==="; } | tee sweep_capture.log

Then:  python3 tests/host/render_demo_gif.py sweep_capture.log
"""
import os
import re
import sys

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SRC = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "sweep_capture.log")
if not os.path.exists(SRC):
    sys.exit("no sweep capture found at %s\n"
             "run the 56-PoC sweep first (see the module docstring) and pass "
             "its log: %s <sweep_capture.log>" % (SRC, sys.argv[0]))
OUT = os.path.join(ROOT, "assets", "sweep-demo.gif")

W, H = 980, 560
BG = (13, 17, 23)
BAR = (22, 27, 34)
FG = (214, 224, 235)
DIM = (110, 118, 129)
GREEN = (63, 185, 80)
ACCENT = (139, 92, 246)
WHITE = (240, 242, 245)

FONT_PATHS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
]
fs = ImageFont.truetype(FONT_PATHS[0], 15)
fb = ImageFont.truetype(FONT_PATHS[1] if os.path.exists(FONT_PATHS[1]) else FONT_PATHS[0], 15)
fsum = ImageFont.truetype(FONT_PATHS[1] if os.path.exists(FONT_PATHS[1]) else FONT_PATHS[0], 19)

# ---- parse the real capture ---------------------------------------------
raw = open(SRC, encoding="utf-8").read()
selftest = re.search(r"SELFTEST OK: (.*)", raw).group(1)
sweep_ts = re.search(r"=== SWEEP (\S+) ===", raw).group(1)
passes = re.findall(r"^PASS (v[01]\d{2}_[a-z0-9_]+) \| (.*)$", raw, re.M)
assert len(passes) == 56, f"expected 56 PASS lines, got {len(passes)}"

# ---- build the line stream (text, color, bold) ---------------------------
LH = 22
lines = []
lines.append(("flatsat-electr0sm0g-lab  —  56-PoC simulator sweep  ·  run " + sweep_ts, DIM, False))
lines.append((selftest, (148, 163, 184), False))
lines.append(("", None, False))
for name, tail in passes:
    lines.append(("PASS  " + name + "  |  " + tail, GREEN, True))
lines.append(("", None, False))
lines.append(("56/56 PASS — same PoC, two targets: simulator and FlatSat 1 (image H)", WHITE, True))

MAXVIS = 22  # visible lines in the window

def render(visible):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 34], fill=BAR)
    d.ellipse([12, 12, 24, 24], fill=(239, 83, 80))
    d.ellipse([30, 12, 42, 24], fill=(232, 178, 48))
    d.ellipse([48, 12, 60, 24], fill=(63, 185, 80))
    d.text((78, 9), "python3 simulator/flatsat_sim.py --selftest  &&  56-PoC sweep (POC OK x56)",
           font=fs, fill=DIM)
    y0 = 48
    for i, (text, color, bold) in enumerate(visible):
        if not text:
            continue
        font = fb if bold else fs
        d.text((24, y0 + i * LH), text, font=font, fill=color or FG)
    return img

frames = []
n = len(lines)
# intro: header + selftest first
for k in (3, 4, 5):
    frames.append(render(lines[:k]))
# stream the 56 PASS lines, 2 frames each, scrolling window
start = 3
for i in range(56):
    shown = lines[: start + 1 + i + 1]
    vis = shown[-MAXVIS:] if len(shown) > MAXVIS else shown
    for _ in range(2):
        frames.append(render(vis))
# the streamed window already ends on the 56/56 summary line: hold it
for _ in range(14):
    frames.append(render(lines[-MAXVIS:]))

os.makedirs(os.path.dirname(OUT), exist_ok=True)
frames[0].save(OUT, save_all=True, append_images=frames[1:],
               duration=90, loop=0, optimize=True)
print(f"wrote {OUT} ({len(frames)} frames, {os.path.getsize(OUT) / 1e6:.2f} MB)")
