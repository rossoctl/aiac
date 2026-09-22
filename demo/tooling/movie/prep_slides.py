#!/usr/bin/env python3
"""Apply each slide's declared `crop` to produce the image the film actually shows.

A cropped slide is written as <stem>.crop.png next to the source and the slide's
`img` is rewritten to point at it, so the original stays untouched and re-running is
idempotent. Slides with no `crop` are passed through.
"""
import json, os, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from slides import SLIDES

BUNDLE = json.load(open(os.path.join(HERE, "bundle.json")))["bundle"]
SDIR = os.path.join(BUNDLE, "movie", "slides")
SRC = os.path.join(HERE, "slides-src")   # the authored diagrams, committed


def main():
    # Stage the authored diagrams into the bundle. They are committed under
    # slides-src/ because they are source, not build output — without them a clean
    # checkout cannot rebuild the film. title.png and outro.png are absent here by
    # design: build_title.py and build_outro.py generate them.
    os.makedirs(SDIR, exist_ok=True)
    for f in sorted(os.listdir(SRC)) if os.path.isdir(SRC) else []:
        if f.endswith(".png") and not os.path.exists(os.path.join(SDIR, f)):
            shutil.copy2(os.path.join(SRC, f), os.path.join(SDIR, f))
            print(f"  staged   {f}")

    for s in SLIDES:
        src = os.path.join(SDIR, s["img"])
        if not os.path.exists(src):
            hint = ("  run build_title.py" if s["img"] == "title.png"
                    else "  run build_outro.py" if s["img"] == "outro.png"
                    else f"  expected in slides-src/")
            print(f"  {s['id']:4s} MISSING {s['img']}{hint}")
            continue
        crop = s.get("crop")
        if not crop:
            print(f"  {s['id']:4s} as-is    {s['img']}")
            continue
        x, y, w, h = crop
        out = os.path.join(SDIR, os.path.splitext(s["img"])[0] + ".crop.png")
        r = subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-i", src,
                            "-vf", f"crop={w}:{h}:{x}:{y}", "-y", out],
                           capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"{s['id']}: crop failed\n{r.stderr[-400:]}")
        print(f"  {s['id']:4s} cropped  {os.path.basename(out)}  "
              f"({w}x{h} from {x},{y})")


if __name__ == "__main__":
    main()
