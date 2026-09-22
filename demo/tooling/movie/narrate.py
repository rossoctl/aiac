#!/usr/bin/env python3
"""Stage 2 — one narration clip per task, via Piper. Measures each duration.

Speaks the task line then the summary, both verbatim from the capture — the same
text a human reads (see ../movie.md). This is the fallback track; human recordings
in <bundle>/movie/voice/ take precedence via mix_voice.py.
Durations feed stage 3; they are never hand-tuned.
"""
import json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
VENV = "/tmp/voice-audition/.tts-venv/bin/python"
MODEL = "/tmp/voice-audition/models/en_US-ryan-high.onnx"
BUNDLE = json.load(open(os.path.join(HERE, "bundle.json")))["bundle"]
OUT = os.path.join(BUNDLE, "movie", "audio")


def duration(path):
    r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration",
                        "-of", "default=nw=1:nk=1", path], capture_output=True, text=True)
    return float(r.stdout.strip())


def main():
    os.makedirs(OUT, exist_ok=True)
    tasks = json.load(open(os.path.join(BUNDLE, "movie", "shotlist.json")))
    if not os.path.exists(MODEL):
        sys.exit(f"voice model missing: {MODEL}")

    total = 0.0
    for t in tasks:
        n = t["n"]
        # task line then summary, both verbatim from the capture
        text = f'{t["task"]}. {t["summary"]}'
        src = "task + summary (verbatim)"
        wav = os.path.join(OUT, f"t{n:02d}.wav")
        r = subprocess.run([VENV, "-m", "piper", "-m", MODEL, "-f", wav],
                           input=text, text=True, capture_output=True)
        if not os.path.exists(wav):
            sys.exit(f"task {n}: piper failed\n{r.stderr[-400:]}")
        d = duration(wav)
        t["narration_s"] = round(d, 2)
        t["narration_src"] = src
        total += d
        print(f"  task {n:2d}  {d:5.1f}s  ({src})")

    json.dump(tasks, open(os.path.join(BUNDLE, "movie", "shotlist.json"), "w"), ensure_ascii=False, indent=1)
    print(f"\nnarration total: {total:.0f}s = {total/60:.1f} min")


def repace():
    """Re-fit typing speed to the new durations (stage 3). Always after a change
    to narration_s, or the player paces to stale numbers."""
    import subprocess
    subprocess.run(["python3", os.path.join(HERE, "pace.py")], check=True)


if __name__ == "__main__":
    main()
    repace()
