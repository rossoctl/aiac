#!/usr/bin/env python3
"""Stage 5 — build the narration track from the timeline and mux it onto the video.

Each clip is placed at its task's start offset (timeline.json), so audio lands
where its task actually begins rather than drifting on accumulated error.
"""
import json, os, subprocess, sys, glob

HERE = os.path.dirname(os.path.abspath(__file__))
TEXT_LEAD = 1.8   # Delay every clip this long past its task's recorded start, so the
                  # caption is on screen BEFORE the voice begins.
                  #
                  # Measured, not derived: the recorded start is the driver's
                  # wall-clock instant, but the encoded frame showing the new caption
                  # lands ~1.5s later (Playwright's variable-rate screencast plus the
                  # band's 300ms fade). Frame checks put task 4's caption at ~72.0s
                  # against a 70.5s audio start, so 0.2s of intended lead was really
                  # 1.5s of lag. 1.8s = that 1.5s plus the 0.2s the caption should
                  # genuinely lead by. Re-measure if the render pipeline changes:
                  # extract a frame at a task's audio start and confirm its caption is
                  # already the new one (see ../movie.md Pass 9).
BUNDLE = json.load(open(os.path.join(HERE, "bundle.json")))["bundle"]
MDIR = os.path.join(BUNDLE, "movie")
AUD = os.path.join(MDIR, "audio")          # synthesised
VOICE = os.path.join(MDIR, "voice")        # human recordings win when present
VEXT = ("wav", "aiff", "aif", "m4a", "mp3", "caf")


def clip(n):
    """Prefer a human recording for task n; fall back to the synthesised clip.

    `mix_voice.py` writes tNN.joined.wav from the task-line and summary parts, so
    that is checked first — it is what the timings were measured from, and using
    anything else here would desync audio from the render.
    """
    joined = os.path.join(VOICE, f"t{n:02d}.joined.wav")
    if os.path.exists(joined):
        return joined
    for e in VEXT:
        for name in (f"t{n:02d}.{e}", f"t{n:02d}a.{e}", f"t{n:02d}b.{e}"):
            p = os.path.join(VOICE, name)
            if os.path.exists(p):
                return p
    return os.path.join(AUD, f"t{n:02d}.wav")
OUT = os.path.join(MDIR, "uc1-demo.mp4")


def main():
    tl = json.load(open(os.path.join(MDIR, "timeline.json")))
    vids = glob.glob(os.path.join(MDIR, "video", "*.webm"))
    if not vids:
        sys.exit("no video captured")
    vid = max(vids, key=os.path.getsize)
    total = tl["total"]

    # Playwright's screencast is variable-rate: the encoded video runs slightly longer
    # than the driver's wall-clock timeline (437.4s vs 435.0s in one cut), so offsets
    # are scaled by the real ratio. This is a small residual correction — the large
    # error was the driver timestamping the request rather than the painted frame,
    # fixed in render.mjs (see ../movie.md Pass 9).
    r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration",
                        "-of", "default=nw=1:nk=1", vid], capture_output=True, text=True)
    vid_dur = float(r.stdout.strip())
    scale = vid_dur / total if total else 1.0
    print(f"video {vid_dur:.2f}s vs driver {total:.2f}s -> offset scale {scale:.5f}")

    # one delayed input per task, all mixed into a single track
    cmd = ["ffmpeg", "-y", "-i", vid]
    human = 0
    for e in tl["timeline"]:
        if "slide" in e:                      # a slide's clip is named by its id
            # the normalised derivative, matching what mix_voice.py measured
            p = os.path.join(VOICE, f"{e['slide']}.norm.wav")
            if not os.path.exists(p):
                p = os.path.join(VOICE, f"{e['slide']}.wav")
        else:
            p = clip(e["n"])
        if os.sep + "voice" + os.sep in p:
            human += 1
        cmd += ["-i", p]

    parts, labels = [], []
    for i, e in enumerate(tl["timeline"], start=1):
        ms = int((e["start"] * scale + TEXT_LEAD) * 1000)
        parts.append(f"[{i}:a]adelay={ms}|{ms},aformat=sample_fmts=fltp:sample_rates=44100:channel_layouts=stereo[a{i}]")
        labels.append(f"[a{i}]")
    fc = ";".join(parts) + ";" + "".join(labels) + f"amix=inputs={len(labels)}:dropout_transition=0:normalize=0[mix]"

    cmd += ["-filter_complex", fc, "-map", "0:v", "-map", "[mix]",
            "-c:v", "libx264", "-preset", "medium", "-crf", "20",
            "-pix_fmt", "yuv420p", "-r", "30",
            "-c:a", "aac", "-b:a", "192k",
            "-t", f"{vid_dur:.2f}", OUT]

    print(f"video: {os.path.basename(vid)}  ({os.path.getsize(vid)/1e6:.1f} MB)")
    print(f"mixing {len(labels)} narration clips over {total:.0f}s "
          f"({human} human, {len(labels)-human} synthesised) "
          f"· text leads audio by {TEXT_LEAD}s")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("ffmpeg failed:\n" + r.stderr[-2500:])

    d = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration",
                        "-of", "default=nw=1:nk=1", OUT], capture_output=True, text=True)
    print(f"\n{OUT}")
    print(f"  {os.path.getsize(OUT)/1e6:.1f} MB, {float(d.stdout.strip())/60:.1f} min")


if __name__ == "__main__":
    main()
