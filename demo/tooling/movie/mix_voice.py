#!/usr/bin/env python3
"""Use human recordings instead of synthesised narration.

Reads <bundle>/movie/voice/tNN.{wav,aiff,m4a,mp3}, measures each clip, and writes
those durations into shotlist.json as `narration_s`. The render then paces each
task to the real recording, so timing follows the voice rather than the reverse.

Falls back to the synthesised clip for any task not yet recorded, so a partial
recording session still produces a complete film.
"""
import glob, json, os, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from slides import SLIDES

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE = json.load(open(os.path.join(HERE, "bundle.json")))["bundle"]
MDIR = os.path.join(BUNDLE, "movie")
VOICE = os.path.join(MDIR, "voice")
AUD = os.path.join(MDIR, "audio")          # synthesised, the fallback
EXT = ("wav", "aiff", "aif", "m4a", "mp3", "caf")


def duration(p):
    r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration",
                        "-of", "default=nw=1:nk=1", p], capture_output=True, text=True)
    try:
        return float(r.stdout.strip())
    except ValueError:
        return None


GAP = 0.45     # silence between the spoken task line and the summary
TARGET_I = -18 # LUFS. Human takes are quiet (~-35 LUFS as recorded) while the
               # synthesised clips are near full scale; loudnorm brings every clip
               # to the same perceived level so a part-recorded film is consistent.

# Denoise chain, applied BEFORE loudnorm. Normalisation lifts a take by ~14 dB, which
# lifts its noise floor with it — room tone that is inaudible in the raw file becomes
# audible in the film. Order matters: clean first, then level.
#
# This is the GENTLE chain, chosen on listening (2026-09-17): a highpass to drop rumble
# and desk noise, plus mild spectral reduction. The aggressive variant — stronger
# afftdn, a lowpass, and a noise gate — pushed the silences to -83 dB but audibly
# processed the voice, so it was rejected. Keep it gentle: some room tone is preferable
# to artifacts on speech.
DENOISE = "highpass=f=75,afftdn=nf=-20:nt=w"


def normalise(src, out):
    """Loudness-normalise one clip to TARGET_I. Rebuilt only when the source is newer.

    Every clip in the film goes through this, tasks and slides alike — a raw take sits
    around -34 dB mean while a normalised one is near -19 dB, so a clip that skips this
    step is ~15 dB quieter than everything around it (see ../movie.md Pass 12).
    """
    if (os.path.exists(out)
            and os.path.getmtime(out) >= os.path.getmtime(src)):
        return out
    r = subprocess.run(
        ["ffmpeg", "-hide_banner", "-loglevel", "error", "-i", src,
         "-af", f"{DENOISE},loudnorm=I={TARGET_I}:TP=-1.5:LRA=11",
         "-ac", "1", "-y", out],
        capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"normalising {os.path.basename(src)} failed\n{r.stderr[-400:]}")
    return out


def part(n, p):
    for e in EXT:
        f = os.path.join(VOICE, f"t{n:02d}{p}.{e}")
        if os.path.exists(f):
            return f
    return None


def find(n):
    """Return one narration clip for task n, joining its two parts.

    The task line (tNNa) and the summary (tNNb) are recorded separately and are
    concatenated here into tNN.joined.wav with a short gap. A single tNN.* take is
    used as-is.
    """
    a, b = part(n, "a"), part(n, "b")
    if a and b:
        out = os.path.join(VOICE, f"t{n:02d}.joined.wav")
        # rebuild only when a part is newer than the join
        if (not os.path.exists(out)
                or os.path.getmtime(out) < max(os.path.getmtime(a), os.path.getmtime(b))):
            r = subprocess.run(
                ["ffmpeg", "-hide_banner", "-loglevel", "error", "-i", a, "-i", b,
                 "-filter_complex",
                 f"[0:a]aresample=44100[a0];"
                 f"aevalsrc=0:d={GAP}:s=44100[g];"
                 f"[1:a]aresample=44100[a1];"
                 f"[a0][g][a1]concat=n=3:v=0:a=1,"
                 f"{DENOISE},loudnorm=I={TARGET_I}:TP=-1.5:LRA=11[o]",
                 "-map", "[o]", "-ac", "1", "-y", out], capture_output=True, text=True)
            if r.returncode != 0:
                sys.exit(f"task {n}: joining caption+summary failed\n{r.stderr[-500:]}")
        return out
    if a or b:                       # only one half recorded — use it, flag below
        return a or b
    for e in EXT:
        f = os.path.join(VOICE, f"t{n:02d}.{e}")
        if os.path.exists(f):
            return f
    return None


def main():
    tasks = json.load(open(os.path.join(MDIR, "shotlist.json")))
    used = missing = 0
    print("task  source    duration")
    for t in tasks:
        n = t["n"]
        p = find(n)
        if p:
            d = duration(p)
            if d is None or d < 0.4:
                sys.exit(f"task {n}: {os.path.basename(p)} unreadable or too short")
            t["narration_s"] = round(d, 2)
            t["narration_src"] = "voice/" + os.path.basename(p)
            used += 1
            half = "" if ".joined." in p or p.endswith(f"t{n:02d}.wav") else "  <- only one half recorded"
            kind = "caption+summary" if ".joined." in p else "single take"
            print(f"{n:4d}  human     {d:6.1f}s  {kind}{half}")
        else:
            syn = os.path.join(AUD, f"t{n:02d}.wav")
            d = duration(syn) if os.path.exists(syn) else None
            if d is None:
                sys.exit(f"task {n}: no recording and no synthesised fallback")
            t["narration_s"] = round(d, 2)
            t["narration_src"] = "synth (not yet recorded)"
            missing += 1
            print(f"{n:4d}  synth     {d:6.1f}s  <- ./record.sh {n}")

    # slides: one take each, no fallback — an unrecorded slide is simply skipped so
    # the film still builds while a recording session is in progress.
    sl = []
    for s in SLIDES:
        p = None
        for e in EXT:
            c = os.path.join(VOICE, f"{s['id']}.{e}")
            if os.path.exists(c):
                p = c
                break
        if p:
            norm = normalise(p, os.path.join(VOICE, f"{s['id']}.norm.wav"))
            d = duration(norm)
            # point at the cropped derivative when the slide declares a crop, so the
            # render never shows the uncropped original (see prep_slides.py)
            img = s["img"]
            if s.get("crop"):
                img = os.path.splitext(img)[0] + ".crop.png"
            sl.append(dict(s, img=img, narration_s=round(d, 2),
                           clip=os.path.basename(norm)))
            print(f"  {s['id']:4s} slide     {d:6.1f}s  {s['title'][:44]}")
        else:
            print(f"  {s['id']:4s} -              -  not recorded, slide skipped")
    json.dump(sl, open(os.path.join(MDIR, "slides.json"), "w"), ensure_ascii=False, indent=1)

    json.dump(tasks, open(os.path.join(MDIR, "shotlist.json"), "w"), ensure_ascii=False, indent=1)
    total = sum(t["narration_s"] for t in tasks) + sum(s["narration_s"] for s in sl)
    print(f"\n{used} human, {missing} synthesised · narration total {total:.0f}s = {total/60:.1f} min")
    print("shotlist.json updated — now: node render.mjs && python3 mux.py")
    if missing:
        print(f"\n{missing} task(s) still synthesised; re-run this after recording them.")


def repace():
    """Re-fit typing speed to the new durations (stage 3). Always after a change
    to narration_s, or the player paces to stale numbers."""
    import subprocess
    subprocess.run(["python3", os.path.join(HERE, "pace.py")], check=True)


if __name__ == "__main__":
    main()
    repace()
