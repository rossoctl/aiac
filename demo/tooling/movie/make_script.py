#!/usr/bin/env python3
"""Write the human recording script: one numbered block per task, task caption
then summary. This is the text to read aloud, in order (see ../movie.md)."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from slides import SLIDES

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE = json.load(open(os.path.join(HERE, "bundle.json")))["bundle"]
MDIR = os.path.join(BUNDLE, "movie")


def main():
    tasks = json.load(open(os.path.join(MDIR, "shotlist.json")))
    out = [
        "# Recording script — UC-1 demo film",
        "",
        "**Two recordings per task**, made one after the other:",
        "",
        "- the **task line** → `voice/tNNa.wav`",
        "- the **summary**   → `voice/tNNb.wav`",
        "",
        "Both lines stay on screen and the one you are reading is highlighted. The build",
        "joins them with a short gap, so a fluffed summary never costs you the task line —",
        "you can re-record either on its own. Leave ~0.4s of silence at each end.",
        "",
        "You read the **captured summary verbatim** — the same text shown on screen,",
        "identifiers and all. There is no separate narration script to keep in step.",
        "",
        "## How to record",
        "",
        "From `demo/tooling/movie/`:",
        "",
        "```bash",
        "./record.sh 1-3        # TRY THIS FIRST — three tasks, then check the result",
        "./record.sh            # everything not yet recorded (resumes where you stopped)",
        "./record.sh --from 7   # continue from task 7 to the end",
        "./record.sh 7-9        # just tasks 7 to 9",
        "./record.sh 7          # re-record task 7 (both parts)",
        "./record.sh --list     # per-task status: task+summary / one part only / -",
        "MIC=:2 ./record.sh     # use the Thunderbolt dock instead of the built-in mic",
        "```",
        "",
        "**Numbering is by task, 1–21** — the same numbers as the film and the blocks",
        "below. The two parts of a task are not numbered separately; `./record.sh 7`",
        "does task 7's line and its summary, and the review prompt lets you redo just",
        "one of them.",
        "",
        "**`q` quits at any prompt** and keeps everything already saved; plain",
        "`./record.sh` then resumes from the first unrecorded task. A trial run costs",
        "nothing — record 1-3, build the film, continue only if you like how it sounds.",
        "",
        "**SPACE starts and stops every recording.** For each task you are prompted",
        "twice: SPACE to start the task line, SPACE to stop it — then, once it is saved,",
        "SPACE to start the summary and SPACE to stop that. Four presses per task, all",
        "the same key. Any other key is ignored while recording, so a stray press cannot",
        "cut a take short.",
        "",
        "After both: `ENTER next · h hear both · 1 hear task · 2 hear summary ·",
        "a redo task · b redo summary · q quit`.",
        "",
        "Every take reports duration and peak level. Default input is",
        "`[1] MacBook Pro Microphone` — `[0]` is a Webex virtual device that records",
        "**silence**, and a silent take is flagged `SILENT? check MIC`.",
        "",
        "**Then put your voice in the film:**",
        "",
        "```bash",
        "python3 mix_voice.py    # measures your takes, re-times the film to them",
        "node render.mjs",
        "python3 mux.py",
        "```",
        "",
        "Timing follows your reading, not the reverse — any task you have not recorded",
        "keeps its synthesised clip, so the film always builds.",
        "",
        "---", "",
    ]
    for t in tasks:
        body = t["summary"]
        words = len((t["task"] + " " + body).split())
        cw, sw = len(t["task"].split()), len(body.split())
        out += [f"## {t['n']:02d}  ·  ~{words} words total", "",
                f"**a — task line** ({cw}w) · `voice/t{t['n']:02d}a.wav`", "",
                f"> {t['task']}", "",
                f"**b — summary** ({sw}w) · `voice/t{t['n']:02d}b.wav`", "",
                f"> {body}", "", "---", ""]
    # the slides: one take each, id-named (i0, i1, ... s2, o1)
    out += ["", "# Slides", "",
            "One take per slide — `voice/<id>.wav`. These are **authored** scripts, not",
            "captured text, so read them as written or tell me to change the wording.",
            "", "---", ""]
    for s in SLIDES:
        where = {"intro": "intro", "outro": "outro"}.get(
            s["at"], "after task " + s["at"].split(":")[-1])
        out += [f"## {s['id']}  ·  {where}  ·  ~{len(s['script'].split())} words  "
                f"·  `voice/{s['id']}.wav`", "",
                f"**{s['title']}**", "", f"> {s['script']}", "", "---", ""]

    p = os.path.join(MDIR, "RECORDING-SCRIPT.md")
    open(p, "w").write("\n".join(out))
    print(f"{p}\n  21 blocks, {sum(len((t['summary'] + ' ' + t['task']).split()) for t in tasks)} words total")
    os.makedirs(os.path.join(MDIR, "voice"), exist_ok=True)
    print(f"  record into: {os.path.join(MDIR, 'voice')}/t01a.wav, t01b.wav … t21b.wav")


if __name__ == "__main__":
    main()
