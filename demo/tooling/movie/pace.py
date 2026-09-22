#!/usr/bin/env python3
"""Stage 3 — fit each task's replay to its narration, and decide if it needs
fast-forward at all.

Fixed typing speeds meant a task could accelerate through its steps and then sit on
a finished screen for 20s waiting for the voice. Instead: measure the narration,
compute the per-character speed that makes the replay land just before the voice
finishes, and only fall back to fast-forward when even the slowest readable typing
cannot fill the time (a 49-step task) or the steps cannot be stretched enough.

Writes `pace` per task into shotlist.json: {cps_normal, cps_fast, ff_from, tail}.
"""
import json, os

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE = json.load(open(os.path.join(HERE, "bundle.json")))["bundle"]
MDIR = os.path.join(BUNDLE, "movie")

SLOW = 0.055     # s/char — slowest that still reads as deliberate typing
FAST_D = 0.010   # s/char — a comfortable default
FLOOR = 0.0015   # s/char — the fastest legible blur
PER_STEP = 0.52  # output reveal + settle, per step (measured, not assumed —
                 # the render's real per-step cost, see ../movie.md Pass 8)
TAIL = 1.4       # card/voice tail after the last step
REJ_HOLD = 4.2   # the rejection hold, from the ADR
LEAD = 2.0       # TARGET, not a guarantee: aim to finish the replay this long
                 # before the voice does, so the last result is readable before the
                 # task changes. A task with more steps than time (2, 3, 15) cannot
                 # reach it and is left as fast as is legible — that is accepted.


def main():
    tasks = json.load(open(os.path.join(MDIR, "shotlist.json")))
    print("task steps  narr   plan    lead  mode")
    tot_idle = 0.0
    for t in tasks:
        st = t["steps"]
        chars = sum(len(s.get("cmd") or "") for s in st)
        holds = sum(REJ_HOLD for s in st
                    if str(s.get("explain") or "").startswith("REJECTED"))
        fixed = len(st) * PER_STEP + holds
        # aim to land LEAD seconds early: the final output stays on screen, read,
        # while the narration finishes.
        budget = max(0.0, t["narration_s"] - LEAD - fixed)

        if chars == 0:
            cps = FAST_D
        else:
            cps = budget / chars          # speed that exactly fills the voice

        ff_from = len(st)                 # default: no fast-forward at all
        if cps > SLOW:
            cps = SLOW                    # cannot stretch further; voice will lead
        elif cps < FLOOR:
            # even a blur overruns: type the first 3 normally, accelerate the rest
            ff_from = 3
            head = sum(len(st[i].get("cmd") or "") for i in range(min(3, len(st))))
            rest = chars - head
            cps = FAST_D
            fast = max(FLOOR, (budget - head * FAST_D) / rest) if rest else FLOOR
            t["pace"] = {"cps_normal": round(cps, 5), "cps_fast": round(fast, 5),
                         "ff_from": 3, "tail": TAIL, "per_step": PER_STEP}
            plan = head * cps + rest * fast + fixed
            idle = max(0.0, t["narration_s"] - plan); tot_idle += idle
            print(f"{t['n']:4d} {len(st):5d} {t['narration_s']:6.1f} {plan:7.1f}"
                  f" {t['narration_s']-plan:+5.1f}  fast-forward from step 4")
            continue

        t["pace"] = {"cps_normal": round(cps, 5), "cps_fast": round(cps, 5),
                     "ff_from": ff_from, "tail": TAIL, "per_step": PER_STEP}
        plan = chars * cps + fixed
        idle = max(0.0, t["narration_s"] - plan); tot_idle += idle
        mode = "full speed (nothing to stretch)" if cps >= SLOW - 1e-9 else f"even pace {cps*1000:.0f}ms/char"
        print(f"{t['n']:4d} {len(st):5d} {t['narration_s']:6.1f} {plan:7.1f} {t['narration_s']-plan:+5.1f}  {mode}")

    json.dump(tasks, open(os.path.join(MDIR, "shotlist.json"), "w"),
              ensure_ascii=False, indent=1)
    ff = sum(1 for t in tasks if t["pace"]["ff_from"] < len(t["steps"]))
    short = [t["n"] for t in tasks
             if t["narration_s"] - (sum(len(s.get("cmd") or "") for s in t["steps"])
                                    * t["pace"]["cps_normal"]
                                    + len(t["steps"]) * t["pace"]["per_step"]) < LEAD - 0.3]
    print(f"\nfast-forward on {ff}/21 · target lead {LEAD}s · total slack {tot_idle:.0f}s")
    if short:
        print(f"below the {LEAD}s target (more steps than the voice has time for, "
              f"accepted): {short}")


if __name__ == "__main__":
    main()
