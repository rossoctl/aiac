# Glossary — UC-1 demo film

Vocabulary for the demo film built from a **capture bundle**. Scoped to
`demo/tooling/` and deliberately **not** part of the `aiac/` domain glossary
(`aiac/CONTEXT.md`), which fixes Policy Rules Builder vocabulary only — grants,
prohibitions, contradictions and conflicts. Nothing here is domain language; it
is production vocabulary for one deliverable.

The capture pipeline's own schema terms (`task`, `steps`, `cmd`, `output`,
`explain`, `sent`, `elapsed_ms`) are fixed by `plan.md` and are not redefined
here.

## Language

**Capture** (a.k.a. **capture bundle**):
The frozen `capture.jsonl` plus its sibling artifacts (`raw-capture.jsonl`,
`logs/`, `generated/`) produced by one demo run. The sole source of on-screen
fact for the film.
_Avoid_: **script** — that already names the demo's own `run/*.py` and, in
`plan.md`, the narration prose. Also avoid: recording, trace.

**Replay**:
Animated playback of a capture in which each `cmd` is typed and each `output`
revealed, as if a developer were issuing them live. Distinct from the
**viewer** (`capture.viewer.html`, built by `tools/build_jsonl_viewer.py`), a
static click-to-expand JSON inspector used to debug the capture.
_Avoid_: playback, simulation.

**Verbatim zone**:
The region of the frame that may show only `cmd` and `output` — captured bytes,
never authored prose. Whitespace reformatting (pretty-printing a JSON body) is
permitted; changing, abridging, or paraphrasing content is not.
_Avoid_: terminal (names the widget, not the guarantee).

**Authored zone**:
The region that shows the free-text fields — `task`, `summary`, `explain`. Always
rendered visually distinct from the **verbatim zone**, so a viewer can tell
captured bytes from written prose.
_Avoid_: narration zone (narration is audio; this is on-screen text).

**Slide**:
A narrated still that brackets or punctuates the replay: the intro sequence, the
State 2 diagram after task 11, and the outro. Defined in `slides.py` (id, anchor,
title, script) and rendered by `slide.html` on its own page, so the **verbatim
zone**'s DOM and scroll position survive underneath. Unlike a **narration clip** for
a task, a slide's script is **authored prose**, not captured text — slides describe
the system, they do not replay it.
_Avoid_: card (that is the **summary card**), title (only `i0` is a title card).

**Summary card**:
The panel that appears beneath the **verbatim zone** once a task's steps finish,
carrying that task's `task` caption and `summary`. It holds for whatever remains
of the task's **narration clip** after the replay ends — never a hand-tuned
constant. Where the replay outlasts the clip the card is brief; where the clip
outlasts the replay the card absorbs the remainder.
_Avoid_: overlay (rejected — it competes with narration for attention), lower
third.

**Narration clip**:
The audio for one task, reading its `task` line as a spoken title and then its
`summary` — both **verbatim from the capture**, identifiers included, so what is
heard is exactly what the frame shows. One clip per task, starting when that task's first `cmd` begins typing
and running concurrently with the replay. Its measured duration and the replay's
own length together set the task's on-screen length: a task runs for whichever is
longer, so narration is never truncated and the replay is never raced.

Two sources, and a **human recording always wins**: a take in
`<bundle>/movie/voice/` if one exists, otherwise the Piper-synthesised clip in
`audio/tNN.wav`. The two coexist per task, so a partial recording session still
builds a complete film. Timing follows the clip, never the reverse.

A human take is recorded as **one continuous read** with a SPACE press marking the
caption/summary boundary, then cut into `tNNa` (caption) and `tNNb` (summary) and
rejoined as `tNN.joined.wav` with a short gap. Splitting means a fluffed summary
costs only that half.
_Avoid_: voiceover, track (the mixed result is the audio track); scratch track
(the synthesised clips are a fallback, not a separate artifact).

**Fast-forward**:
The accelerated typing mode used when a task has more to type than its **narration
clip** has time for — entered after the first three steps and marked on-screen so
the speed change reads as deliberate. It never drops a step, and is suppressed for
the duration of a **rejection hold**. Engaged only where `pace.py` finds that even
the fastest legible typing would overrun the voice (3 of 21 tasks in the current
cut), never as a blanket rule. See `adr/0001-uniform-replay-pacing.md`.
_Avoid_: montage, skip (both imply omission; every step is shown).

**Fitted pacing**:
Solving typing speed from the narration rather than fixing it in advance: a task's
command characters are spread across whatever time the voice needs, so the replay
finishes about two seconds **before** the clip does — the last output stays readable
while the narration closes. That two-second **lead** is a target, not a guarantee: a
task with more steps than the voice has time for is left as fast as is legible. Computed by `pace.py` into a per-task `pace` block and
clamped to a readable band; the fallbacks are a hold (too little to type) or
**fast-forward** (too much).
_Avoid_: sync, stretching (the steps are not slowed individually — the whole task is
fitted).

**Rejection hold**:
The 4.2-second pause and red highlight given to a step whose `explain` begins
`REJECTED`, with **fast-forward** suppressed for it. The one deliberate departure
from uniform pacing, keyed on the step's own content rather than on any task
number, so it follows the beat through a regenerated capture and fires not at all
in the roughly half of runs that contain no rejection.
_Avoid_: pause, task-7 hold (it is not bound to a task).
