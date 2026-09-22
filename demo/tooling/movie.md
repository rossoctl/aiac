# Plan: UC-1 demo film — replay `capture.jsonl` as a narrated `.mp4`

## Goal

Turn a frozen **capture** into a watchable film: a developer appears to type each
`cmd` and receive each `output` live, a **summary card** explains each task as it
completes, and a narrator speaks over the whole thing. Target runtime ~7.5 min.

This file is the build's working log. It carries the decisions that are settled,
the stage-by-stage mechanism, and — at the bottom — the running list of problems
found while rendering and what fixed them. Update it as the film is iterated; it
is meant to be edited, not archived.

Vocabulary is fixed in `GLOSSARY-film.md`. Decisions with real trade-offs are in
`adr/0001-uniform-replay-pacing.md`. This file does not restate them; it points at
them.

**Narration is the capture's own text.** Each clip speaks the `task` line then the
`summary`, verbatim — identifiers included. There is no separate narration script:
what is heard is what is on screen, so prose changes upstream cannot desync the two.

## Source of truth

```
demo/out/uc1-onboarding_20260915-135453/
  capture.jsonl        21 tasks, 203 steps — the replay source
  logs/dev.log         Act III verdicts (developer)
  logs/test.log        Act III verdicts (tester)
  logs/devops.log      Act III refusal (devops)
```

Everything on screen comes from those four files. Nothing is invented; if the
film needs a claim they cannot support, the answer is to ask, not to write it.
`capture.jsonl` is regenerated upstream whenever narration prose changes — never
hand-edit it, and re-read it before a final render.

## Toolchain

| Tool | Version | Role |
|---|---|---|
| ffmpeg | 9.0.1 (`libx264`, `aac`) | frame → video, audio mux |
| node | 26.0.0 | Playwright host |
| Playwright | (fetched at build) | drives the replay page, captures frames |
| Python | 3.14.3 | build orchestration |
| piper-tts | 1.8.0 | narration, offline |
| Piper model | `en_US-ryan-high` (~121 MB) | the voice |

Piper lives in its own venv so it never touches the repo's `.venv`. The model is
a large binary — keep it out of git.

## Files

The build scripts live in the tooling tree; **everything they produce is written
into the capture bundle it was built from**, so a bundle carries its own film and
two bundles never overwrite each other's output.

```
demo/tooling/movie/          the build (source, versioned)
  slides-src/*.png  the authored diagrams — source, not build output
  read_capture.py   stage 1
  narrate.py        stage 2
  player.html       the replay page (1920x1080)
  render.mjs        stage 4
  mux.py            stage 5
  bundle.json       written by stage 1 — which bundle this build targets

demo/out/<bundle>/movie/     the artifacts (generated, not versioned)
  shotlist.json     the shot list, with measured narration durations
  audio/t01..t21.wav  narration clips
  video/*.webm      raw screen capture
  timeline.json     per-task start/end offsets, from the actual render
  uc1-demo.mp4      the film
```

Run in order. Stage 1 takes the bundle path and records it in `bundle.json`;
later stages read that, so they need no argument.

```bash
cd demo/tooling/movie
python3 read_capture.py ../../out/uc1-onboarding_20260915-135453
python3 build_title.py     # renders the opening title card
python3 prep_slides.py     # applies each slide's declared crop
./record.sh                # your narration (or narrate.py to synthesise)
python3 mix_voice.py       # measures takes, re-paces, writes slides.json
node render.mjs
python3 mux.py
```

`build_title.py` and `prep_slides.py` only need re-running when a slide or its crop
changes.

Generated artifacts are large (a ~121 MB voice model, raw video, 21 wavs) — keep
`demo/out/*/movie/` out of git.

## Pipeline stages

Ordered because each depends on the last. Stage 2 before stage 4 is the important
one: card dwell is derived from measured audio, so the audio must exist first.

1. **Read** — parse `capture.jsonl`; for tasks 19–21 also parse the three logs
   into `(cmd, output)` pairs. Result: a per-task step list.
2. **Narrate** — one clip per task, speaking the **task line then the summary**,
   both verbatim from `capture.jsonl`. Two sources, and a human recording always
   wins:
   - `mix_voice.py` — measures human takes in `<bundle>/movie/voice/tNN.*` and
     writes their durations into `shotlist.json`. Any task not yet recorded keeps
     its synthesised clip, so a partial session still builds a complete film.
     `make_script.py` writes the read-aloud script from the same verbatim text.
   - `narrate.py` — synthesises all 21 with Piper as the fallback track.

   Either way the measured duration is what stage 3 paces to.
3. **Time** — `pace.py` fits typing speed to each task's measured narration, aiming
   to finish `LEAD` (2s) before the voice so the last result is readable. Writes `pace`
   per task into `shotlist.json`. Runs automatically after `mix_voice.py` /
   `narrate.py`; run it by hand only if you edit durations directly.
4. **Render** — drive the replay page in Playwright against the shot plan;
   capture frames at a fixed rate.
5. **Mux** — ffmpeg: frames → H.264, concatenate the narration clips into one
   track, mux, write `uc1-demo.mp4`.

## What the frame does

Four horizontal bands, fixed for the whole film. Heights are in `player.html`;
`TERM_H` in the script must equal `1080 - band_top - narration_height` or the
scroll maths drifts.

```
 50px   window chrome — title, progress ticks, task counter
 96px   TASK BAND     — "TASK n OF 21" + the caption
684px   VERBATIM ZONE — the terminal, scrolling upward
250px   NARRATION     — the summary, while it is spoken
```

**Task band.** The caption appears with the task's **first** command and stays put
until the task ends. It is never an interstitial and never animates away
mid-task — a viewer glancing at any frame can tell which task they are in.

**Verbatim zone.** Strict alternation, one step at a time: `cmd` types character
by character, then its `output` appears beneath it, then the next `cmd` types
below that. The stack **scrolls upward** as it grows (a CSS `translateY` on
`#scroll`, recomputed after every append and every ~14 typed characters) so the
newest line is always in view. Each task starts from a cleared screen.

`output` never types — it flows in at once. JSON bodies are pretty-printed (195 of
203 outputs parse as JSON; 4 are Rego, passed through unformatted; 4 are bare
`204`).

**Two output reshapings**, both required — see Pass 2:

- **LLM decisions are unescaped.** A chat-completions body carries the actual
  verdict as an escaped JSON string inside `.choices[].message.content`, wrapped in
  an envelope of ids and token counts. `shapeOutput()` lifts `content` out,
  double-decodes it and shows *that*, so the frame reads
  `"approved": false, "reason": "…"` instead of `cache_read_input_tokens`.
- **Token accounting is folded** to `"usage": { … token counts … }` wherever an
  envelope survives.

`explain`, where present, renders beneath the output with a violet rule — visually
distinct so it can never be mistaken for captured bytes.

**Pacing**: first 3 steps of every task type at normal speed, the rest accelerate
under a fast-forward marker. One rule, applied in every task by **step position** —
never by task identity — and no step is ever dropped.

**One exception, deliberate**: a step whose `explain` begins `REJECTED` gets a
**4.2s hold** and a red inset highlight, and fast-forward is switched off for it.
This is the film's strongest beat (task 7, step 8) and at uniform pace it scrolled
past in under a second — it was invisible in the Pass 1 render. The exception is
keyed on content (`/^REJECTED/`), not on a task number, so it survives a
regenerated capture and fires wherever a rejection actually occurs. Recorded as a
named exception in `adr/0001-uniform-replay-pacing.md`, which states the governing
rule: a pacing rule may key on step position or on a step's own content, never on a
task's identity.

**Narration zone.** The summary appears at the bottom **as it is being narrated**,
under a live `NARRATING` indicator, and holds for the task. It is not a post-task
card: narration starts with the task's first command, so screen text and speech
begin together. The zone shows `summary` verbatim — and the narrator reads that same
text, identifiers included, so screen and voice never diverge.

**What is spoken.** Each clip reads the **task caption first, as a spoken title**,
then the summary — so a listener hears what the task is before hearing what
happened. The task band carries a gate-coloured inset rule for the first ~2.6s to
mark the caption being read. Caption-plus-summary is 292s synthesised, against 224s
for summary alone.

Task length is `max(replay, narration) + tail`, so neither is ever truncated.

## Measured numbers

Recompute these after any prose change upstream — they are the current build, not
constants.

| | |
|---|---|
| Tasks / steps | 21 / 203 |
| Narration total | 224s (17 verbatim + 4 rewritten) |
| Estimated runtime | ~450s / 7.5 min |
| Longest clip | task 6, 26.3s (the policy, read in full) |
| Shortest clip | task 15, 3.7s |
| Outputs > 12 KB | 7, in tasks 1, 3, 5, 12 |
| All latency | tasks 6, 7, 14, 15 (273s); every other task is sub-ms |

## Known hazards

Things that have already bitten, or will. Each is a real failure mode, not a
theoretical one.

- **`say` silently substitutes voices.** Not used any more (Piper replaced it),
  but if anyone reintroduces it: `say -v <missing>` exits 0 and renders the
  default voice. Six names did this on this machine.
- **The strongest beat is non-deterministic.** Task 7's evaluator rejection is in
  roughly half of runs. `grep -c REJECTED capture.jsonl` must return 2. If a
  re-cut returns 0, Act I has lost its climax and needs restructuring.
- **Act III's verdicts are not in the capture.** Tasks 19–21 hold only a login
  step; the eight allow/deny results are in `logs/`. Rendering from the capture
  alone yields three redacted-token responses under narration that promises
  verdicts.
- **Captions churn.** Key everything on task index or a stable substring, never
  an exact caption string.
- **Single-line JSON.** Most outputs are one unwrapped line up to 12,613 chars —
  ~130 wrapped terminal lines. Pretty-printing is not cosmetic; without it the
  frame is a wall.
- **Identical cmds.** All 12–13 steps in tasks 6, 7, 14, 15 share one `cmd`
  string. Expected, not a parse bug.
- **Local identifiers on screen.** `localtest.me`, cluster UUIDs and the internal
  LiteLLM host are visible throughout. Not sensitive; they date the recording.

## Do not

- Run the demo or touch the cluster to re-check a frame. A run is ~25 minutes and
  bills ~100 real LLM completions. The capture is the boundary.
- Hand-edit `capture.jsonl`. It is generated; edits are overwritten.
- Paraphrase, abridge or invent anything in the **verbatim zone**.

## Iteration log

Append an entry per render pass: what looked wrong, what changed, what it cost.
Newest last.

### Pass 1 — first render (2026-09-15)

Two bugs, both found before any usable footage existed.

**`page.evaluate(__start)` never returned.** `__start` was `async` and awaited
`window.__next` once per task, so the driver's own `evaluate()` call blocked
forever on the whole film and never reached its first `waitForFunction`. Three
renders died with an empty log and a 0-byte `.webm` and looked like an environment
problem. Fix: `__start` is now a synchronous kick-off that fires `__runAll()` and
returns `true` immediately; the driver owns the pacing loop.

**Node buffers stdout when it is not a TTY.** Diagnostics were being written but
never appeared, which is what disguised the bug above as "the render is hung".
Fix: redirect to a log file and read that (`node render.mjs > /tmp/render.log`),
and prefer `process.stdout.write` in probes.

Also verified in isolation before re-running the full render: Playwright
finalizes the `.webm` correctly on `context.close()` (1.14 MB / 13.4s for a
two-task probe), so video capture was never the problem.

### Pass 2 — layout and legibility rewrite (2026-09-15)

The Pass 1 render completed (338.6s, 35.8 MB, streams verified: 1920x1080 H.264
30fps + AAC, audio mean -20.4 dB / peak -2.8 dB). Frame inspection at the key
beats found two defects and prompted four layout changes. All six are now in
`player.html`.

Defects found by looking at actual frames:

1. **LLM boilerplate filled the screen.** At task 7 the frame showed `usage`,
   `completion_tokens` and `cache_read_input_tokens` while the summary described a
   rejection. Pretty-printing had expanded the chat *envelope*; the decision itself
   was buried as an escaped string in `.choices[].message.content`. Fixed by
   `shapeOutput()` (see "What the frame does").
2. **The rejection beat was invisible.** 13 steps in ~13s with the DOM trimmed to
   30 blocks meant the strongest moment in the film scrolled past in under a
   second. Fixed with a content-keyed 4.2s hold — the one deliberate exception to
   uniform pacing.

Layout changes:

3. Task caption moved out of the bottom card into a **task band** below the window
   chrome, appearing with the first command and holding for the whole task.
4. The terminal now **scrolls upward** as `cmd` → `output` → `cmd` → `output`
   accumulate, instead of being a bottom-anchored block.
5. The summary shows **while it is narrated** (bottom zone, live `NARRATING`
   indicator) rather than as a post-task interstitial.
6. Each task starts from a **cleared screen**, so no task inherits the tail of the
   one before it.

Verified before re-rendering: a single-task probe of task 7 captured the rejection
frame with the band, the upward scroll, the unescaped decision
(`"approved": false` in red), the highlighted REJECTED hold, and the narration zone
all correct simultaneously.

### Pass 3 — Pass 2 rendered and verified (2026-09-15)

`uc1-demo.mp4`, 276.7s (4.6 min), 73.5 MB. All six Pass 2 changes confirmed on
extracted frames: task band present and correct, terminal scrolling upward,
`cmd` -> `output` alternation, LLM decisions unescaped to
`"approved": true/false` + `"reason"` with no token boilerplate, narration zone
live at the bottom, per-task screen clear.

The rejection hold works: at **112s** the REJECTED block is on screen, red-inset,
`"approved": false` in red, held long enough to read. In Pass 1 the same beat was
unreadable.

Runtime dropped from 338.6s to 276.7s despite adding a 4.2s hold — the rewrite
types two characters per tick instead of one, so replays are faster (task 2:
31.3s -> 20.5s). Narration is unchanged at 224s, so more tasks are now
narration-bound than replay-bound, which is the right balance for a demo: the
voice sets the pace and the terminal keeps up.

Note for the next pass: **`mux.py` output grew from 35.8 MB to 73.5 MB** for a
*shorter* film. The scrolling transform makes almost every frame differ from the
last, which defeats H.264 inter-frame compression at `-crf 20`. Not a defect —
but if file size matters, raise `-crf` or drop to 24 fps.

### Pass 4 — human narration (2026-09-16)

Synthesised narration was judged not good enough (Piper `en_US-ryan-high` was
itself a replacement for macOS `say`; see the voice addendum in the ADR). The film
now takes **human recordings**, and narration covers the **task caption as well as
the summary**.

New in `demo/tooling/movie/`:

- `make_script.py` → writes `<bundle>/movie/RECORDING-SCRIPT.md`: 21 numbered
  blocks, caption then summary, 851 words (~6 min of speech).
- `record.sh` → walks the untaken blocks, prints each, records on ENTER, stops on
  `q`, offers a re-take. `./record.sh 7` redoes one task.
- `mix_voice.py` → measures the takes and re-times the film to them.

`mux.py` now prefers `voice/tNN.*` over `audio/tNN.wav` per task, so recorded and
synthesised clips can coexist while a session is in progress.

**Device trap:** on this machine the default avfoundation audio input `[0]` is
`WebexMediaAudioDevice`, a virtual device that records silence. `record.sh`
defaults to `[1] MacBook Pro Microphone`; override with `MIC=:2` for the dock. List
inputs with `ffmpeg -f avfoundation -list_devices true -i ""`.

**Timing follows the voice**, not the reverse: read at whatever pace suits, and
`max(replay, narration)` stretches the replay to match. Caption-plus-summary is
292s synthesised versus 224s for summary alone, so expect the film to run longer
than the 276.7s Pass 3 cut.

### Pass 5 — human narration, two takes per task (2026-09-16)

`record.sh` records **two separate clips per task**: the task line
(`voice/tNNa.wav`) and the summary (`voice/tNNb.wav`). Both lines stay on screen
with the one being read highlighted.

**SPACE starts and stops every recording** — four presses per task, always the same
key. `wait_space()` ignores every other key while a take is running, so a stray
press cannot cut a recording short; the start gate additionally accepts `s` (skip)
and `q` (quit).

Recording the parts separately (rather than one take split at a keypress) is what
makes per-part review possible. The prompt after each task is:

```
ENTER next · h hear both · 1 hear task · 2 hear summary · a redo task · b redo summary · q quit
```

so a fluffed summary costs only the summary.

**Numbering stays 1–21, by task.** Parts are not numbered separately:
`./record.sh 7` does both of task 7's parts, and `a`/`b` at the prompt redo one.

```bash
./record.sh 1-3        # trial run
./record.sh            # resume: every task missing either part
./record.sh --from 7   # task 7 to the end
./record.sh --list     # task+summary / one part only / -
```

`q` exits keeping saved work; `mix_voice.py` falls back to the synthesised clip for
anything unrecorded, so the film builds at any point.

- `mix_voice.py` joins each a+b pair into `tNN.joined.wav` with a 0.45s gap and
  measures **that** — rebuilt only when a part is newer than the join.
- `mux.py` prefers `tNN.joined.wav`, since that is what the timings were measured
  from; using a half would desync audio from the render.

Each take reports duration and peak level, flagging `SILENT? check MIC` at or below
-90 dB — this catches the `[0] WebexMediaAudioDevice` trap (verified: silence reads
-91.0 dB) rather than leaving it to be discovered at mux time.

### Pass 6 — narration is the capture's text, verbatim (2026-09-16)

`narration.md` is **deleted**. Both the read-aloud script and the synthesised
fallback now speak `task` then `summary` straight from `capture.jsonl`, identifiers
and all.

It existed because TTS mangled `spiffe://localtest.me/ns/team1/sa/github-agent` and
36-character UUIDs, so four tasks had hand-written spoken variants. With a human
reading there is nothing to work around, and the layer was a liability: a second
copy of the prose to keep in step with a `summary` that is regenerated upstream.

Consequences:

- **What is heard is what is on screen.** No drift is possible between the narration
  and the summary card, and a prose change upstream propagates to both by
  regenerating the script.
- `make_script.py` and `narrate.py` lost their `narration.md` parsing; three fewer
  moving parts.
- Read-aloud total is 848 words across 21 tasks.
- An earlier intermediate step — respelling identifiers for the ear
  (`issue-operations` for `issue_operations`) — is also dropped. The reader handles
  the literal text.

### Pass 7 — typing speed fitted to the narration (2026-09-16)

Fast-forward was firing on every task and then the frame sat on a finished screen
waiting for the voice — the worst of both, and visibly wrong: accelerate, then idle.
Measured across the film it was **~190s of dead screen**, over half the runtime.

The rule was backwards. Typing speed was a constant and narration was whatever it
was; now narration is the given and **typing speed is solved for**. New stage 3
(`pace.py`) computes, per task:

```
budget = narration − tail − (per-step reveals + any rejection holds)
cps    = budget / total command characters
```

clamped to a readable band (55ms/char slowest, 1.5ms/char fastest blur). Three
outcomes:

- **cps lands in the band** → one even speed for the whole task, replay and voice
  finish together. 17 of 21 tasks.
- **cps above the slow bound** → the task has too little to type to fill the voice;
  type at 55ms/char and accept a short hold. 4 tasks (1, 8, 13, 16 — one-step tasks
  where the frame simply has nothing left to show).
- **cps below the fast bound** → even a blur overruns; fall back to normal-then-
  fast-forward. **2 tasks** (5 and 15), where before it was all 21.

Idle drops from ~190s to **41s**, and 12 tasks that never needed fast-forward no
longer get it.

`pace.py` runs automatically at the end of `mix_voice.py` and `narrate.py`, since
both change `narration_s` and the player would otherwise pace to stale numbers.
`player.html` reads `pace` per task rather than hardcoding speeds, and `typeCmd()`
batches characters below ~8ms/char so a sub-millisecond speed is actually achievable
(a per-character `await` costs more than the delay itself).

**This makes the fast-forward marker meaningful.** It now appears only where the
replay genuinely has more to show than the voice has time for, which is what the
badge always claimed.

### Pass 8 — a 2s lead, and text before voice (2026-09-16)

Two timing faults visible once the whole film was narrated by a human.

**1. The replay was overrunning the voice.** Act III left only ~0.5s between the
last verdict appearing and the task changing — the viewer heard the narration end
before they could read the result, then it vanished. Eight tasks were actually
*finishing after* the narration (task 2 by 2.8s), because `pace.py`'s per-step cost
was modelled at 0.35s when the render's real cost is ~0.52s.

Fixed by correcting `PER_STEP` to the measured 0.52s and introducing `LEAD = 2.0`:
the budget is now `narration − LEAD − fixed`, so the replay aims to finish two
seconds before the voice does and the final output is readable while the narration
closes. Twelve tasks land at exactly +2.0s, Act III among them.

`LEAD` is a **target, not a guarantee**. Tasks 2, 3 and 15 have more steps than the
voice has time for (task 2: 49 steps, whose per-step reveals alone are 25s against
32s of narration) and land 0.7–1.1s *after* the voice instead. They are left as fast
as is legible; forcing the target would mean compressing the per-step gap to the
point where the steps stop reading as separate commands. Accepted deliberately.

**2. The voice was starting before the text.** Narration was placed at each task's
exact start offset, so voice and caption began together and any render lag put the
voice first. `mux.py` now delays every clip by `TEXT_LEAD = 0.2`s, so the task band
and summary appear a beat before the reading starts.

### Pass 10 — intro, mid-film state slide, and outro (2026-09-16)

Seven narrated slides now bracket and punctuate the replay:

| id | where | slide |
|---|---|---|
| `i0` | intro | title card — what the demo shows, and the mapping exercise |
| `i1` | intro | `policy.md` — the entire human input |
| `i2` | intro | the GH AgentCard, magnified on its two skills |
| `i3` | intro | the MCP tool descriptions, magnified on four capabilities |
| `i4` | intro | State 1 — before onboarding |
| `s2` | after task 11 | State 2 — the agent alone, outbound still empty |
| `s3` | after task 18 | State 3 — after onboarding, both gates populated |
| `o1` | outro | *Now scale it* — one agent and one tool versus three and five |

The three state diagrams sit at the film's own act boundaries: State 1 before anything
happens, State 2 at task 11 (the agent alone), State 3 at task 18 — the last task that
changes the system. The three test scenarios then run against a diagram the viewer has
just been walked through, and the outro is argument alone rather than another diagram.

`i0` and `o1` are **built** (`build_title.py`, `build_outro.py`) rather than supplied,
so their wording and counts track the film without a re-export.

The six authored diagrams are **committed** under `demo/tooling/movie/slides-src/`
(4.5 MB) and staged into `<bundle>/movie/slides/` by `prep_slides.py`. They are source
in the same sense as `slides.py`: without them a clean checkout cannot rebuild the
film, and `demo/out/` is ignored precisely because everything in it is reproducible.
`title.png`, `outro.png` and any `*.crop.png` stay out of git — their generators are
committed instead.

Verified: emptying `<bundle>/movie/slides/` and running `prep_slides.py`,
`build_title.py`, `build_outro.py` restores all nine images.

- `slides.py` holds the id, anchor, title, spoken script and optional `crop` for
  each. A `crop` exists because a source PNG can carry something that should not be on
  screen — `i1`'s original included a real `kubectl get configmap` command from the
  author's own system, cropped away to leave the policy box. `prep_slides.py` writes
  `<stem>.crop.png` and `mix_voice.py` points the render at that, so the original is
  never shown and never modified.
- The scripts are
  **authored**, unlike task narration which is verbatim capture — they describe what
  the diagrams show and nothing more.
- `slide.html` renders one slide: caption band plus the image fitted to the frame. A
  title card renders `bare` (full frame, no band) since it carries its own heading.
- `render.mjs` drives slides on a **second page** in the same context, brought to the
  front for its duration, so the replay's DOM and scroll position are untouched. An
  anchor is `intro`, `after:<task>` or `outro`.
- Each slide holds for its own narration plus a 1.2s beat.
- An **unrecorded slide is skipped**, not stubbed, so the film builds at any point in
  a recording session.

Record them with `./record.sh slides` (or `./record.sh i0`) — a single take each, no
task/summary split.

### Frame-review checklist

What to look at after any render, in rough order of how often it has been wrong.
Extract stills with `ffmpeg -ss <t> -i uc1-demo.mp4 -frames:v 1 out.png` using
offsets from `timeline.json` — do not judge a render without looking at frames.

- does the decision, not the envelope, fill the verbatim zone (LLM tasks)
- is the REJECTED beat actually on screen long enough to read
- does the scroll keep the newest line in view, never mid-line or clipped
- task band: present and correct on every task, no stale caption
- narration zone: text on screen while its clip plays, not before or after
- fast-forward marker: reads as deliberate, not as a glitch
- 12 KB outputs (tasks 1, 3, 5, 12): scroll at a watchable rate
- A/V drift at the end of the film, not just the start
- Act III: log-sourced steps look native beside capture-sourced ones


## Open questions

- **Has upstream prose settled?** Narration is generated from `summary`; the
  capture thread is still refining it. Cheap to regenerate, but worth asking
  before a final render.
- **Should the `opa eval` steps move upstream?** Adding them to tasks 19–21 in the
  capture would let the film read one source instead of two and would fix it for
  every future re-cut. Cleaner, but blocks on another thread.
- **Task 6's 26s clip.** Kept long deliberately — it speaks the policy in full,
  which is the film's thesis. Revisit if it drags on screen.
