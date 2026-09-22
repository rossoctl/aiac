# Uniform replay pacing, keyed on step position and content — never on task identity

_Scoped to the UC-1 demo film (`demo/tooling/`), not `aiac/` architecture. Vocabulary: `../GLOSSARY-film.md`._

The UC-1 demo film replays a **capture** by typing each `cmd` and revealing each
`output`. Step counts per task are wildly uneven (49, 33 and 27 in tasks 2, 5 and
3 against 1–2 elsewhere) and each task is narrated, so pacing needs a rule. No step
is ever dropped.

**Typing speed is solved for, not fixed.** The narration is the given: `pace.py`
measures each task's clip, subtracts the fixed costs (per-step output reveals, any
holds) and a two-second lead, and divides what remains by the task's command
characters. That per-task speed is what the player types at, so the replay lands
about two seconds before the voice finishes and the last output stays readable while
the narration closes.

Two fallbacks, when the fit does not land inside a readable band:

- **Too little to type** — the task cannot fill the voice even at the slowest
  readable speed, so it types at that speed and the frame holds. Mostly the
  single-step tasks (8, 13, 16), where the terminal genuinely has nothing more to
  show.
- **Too much to type** — even the fastest legible speed would overrun, so the task
  falls back to the original rule: the first three steps at normal speed, the
  remainder accelerated under an on-screen **fast-forward** marker. With the
  narrator's own pacing this fires on 3 of 21 tasks; with the shorter synthesised
  narration it fired on 2. It was once the primary mechanism (see "How this rule
  changed" below).

The constraint that matters is **what a rule may key on**:

- **Never a task's identity** — not its number, not its caption. `capture.jsonl`
  is regenerated upstream whenever narration changes, so any rule that branches on
  "task 7" has to be re-audited after every regeneration and silently mis-fires if
  task order ever shifts.
- **Step position is allowed** — "the first three steps of whatever task this is"
  holds for any capture.
- **A step's own content is allowed** — a rule that reads the step it is rendering
  travels with that step wherever it lands.

This is deliberately narrower than "no special cases", which is how this ADR was
originally worded. That phrasing did not survive the first render (see the
exception below); the principle above is what it was actually protecting.

## Status

accepted. Amended twice as the film was built: the "no special cases" phrasing on
2026-09-15 (see "Exception: the rejection hold"), and the primary mechanism on
2026-09-22, when fitted pacing replaced fixed speeds (see "How this rule changed").

## How this rule changed

The rule above is the second version. The first fixed typing speed as a constant and
let the narration be whatever length it was, which produced the worst of both: a task
would accelerate through its steps under a fast-forward marker and then sit on a
finished screen waiting for the voice. Measured across the film it was **~190 seconds
of dead screen**, over half the runtime, and fast-forward fired on **all 21 tasks**
including 12 where a full-speed replay would have finished before the narration
anyway.

Inverting it — narration given, speed derived — cut idle time to ~54s and reduced
fast-forward to 3 tasks. Two consequences worth stating:

- **The fast-forward marker now means something.** It appears only where the replay
  genuinely has more to show than the voice has time for, which is what the badge
  always claimed.
- **Pacing depends on measured audio**, so `pace.py` must run after anything that
  changes a clip's duration. `mix_voice.py` and `narrate.py` both call it; editing a
  duration by hand and skipping it leaves the player pacing to stale numbers.

The two-second lead is a **target, not a guarantee**. Tasks 2, 3 and 15 have more
steps than the voice has time for — task 2's 49 per-step reveals alone are ~25s
against ~32s of narration — and land fractionally after the voice instead. Forcing
the target would mean compressing the per-step gap until the steps stop reading as
separate commands, so they are left as fast as is legible.

## Considered options

The four LLM tasks (6, 7, 14, 15) make the uniform rule look wrong: all 12–13
steps in each carry the **identical** `cmd`
(`POST …/v1/chat/completions`), so the replay types the same URL 13 times, which
reads as repetition rather than progress. The rejected alternative was a
per-task **verdict feed** for those four: type the POST line once, then stream
each call's focal entity and approve/REJECTED verdict beneath it.

It was rejected because it keys on **task identity**: "for tasks 6, 7, 14 and 15,
render differently". While task count and order are stable at 21 today, a renderer
that branches on task number has to be re-audited after every regeneration. A rule
keyed on step position or on a step's own content does not.

Note what this does *not* rule out: a verdict feed keyed on content — "any step
whose output carries an `approved` field renders as a verdict line" — would be
admissible under the principle above. It was not adopted because the simpler
`explain`-in-the-authored-zone treatment proved sufficient once the LLM decision
was unescaped (Pass 2), not because content-keyed rules are forbidden.

## Consequences

- The repeated-URL problem is accepted, not solved. The varying content of those
  50 LLM steps reaches the screen through each step's `explain` — rendered in the
  **authored zone** beneath the `output` — plus the **narration clip**.
- This is what keeps the task-7 evaluator rejection visible. That beat (a second
  LLM catching the first omitting `issue_operations` for `developer`, quoting the
  policy back, and forcing a retry) is the strongest single moment in the
  capture, and it is **non-deterministic** — roughly half of runs have it.
  Verify with `grep -c REJECTED capture.jsonl` before any re-cut; this bundle
  returns 2.
- `explain` is present on all 50 LLM steps, so the fallback is total for the
  tasks that need it.
- Long outputs are pretty-printed and fast-scrolled rather than truncated, so
  the **verbatim zone** stays complete: 195 of 203 outputs parse as JSON, 4 are
  Rego (passed through unformatted), 4 are bare `204` status lines.
- Those four `204` steps render their **request body** instead of the status line —
  up to 12 KB of computed policy that is otherwise invisible, since the substance of
  such a call is what was sent, not what came back. Keyed on the response carrying no
  substance (under 12 characters), never on a task number, so it follows the pattern
  wherever it occurs.

## Exception: the rejection hold

One step type is paced differently. A step whose `explain` begins `REJECTED` gets a
**4.2 second hold** and a red inset highlight, with fast-forward suppressed for
that step.

**Why.** Task 7's evaluator rejection is the film's strongest beat — the only
moment the system is seen catching its own error. Under strictly uniform pacing it
rendered as the 8th of 13 near-identical steps and scrolled past in under a second;
frame inspection of the Pass 1 render found it effectively invisible. A viewer
could not read the one thing the act is built around.

**Why it is consistent with this ADR.** The rule keys on the step's own `explain`
content, never on a task number. Concretely:

- If a regenerated capture puts the rejection in a different task, the hold follows
  it.
- If a run produces two rejections, both hold.
- If a run produces none — which is roughly half of runs, since the beat is
  **non-deterministic** — nothing fires and pacing is exactly uniform.

So the renderer still carries no knowledge of any particular task, which is the
property this ADR exists to protect.

**Cost.** The hold adds ~4.2s to any task containing a rejection. Measured across
the whole film it is invisible against the rewrite that accompanied it: total
runtime fell from 338.6s to 276.7s.

## Addendum — Act III sources the demo logs

Tasks 19–21 in `capture.jsonl` carry **one step each: the ROPC login**. The eight
allow/deny verdicts their `summary` describes ("source read and write and issue
reads allowed, closing an issue denied") are not in the capture — the strings
"allowed" and "denied" appear in those tasks only inside the authored `summary`.
Replaying the capture alone would therefore narrate a payoff over three
near-identical redacted-token responses.

The verdicts are real and were captured, in `logs/dev.log`, `logs/test.log` and
`logs/devops.log`, as `opa eval` invocations against the generated Rego plus a
result table. For tasks 19–21 the **verbatim zone** therefore reads those logs in
addition to the capture step: the `opa eval` line types as a `cmd`, the inbound
result and verdict table reveal as `output`. Both are real captured terminal
text, so the no-invented-content guarantee holds; the film's source is two files
rather than one.

Parse shape, verified: 3 typeable commands in `dev.log` and `test.log`, 2 in
`devops.log` (it stops at the inbound gate by design), 8 verdict rows in total.

The alternative — asking the capture thread to add these steps upstream so the
film needs a single source — remains the cleaner long-term fix and would make
this addendum obsolete. It was not taken because it blocks the film on another
thread.

## Addendum — narration runs concurrently with the replay

Narration for a task begins when its first `cmd` starts typing, not after the
last one finishes. The task's on-screen length is `max(replay, narration clip)`:
where speech outlasts the replay the **summary card** absorbs the remainder;
where the replay outlasts speech the card is brief.

This was not the original design — strictly sequential playback (commands silent,
then card plus narration) was chosen first and is simpler to sync. Measuring the
real `Ava (Premium)` clips showed why it fails: narration length and step count
are inversely correlated. Task 1 has 2 steps and 22.7s of speech; task 3 has 27
steps and 9.6s. Sequential playback therefore holds a near-static frame for ~23s
on the talk-heavy tasks while racing the step-heavy ones, and adds roughly three
minutes of dead air. Measured narration totals 286s across the 21 tasks;
estimated film runtime under the concurrent model is ~7.9 minutes.

Sync remains derived rather than hand-tuned: both inputs are measured, so a prose
change upstream re-measures and re-times with no manual intervention.

## Addendum — narration uses Piper, not macOS `say`

Narration is generated by **Piper** (`pip install piper-tts`) using the
`en_US-ryan-high` voice model, not by macOS `say`. `say` was the original choice
for having no dependencies; it was abandoned on listening evidence — `Ava
(Premium)` is the highest tier `say` exposes (macOS does not offer the Siri
neural voices to the command at all) and it was judged not good enough for the
film. A blind A/B of the same sentence across Ava (Premium), Ryan-high,
Lessac-high and Amy-medium selected Ryan-high.

Consequences:

- The pipeline gains a Python dependency and a ~129 MB voice model, against
  `say`'s zero. Both are offline, so there is still no API key, no network at
  render time, and no per-render cost — narration still regenerates automatically
  when upstream prose changes.
- Measured narration totals 261s across the 21 tasks (Ava measured 286s), giving
  an estimated ~7.7 minute film under the concurrent model.
- The voice model is pinned by filename. Piper fails loudly on a missing model,
  which removes a hazard `say` carries: `say` **silently substitutes the default
  voice** for any `-v` name it lacks. On this machine `-v Ava`, `-v Evan`,
  `-v Alex`, `-v Allison`, `-v Susan` and `-v Tom` each exited 0 and produced
  audio byte-identical to Samantha. Had the pipeline stayed on `say` and pinned an
  uninstalled voice, it would have shipped the wrong narrator with nothing to
  indicate it.
