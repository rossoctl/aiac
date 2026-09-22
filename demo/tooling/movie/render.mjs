// Stage 4 — drive player.html and capture video.
// Each task advances only when max(replay, narration) has elapsed, so the
// on-screen pacing matches the audio that will be muxed over it (../movie.md).
import { chromium } from 'playwright';
import { readFileSync, mkdirSync, writeFileSync } from 'fs';
import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

const HERE = dirname(fileURLToPath(import.meta.url));
const BUNDLE = JSON.parse(readFileSync(resolve(HERE, 'bundle.json'), 'utf8')).bundle;
const MDIR = resolve(BUNDLE, 'movie');
const tasks = JSON.parse(readFileSync(resolve(MDIR, 'shotlist.json'), 'utf8'));
// Slides are optional: an unrecorded slide is absent from slides.json and simply
// does not appear, so the film builds mid-recording-session.
let slides = [];
try { slides = JSON.parse(readFileSync(resolve(MDIR, 'slides.json'), 'utf8')); } catch {}
const slidesAt = k => slides.filter(s => s.at === k);
// Beat held after a slide's narration ends, before the film moves on. Intro slides
// get a short one so the opening does not drag on its way to task 1; the two state
// diagrams keep a longer beat because the viewer is still reading a dense picture when
// the narration stops. The final slide persists regardless (see showSlide's `keep`).
const INTRO_TAIL = 0.5;
const STATE_TAIL = 1.2;
const slideTail = s => (s.at === 'intro' ? INTRO_TAIL : STATE_TAIL);
const VID = resolve(MDIR, 'video');
// The audio is delayed by TEXT_LEAD (mux.py) so the caption precedes the voice. The
// task must therefore stay on screen until TEXT_LEAD + narration has elapsed, plus a
// hold so the last result is readable after the narration stops. Without the
// TEXT_LEAD term a task ends while its own narration is still playing (../movie.md
// Pass 13).
const TEXT_LEAD = 1.8;         // must match TEXT_LEAD in mux.py
const CARD_TAIL = 2.0;         // seconds the frame holds AFTER the voice finishes
mkdirSync(VID, { recursive: true });

const browser = await chromium.launch();
const ctx = await browser.newContext({
  viewport: { width: 1920, height: 1080 },
  recordVideo: { dir: VID, size: { width: 1920, height: 1080 } },
});
const page = await ctx.newPage();
page.on('console', m => { if (m.type() === 'error') console.log('  [page]', m.text()); });
await page.goto('file://' + resolve(HERE, 'player.html'));
await page.waitForTimeout(1200);   // let fonts settle before the first frame

const t0 = Date.now();
const timeline = [];

// Show one slide as an overlay on the replay page. Playwright's screencast is
// per-page, so a slide MUST render in the recorded page — a second page records to
// its own file and never reaches the film (see ../movie.md Pass 11).
async function showSlide(s, keep = false) {
  await page.evaluate(x => window.__showSlide(x), {
    id: s.id, title: s.title, src: 'file://' + resolve(MDIR, 'slides', s.img),
    kicker: s.at === 'intro' ? 'INTRO' : s.at === 'outro' ? 'OUTRO' : 'STATE',
    bare: s.img === 'title.png' || s.img === 'outro.png',
  });
  await page.waitForFunction(id => window.__shown === id, s.id, { timeout: 20000 });
  const start = (Date.now() - t0) / 1000;
  await page.waitForTimeout((TEXT_LEAD + s.narration_s + slideTail(s)) * 1000);
  const end = (Date.now() - t0) / 1000;
  timeline.push({ slide: s.id, start, end, dur: +(end - start).toFixed(2),
                  narration: s.narration_s });
  console.log(`slide ${s.id.padEnd(3)}  ${s.narration_s.toFixed(1)}s  ${s.title}`);
  // The last slide of the film is kept up: dismissing it reveals the replay still
  // showing the final task, so the video appears to jump back (../movie.md Pass 13).
  if (!keep) await page.evaluate(() => window.__hideSlide());
}

for (const s of slidesAt('intro')) await showSlide(s);

await page.evaluate(t => window.__start(t), tasks);

for (const t of tasks) {
  // Timestamp the moment this task is actually painted, not the moment we asked for
  // it: the page only switches band/summary when __runAll picks the task up, and the
  // band fades in over 300ms. Recording the request time put every audio clip ~2.8s
  // ahead of its caption (see ../movie.md Pass 9).
  await page.waitForFunction(n => window.__painted === n, t.n, { timeout: 300000 });
  await page.waitForTimeout(320);              // let the band's fade-in complete
  const start = (Date.now() - t0) / 1000;
  // wait for the replay of this task to finish (card shown)
  await page.waitForFunction(n => window.__done === n, t.n, { timeout: 300000 });
  const replayEnd = (Date.now() - t0) / 1000;
  const replay = replayEnd - start;
  // hold until narration for this task has had its full run, plus a tail
  const need = Math.max(replay, TEXT_LEAD + t.narration_s) + CARD_TAIL;
  const remain = need - replay;
  if (remain > 0) await page.waitForTimeout(remain * 1000);
  const end = (Date.now() - t0) / 1000;
  timeline.push({ n: t.n, start, end, dur: +(end - start).toFixed(2),
                  replay: +replay.toFixed(2), narration: t.narration_s });
  console.log(`task ${String(t.n).padStart(2)}  replay ${replay.toFixed(1)}s  ` +
              `narr ${t.narration_s.toFixed(1)}s  shot ${(end - start).toFixed(1)}s`);
  // A mid-film slide must play BEFORE the player is released: __next() starts the
  // following task immediately, so showing the slide afterwards means that task runs
  // hidden behind it and is already finished when the slide clears (see ../movie.md
  // Pass 13).
  for (const s of slidesAt('after:' + t.n)) await showSlide(s);
  await page.evaluate(() => window.__next && window.__next());
}

{
  const outro = slidesAt('outro');
  for (let i = 0; i < outro.length; i++) {
    await showSlide(outro[i], i === outro.length - 1);   // keep the last one up
  }
}

await page.waitForTimeout(1200);   // hold the closing frame
const total = (Date.now() - t0) / 1000;
writeFileSync(resolve(MDIR, 'timeline.json'), JSON.stringify({ total, timeline }, null, 1));
await ctx.close();
await browser.close();
console.log(`\ntotal ${total.toFixed(1)}s = ${(total / 60).toFixed(1)} min -> video/`);
