#!/usr/bin/env python3
"""Render the closing card to <bundle>/movie/slides/outro.png.

The spoken close moves off the State 3 diagram to an argument about scale: this film
onboarded one agent and one tool, and that was already not simple. The card makes the
comparison countable — the number of authorization decisions grows with the product of
agents and tools, not their sum.
"""
import json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE = json.load(open(os.path.join(HERE, "bundle.json")))["bundle"]
OUT = os.path.join(BUNDLE, "movie", "slides", "outro.png")

HTML = """<!doctype html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500;600&display=swap">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{width:1920px;height:1080px;background:#0D1117;color:#D6DEE8;
  font-family:"IBM Plex Sans",sans-serif;display:flex;flex-direction:column;
  justify-content:center;padding:0 130px;overflow:hidden}
.eyebrow{font-family:"IBM Plex Mono",monospace;font-size:21px;letter-spacing:.28em;
  text-transform:uppercase;color:#4FC3CC;font-weight:600}
h1{font-size:72px;font-weight:600;letter-spacing:-.02em;line-height:1.06;margin-top:22px;
  color:#F2F6FA}
.cols{display:flex;gap:0;margin-top:52px;align-items:stretch}
.col{flex:1;padding:30px 40px}
.col:first-child{border-left:3px solid #6BC48C}
.col:last-child{border-left:3px solid #E0B341;margin-left:46px}
.lab{font-family:"IBM Plex Mono",monospace;font-size:19px;letter-spacing:.2em;
  text-transform:uppercase;color:#5A6472;font-weight:600}
.big{font-size:60px;font-weight:600;margin-top:14px;line-height:1.1;letter-spacing:-.02em}
.col:first-child .big{color:#6BC48C}
.col:last-child .big{color:#E0B341}
.det{font-family:"IBM Plex Mono",monospace;font-size:21px;color:#8A95A4;margin-top:18px;
  line-height:1.75}
.det b{color:#D6DEE8;font-weight:600}
.claim{margin-top:56px;font-size:33px;color:#F2F6FA;line-height:1.35;max-width:1400px;
  border-top:1px solid #242C36;padding-top:34px}
.claim b{color:#4FC3CC;font-weight:600}
</style></head><body>
  <div class="eyebrow">One agent, one tool &middot; now scale it</div>
  <h1>And that was a simple case</h1>
  <div class="cols">
    <div class="col">
      <div class="lab">what that just took</div>
      <div class="big">1 agent<br>1 tool</div>
      <div class="det">2 agent scopes &middot; 4 tool scopes<br>
        <b>21 steps</b> &middot; 2 gates &middot; 8 verdicts</div>
    </div>
    <div class="col">
      <div class="lab">now one agentic flow</div>
      <div class="big">3 agents<br>5 tools</div>
      <div class="det">every agent &times; every tool it may call<br>
        <b>&times; every user on whose behalf it acts</b></div>
    </div>
  </div>
  <div class="claim">If the simple case took all that, consider the flow &mdash; the
    decisions grow with the <b>product</b>, not the sum. That is the problem
    <b>AIAC</b> exists to solve.</div>
</body></html>"""


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    html = os.path.join(HERE, ".outro.html")
    open(html, "w").write(HTML)
    mjs = os.path.join(HERE, ".outro.mjs")
    open(mjs, "w").write(f"""
import {{ chromium }} from 'playwright';
const b = await chromium.launch();
const c = await b.newContext({{ viewport: {{ width:1920, height:1080 }} }});
const p = await c.newPage();
await p.goto('file://{html}');
await p.waitForTimeout(900);
await p.screenshot({{ path: '{OUT}' }});
await c.close(); await b.close();
""")
    r = subprocess.run(["node", "--no-warnings", mjs], capture_output=True, text=True)
    os.remove(mjs); os.remove(html)
    if r.returncode != 0:
        sys.exit("outro render failed:\n" + r.stderr[-600:])
    print(f"{OUT}  ({os.path.getsize(OUT)/1024:.0f} KB)")


if __name__ == "__main__":
    main()
