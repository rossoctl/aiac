#!/usr/bin/env python3
"""Render the opening title card to <bundle>/movie/slides/title.png.

Built rather than supplied so the wording tracks the film. Uses the same palette and
faces as player.html so the card does not look pasted in from elsewhere.
"""
import json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE = json.load(open(os.path.join(HERE, "bundle.json")))["bundle"]
OUT = os.path.join(BUNDLE, "movie", "slides", "title.png")

HTML = """<!doctype html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500;600&display=swap">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{width:1920px;height:1080px;background:#0D1117;color:#D6DEE8;
  font-family:"IBM Plex Sans",sans-serif;display:flex;flex-direction:column;
  justify-content:center;padding:0 130px;overflow:hidden}
.eyebrow{font-family:"IBM Plex Mono",monospace;font-size:21px;letter-spacing:.28em;
  text-transform:uppercase;color:#4FC3CC;font-weight:600}
h1{font-size:76px;font-weight:600;letter-spacing:-.02em;line-height:1.06;margin-top:24px;
  color:#F2F6FA}
.sub{font-size:29px;color:#8A95A4;margin-top:26px;line-height:1.45;max-width:1300px}
.rule{width:120px;height:4px;background:#4FC3CC;margin:34px 0 0}
/* the mapping exercise: what the system already knows, plus the policy, becomes the
   two questions the film answers. This is the spine of the spoken intro. */
.map{margin-top:34px;display:flex;align-items:center;gap:34px}
.known{display:flex;flex-direction:column;gap:11px}
.known span{font-family:"IBM Plex Mono",monospace;font-size:21px;color:#BEC9D6;
  border:1px solid #2C3641;border-left:3px solid #4FC3CC;border-radius:3px;
  padding:11px 20px;background:rgba(79,195,204,.05)}
.arrow{font-size:40px;color:#4FC3CC;opacity:.8}
.asks{display:flex;flex-direction:column;gap:14px}
.asks div{font-size:25px;color:#D6DEE8;line-height:1.35;max-width:660px}
.asks b{color:#6BC48C;font-weight:600}
/* the mechanism, named in the closing line of the spoken intro */
.how{margin-top:38px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.how .lb{font-family:"IBM Plex Mono",monospace;font-size:18px;letter-spacing:.2em;
  text-transform:uppercase;color:#5A6472;font-weight:600;margin-right:6px}
.how .s{font-size:23px;color:#BEC9D6;border:1px solid #2C3641;border-radius:3px;
  padding:10px 18px;background:rgba(180,154,224,.06);border-left:3px solid #B49AE0}
.how .s b{color:#C9B4EC;font-weight:600}
.how .p{font-size:26px;color:#5A6472}
/* the payoff line: a positive claim, not a parenthetical aside */
.claim{margin-top:40px;font-size:31px;color:#D6DEE8;line-height:1.35;max-width:1180px;
  border-top:1px solid #242C36;padding-top:30px}
.claim b{color:#6BC48C;font-weight:600}
</style></head><body>
  <div class="eyebrow">Agent Identity &amp; Access Control &middot; UC-1 Onboarding</div>
  <h1>Onboarding an agent and a tool</h1>
  <div class="sub">Step by step, manually, against a system that is already
    running &mdash; existing users, existing agents and tools, existing rules.</div>
  <div class="rule"></div>
  <div class="map">
    <div class="known">
      <span>user IdP profiles</span>
      <span>agent cards</span>
      <span>MCP tool descriptions</span>
      <span>+ the enterprise policy</span>
    </div>
    <div class="arrow">&rarr;</div>
    <div class="asks">
      <div>which users may access <b>which agents and tools</b></div>
      <div>which tools each agent may use <b>on behalf of the user who invoked it</b></div>
    </div>
  </div>
  <div class="how">
    <span class="lb">how</span>
    <span class="s">each decision <b>scoped in isolation</b></span>
    <span class="p">+</span>
    <span class="s">an <b>LLM applies the mapping</b> against the policy</span>
  </div>
  <div class="claim">We <b>automate the mapping</b>, so the rules never have to be
    written by hand.</div>
</body></html>"""


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    html = os.path.join(HERE, ".title.html")
    open(html, "w").write(HTML)
    js = f"""
import {{ chromium }} from 'playwright';
const b = await chromium.launch();
const c = await b.newContext({{ viewport: {{ width:1920, height:1080 }} }});
const p = await c.newPage();
await p.goto('file://{html}');
await p.waitForTimeout(900);
await p.screenshot({{ path: '{OUT}' }});
await c.close(); await b.close();
"""
    mjs = os.path.join(HERE, ".title.mjs")
    open(mjs, "w").write(js)
    r = subprocess.run(["node", "--no-warnings", mjs], capture_output=True, text=True)
    os.remove(mjs); os.remove(html)
    if r.returncode != 0:
        sys.exit("title render failed:\n" + r.stderr[-600:])
    print(f"{OUT}  ({os.path.getsize(OUT)/1024:.0f} KB)")


if __name__ == "__main__":
    main()
