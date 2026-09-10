#!/usr/bin/env python3
"""Build a self-contained HTML viewer for a .jsonl file: click a line to
expand/collapse its pretty-printed JSON. Usage: build_jsonl_viewer.py <path.jsonl> [out.html]
"""
import json, sys, os

def build_viewer(src, out=None):
    """Build the HTML viewer for the .jsonl at `src`. Returns the output path."""
    out = out or os.path.splitext(src)[0] + ".viewer.html"

    lines = []
    with open(src) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            lines.append(json.loads(line))

    data_json = json.dumps(lines, ensure_ascii=False).replace("</script>", "<\\/script>")
    title = os.path.basename(src)

    template = TEMPLATE.replace("__TITLE__", title).replace("__DATA__", data_json)
    with open(out, "w") as f:
        f.write(template)
    return out, len(lines)


def main():
    if len(sys.argv) < 2:
        print("usage: build_jsonl_viewer.py <path.jsonl> [out.html]", file=sys.stderr)
        sys.exit(1)

    src = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else None
    out, count = build_viewer(src, out)
    print(f"wrote {out} ({count} lines)")

TEMPLATE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>__TITLE__ viewer</title>
<style>
  :root {
    --bg: #f7f7f5;
    --panel: #ffffff;
    --border: #e3e1dc;
    --text: #2b2a28;
    --muted: #7a7772;
    --accent: #b5533c;
    --ok: #3d7a4f;
    --err: #b5423c;
    --code-bg: #2b2a28;
    --code-text: #eae6de;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    padding: 24px;
  }
  h1 { font-size: 16px; font-weight: 600; margin: 0 0 4px 0; }
  .sub { color: var(--muted); font-size: 13px; margin-bottom: 16px; }
  .row {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 8px;
    overflow: hidden;
  }
  .row.open { border-color: var(--accent); }
  .row-header {
    display: flex;
    align-items: baseline;
    gap: 10px;
    padding: 10px 14px;
    cursor: pointer;
    user-select: none;
  }
  .row-header:hover { background: #faf5f2; }
  .idx {
    font-family: ui-monospace, Menlo, monospace;
    font-size: 12px;
    color: var(--muted);
    min-width: 24px;
  }
  .label {
    font-weight: 500;
    font-size: 13.5px;
    flex: 1;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    font-family: ui-monospace, Menlo, monospace;
  }
  .badge {
    font-family: ui-monospace, Menlo, monospace;
    font-size: 11px;
    padding: 1px 6px;
    border-radius: 4px;
    background: #eee;
    color: var(--muted);
  }
  .badge.ok { background: #e6f2e8; color: var(--ok); }
  .badge.err { background: #f7e6e4; color: var(--err); }
  .ts {
    font-family: ui-monospace, Menlo, monospace;
    font-size: 11px;
    color: var(--muted);
  }
  .caret { color: var(--muted); font-size: 11px; transition: transform 0.15s ease; }
  .row.open .caret { transform: rotate(90deg); }
  .row-body { display: none; padding: 0 14px 14px 14px; }
  .row.open .row-body { display: block; }
  pre {
    background: var(--code-bg);
    color: var(--code-text);
    padding: 12px 14px;
    border-radius: 6px;
    overflow-x: auto;
    font-size: 12.5px;
    line-height: 1.5;
    margin: 0;
    white-space: pre-wrap;
    word-break: break-word;
  }
  .hint { color: var(--muted); font-size: 12px; margin-top: 14px; }
  kbd {
    background: #eeeae3;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 1px 5px;
    font-family: ui-monospace, Menlo, monospace;
    font-size: 11px;
  }
</style>
</head>
<body>
<h1>__TITLE__</h1>
<div class="sub" id="subtitle"></div>
<div id="list"></div>
<div class="hint">Click a row to expand/collapse. <kbd>&darr;</kbd>/<kbd>j</kbd> next &middot; <kbd>&uarr;</kbd>/<kbd>k</kbd> previous &middot; <kbd>Enter</kbd>/<kbd>space</kbd> toggle &middot; opening a row closes the previous one.</div>

<script>
const DATA = __DATA__;

const list = document.getElementById('list');
document.getElementById('subtitle').textContent = DATA.length + ' lines';

function labelFor(obj) {
  if (typeof obj.task === 'string') return obj.task;
  if (typeof obj.cmd === 'string') return obj.cmd;
  if (obj.request && (obj.request.method || obj.request.url)) {
    return [obj.request.method, obj.request.url].filter(Boolean).join(' ');
  }
  if (typeof obj.name === 'string') return obj.name;
  if (typeof obj.event === 'string') return obj.event;
  if (typeof obj.message === 'string') return obj.message;
  for (const k of Object.keys(obj)) {
    if (typeof obj[k] === 'string') return obj[k];
  }
  return '(line)';
}

function statusFor(obj) {
  const status = obj.response && obj.response.status;
  if (status == null) return null;
  const cls = status >= 200 && status < 400 ? 'ok' : 'err';
  return { text: String(status), cls };
}

const rows = [];
let openIndex = -1;
let focusIndex = 0;

DATA.forEach((obj, i) => {
  const row = document.createElement('div');
  row.className = 'row';

  const header = document.createElement('div');
  header.className = 'row-header';
  header.tabIndex = 0;

  const idx = document.createElement('div');
  idx.className = 'idx';
  idx.textContent = String(i + 1).padStart(2, '0');

  const label = document.createElement('div');
  label.className = 'label';
  label.textContent = labelFor(obj);

  header.appendChild(idx);
  header.appendChild(label);

  const status = statusFor(obj);
  if (status) {
    const badge = document.createElement('div');
    badge.className = 'badge ' + status.cls;
    badge.textContent = status.text;
    header.appendChild(badge);
  }

  if (typeof obj.ts === 'string') {
    const ts = document.createElement('div');
    ts.className = 'ts';
    ts.textContent = obj.ts;
    header.appendChild(ts);
  }

  const caret = document.createElement('div');
  caret.className = 'caret';
  caret.textContent = '\\u25b8';
  header.appendChild(caret);

  const body = document.createElement('div');
  body.className = 'row-body';
  const pre = document.createElement('pre');
  pre.textContent = JSON.stringify(obj, null, 2);
  body.appendChild(pre);

  row.appendChild(header);
  row.appendChild(body);
  list.appendChild(row);

  header.addEventListener('click', () => toggle(i));
  rows.push(row);
});

function setOpen(i) {
  if (openIndex >= 0 && rows[openIndex]) rows[openIndex].classList.remove('open');
  openIndex = i;
  if (i >= 0 && rows[i]) {
    rows[i].classList.add('open');
    rows[i].scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }
}

function toggle(i) {
  setOpen(openIndex === i ? -1 : i);
  focusIndex = i;
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'ArrowDown' || e.key === 'j') {
    e.preventDefault();
    focusIndex = Math.min(focusIndex + 1, rows.length - 1);
    setOpen(focusIndex);
  } else if (e.key === 'ArrowUp' || e.key === 'k') {
    e.preventDefault();
    focusIndex = Math.max(focusIndex - 1, 0);
    setOpen(focusIndex);
  } else if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    toggle(focusIndex);
  } else if (e.key === 'Escape') {
    setOpen(-1);
  }
});
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
