
import os, json, datetime
from typing import List
from jinja2 import Environment, BaseLoader
from .core import Finding

def write_json(findings: List[Finding], outdir: str):
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "report.json"), "w", encoding="utf-8") as f:
        json.dump([f.__dict__ for f in findings], f, indent=2, ensure_ascii=False)

def write_md(findings: List[Finding], outdir: str):
    os.makedirs(outdir, exist_ok=True)
    lines = ["# jssecpro Report", "", f"_Generated: {datetime.datetime.utcnow().isoformat()}Z_", ""]
    for f in findings:
        lines.append(f"## [{f.severity}] {f.plugin}")
        lines.append(f"- **Location**: `{f.location}`")
        if f.line is not None: lines.append(f"- **Line**: {f.line}")
        lines.append(f"- **Message**: {f.message}")
        if f.extra:
            import json as _j
            lines.append(f"- **Extra**: `{_j.dumps(f.extra, ensure_ascii=False)}`")
        lines.append("")
    with open(os.path.join(outdir, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def write_html(findings: List[Finding], outdir: str):
    import os, datetime
    from jinja2 import Environment, BaseLoader

    os.makedirs(outdir, exist_ok=True)

    tpl = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>jssecpro Report</title>
<style>
:root{
  --bg1:#020a12; --bg2:#041e2e; --bg3:#00334d;
  --glass:rgba(0,40,70,.45); --glass-strong:rgba(0,60,100,.65);
  --text:#dff6ff; --muted:#a5d8ff; --sky:#37b6ff;
  --shadow:0 8px 28px rgba(0,0,0,.35); --blur:18px;
}

*{box-sizing:border-box} html,body{height:100%;margin:0}
body{
  font-family:system-ui, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  color:var(--text); padding:28px;
  background: radial-gradient(circle at 12% -10%, var(--bg3), var(--bg2), var(--bg1)) fixed;
  box-shadow: inset 0 0 180px rgba(55,182,255,.25);
}
body::after{
  content:""; position:fixed; inset:0; pointer-events:none;
  background: repeating-linear-gradient(180deg, rgba(55,182,255,.05), rgba(55,182,255,.05) 1px, transparent 2px, transparent 4px);
  mix-blend-mode:overlay; opacity:.25;
}

/* Sticky summary bar */
.header{
  position:sticky; top:12px; z-index:30;
  display:flex; flex-direction:column; gap:10px;
  backdrop-filter: blur(var(--blur));
  background: linear-gradient(135deg, var(--glass-strong), rgba(5,20,40,.5));
  border:1px solid rgba(81,178,255,.25);
  border-radius:18px; padding:14px 16px; margin-bottom:18px; box-shadow:var(--shadow);
}
.title{display:flex; align-items:center; gap:12px; flex-wrap:wrap}
.brand{display:flex; align-items:center; gap:10px; font-weight:700; letter-spacing:.4px; font-size:clamp(18px,2.6vw,22px)}
.brand .dot{width:10px; height:10px; background:var(--sky); border-radius:999px; box-shadow:0 0 14px var(--sky)}
.ts{color:var(--muted); font-size:12px; opacity:.9}

.controls{display:flex; flex-wrap:wrap; gap:8px; margin-left:auto}
.btn{
  cursor:pointer; border:1px solid rgba(81,178,255,.25);
  background: linear-gradient(180deg, rgba(18,28,48,.7), rgba(10,18,32,.6));
  color:var(--text); padding:6px 10px; border-radius:10px; font-size:12px;
  transition:all .15s ease; user-select:none;
}
.btn:hover{ border-color:rgba(55,182,255,.7); box-shadow:0 0 12px rgba(55,182,255,.35) inset, 0 0 10px rgba(55,182,255,.2) }
.btn.active{ outline:1px solid var(--sky); box-shadow:0 0 0 2px rgba(55,182,255,.2) }

.summary{display:flex; flex-wrap:wrap; gap:8px}
.chip{
  display:inline-flex; align-items:center; gap:6px;
  border-radius:999px; border:1px solid rgba(81,178,255,.25);
  background: linear-gradient(180deg, rgba(10,18,32,.6), rgba(7,14,26,.45));
  padding:6px 10px; font-size:12px; color:var(--text);
}
.chip .dot{width:8px; height:8px; border-radius:999px; box-shadow:0 0 8px currentColor}
.dot.CRITICAL{color:#ff6b6b; background:#ff6b6b}
.dot.HIGH{color:#ffb266; background:#ffb266}
.dot.MEDIUM{color:#ffe666; background:#ffe666}
.dot.LOW{color:#66d1ff; background:#66d1ff}
.dot.INFO{color:#9ab6ff; background:#9ab6ff}

/* Cards grid */
.container{display:grid; grid-template-columns:repeat(12,1fr); gap:14px}
@media (max-width:900px){ .container{grid-template-columns:1fr} }
.card{
  grid-column:span 12;
  backdrop-filter: blur(var(--blur));
  background: linear-gradient(135deg, var(--glass), rgba(10,30,50,.35));
  border:1px solid rgba(81,178,255,.18);
  border-radius:16px; padding:16px; box-shadow:var(--shadow);
}
.card-header{display:flex; align-items:center; gap:10px; flex-wrap:wrap}
.badge{
  font-size:11px; text-transform:uppercase; letter-spacing:.4px; font-weight:700;
  border-radius:999px; padding:4px 10px; border:1px solid; opacity:.95;
}
.badge.CRITICAL{color:#ff7373; border-color:#ff7373; background:rgba(255,115,115,.12); text-shadow:0 0 8px #ff7373}
.badge.HIGH{color:#ffb97a; border-color:#ffb97a; background:rgba(255,185,122,.12); text-shadow:0 0 8px #ffb97a}
.badge.MEDIUM{color:#ffe066; border-color:#ffe066; background:rgba(255,224,102,.12); text-shadow:0 0 8px #ffe066}
.badge.LOW{color:#73d6ff; border-color:#73d6ff; background:rgba(115,214,255,.12); text-shadow:0 0 8px #37b6ff}
.badge.INFO{color:#a8bdff; border-color:#a8bdff; background:rgba(168,189,255,.12); text-shadow:0 0 8px #37b6ff}

.loc{font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color:var(--muted); font-size:12px; opacity:.95}
.msg{margin:8px 0 0 0; line-height:1.45}
pre{margin:12px 0 0 0; padding:12px; border-radius:12px; overflow:auto; background:rgba(0,0,0,.25); color:var(--text); border:1px solid rgba(81,178,255,.15)}
code{background:rgba(55,182,255,.08); color:var(--text); padding:2px 6px; border-radius:6px}
hr.sep{border:none; height:1px; margin:14px 0; background:linear-gradient(90deg, rgba(55,182,255,0), rgba(55,182,255,.35), rgba(55,182,255,0))}

/* Footer */
.footer{ text-align:center; color:var(--muted); font-size:12px; margin:28px 0 4px; opacity:.9; border-top:1px solid rgba(81,178,255,.25); padding-top:12px }
.footer .mark{ color:var(--sky); text-shadow:0 0 12px rgba(55,182,255,.65) }
</style>
</head>
<body>

  <div class="header" role="region" aria-label="Report Summary">
    <div class="title">
      <span class="brand"><span class="dot"></span> jssecpro <span class="mark">/ report</span></span>
      <span class="ts">{{ ts }}Z</span>

      <div class="controls" id="controls" role="toolbar" aria-label="Severity Filters">
        <button class="btn active" data-filter="ALL" aria-pressed="true">All</button>
        <button class="btn" data-filter="CRITICAL" aria-pressed="false">Critical</button>
        <button class="btn" data-filter="HIGH" aria-pressed="false">High</button>
        <button class="btn" data-filter="MEDIUM" aria-pressed="false">Medium</button>
        <button class="btn" data-filter="LOW" aria-pressed="false">Low</button>
        <button class="btn" data-filter="INFO" aria-pressed="false">Info</button>
      </div>
    </div>

    <div class="summary" id="summary">
      <span class="chip"><span class="dot CRITICAL"></span> Critical: <strong id="c_CRITICAL">0</strong></span>
      <span class="chip"><span class="dot HIGH"></span> High: <strong id="c_HIGH">0</strong></span>
      <span class="chip"><span class="dot MEDIUM"></span> Medium: <strong id="c_MEDIUM">0</strong></span>
      <span class="chip"><span class="dot LOW"></span> Low: <strong id="c_LOW">0</strong></span>
      <span class="chip"><span class="dot INFO"></span> Info: <strong id="c_INFO">0</strong></span>
    </div>
  </div>

  <div class="container" id="cards">
    {% if not findings %}
      <div class="card">✅ No findings detected. Enjoy your day.</div>
    {% endif %}
    {% for f in findings %}
    <article class="card finding" data-sev="{{f.severity}}">
      <div class="card-header">
        <span class="badge {{f.severity}}">{{f.severity}}</span>
        <span class="loc">{{f.plugin}}</span>
      </div>
      <hr class="sep"/>
      <div class="loc"><code>{{ f.location }}{{ ":"+f.line|string if f.line else "" }}</code></div>
      <p class="msg">{{ f.message }}</p>
      {% if f.extra %}<pre>{{ f.extra|tojson(indent=2) }}</pre>{% endif %}
    </article>
    {% endfor %}
  </div>

  <div class="footer">
    Report generated by <span class="mark">jssecpro</span> • Author: <strong class="mark">w01f</strong>
  </div>

<script>
(function(){
  const cards = Array.from(document.querySelectorAll('.finding'));
  const buttons = Array.from(document.querySelectorAll('.btn'));

  function setCounts(){
    const counts = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
    cards.forEach(c => { const s=c.dataset.sev||'INFO'; if (counts[s]!=null) counts[s]++; });
    for (const k in counts){
      const el = document.getElementById('c_'+k);
      if (el) el.textContent = counts[k];
    }
  }
  function filterTo(sev){
    cards.forEach(c => c.style.display = (sev==='ALL' || c.dataset.sev===sev) ? '' : 'none');
    buttons.forEach(b => {
      const active = b.dataset.filter===sev;
      b.classList.toggle('active', active);
      b.setAttribute('aria-pressed', active ? 'true' : 'false');
    });
  }
  buttons.forEach(b => b.addEventListener('click', () => filterTo(b.dataset.filter)));
  setCounts();
})();
</script>

</body>
</html>"""

    env = Environment(loader=BaseLoader())
    html = env.from_string(tpl).render(
        findings=[f.__dict__ for f in findings],
        ts=datetime.datetime.utcnow().isoformat()
    )
    with open(os.path.join(outdir, "report.html"), "w", encoding="utf-8") as f:
        f.write(html)