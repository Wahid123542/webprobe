"""
Reporter - generates terminal summary and HTML report
"""

from datetime import datetime
from src.utils import print_status, RED, GREEN, YELLOW, CYAN, BOLD, RESET, GRAY

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#16a34a",
}
SEVERITY_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fffbeb",
    "LOW":      "#f0fdf4",
}


class Reporter:
    def __init__(self, target, pages, forms, findings):
        self.target = target
        self.pages = pages
        self.forms = forms
        self.findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def print_summary(self):
        counts = {}
        for f in self.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        print(f"  {'─'*50}")
        print(f"  {BOLD}Scan Summary{RESET}")
        print(f"  {'─'*50}")
        print(f"  {CYAN}Target:{RESET}   {self.target}")
        print(f"  {CYAN}Pages:{RESET}    {len(self.pages)}")
        print(f"  {CYAN}Forms:{RESET}    {len(self.forms)}")
        print(f"  {CYAN}Findings:{RESET} {len(self.findings)}")
        print()
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            n = counts.get(sev, 0)
            if n:
                color = RED if sev in ("CRITICAL", "HIGH") else YELLOW if sev == "MEDIUM" else GREEN
                print(f"    {color}{sev}{RESET}: {n}")

    def save_html(self, path):
        html = self._build_html()
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def _build_html(self):
        counts = {s: 0 for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
        for f in self.findings:
            if f["severity"] in counts:
                counts[f["severity"]] += 1

        vuln_types = {}
        for f in self.findings:
            vuln_types[f["type"]] = vuln_types.get(f["type"], 0) + 1

        findings_html = ""
        for i, f in enumerate(self.findings):
            color = SEVERITY_COLOR.get(f["severity"], "#6b7280")
            bg = SEVERITY_BG.get(f["severity"], "#f9fafb")
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}; background: {bg};">
                <div class="finding-header">
                    <span class="badge" style="background:{color}">{f['severity']}</span>
                    <span class="finding-type">{f['type']}</span>
                    <span class="finding-num">#{i+1}</span>
                </div>
                <div class="finding-body">
                    <div class="field">
                        <label>URL</label>
                        <code>{f['url']}</code>
                    </div>
                    <div class="field">
                        <label>Detail</label>
                        <span>{f['detail']}</span>
                    </div>
                    <div class="field">
                        <label>Evidence</label>
                        <code>{f['evidence']}</code>
                    </div>
                    <div class="field remediation">
                        <label>Remediation</label>
                        <span>{f['remediation']}</span>
                    </div>
                </div>
            </div>"""

        if not self.findings:
            findings_html = """
            <div style="text-align:center; padding:3rem; color:#16a34a;">
                <div style="font-size:3rem">✓</div>
                <div style="font-size:1.2rem; font-weight:600; margin-top:1rem">No vulnerabilities detected</div>
                <div style="color:#6b7280; margin-top:.5rem">This does not guarantee the application is secure.</div>
            </div>"""

        vuln_breakdown = "".join([
            f'<div class="stat-item"><span class="stat-label">{t}</span><span class="stat-val">{n}</span></div>'
            for t, n in vuln_types.items()
        ]) or '<div class="stat-item"><span class="stat-label">None found</span></div>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebProbe Report — {self.target}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0f172a; color: #e2e8f0; min-height: 100vh; }}

  .header {{ background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
             border-bottom: 1px solid #1e3a5f; padding: 2rem 3rem; }}
  .header-top {{ display:flex; align-items:center; gap:1rem; margin-bottom:.5rem; }}
  .logo {{ font-size:1.6rem; font-weight:800; color:#38bdf8;
           letter-spacing:.08em; text-transform:uppercase; }}
  .subtitle {{ color:#64748b; font-size:.9rem; }}
  .target-pill {{ display:inline-block; background:#1e3a5f; border:1px solid #2563eb;
                  color:#93c5fd; padding:.3rem .9rem; border-radius:999px;
                  font-family:monospace; font-size:.85rem; margin-top:.8rem; }}

  .stats-bar {{ display:flex; gap:1rem; padding:1.5rem 3rem;
               background:#0f172a; border-bottom:1px solid #1e293b; flex-wrap:wrap; }}
  .stat-card {{ background:#1e293b; border:1px solid #334155; border-radius:10px;
                padding:1rem 1.5rem; min-width:120px; text-align:center; flex:1; }}
  .stat-card .num {{ font-size:2rem; font-weight:700; line-height:1; }}
  .stat-card .lbl {{ font-size:.75rem; color:#64748b; text-transform:uppercase;
                     letter-spacing:.05em; margin-top:.3rem; }}
  .crit {{ color:#dc2626; }} .high {{ color:#ea580c; }}
  .med  {{ color:#d97706; }} .low  {{ color:#16a34a; }}
  .info-c {{ color:#38bdf8; }}

  .main {{ padding:2rem 3rem; max-width:1100px; margin:0 auto; }}

  .section-title {{ font-size:1rem; font-weight:700; color:#94a3b8;
                    text-transform:uppercase; letter-spacing:.08em;
                    margin:2rem 0 1rem; }}

  .meta-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr));
               gap:1rem; margin-bottom:2rem; }}
  .meta-card {{ background:#1e293b; border:1px solid #334155; border-radius:8px;
               padding:1rem; }}
  .meta-card .stat-label {{ color:#64748b; font-size:.75rem; text-transform:uppercase;
                            letter-spacing:.05em; }}
  .meta-card .stat-val {{ font-size:1.3rem; font-weight:700; color:#e2e8f0;
                          margin-top:.2rem; }}

  .finding {{ border-radius:8px; margin-bottom:1rem; overflow:hidden; }}
  .finding-header {{ display:flex; align-items:center; gap:.75rem;
                     padding:.75rem 1rem; background:rgba(0,0,0,.15); }}
  .badge {{ color:#fff; font-size:.7rem; font-weight:700; padding:.2rem .6rem;
            border-radius:4px; text-transform:uppercase; letter-spacing:.05em; }}
  .finding-type {{ font-weight:700; font-size:.95rem; color:#e2e8f0; flex:1; }}
  .finding-num {{ color:#475569; font-size:.8rem; }}
  .finding-body {{ padding:1rem; display:grid; gap:.75rem; }}
  .field {{ display:grid; gap:.2rem; }}
  .field label {{ font-size:.72rem; font-weight:600; color:#64748b;
                  text-transform:uppercase; letter-spacing:.05em; }}
  .field code {{ font-family:monospace; font-size:.82rem; color:#93c5fd;
                 background:#0f172a; padding:.3rem .6rem; border-radius:4px;
                 word-break:break-all; }}
  .field span {{ font-size:.88rem; color:#cbd5e1; }}
  .remediation label {{ color:#4ade80; }}
  .remediation span {{ color:#86efac; }}

  .stat-item {{ display:flex; justify-content:space-between; align-items:center;
               padding:.4rem 0; border-bottom:1px solid #1e293b; }}
  .stat-item:last-child {{ border:none; }}
  .stat-label {{ color:#94a3b8; font-size:.85rem; }}
  .stat-val {{ font-weight:700; color:#e2e8f0; }}

  .breakdown {{ background:#1e293b; border:1px solid #334155; border-radius:8px;
               padding:1rem 1.5rem; margin-bottom:2rem; }}

  footer {{ text-align:center; padding:2rem; color:#334155; font-size:.8rem; }}
</style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <div class="logo">WebProbe</div>
    <div class="subtitle">Vulnerability Scanner Report</div>
  </div>
  <div style="color:#64748b;font-size:.85rem">{self.timestamp}</div>
  <div class="target-pill">🎯 {self.target}</div>
</div>

<div class="stats-bar">
  <div class="stat-card"><div class="num info-c">{len(self.findings)}</div><div class="lbl">Total Findings</div></div>
  <div class="stat-card"><div class="num crit">{counts['CRITICAL']}</div><div class="lbl">Critical</div></div>
  <div class="stat-card"><div class="num high">{counts['HIGH']}</div><div class="lbl">High</div></div>
  <div class="stat-card"><div class="num med">{counts['MEDIUM']}</div><div class="lbl">Medium</div></div>
  <div class="stat-card"><div class="num low">{counts['LOW']}</div><div class="lbl">Low</div></div>
  <div class="stat-card"><div class="num info-c">{len(self.pages)}</div><div class="lbl">Pages Crawled</div></div>
  <div class="stat-card"><div class="num info-c">{len(self.forms)}</div><div class="lbl">Forms Tested</div></div>
</div>

<div class="main">

  <div class="section-title">Vulnerability Breakdown</div>
  <div class="breakdown">{vuln_breakdown}</div>

  <div class="section-title">Findings ({len(self.findings)})</div>
  {findings_html}

</div>

<footer>
  WebProbe — github.com/Wahid123542 · For authorized security testing only
</footer>

</body>
</html>"""
