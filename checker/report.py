"""
report.py — HTML audit report generator for DSGVO compliance scans.
"""

from pathlib import Path
from checker.scanner import ScanResult
from checker.checks import CheckResult


SEVERITY_COLOR = {
    "critical": "#ef4444",
    "warning":  "#f59e0b",
    "info":     "#3b82f6",
}

RATING_COLOR = {
    "A": "#22c55e",
    "B": "#84cc16",
    "C": "#f59e0b",
    "D": "#f97316",
    "F": "#ef4444",
}


def _check_row(check: CheckResult) -> str:
    icon = "✓" if check.passed else "✗"
    color = "#22c55e" if check.passed else SEVERITY_COLOR.get(check.severity, "#ef4444")
    items_html = ""
    if check.found_items and not check.passed:
        items = "".join(f'<li>{i}</li>' for i in check.found_items[:5])
        items_html = f'<ul class="found-items">{items}</ul>'

    rec_html = ""
    if check.recommendation:
        rec_html = f'<p class="rec">→ {check.recommendation}</p>'

    ref_html = ""
    if check.gdpr_reference:
        ref_html = f'<span class="ref">{check.gdpr_reference}</span>'

    return f"""
    <div class="check-row {'passed' if check.passed else 'failed'}">
      <div class="check-icon" style="color:{color}">{icon}</div>
      <div class="check-body">
        <div class="check-header">
          <span class="check-name">{check.name}</span>
          {ref_html}
        </div>
        <p class="check-detail">{check.detail}</p>
        {rec_html}
        {items_html}
      </div>
    </div>"""


def generate_html_report(result: ScanResult, output_path: Path) -> Path:
    """
    Generate an HTML compliance audit report.

    Args:
        result:      ScanResult from scanner.scan()
        output_path: Where to write the .html file.

    Returns:
        Path to written report.
    """
    rating_color = RATING_COLOR.get(result.rating, "#64748b")
    checks_html = "".join(_check_row(c) for c in result.checks)

    critical_count = len(result.critical_failures)
    passed_count = len(result.passed)
    total_count = len(result.checks)

    if result.error:
        body_content = f'<div class="error-banner">Scan failed: {result.error}</div>'
    else:
        body_content = f"""
        <div class="score-card">
          <div class="score-rating" style="color:{rating_color}">{result.rating}</div>
          <div class="score-details">
            <div class="score-number">{result.score}<span class="score-unit">/100</span></div>
            <div class="score-sub">{passed_count}/{total_count} checks passed
              {'· ' + str(critical_count) + ' critical issue(s)' if critical_count else ''}
            </div>
          </div>
        </div>
        <div class="checks-list">{checks_html}</div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>DSGVO Compliance Report — {result.url}</title>
<style>
  :root {{
    --bg: #0f1117;
    --surface: #1a1d27;
    --border: #2a2d3a;
    --text: #e2e8f0;
    --muted: #64748b;
    --accent: #3b82f6;
    --green: #22c55e;
    --red: #ef4444;
    --yellow: #f59e0b;
    --mono: 'Courier New', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 15px;
    line-height: 1.6;
    padding: 2rem;
  }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  header {{
    border-bottom: 1px solid var(--border);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
  }}
  header h1 {{
    font-size: 1.4rem;
    font-weight: 600;
    color: var(--accent);
    margin-bottom: 0.25rem;
  }}
  header p {{ color: var(--muted); font-size: 0.875rem; }}
  .score-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
    display: flex;
    align-items: center;
    gap: 1.5rem;
    margin-bottom: 2rem;
  }}
  .score-rating {{
    font-size: 4rem;
    font-weight: 700;
    line-height: 1;
    min-width: 80px;
    text-align: center;
  }}
  .score-number {{
    font-size: 2rem;
    font-weight: 600;
  }}
  .score-unit {{ font-size: 1rem; color: var(--muted); }}
  .score-sub {{ color: var(--muted); font-size: 0.875rem; margin-top: 0.25rem; }}
  .checks-list {{ display: flex; flex-direction: column; gap: 0.75rem; }}
  .check-row {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem 1.25rem;
    display: flex;
    gap: 1rem;
    align-items: flex-start;
  }}
  .check-row.passed {{ border-left: 3px solid var(--green); }}
  .check-row.failed {{ border-left: 3px solid var(--red); }}
  .check-icon {{
    font-size: 1.1rem;
    font-weight: 700;
    min-width: 20px;
    margin-top: 2px;
  }}
  .check-body {{ flex: 1; }}
  .check-header {{
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 0.25rem;
    flex-wrap: wrap;
  }}
  .check-name {{ font-weight: 600; font-size: 0.95rem; }}
  .ref {{
    font-size: 0.72rem;
    color: var(--accent);
    background: rgba(59,130,246,0.1);
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    letter-spacing: 0.02em;
  }}
  .check-detail {{ color: var(--muted); font-size: 0.875rem; margin-bottom: 0.25rem; }}
  .rec {{
    font-size: 0.875rem;
    color: var(--yellow);
    margin-top: 0.4rem;
  }}
  .found-items {{
    margin-top: 0.5rem;
    padding-left: 1.2rem;
    font-size: 0.8rem;
    color: var(--red);
    font-family: var(--mono);
  }}
  .found-items li {{ margin-bottom: 0.2rem; word-break: break-all; }}
  .error-banner {{
    background: rgba(239,68,68,0.1);
    border: 1px solid var(--red);
    border-radius: 8px;
    padding: 1rem 1.25rem;
    color: var(--red);
  }}
  footer {{
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 0.8rem;
  }}
</style>
</head>
<body>
<div class="container">
<header>
  <h1>DSGVO Compliance Report</h1>
  <p>
    URL: <strong>{result.final_url}</strong> &nbsp;·&nbsp;
    Scanned: {result.scanned_at} &nbsp;·&nbsp;
    Duration: {result.duration_seconds}s &nbsp;·&nbsp;
    Tool: dsgvo-compliance-checker by Edwin Tkalic
  </p>
</header>

{body_content}

<footer>
  This report is for informational purposes only and does not constitute legal advice.
  DSGVO compliance requires ongoing review — this tool checks technical indicators only.
  &nbsp;·&nbsp; github.com/tkalic/dsgvo-compliance-checker
</footer>
</div>
</body>
</html>"""

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path
