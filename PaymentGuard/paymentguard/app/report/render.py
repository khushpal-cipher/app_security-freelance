from __future__ import annotations

import html

from app.models import Report

_SEVERITY_COLOR = {
    "CRITICAL": "#d97757",
    "PASS": "#3d7a5c",
    "ERROR": "#8a8a86",
}


def _finding_html(finding) -> str:
    color = _SEVERITY_COLOR.get(finding.severity, "#8a8a86")
    evidence_items = "".join(f"<li>{html.escape(e)}</li>" for e in finding.evidence)
    return f"""
    <div class="finding">
      <div class="finding-header">
        <span class="badge" style="background:{color}">{finding.severity}</span>
        <h3>{html.escape(finding.title)}</h3>
      </div>
      <p class="check-name">check: {html.escape(finding.check)}</p>
      <ul class="evidence">{evidence_items}</ul>
      <p class="remediation"><strong>Remediation:</strong> {html.escape(finding.remediation)}</p>
    </div>
    """


def render_report_html(report: Report) -> str:
    findings_html = "".join(_finding_html(f) for f in report.findings)
    overall = "CRITICAL" if any(f.severity == "CRITICAL" for f in report.findings) else "PASS"
    overall_color = _SEVERITY_COLOR.get(overall, "#8a8a86")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PaymentGuard Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@600;700&family=Lora:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {{ color-scheme: light; }}
  body {{
    margin: 0; background: #faf9f5; color: #141413;
    font-family: 'Lora', Georgia, serif; padding: 2.5rem 1.5rem 4rem;
  }}
  .wrap {{ max-width: 760px; margin: 0 auto; }}
  h1 {{ font-family: 'Poppins', sans-serif; font-size: 1.8rem; margin-bottom: 0.25rem; }}
  h3 {{ font-family: 'Poppins', sans-serif; font-size: 1.05rem; margin: 0; }}
  .meta {{ color: #55534d; font-size: 0.9rem; margin-bottom: 1.5rem; }}
  .overall {{
    display: inline-block; padding: 0.4rem 0.9rem; border-radius: 999px;
    color: #faf9f5; font-family: 'Poppins', sans-serif; font-weight: 600; font-size: 0.85rem;
    background: {overall_color}; margin-bottom: 1.5rem;
  }}
  .disclaimer {{
    background: #f0efe9; border-left: 3px solid #d97757; padding: 0.9rem 1.1rem;
    font-size: 0.85rem; color: #55534d; margin-bottom: 2rem; border-radius: 4px;
  }}
  .finding {{
    border: 1px solid #e5e3da; border-radius: 8px; padding: 1.2rem 1.4rem; margin-bottom: 1.2rem;
    background: #fff;
  }}
  .finding-header {{ display: flex; align-items: center; gap: 0.7rem; margin-bottom: 0.4rem; }}
  .badge {{
    color: #fff; font-family: 'Poppins', sans-serif; font-size: 0.72rem; font-weight: 600;
    padding: 0.2rem 0.55rem; border-radius: 4px; letter-spacing: 0.03em;
  }}
  .check-name {{ font-size: 0.78rem; color: #8a8a86; margin: 0 0 0.7rem; font-family: monospace; }}
  .evidence {{ margin: 0 0 0.8rem; padding-left: 1.2rem; font-size: 0.92rem; }}
  .evidence li {{ margin-bottom: 0.3rem; }}
  .remediation {{ font-size: 0.92rem; margin: 0; }}
</style>
</head>
<body>
  <div class="wrap">
    <h1>PaymentGuard Report</h1>
    <p class="meta">Target: {html.escape(report.app_base_url)} &middot; Webhook: {html.escape(report.webhook_url)}<br>
    Generated: {report.generated_at.isoformat()} &middot; Report ID: {html.escape(report.id)}</p>
    <span class="overall">Overall: {overall}</span>
    <div class="disclaimer">{html.escape(report.disclaimer)}</div>
    {findings_html}
  </div>
</body>
</html>"""
