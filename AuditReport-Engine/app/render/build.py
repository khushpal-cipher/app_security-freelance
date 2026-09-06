from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

from app.models import Report

TEMPLATES_DIR = Path(__file__).parent / "templates"


def render_html(report: Report) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("report.html.j2")
    css = (TEMPLATES_DIR / "styles.css").read_text()
    return template.render(report=report, css=css)


def render_pdf(report: Report, output_path: str | Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    html_content = render_html(report)
    HTML(string=html_content, base_url=str(TEMPLATES_DIR)).write_pdf(str(output_path))
    return output_path
