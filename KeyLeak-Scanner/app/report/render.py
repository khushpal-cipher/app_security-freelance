from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.models import ScanResult

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
)


def render_report(result: ScanResult) -> str:
    template = _env.get_template("report.html")
    return template.render(result=result)
