import json
from pathlib import Path

from app.main import load_report
from app.models import Finding, Report, ReportMeta
from app.render.build import render_pdf

SAMPLE_PATH = Path(__file__).parent.parent / "samples" / "findings.json"


def test_sample_findings_load_and_score():
    report = load_report(SAMPLE_PATH)
    assert len(report.findings) == 8
    assert all(f.cvss_score > 0 for f in report.findings)
    assert report.counts_by_severity["critical"] >= 1


def test_render_pdf_from_sample(tmp_path):
    report = load_report(SAMPLE_PATH)
    out = render_pdf(report, tmp_path / "report.pdf")
    assert out.exists()
    data = out.read_bytes()
    assert data.startswith(b"%PDF")
    assert len(data) > 5000


def test_render_pdf_with_empty_findings(tmp_path):
    report = Report(meta=ReportMeta(client_name="Empty Co"), findings=[])
    out = render_pdf(report, tmp_path / "empty.pdf")
    assert out.exists()
    assert out.read_bytes().startswith(b"%PDF")


def test_deterministic_output(tmp_path):
    report = load_report(SAMPLE_PATH)
    out1 = render_pdf(report, tmp_path / "a.pdf")
    out2 = render_pdf(report, tmp_path / "b.pdf")
    # Both renders of identical input should produce identical byte size
    # (PDF metadata timestamps aside, layout/content must match).
    assert abs(len(out1.read_bytes()) - len(out2.read_bytes())) < 50
