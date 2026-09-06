# AuditReport-Engine

Turns raw security findings (from a pentest, an automated scanner, or the other
tools in this suite) into a polished, client-ready PDF report — the artifact
clients actually pay a security consultancy for. A pile of JSON findings isn't
a deliverable; a branded report with an executive summary a founder can
understand, a scored and prioritized findings table, and a technical appendix
a developer can act on, is.

## What it does

1. Reads a JSON array (or object) of findings.
2. Scores each finding with a real **CVSS 3.1** base-score calculation from a
   standard vector string (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, etc.) —
   no invented scoring, this is the same formula used by NVD.
3. Groups and sorts findings by severity (critical / high / medium / low).
4. Renders a multi-page PDF: cover page, executive summary, sortable findings
   table, per-finding detail cards (plain-English narrative *and* technical
   detail, side by side), a fix-prompt appendix, and a scope & limitations
   page.

Everything happens locally and offline — no network calls at render time, no
external services, deterministic output for the same input.

## Architecture

```
app/
  main.py                    CLI entry point: JSON in, PDF out
  models.py                  Pydantic models (Finding, Report, ReportMeta,
                              ScopeLimitations) — validates and scores on load
  scoring/
    cvss.py                  CVSS 3.1 base-score formula + severity bands
  render/
    build.py                 Jinja2 -> HTML -> WeasyPrint -> PDF
    templates/
      report.html.j2         Report structure
      styles.css             Severity color tokens, print layout, page numbers
samples/
  findings.json               8 realistic sample findings across all severities
tests/
  test_cvss.py                Scorer verified against official FIRST.org reference vectors
  test_render.py               Render pipeline smoke tests (including empty input)
```

The `Finding` model computes `cvss_score` and `severity` itself from the
vector string at construction time — callers can't hand it an inconsistent
score/severity pair, and the report always reflects the actual rubric.

## Setup

Requires Python 3.11 and WeasyPrint's native rendering libraries (Pango,
Cairo, GDK-Pixbuf — installed via Homebrew on macOS).

```bash
brew install pango gdk-pixbuf libffi   # WeasyPrint's native dependencies
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python -m app.main samples/findings.json out/report.pdf
```

Or point it at findings produced by the earlier projects in this suite:

```bash
python -m app.main /path/to/scanner-output/findings.json out/report.pdf
```

## Input schema

A findings file is either a bare array of findings, or an object with
optional `meta` and `scope` sections:

```json
{
  "meta": { "client_name": "...", "assessment_name": "..." },
  "scope": { "tested": ["..."], "not_tested": ["..."] },
  "findings": [
    {
      "id": "AFT-001",
      "title": "SQL Injection in Invoice Search Endpoint",
      "category": "Injection",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "attacker_narrative": "Plain-English explanation for a non-technical reader.",
      "technical_detail": "The actual vulnerable code path, payload, and evidence.",
      "fix_prompt": "A remediation instruction precise enough to hand to a developer or AI coding assistant.",
      "affected_asset": "api.example.com/api/v2/invoices/search"
    }
  ]
}
```

Input is validated against this schema (Pydantic) before rendering; malformed
JSON or an invalid CVSS vector fails fast with a clear error instead of
producing a broken PDF. An empty `findings` array renders cleanly (a "no
findings identified" report), rather than crashing.

## Tests

```bash
python -m pytest
```

`test_cvss.py` checks the scorer against six vectors independently verified
against the official FIRST.org CVSS 3.1 calculator. `test_render.py` renders
the sample findings and an empty-findings report end-to-end and asserts a
valid PDF comes out.

## Sample output

Run the command above and open `out/report.pdf` — an 11-page report covering
8 sample findings (1 critical, 1 high, 5 medium, 1 low) for a fictional
fintech client, including the SQL injection and broken-access-control
findings that would headline a real pentest report.

## Design notes

- **Why a real CVSS formula, not a lookup table:** a client-facing report
  claiming a CVSS score needs to actually match the industry-standard
  calculation, or it undermines the report's credibility the moment someone
  checks it against the NVD calculator.
- **Why system fonts instead of webfonts:** the brief requires no external
  network calls at render time and deterministic output — a webfont fetch
  would violate both.
- **Why a scope & limitations page is non-optional:** it's the report's legal
  safety net — stating exactly what was and wasn't tested protects both the
  assessor and the client from a report being read as a broader guarantee
  than it is.
