from __future__ import annotations

import json
import sys
from pathlib import Path

from pydantic import ValidationError

from app.models import Report
from app.render.build import render_pdf


def load_report(findings_path: str | Path) -> Report:
    path = Path(findings_path)
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    raw = json.loads(path.read_text())

    if isinstance(raw, list):
        raw = {"meta": {}, "findings": raw}
    elif isinstance(raw, dict):
        raw.setdefault("meta", {})
        raw.setdefault("findings", [])
    else:
        raise ValueError("Findings JSON must be an object or an array of findings.")

    return Report.model_validate(raw)


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]

    if len(argv) != 2:
        print("Usage: python -m app.main <findings.json> <out/report.pdf>", file=sys.stderr)
        return 1

    findings_path, output_path = argv

    try:
        report = load_report(findings_path)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in {findings_path}: {e}", file=sys.stderr)
        return 1
    except ValidationError as e:
        print(f"Error: findings JSON failed schema validation:\n{e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    output = render_pdf(report, output_path)
    print(f"Report written to {output} ({len(report.findings)} findings).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
