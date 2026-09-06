"""CVSS 3.1 base score calculator.

Implements the official base score formula from the CVSS 3.1 specification
(FIRST.org). Accepts a standard CVSS vector string and returns a score in
[0.0, 10.0] plus its severity band.
"""
from __future__ import annotations

import math
import re

AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC_WEIGHTS = {"L": 0.77, "H": 0.44}
PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
UI_WEIGHTS = {"N": 0.85, "R": 0.62}
CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}

VECTOR_RE = re.compile(
    r"^CVSS:3\.1/AV:(?P<AV>[NALP])/AC:(?P<AC>[LH])/PR:(?P<PR>[NLH])/"
    r"UI:(?P<UI>[NR])/S:(?P<S>[UC])/C:(?P<C>[HLN])/I:(?P<I>[HLN])/A:(?P<A>[HLN])$"
)

SEVERITY_BANDS = [
    (0.0, 0.0, "none"),
    (0.1, 3.9, "low"),
    (4.0, 6.9, "medium"),
    (7.0, 8.9, "high"),
    (9.0, 10.0, "critical"),
]


def parse_vector(vector: str) -> dict[str, str]:
    match = VECTOR_RE.match(vector.strip())
    if not match:
        raise ValueError(f"Invalid or unsupported CVSS 3.1 vector string: {vector!r}")
    return match.groupdict()


def severity_band(score: float) -> str:
    for lo, hi, name in SEVERITY_BANDS:
        if lo <= score <= hi:
            return name
    raise ValueError(f"Score out of range: {score}")


def _roundup(value: float) -> float:
    """CVSS spec's Roundup: round to 1 decimal, always rounding up."""
    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000
    return (math.floor(int_value / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    """Compute the CVSS 3.1 base score from a full vector string."""
    parts = parse_vector(vector)
    changed = parts["S"] == "C"

    av = AV_WEIGHTS[parts["AV"]]
    ac = AC_WEIGHTS[parts["AC"]]
    pr = (PR_WEIGHTS_CHANGED if changed else PR_WEIGHTS_UNCHANGED)[parts["PR"]]
    ui = UI_WEIGHTS[parts["UI"]]
    c = CIA_WEIGHTS[parts["C"]]
    i = CIA_WEIGHTS[parts["I"]]
    a = CIA_WEIGHTS[parts["A"]]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    if not changed:
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if not changed:
        score = _roundup(min(impact + exploitability, 10))
    else:
        score = _roundup(min(1.08 * (impact + exploitability), 10))

    return score
