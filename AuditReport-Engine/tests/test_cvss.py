from app.scoring.cvss import base_score, severity_band

# Reference vectors + expected scores from the official FIRST.org CVSS 3.1
# calculator (https://www.first.org/cvss/calculator/3.1).
REFERENCE_VECTORS = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", 3.1),
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N", 3.7),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
]


def test_reference_vectors_match_official_calculator():
    for vector, expected in REFERENCE_VECTORS:
        assert base_score(vector) == expected, f"vector={vector}"


def test_severity_bands():
    assert severity_band(0.0) == "none"
    assert severity_band(3.9) == "low"
    assert severity_band(4.0) == "medium"
    assert severity_band(6.9) == "medium"
    assert severity_band(7.0) == "high"
    assert severity_band(8.9) == "high"
    assert severity_band(9.0) == "critical"
    assert severity_band(10.0) == "critical"


def test_invalid_vector_raises():
    import pytest

    with pytest.raises(ValueError):
        base_score("not-a-vector")
