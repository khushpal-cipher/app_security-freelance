from pathlib import Path

import pytest

from app.spec.loader import SpecError, load_endpoints

EXAMPLE = (Path(__file__).resolve().parent.parent / "endpoints.example.yaml").read_text()


def test_loads_the_example_spec():
    endpoints = load_endpoints(EXAMPLE)
    assert len(endpoints) == 5
    assert endpoints[0].path == "/api/public/health"
    assert endpoints[0].expects_auth is False


def test_rejects_invalid_yaml():
    with pytest.raises(SpecError):
        load_endpoints("endpoints: [not: valid: yaml:")


def test_rejects_empty_spec():
    with pytest.raises(SpecError):
        load_endpoints("")


def test_rejects_path_missing_leading_slash():
    with pytest.raises(SpecError):
        load_endpoints("endpoints:\n  - path: api/no-slash\n")


def test_rejects_missing_endpoints_key():
    with pytest.raises(SpecError):
        load_endpoints("not_endpoints: []\n")
