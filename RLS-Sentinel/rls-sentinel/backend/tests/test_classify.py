from app.models import AccessType, Severity
from app.scanner.classify import (
    classify_read,
    classify_write_advisory,
    has_sensitive_columns,
)
from app.scanner.probe_read import ReadResult


def test_has_sensitive_columns_detects_common_markers():
    assert has_sensitive_columns(["id", "email", "created_at"]) == ["email"]
    assert has_sensitive_columns(["id", "phone_number", "token"]) == [
        "phone_number",
        "token",
    ]
    assert has_sensitive_columns(["id", "name", "created_at"]) == []


def test_classify_read_not_accepted_returns_none():
    result = ReadResult("orders", 403, False, [])
    assert classify_read(result) is None


def test_classify_read_plain_table_is_medium():
    result = ReadResult("orders", 200, True, ["id", "quantity"])
    c = classify_read(result)
    assert c is not None
    assert c.severity == Severity.MEDIUM
    assert c.access_type == AccessType.READ
    assert c.table_name == "orders"


def test_classify_read_sensitive_table_is_high():
    result = ReadResult("profiles", 200, True, ["id", "email", "phone"])
    c = classify_read(result)
    assert c is not None
    assert c.severity == Severity.HIGH
    assert "email" in c.description


def test_classify_read_empty_columns_returns_none():
    # An RLS-protected table returns this exact response (200, no rows) to
    # every anon caller — same as a correctly locked-down table. No finding.
    result = ReadResult("empty_table", 200, True, [])
    assert classify_read(result) is None


def test_classify_write_advisory_fires_when_table_readable():
    # No live write/delete request is ever sent (Supabase doesn't honor a
    # safe dry-run for those) — the advisory is inferred from read exposure.
    result = ReadResult("orders", 200, True, ["id", "quantity"])
    c = classify_write_advisory(result)
    assert c is not None
    assert c.severity == Severity.MEDIUM
    assert c.access_type == AccessType.WRITE


def test_classify_write_advisory_none_when_read_blocked():
    result = ReadResult("orders", 403, False, [])
    assert classify_write_advisory(result) is None


def test_classify_write_advisory_none_when_read_empty():
    # Same response an RLS-protected table gives — nothing to infer from.
    result = ReadResult("orders", 200, True, [])
    assert classify_write_advisory(result) is None
