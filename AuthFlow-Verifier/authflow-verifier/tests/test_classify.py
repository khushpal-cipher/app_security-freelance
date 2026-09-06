from app.detect.classify import build_skipped_finding, classify
from app.models import Classification, EndpointSpec, ProbeOutcome, Severity


def ep(**kwargs) -> EndpointSpec:
    defaults = {"path": "/api/thing", "method": "GET", "expects_auth": True}
    defaults.update(kwargs)
    return EndpointSpec(**defaults)


def test_anon_success_on_protected_endpoint_is_auth_bypass():
    anon = ProbeOutcome(status_code=200, record_count=1, body_size=50)
    authed = ProbeOutcome(status_code=200, record_count=1, body_size=50)
    finding = classify(ep(), anon, authed)
    assert finding.classification == Classification.auth_bypass
    assert finding.severity == Severity.critical
    assert finding.fix_prompt is not None


def test_anon_sees_more_records_than_authed_is_inverted_policy():
    anon = ProbeOutcome(status_code=200, record_count=5, body_size=500)
    authed = ProbeOutcome(status_code=200, record_count=2, body_size=200)
    finding = classify(ep(), anon, authed)
    assert finding.classification == Classification.inverted_policy
    assert finding.severity == Severity.critical
    assert "5" in finding.fix_prompt and "2" in finding.fix_prompt


def test_anon_rejected_with_401_is_pass():
    anon = ProbeOutcome(status_code=401, record_count=None, body_size=20)
    authed = ProbeOutcome(status_code=200, record_count=1, body_size=100)
    finding = classify(ep(), anon, authed)
    assert finding.classification == Classification.pass_
    assert finding.severity == Severity.pass_
    assert finding.fix_prompt is None


def test_anon_rejected_with_403_is_pass():
    anon = ProbeOutcome(status_code=403, record_count=None, body_size=20)
    authed = ProbeOutcome(status_code=200, record_count=1, body_size=100)
    finding = classify(ep(), anon, authed)
    assert finding.classification == Classification.pass_


def test_endpoint_not_expecting_auth_is_info_only():
    anon = ProbeOutcome(status_code=200, record_count=1, body_size=50)
    authed = ProbeOutcome(status_code=200, record_count=1, body_size=50)
    finding = classify(ep(expects_auth=False), anon, authed)
    assert finding.classification == Classification.info
    assert finding.severity == Severity.info


def test_request_failure_is_error_not_pass():
    anon = ProbeOutcome(error="timeout")
    authed = ProbeOutcome(status_code=200, record_count=1, body_size=50)
    finding = classify(ep(), anon, authed)
    assert finding.classification == Classification.error
    assert finding.severity == Severity.warning


def test_anon_500_is_warn_not_pass():
    anon = ProbeOutcome(status_code=500, record_count=None, body_size=0)
    authed = ProbeOutcome(status_code=200, record_count=1, body_size=50)
    finding = classify(ep(), anon, authed)
    assert finding.classification == Classification.warn


def test_equal_record_counts_is_still_auth_bypass_not_inverted():
    # anon succeeds and sees the SAME data as an authed user — still a bypass,
    # just not the "sees more" variant.
    anon = ProbeOutcome(status_code=200, record_count=3, body_size=300)
    authed = ProbeOutcome(status_code=200, record_count=3, body_size=300)
    finding = classify(ep(), anon, authed)
    assert finding.classification == Classification.auth_bypass


def test_skipped_write_finding_has_no_probe_data():
    finding = build_skipped_finding(ep(method="DELETE"), "needs allow_write")
    assert finding.classification == Classification.skipped
    assert finding.severity == Severity.info
    assert finding.anon.status_code is None
