import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detect.classify import classify_price_tamper, classify_webhook_forgery


def test_price_tamper_critical_when_charge_matches_attacker_price():
    finding = classify_price_tamper(baseline_amount=100000, tampered_amount=100, requested_tamper_amount=100)
    assert finding.severity == "CRITICAL"
    assert finding.check == "price_tamper"


def test_price_tamper_critical_when_amount_shifts_but_not_exact():
    finding = classify_price_tamper(baseline_amount=100000, tampered_amount=50000, requested_tamper_amount=100)
    assert finding.severity == "CRITICAL"


def test_price_tamper_pass_when_server_recomputes():
    finding = classify_price_tamper(baseline_amount=100000, tampered_amount=100000, requested_tamper_amount=100)
    assert finding.severity == "PASS"


def test_price_tamper_error_on_missing_data():
    finding = classify_price_tamper(baseline_amount=None, tampered_amount=100, requested_tamper_amount=100)
    assert finding.severity == "ERROR"


def test_webhook_forge_critical_when_unsigned_accepted():
    attempts = [
        {"variant": "no signature header", "status_code": 200, "error": None},
        {"variant": "garbage signature header", "status_code": 400, "error": None},
        {"variant": "well-formed signature, wrong secret", "status_code": 400, "error": None},
    ]
    finding = classify_webhook_forgery(attempts)
    assert finding.severity == "CRITICAL"
    assert finding.check == "webhook_forge"


def test_webhook_forge_pass_when_all_rejected():
    attempts = [
        {"variant": "no signature header", "status_code": 400, "error": None},
        {"variant": "garbage signature header", "status_code": 400, "error": None},
        {"variant": "well-formed signature, wrong secret", "status_code": 400, "error": None},
    ]
    finding = classify_webhook_forgery(attempts)
    assert finding.severity == "PASS"


def test_webhook_forge_critical_on_any_2xx():
    attempts = [
        {"variant": "no signature header", "status_code": 400, "error": None},
        {"variant": "garbage signature header", "status_code": 204, "error": None},
        {"variant": "well-formed signature, wrong secret", "status_code": 400, "error": None},
    ]
    finding = classify_webhook_forgery(attempts)
    assert finding.severity == "CRITICAL"
