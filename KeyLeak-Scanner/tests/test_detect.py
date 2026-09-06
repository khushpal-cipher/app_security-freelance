from pathlib import Path

from app.detect.classify import mask_secret, scan_text
from app.detect.entropy import shannon_entropy, find_high_entropy_candidates
from app.models import Severity

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "demo" / "vulnerable-app"


def load_fixture(name: str) -> str:
    return (FIXTURE_DIR / name).read_text()


def test_shannon_entropy_of_uniform_random_is_high():
    assert shannon_entropy("Zx9qLpT2vR8mK5wN3jH7cF1sB6dY4eA0uV2gI9oP3rQ") > 4.0


def test_shannon_entropy_of_repeated_chars_is_low():
    assert shannon_entropy("aaaaaaaaaaaaaaaaaaaa") == 0.0


def test_entropy_candidate_requires_keyword_proximity():
    # High-entropy string with no nearby keyword should NOT be flagged.
    text = "var unrelatedBlob = 'Zx9qLpT2vR8mK5wN3jH7cF1sB6dY4eA0uV2gI9oP3rQ';"
    assert find_high_entropy_candidates(text) == []

    # Same string near "secret" SHOULD be flagged.
    text2 = "var apiSecret = 'Zx9qLpT2vR8mK5wN3jH7cF1sB6dY4eA0uV2gI9oP3rQ';"
    results = find_high_entropy_candidates(text2)
    assert len(results) == 1


def test_stripe_live_key_detected_as_critical():
    text = load_fixture("app.js")
    findings = scan_text(text, "demo/app.js")
    providers = {f.provider: f for f in findings}
    assert "stripe_live" in providers
    assert providers["stripe_live"].severity == Severity.critical


def test_openai_key_detected_as_high():
    text = load_fixture("app.js")
    findings = scan_text(text, "demo/app.js")
    providers = {f.provider: f for f in findings}
    assert "openai" in providers
    assert providers["openai"].severity == Severity.high


def test_aws_access_key_detected_as_high():
    text = load_fixture("app.js")
    findings = scan_text(text, "demo/app.js")
    providers = {f.provider: f for f in findings}
    assert "aws_access" in providers
    assert providers["aws_access"].severity == Severity.high


def test_supabase_service_role_jwt_is_worst_finding():
    text = load_fixture("app.js")
    findings = scan_text(text, "demo/app.js")
    providers = {f.provider: f for f in findings}
    assert "supabase_service_role_jwt" in providers
    finding = providers["supabase_service_role_jwt"]
    assert finding.severity == Severity.critical
    assert "Row Level Security" in finding.reason or "bypasses" in finding.reason.lower()


def test_non_service_role_jwt_is_not_flagged_critical():
    # A JWT without role:service_role should not trigger the supabase rule.
    import base64
    import json

    def b64url(obj):
        raw = json.dumps(obj).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64url({"alg": "HS256", "typ": "JWT"})
    payload = b64url({"role": "anon", "iss": "supabase-demo"})
    jwt = f"{header}.{payload}.somesignature"
    findings = scan_text(f"var token = '{jwt}';", "inline")
    assert not any(f.provider == "supabase_service_role_jwt" for f in findings)


def test_generic_high_entropy_detected_in_sourcemap():
    text = load_fixture("app.js.map")
    findings = scan_text(text, "demo/app.js.map")
    providers = {f.provider for f in findings}
    assert "generic_high_entropy" in providers or "stripe_live" in providers


def test_secrets_are_masked_never_shown_in_full():
    raw_secret = "sk_live_51NfakeDemoKeyDoNotUse00000000000000000000"
    masked = mask_secret(raw_secret)
    assert masked != raw_secret
    assert raw_secret[6:] not in masked
    assert masked.startswith(raw_secret[:6])


def test_full_app_js_finds_all_five_planted_secret_types():
    text = load_fixture("app.js")
    findings = scan_text(text, "demo/app.js")
    providers = {f.provider for f in findings}
    expected = {"stripe_live", "openai", "aws_access", "supabase_service_role_jwt", "generic_high_entropy"}
    assert expected.issubset(providers)
