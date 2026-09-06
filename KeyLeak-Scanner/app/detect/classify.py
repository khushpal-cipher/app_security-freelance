import base64
import json
import logging

from app.detect.entropy import find_high_entropy_candidates
from app.detect.rules import JWT_RE, RULES
from app.models import Finding, Severity

logger = logging.getLogger("keyleak.classify")

MASK_VISIBLE_CHARS = 6


def mask_secret(secret: str) -> str:
    visible = secret[:MASK_VISIBLE_CHARS]
    return f"{visible}{'*' * max(0, len(secret) - MASK_VISIBLE_CHARS)}"[:40]


def _decode_jwt_payload(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload_b64 = parts[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload_b64 + padding)
        return json.loads(raw)
    except Exception:
        return None


def scan_text(text: str, location: str) -> list[Finding]:
    """Run the full detection pipeline over one asset's text content."""
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    def add(provider: str, severity: str, raw_secret: str, reason: str):
        masked = mask_secret(raw_secret)
        key = (provider, masked, location)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            Finding(
                provider=provider,
                severity=Severity(severity),
                snippet_masked=masked,
                location=location,
                reason=reason,
            )
        )

    # Named regex rules (Stripe, OpenAI, AWS, ...)
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            add(rule.name, rule.severity, m.group(0), rule.reason)

    # JWTs: decode payload, check for service_role — the single worst finding possible.
    for m in JWT_RE.finditer(text):
        token = m.group(0)
        payload = _decode_jwt_payload(token)
        if payload is None:
            continue
        role = payload.get("role")
        if role == "service_role":
            add(
                "supabase_service_role_jwt",
                "critical",
                token,
                "Supabase SERVICE_ROLE JWT — bypasses Row Level Security entirely. "
                "Anyone holding this key has unrestricted read/write access to the full database.",
            )
        else:
            logger.debug("jwt_found", extra={"location": location, "role": role})

    # Generic high-entropy secrets near a keyword hint.
    for candidate, _idx in find_high_entropy_candidates(text):
        add(
            "generic_high_entropy",
            "medium",
            candidate,
            "High-entropy string near a key/token/secret keyword — possible unlabeled credential.",
        )

    return findings


SEVERITY_ORDER = {Severity.critical: 0, Severity.high: 1, Severity.medium: 2}


def rank_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])
