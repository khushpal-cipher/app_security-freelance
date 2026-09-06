import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern
    severity: str  # critical | high | medium
    reason: str


# JWT structure: header.payload.signature, each base64url. Matched separately
# because its severity depends on decoded payload content, not the pattern alone.
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

RULES: list[Rule] = [
    Rule(
        name="stripe_live",
        pattern=re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
        severity="critical",
        reason="Stripe live secret key — grants full account access to charges, customers, and payouts.",
    ),
    Rule(
        name="openai",
        pattern=re.compile(r"sk-[A-Za-z0-9]{20,}"),
        severity="high",
        reason="OpenAI API key — allows billed API usage under the account owner's quota.",
    ),
    Rule(
        name="aws_access",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        severity="high",
        reason="AWS access key ID — usable for programmatic access to AWS resources if paired with a secret key.",
    ),
]
