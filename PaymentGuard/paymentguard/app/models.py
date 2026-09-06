from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator

Severity = Literal["CRITICAL", "PASS", "ERROR"]


class CheckRequest(BaseModel):
    app_base_url: str = Field(..., description="Base URL of the app under test, e.g. http://localhost:8010")
    webhook_url: str = Field(..., description="Full URL of the app's Stripe webhook endpoint")
    stripe_test_key: str | None = Field(default=None, description="Optional sk_test_... key for live cross-check")
    authorized: bool = Field(..., description="Must be true: confirms you own/are authorized to test this target")

    @field_validator("stripe_test_key")
    @classmethod
    def reject_live_keys(cls, v: str | None) -> str | None:
        if v and v.startswith("sk_live"):
            raise ValueError("Refusing sk_live key: PaymentGuard only runs against Stripe test mode.")
        return v

    @field_validator("authorized")
    @classmethod
    def require_authorization(cls, v: bool) -> bool:
        if not v:
            raise ValueError("authorized must be true: you must confirm you own/are authorized to test this target.")
        return v


class Finding(BaseModel):
    check: str
    severity: Severity
    title: str
    evidence: list[str]
    remediation: str


class Report(BaseModel):
    id: str
    app_base_url: str
    webhook_url: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    findings: list[Finding]
    disclaimer: str = (
        "PaymentGuard tests exactly two categories: (1) client-supplied price trust on the "
        "checkout/order endpoint, and (2) acceptance of unsigned/forged Stripe webhook events. "
        "It is not a full PCI/security audit and does not test authentication, injection, "
        "business logic beyond pricing, or infrastructure security."
    )
