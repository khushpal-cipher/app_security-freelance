from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.scoring.cvss import base_score, parse_vector, severity_band

Severity = Literal["critical", "high", "medium", "low"]


class Finding(BaseModel):
    id: str
    title: str
    category: str
    cvss_vector: str
    attacker_narrative: str
    technical_detail: str
    fix_prompt: str
    affected_asset: str

    cvss_score: float = 0.0
    severity: Severity = "low"

    @field_validator("cvss_vector")
    @classmethod
    def validate_vector(cls, v: str) -> str:
        parse_vector(v)
        return v

    def model_post_init(self, __context) -> None:
        score = base_score(self.cvss_vector)
        band = severity_band(score)
        if band == "none":
            band = "low"
        self.cvss_score = score
        self.severity = band


class ScopeLimitations(BaseModel):
    tested: list[str] = Field(default_factory=list)
    not_tested: list[str] = Field(default_factory=list)
    disclaimer: str = (
        "This assessment reflects a point-in-time review of the systems and scope "
        "listed above. It is not exhaustive and does not guarantee the absence of "
        "vulnerabilities outside this scope or discovered after the assessment date."
    )


class ReportMeta(BaseModel):
    client_name: str = "Client"
    assessment_name: str = "Security Assessment"
    report_date: date = Field(default_factory=date.today)
    prepared_by: str = "AuditReport-Engine"


class Report(BaseModel):
    meta: ReportMeta
    findings: list[Finding] = Field(default_factory=list)
    scope: ScopeLimitations = Field(default_factory=ScopeLimitations)

    @property
    def findings_sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.cvss_score, reverse=True)

    @property
    def counts_by_severity(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    @property
    def risk_statement(self) -> str:
        counts = self.counts_by_severity
        total = sum(counts.values())
        if total == 0:
            return (
                "No security findings were identified during this assessment. "
                "This does not guarantee the absence of all risk, but no exploitable "
                "issues were found within the tested scope."
            )
        if counts["critical"] > 0:
            headline = (
                f"This assessment identified {counts['critical']} critical issue"
                f"{'s' if counts['critical'] != 1 else ''} that could allow an "
                "attacker to directly compromise sensitive data or systems. "
                "These should be treated as urgent."
            )
        elif counts["high"] > 0:
            headline = (
                f"This assessment identified {counts['high']} high-severity issue"
                f"{'s' if counts['high'] != 1 else ''} that pose a significant risk "
                "and should be prioritized for remediation."
            )
        else:
            headline = (
                "This assessment did not identify any critical or high-severity "
                "issues. The findings below represent lower-risk improvements."
            )
        return (
            f"Out of {total} finding{'s' if total != 1 else ''} identified, "
            f"{counts['critical']} are critical, {counts['high']} are high, "
            f"{counts['medium']} are medium, and {counts['low']} are low severity. "
            f"{headline}"
        )
