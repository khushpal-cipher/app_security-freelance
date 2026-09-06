from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"


class ScanRequest(BaseModel):
    url: str = Field(..., description="Public URL to scan")


class Finding(BaseModel):
    provider: str
    severity: Severity
    snippet_masked: str
    location: str
    reason: str


class ScanResult(BaseModel):
    url: str
    assets_scanned: int
    bytes_scanned: int
    findings: list[Finding]
    errors: list[str] = []
