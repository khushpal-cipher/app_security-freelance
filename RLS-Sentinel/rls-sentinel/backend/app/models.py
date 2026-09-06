import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import Field, Relationship, SQLModel


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class AccessType(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Scan(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    target_url: str
    created_at: datetime = Field(default_factory=_now)
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    findings_count: int = Field(default=0)
    error_message: Optional[str] = Field(default=None)

    findings: list["Finding"] = Relationship(back_populates="scan")


class Finding(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    scan_id: str = Field(foreign_key="scan.id", index=True)
    table_name: str
    access_type: AccessType
    severity: Severity
    description: str
    fix_prompt: str
    created_at: datetime = Field(default_factory=_now)

    scan: Optional[Scan] = Relationship(back_populates="findings")
