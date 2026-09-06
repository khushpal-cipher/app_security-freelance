import logging
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlmodel import Session, select
from starlette.requests import Request

from .config import get_settings
from .db import engine, init_db
from .logging_config import configure_logging
from .models import Finding, Scan, ScanStatus
from .scanner.runner import run_scan
from .scanner.safety import UnsafeTargetError, validate_target_url

settings = get_settings()
configure_logging(settings.log_level)
logger = logging.getLogger("rls_sentinel.api")

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="RLS-Sentinel", version="1.0.0", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target_url: str = Field(..., max_length=2048)
    anon_key: str = Field(..., min_length=1, max_length=4096)
    authorized: Literal[True]
    table_names: list[str] | None = Field(default=None, max_length=50)

    @field_validator("table_names")
    @classmethod
    def validate_table_names(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        cleaned = [name.strip() for name in value if name.strip()]
        return cleaned or None

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        try:
            return validate_target_url(value)
        except UnsafeTargetError as exc:
            raise ValueError(str(exc)) from exc


class ScanCreatedResponse(BaseModel):
    scan_id: str


class FindingResponse(BaseModel):
    id: str
    table_name: str
    access_type: str
    severity: str
    description: str
    fix_prompt: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    target_url: str
    findings_count: int
    error_message: str | None
    findings: list[FindingResponse]


@app.post("/scan", response_model=ScanCreatedResponse, status_code=202)
@limiter.limit(settings.scan_request_rate_limit)
def create_scan(
    request: Request, body: ScanRequest, background_tasks: BackgroundTasks
) -> ScanCreatedResponse:
    with Session(engine) as session:
        scan = Scan(target_url=body.target_url, status=ScanStatus.PENDING)
        session.add(scan)
        session.commit()
        session.refresh(scan)
        scan_id = scan.id

    logger.info(
        "scan requested",
        extra={"target_host": httpx_host(body.target_url), "scan_id": scan_id},
    )
    background_tasks.add_task(
        run_scan, scan_id, body.target_url, body.anon_key, settings, body.table_names
    )
    return ScanCreatedResponse(scan_id=scan_id)


def httpx_host(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).hostname or "unknown"


@app.get("/scan/{scan_id}", response_model=ScanStatusResponse)
def get_scan(scan_id: str) -> ScanStatusResponse:
    with Session(engine) as db_session:
        scan = db_session.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        findings = db_session.exec(
            select(Finding).where(Finding.scan_id == scan_id)
        ).all()
        return ScanStatusResponse(
            scan_id=scan.id,
            status=scan.status,
            target_url=scan.target_url,
            findings_count=scan.findings_count,
            error_message=scan.error_message,
            findings=[
                FindingResponse(
                    id=f.id,
                    table_name=f.table_name,
                    access_type=f.access_type,
                    severity=f.severity,
                    description=f.description,
                    fix_prompt=f.fix_prompt,
                )
                for f in findings
            ],
        )


@app.get("/scan/{scan_id}/report.json")
def get_scan_report(scan_id: str) -> dict:
    with Session(engine) as db_session:
        scan = db_session.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        findings = db_session.exec(
            select(Finding).where(Finding.scan_id == scan_id)
        ).all()
        return {
            "scan_id": scan.id,
            "target_url": scan.target_url,
            "status": scan.status,
            "created_at": scan.created_at.isoformat(),
            "findings_count": scan.findings_count,
            "findings": [
                {
                    "id": f.id,
                    "table_name": f.table_name,
                    "access_type": f.access_type,
                    "severity": f.severity,
                    "description": f.description,
                    "fix_prompt": f.fix_prompt,
                }
                for f in findings
            ],
        }


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
