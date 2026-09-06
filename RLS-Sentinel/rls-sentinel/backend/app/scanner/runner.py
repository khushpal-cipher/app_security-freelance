import asyncio
import logging

import httpx
from sqlmodel import Session

from ..config import Settings
from ..db import engine
from ..models import Finding, Scan, ScanStatus
from ..report.prompts import build_fix_prompt
from .classify import classify_read, classify_write_advisory
from .enumerate import SchemaDiscoveryError, list_tables
from .probe_read import probe_read
from .safety import RateLimiter, UnsafeTargetError, validate_target_url

logger = logging.getLogger("rls_sentinel.scanner")


async def _run_scan_async(
    target_url: str,
    anon_key: str,
    settings: Settings,
    table_names: list[str] | None = None,
) -> list[Finding]:
    base_url = validate_target_url(target_url)
    host = httpx.URL(base_url).host
    rate_limiter = RateLimiter(settings.rate_limit_rps)
    findings: list[Finding] = []

    async with httpx.AsyncClient() as client:
        if table_names:
            tables = table_names
        else:
            tables = await list_tables(
                client, base_url, anon_key, rate_limiter, settings.http_timeout_seconds
            )
        logger.info(
            "enumerated tables", extra={"target_host": host, "table_count": len(tables)}
        )

        for table in tables:
            read_result = await probe_read(
                client, base_url, anon_key, table, rate_limiter, settings.http_timeout_seconds
            )
            if read_result.error:
                logger.warning(
                    "read probe error",
                    extra={"target_host": host, "table_name": table},
                )
                continue
            classification = classify_read(read_result)
            if classification:
                findings.append(
                    Finding(
                        scan_id="",  # set by caller
                        table_name=classification.table_name,
                        access_type=classification.access_type,
                        severity=classification.severity,
                        description=classification.description,
                        fix_prompt=build_fix_prompt(
                            classification.table_name, classification.access_type
                        ),
                    )
                )

            advisory = classify_write_advisory(read_result)
            if advisory:
                findings.append(
                    Finding(
                        scan_id="",
                        table_name=advisory.table_name,
                        access_type=advisory.access_type,
                        severity=advisory.severity,
                        description=advisory.description,
                        fix_prompt=build_fix_prompt(
                            advisory.table_name, advisory.access_type
                        ),
                    )
                )

    return findings


def run_scan(
    scan_id: str,
    target_url: str,
    anon_key: str,
    settings: Settings,
    table_names: list[str] | None = None,
) -> None:
    """Sync entry point for FastAPI BackgroundTasks (runs in a threadpool)."""
    host = httpx.URL(target_url).host if "://" in target_url else target_url
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = ScanStatus.RUNNING
        session.add(scan)
        session.commit()

        try:
            findings = asyncio.run(
                _run_scan_async(target_url, anon_key, settings, table_names)
            )
        except UnsafeTargetError as exc:
            logger.error(
                "scan rejected: unsafe target", extra={"target_host": host}
            )
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)
            session.add(scan)
            session.commit()
            return
        except SchemaDiscoveryError as exc:
            logger.error(
                "scan failed: schema discovery blocked", extra={"target_host": host}
            )
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)
            session.add(scan)
            session.commit()
            return
        except Exception:  # noqa: BLE001 - top-level scan boundary
            logger.error(
                "scan failed", extra={"target_host": host}, exc_info=True
            )
            scan.status = ScanStatus.FAILED
            scan.error_message = "internal error during scan"
            session.add(scan)
            session.commit()
            return

        for finding in findings:
            finding.scan_id = scan_id
            session.add(finding)
        scan.status = ScanStatus.COMPLETE
        scan.findings_count = len(findings)
        session.add(scan)
        session.commit()
        logger.info(
            "scan complete",
            extra={"target_host": host, "scan_id": scan_id, "findings": len(findings)},
        )
