import asyncio
import ipaddress
import json
import logging
import os
import socket
import time
from urllib.parse import urlparse

import httpx

from app.models import WRITE_METHODS, EndpointSpec, ProbeOutcome

logger = logging.getLogger("authflow.runner")

# Dev/demo-only escape hatch so this can be pointed at a local demo API (127.0.0.1)
# without weakening the SSRF guard for real deployments. Off by default.
ALLOW_PRIVATE_HOSTS = os.environ.get("AUTHFLOW_ALLOW_PRIVATE_HOSTS") == "1"

REQUEST_TIMEOUT = 10.0
MAX_RETRIES = 2
RATE_LIMIT_PER_SEC = 5.0


class RunnerError(Exception):
    pass


def validate_base_url(url: str) -> None:
    """Reject non-http(s) schemes and targets resolving to private/loopback/link-local IPs (SSRF guard)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise RunnerError(f"Unsupported URL scheme: {parsed.scheme!r}. Only http/https allowed.")
    if not parsed.hostname:
        raise RunnerError("base_url has no hostname.")

    try:
        addrinfo = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as e:
        raise RunnerError(f"Could not resolve host: {parsed.hostname}") from e

    for _family, _type, _proto, _canon, sockaddr in addrinfo:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            if ALLOW_PRIVATE_HOSTS:
                logger.warning("ssrf_guard_bypassed_dev_mode", extra={"ip": str(ip)})
                continue
            raise RunnerError(f"Refusing to target non-public address: {ip}")


class RateLimiter:
    """Shared async limiter: at most `rate` requests/sec across the whole run."""

    def __init__(self, rate: float = RATE_LIMIT_PER_SEC):
        self._interval = 1.0 / rate
        self._lock = asyncio.Lock()
        self._next_at = 0.0

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            sleep_for = max(0.0, self._next_at - now)
            self._next_at = max(now, self._next_at) + self._interval
        if sleep_for:
            await asyncio.sleep(sleep_for)


def _extract_record_count(body: bytes) -> int | None:
    """Best-effort record count: top-level JSON list length, or the first list-valued
    field under common wrapper keys. Returns None (not 0) when the body isn't a
    recognizable record collection, so classify() can tell 'no data' from 'unknown shape'."""
    if not body:
        return None
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in ("data", "items", "results", "records", "users", "orders"):
            v = data.get(key)
            if isinstance(v, list):
                return len(v)
        return 1
    return None


async def _probe(
    client: httpx.AsyncClient,
    limiter: RateLimiter,
    base_url: str,
    ep: EndpointSpec,
    token: str | None,
) -> ProbeOutcome:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = base_url.rstrip("/") + ep.path
    params = {}
    if ep.zero_match_filter:
        k, _, v = ep.zero_match_filter.partition("=")
        if k:
            params[k] = v

    last_error = "unknown"
    for attempt in range(MAX_RETRIES + 1):
        await limiter.wait()
        try:
            resp = await client.request(
                ep.method.value, url, headers=headers, params=params, timeout=REQUEST_TIMEOUT
            )
            return ProbeOutcome(
                status_code=resp.status_code,
                record_count=_extract_record_count(resp.content),
                body_size=len(resp.content),
            )
        except httpx.TimeoutException:
            last_error = "timeout"
        except httpx.HTTPError:
            last_error = "request_failed"
        if attempt < MAX_RETRIES:
            await asyncio.sleep(2**attempt)

    # Log the failure shape only — never headers/tokens.
    logger.warning('{"event":"probe_failed","path":"%s","error":"%s"}', ep.path, last_error)
    return ProbeOutcome(status_code=None, record_count=None, body_size=0, error=last_error)


ProbePair = tuple[EndpointSpec, ProbeOutcome | None, ProbeOutcome | None, str | None]


async def run_differential(
    base_url: str,
    user_token: str,
    endpoints: list[EndpointSpec],
    allow_write: bool,
) -> list[ProbePair]:
    """Probe each endpoint as both anon and authed. Returns one
    (endpoint, anon_result, authed_result, skip_reason) tuple per endpoint —
    anon/authed are None and skip_reason is set when a write method was skipped."""
    validate_base_url(base_url)
    limiter = RateLimiter()
    results: list[ProbePair] = []
    headers = {"User-Agent": "AuthFlow-Verifier/1.0 (+authorized security test)"}

    async with httpx.AsyncClient(headers=headers, follow_redirects=False) as client:
        for ep in endpoints:
            if ep.method in WRITE_METHODS and not (allow_write and ep.zero_match_filter):
                results.append((ep, None, None, "write_method_not_confirmed"))
                continue
            anon = await _probe(client, limiter, base_url, ep, token=None)
            authed = await _probe(client, limiter, base_url, ep, token=user_token)
            results.append((ep, anon, authed, None))

    return results
