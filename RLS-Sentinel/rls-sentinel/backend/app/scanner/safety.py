import asyncio
import re
import time
from urllib.parse import urlsplit

_SUPABASE_HOST_RE = re.compile(r"^[a-zA-Z0-9-]{1,63}\.supabase\.(co|in)$")


class UnsafeTargetError(ValueError):
    """Raised when a target URL fails the safety allowlist."""


def validate_target_url(url: str) -> str:
    """Only *.supabase.co / *.supabase.in HTTPS hosts, no IP literals, no userinfo.

    Full-string-anchored regex on the hostname so tricks like
    'supabase.co.attacker.com' or 'evil-supabase.co' cannot pass.
    """
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise UnsafeTargetError("target_url must use https")
    if parts.username or parts.password:
        raise UnsafeTargetError("target_url must not contain userinfo")
    if parts.port not in (None, 443):
        raise UnsafeTargetError("target_url must use the default https port")
    host = parts.hostname or ""
    if not _SUPABASE_HOST_RE.match(host):
        raise UnsafeTargetError(
            "target_url must be a *.supabase.co or *.supabase.in host"
        )
    return f"https://{host}"


class RateLimiter:
    """Async spaced-interval limiter: at most `rps` acquisitions per second."""

    def __init__(self, rps: float):
        if rps <= 0:
            raise ValueError("rps must be positive")
        self._interval = 1.0 / rps
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._last + self._interval - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = time.monotonic()
            self._last = now
