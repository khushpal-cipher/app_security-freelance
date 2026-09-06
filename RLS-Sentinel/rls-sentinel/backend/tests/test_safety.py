import asyncio
import time

import pytest

from app.scanner.safety import RateLimiter, UnsafeTargetError, validate_target_url


@pytest.mark.parametrize(
    "url",
    [
        "https://abcdefghijklmnop.supabase.co",
        "https://abcdefghijklmnop.supabase.in",
        "https://a.supabase.co",
    ],
)
def test_validate_target_url_accepts_supabase_hosts(url):
    assert validate_target_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "http://abcdefgh.supabase.co",  # not https
        "https://evil-supabase.co",  # no subdomain dot, prefix trick
        "https://supabase.co.attacker.com",  # suffix trick
        "https://attacker.com/supabase.co",  # path trick
        "https://user:pass@abcdefgh.supabase.co",  # userinfo
        "https://1.2.3.4",  # IP literal
        "https://abcdefgh.supabase.co:8443",  # non-default port
        "https://supabase.co",  # bare apex, no project subdomain
        "ftp://abcdefgh.supabase.co",  # wrong scheme
    ],
)
def test_validate_target_url_rejects_unsafe_hosts(url):
    with pytest.raises(UnsafeTargetError):
        validate_target_url(url)


@pytest.mark.asyncio
async def test_rate_limiter_enforces_minimum_spacing():
    limiter = RateLimiter(rps=10)  # 100ms min spacing
    start = time.monotonic()
    for _ in range(3):
        await limiter.acquire()
    elapsed = time.monotonic() - start
    # 3 acquisitions at 10rps must take at least ~200ms (2 intervals)
    assert elapsed >= 0.19


def test_rate_limiter_rejects_non_positive_rps():
    with pytest.raises(ValueError):
        RateLimiter(rps=0)
