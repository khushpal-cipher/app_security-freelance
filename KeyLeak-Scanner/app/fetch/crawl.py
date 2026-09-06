import ipaddress
import logging
import os
import re
import socket
from urllib.parse import urljoin, urlparse

import httpx

# Dev/demo-only escape hatch so the scanner can be pointed at a local demo site
# (127.0.0.1) without weakening the SSRF guard for real deployments. Off by default.
ALLOW_PRIVATE_HOSTS = os.environ.get("KEYLEAK_ALLOW_PRIVATE_HOSTS") == "1"

logger = logging.getLogger("keyleak.crawl")

MAX_TOTAL_BYTES = 20 * 1024 * 1024  # 20MB cap across the whole scan
REQUEST_TIMEOUT = 10.0
MAX_ASSETS = 30  # cap script count so a page with hundreds of scripts can't stall a scan

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
SOURCEMAP_COMMENT_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")


class ScanError(Exception):
    pass


def validate_url(url: str) -> str:
    """Reject non-http(s) schemes and requests aimed at private/loopback/link-local IPs (SSRF guard)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ScanError(f"Unsupported URL scheme: {parsed.scheme!r}. Only http/https allowed.")
    if not parsed.hostname:
        raise ScanError("URL has no hostname.")

    try:
        addrinfo = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as e:
        raise ScanError(f"Could not resolve host: {parsed.hostname}") from e

    for family, _, _, _, sockaddr in addrinfo:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            if ALLOW_PRIVATE_HOSTS:
                logger.warning("ssrf_guard_bypassed_dev_mode", extra={"ip": str(ip)})
                continue
            raise ScanError(f"Refusing to scan non-public address: {ip}")

    return url


class BudgetedFetcher:
    """Tracks cumulative bytes downloaded across a scan and enforces MAX_TOTAL_BYTES."""

    def __init__(self, client: httpx.Client):
        self.client = client
        self.total_bytes = 0
        self.assets_scanned = 0
        self.errors: list[str] = []

    def _remaining(self) -> int:
        return MAX_TOTAL_BYTES - self.total_bytes

    def fetch_text(self, url: str) -> str | None:
        if self._remaining() <= 0:
            self.errors.append(f"Skipped {url}: total download cap ({MAX_TOTAL_BYTES} bytes) reached.")
            return None
        if self.assets_scanned >= MAX_ASSETS:
            self.errors.append(f"Skipped {url}: max asset count ({MAX_ASSETS}) reached.")
            return None
        try:
            with self.client.stream("GET", url, timeout=REQUEST_TIMEOUT, follow_redirects=True) as resp:
                if resp.status_code >= 400:
                    self.errors.append(f"{url}: HTTP {resp.status_code}")
                    return None
                chunks = []
                downloaded = 0
                budget = self._remaining()
                for chunk in resp.iter_bytes():
                    downloaded += len(chunk)
                    if downloaded > budget:
                        chunks.append(chunk[: max(0, budget - (downloaded - len(chunk)))])
                        self.errors.append(f"{url}: truncated at download cap")
                        break
                    chunks.append(chunk)
                data = b"".join(chunks)
        except httpx.HTTPError as e:
            self.errors.append(f"{url}: fetch failed ({type(e).__name__})")
            logger.warning("fetch_failed", extra={"url_host": urlparse(url).hostname, "error": type(e).__name__})
            return None

        self.total_bytes += len(data)
        self.assets_scanned += 1
        return data.decode("utf-8", errors="replace")


def crawl(url: str) -> tuple[list[tuple[str, str]], int, int, list[str]]:
    """
    Fetch the page HTML, its linked JS bundles, and any source maps they reference.
    Returns (assets, assets_scanned, bytes_scanned, errors) where assets is a list of
    (location_label, text_content) pairs ready for the detection pipeline.
    """
    validate_url(url)
    assets: list[tuple[str, str]] = []

    headers = {"User-Agent": "KeyLeak-Scanner/1.0 (+passive security scan)"}
    with httpx.Client(headers=headers) as client:
        fetcher = BudgetedFetcher(client)

        html = fetcher.fetch_text(url)
        if html is None:
            raise ScanError(f"Could not fetch page: {url}")
        assets.append((url, html))

        script_srcs = SCRIPT_SRC_RE.findall(html)
        for src in script_srcs:
            if src.startswith("data:"):
                continue
            js_url = urljoin(url, src)
            try:
                validate_url(js_url)
            except ScanError as e:
                fetcher.errors.append(str(e))
                continue
            js_text = fetcher.fetch_text(js_url)
            if js_text is None:
                continue
            assets.append((js_url, js_text))

            map_match = SOURCEMAP_COMMENT_RE.search(js_text)
            if map_match:
                map_url = urljoin(js_url, map_match.group(1))
                try:
                    validate_url(map_url)
                except ScanError as e:
                    fetcher.errors.append(str(e))
                    continue
                map_text = fetcher.fetch_text(map_url)
                if map_text is not None:
                    assets.append((map_url, map_text))

        return assets, fetcher.assets_scanned, fetcher.total_bytes, fetcher.errors
