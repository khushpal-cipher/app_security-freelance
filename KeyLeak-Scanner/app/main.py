import logging
import time
from collections import defaultdict, deque

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.detect.classify import rank_findings, scan_text
from app.fetch.crawl import ScanError, crawl
from app.models import ScanRequest, ScanResult
from app.report.render import render_report

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":%(message)r}',
)
logger = logging.getLogger("keyleak.main")

app = FastAPI(title="KeyLeak Scanner")
templates = Jinja2Templates(directory="app/templates")

RATE_LIMIT = 10  # requests
RATE_WINDOW = 60  # seconds
_request_log: dict[str, deque] = defaultdict(deque)


def _check_rate_limit(client_ip: str) -> None:
    now = time.time()
    q = _request_log[client_ip]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again shortly.")
    q.append(now)


def run_scan(url: str) -> ScanResult:
    try:
        assets, assets_scanned, bytes_scanned, errors = crawl(url)
    except ScanError as e:
        logger.info('{"event":"scan_rejected","url_host":"%s"}', url.split("/")[2] if "//" in url else "?")
        raise HTTPException(status_code=400, detail=str(e))

    findings = []
    for location, text in assets:
        findings.extend(scan_text(text, location))
    findings = rank_findings(findings)

    logger.info(
        '{"event":"scan_complete","assets":%d,"bytes":%d,"findings":%d}',
        assets_scanned,
        bytes_scanned,
        len(findings),
    )

    return ScanResult(
        url=url,
        assets_scanned=assets_scanned,
        bytes_scanned=bytes_scanned,
        findings=findings,
        errors=errors,
    )


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/scan")
def scan_api(req: ScanRequest, request: Request):
    _check_rate_limit(request.client.host if request.client else "unknown")
    result = run_scan(req.url)
    return result


@app.post("/scan/report", response_class=HTMLResponse)
def scan_report(request: Request, url: str = Form(...)):
    _check_rate_limit(request.client.host if request.client else "unknown")
    try:
        result = run_scan(url)
    except HTTPException as e:
        return templates.TemplateResponse(
            "index.html", {"request": request, "error": e.detail, "prefill_url": url}, status_code=200
        )
    html = render_report(result)
    return HTMLResponse(content=html)
