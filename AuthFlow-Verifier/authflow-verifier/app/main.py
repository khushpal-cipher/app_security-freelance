import logging
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.detect.classify import build_skipped_finding, classify, rank_findings
from app.models import VerifyRequest, VerifyResponse
from app.report.render import render_report
from app.runner.differential import RunnerError, run_differential
from app.spec.loader import SpecError, load_endpoints

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":%(message)r}',
)
logger = logging.getLogger("authflow.main")

app = FastAPI(title="AuthFlow Verifier")
templates = Jinja2Templates(directory="app/templates")

DEFAULT_YAML = (Path(__file__).resolve().parent.parent / "endpoints.example.yaml").read_text()

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


async def run_verification(req: VerifyRequest) -> VerifyResponse:
    try:
        endpoints = load_endpoints(req.endpoints_yaml)
    except SpecError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        probes = await run_differential(req.base_url, req.user_token, endpoints, req.allow_write)
    except RunnerError as e:
        raise HTTPException(status_code=400, detail=str(e))

    findings = []
    for ep, anon, authed, skip_reason in probes:
        if skip_reason:
            findings.append(build_skipped_finding(ep, "Write method skipped: pass allow_write=true and a zero_match_filter to test it."))
        else:
            findings.append(classify(ep, anon, authed))
    findings = rank_findings(findings)

    logger.info(
        '{"event":"verify_complete","base_url_host":"%s","endpoints":%d,"findings":%d}',
        req.base_url.split("/")[2] if "//" in req.base_url else "?",
        len(endpoints),
        len(findings),
    )

    return VerifyResponse(base_url=req.base_url, endpoints_tested=len(endpoints), findings=findings)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "default_yaml": DEFAULT_YAML})


@app.post("/verify", response_model=VerifyResponse)
async def verify_api(req: VerifyRequest, request: Request):
    _check_rate_limit(request.client.host if request.client else "unknown")
    return await run_verification(req)


@app.post("/verify/report", response_class=HTMLResponse)
async def verify_report(
    request: Request,
    base_url: str = Form(...),
    user_token: str = Form(...),
    endpoints_yaml: str = Form(...),
    allow_write: str = Form(default=""),
):
    _check_rate_limit(request.client.host if request.client else "unknown")
    prefill = {
        "base_url": base_url,
        "user_token": user_token,
        "endpoints_yaml": endpoints_yaml,
        "allow_write": bool(allow_write),
    }
    try:
        req = VerifyRequest(
            base_url=base_url,
            user_token=user_token,
            endpoints_yaml=endpoints_yaml,
            allow_write=bool(allow_write),
        )
        result = await run_verification(req)
    except HTTPException as e:
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "error": e.detail, "prefill": prefill, "default_yaml": DEFAULT_YAML},
            status_code=200,
        )
    html = render_report(result)
    return HTMLResponse(content=html)
