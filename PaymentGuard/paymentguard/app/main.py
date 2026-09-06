from __future__ import annotations

import json
import logging
import time
import uuid
from collections import defaultdict

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import ValidationError

from app.checks.price_tamper import run_price_tamper_check
from app.checks.webhook_forge import run_webhook_forge_check
from app.models import CheckRequest, Report
from app.report.render import render_report_html

# --- structured logging (never logs the stripe key) ---
logger = logging.getLogger("paymentguard")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(_handler)


def log_event(event: str, **fields) -> None:
    logger.info(json.dumps({"event": event, "ts": time.time(), **fields}))


def redact_key(key: str | None) -> str:
    if not key:
        return "none"
    return f"{key[:7]}...{key[-4:]}" if len(key) > 11 else "***"


app = FastAPI(title="PaymentGuard")
_reports: dict[str, Report] = {}

# --- naive in-memory rate limit: 10 requests/min per client IP ---
RATE_LIMIT = 10
RATE_WINDOW_SECONDS = 60
_request_log: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(client_ip: str) -> None:
    now = time.time()
    window_start = now - RATE_WINDOW_SECONDS
    timestamps = [t for t in _request_log[client_ip] if t > window_start]
    if len(timestamps) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded: max 10 checks/minute per client.")
    timestamps.append(now)
    _request_log[client_ip] = timestamps


async def _verify_stripe_test_mode(stripe_test_key: str) -> None:
    """Confirm the given key really is a Stripe TEST key by asking Stripe directly."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get("https://api.stripe.com/v1/balance", auth=(stripe_test_key, ""))
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=400, detail=f"Could not reach Stripe to verify key: {exc}") from exc

    if resp.status_code == 401:
        raise HTTPException(status_code=400, detail="Stripe rejected the provided key (invalid credentials).")
    if resp.status_code >= 400:
        raise HTTPException(status_code=400, detail=f"Stripe API error verifying key (HTTP {resp.status_code}).")

    livemode = resp.json().get("livemode")
    if livemode:
        raise HTTPException(status_code=400, detail="Refusing: this key is a LIVE Stripe key, not test mode.")


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return """<!doctype html>
<html><head><meta charset="utf-8"><title>PaymentGuard</title>
<style>
body{font-family:sans-serif;background:#faf9f5;color:#141413;max-width:560px;margin:3rem auto;padding:0 1rem}
input{width:100%;padding:0.5rem;margin:0.3rem 0 1rem;box-sizing:border-box}
button{background:#d97757;color:#fff;border:0;padding:0.6rem 1.2rem;border-radius:4px;cursor:pointer}
label{font-weight:600;font-size:0.9rem}
</style></head>
<body>
<h1>PaymentGuard</h1>
<p>Tests a Stripe checkout for price tampering and webhook forgery (test mode only).</p>
<form action="/check" method="post" onsubmit="return submitForm(event)">
  <label>App base URL</label>
  <input name="app_base_url" value="http://localhost:8012" required>
  <label>Webhook URL</label>
  <input name="webhook_url" value="http://localhost:8012/webhook" required>
  <label>Stripe test key (optional, sk_test_...)</label>
  <input name="stripe_test_key">
  <label><input type="checkbox" name="authorized" style="width:auto" required checked> I am authorized to test this target</label>
  <br><br>
  <button type="submit">Run check</button>
</form>
<pre id="out" style="white-space:pre-wrap"></pre>
<script>
async function submitForm(e) {
  e.preventDefault();
  const f = e.target;
  const body = {
    app_base_url: f.app_base_url.value,
    webhook_url: f.webhook_url.value,
    stripe_test_key: f.stripe_test_key.value || null,
    authorized: f.authorized.checked,
  };
  const resp = await fetch('/check', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  const data = await resp.json();
  if (resp.ok) {
    window.location = '/report/' + data.id;
  } else {
    document.getElementById('out').textContent = JSON.stringify(data, null, 2);
  }
  return false;
}
</script>
</body></html>"""


@app.post("/check")
async def check(request: Request) -> dict:
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    try:
        raw = await request.json()
        payload = CheckRequest(**raw)
    except ValidationError as exc:
        log_event("check_rejected", client_ip=client_ip, reason="validation_error")
        messages = [e["msg"] for e in exc.errors()]
        raise HTTPException(status_code=400, detail=messages) from exc

    log_event(
        "check_started",
        client_ip=client_ip,
        app_base_url=payload.app_base_url,
        webhook_url=payload.webhook_url,
        stripe_key=redact_key(payload.stripe_test_key),
    )

    if payload.stripe_test_key:
        await _verify_stripe_test_mode(payload.stripe_test_key)

    async with httpx.AsyncClient(timeout=10.0) as client:
        price_finding = await run_price_tamper_check(client, payload.app_base_url)
        webhook_finding = await run_webhook_forge_check(client, payload.webhook_url)

    report = Report(
        id=uuid.uuid4().hex[:12],
        app_base_url=payload.app_base_url,
        webhook_url=payload.webhook_url,
        findings=[price_finding, webhook_finding],
    )
    _reports[report.id] = report

    log_event(
        "check_completed",
        client_ip=client_ip,
        report_id=report.id,
        severities=[f.severity for f in report.findings],
    )

    return {"id": report.id, "findings": [f.model_dump() for f in report.findings]}


@app.get("/report/{report_id}", response_class=HTMLResponse)
async def get_report(report_id: str) -> str:
    report = _reports.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return render_report_html(report)
