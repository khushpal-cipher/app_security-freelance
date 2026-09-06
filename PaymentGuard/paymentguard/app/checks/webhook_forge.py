"""Send unsigned / wrongly-signed Stripe webhook events and see if the app accepts them."""
from __future__ import annotations

import hashlib
import hmac
import json
import time

import httpx

from app.detect.classify import classify_webhook_forgery
from app.models import Finding

WRONG_SECRET = "whsec_this_is_not_the_real_signing_secret"


def _fake_event(amount: int = 100000) -> dict:
    return {
        "id": "evt_test_paymentguard",
        "object": "event",
        "type": "payment_intent.succeeded",
        "data": {
            "object": {
                "id": "pi_test_paymentguard",
                "object": "payment_intent",
                "amount": amount,
                "currency": "usd",
                "status": "succeeded",
            }
        },
    }


def _stripe_signature_header(payload_bytes: bytes, secret: str, timestamp: int) -> str:
    signed_payload = f"{timestamp}.".encode() + payload_bytes
    signature = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={signature}"


async def run_webhook_forge_check(client: httpx.AsyncClient, webhook_url: str) -> Finding:
    event = _fake_event()
    body = json.dumps(event).encode()
    timestamp = int(time.time())

    variants = [
        ("no signature header", None),
        ("garbage signature header", f"t={timestamp},v1=deadbeefdeadbeefdeadbeefdeadbeef"),
        ("well-formed signature, wrong secret", _stripe_signature_header(body, WRONG_SECRET, timestamp)),
    ]

    attempts = []
    for variant_name, sig_header in variants:
        headers = {"Content-Type": "application/json"}
        if sig_header:
            headers["Stripe-Signature"] = sig_header
        try:
            resp = await client.post(webhook_url, content=body, headers=headers)
            attempts.append({"variant": variant_name, "status_code": resp.status_code, "error": None})
        except httpx.HTTPError as exc:
            attempts.append({"variant": variant_name, "status_code": None, "error": str(exc)})

    return classify_webhook_forgery(attempts)
