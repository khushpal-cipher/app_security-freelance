"""A correctly-built demo checkout, for the report to show a PASS example.

Runs on :8011. Ignores any client-supplied price and recomputes it from the
server-side catalog; verifies the Stripe webhook signature before trusting events.
"""
from __future__ import annotations

import hashlib
import hmac
import uuid

from fastapi import FastAPI, HTTPException, Request

app = FastAPI(title="Secure Demo Shop")

CATALOG = {"premium_widget": 100000}  # real price: $1000.00, in cents
WEBHOOK_SECRET = "whsec_demo_secret_only_the_real_app_and_stripe_know_this"


@app.post("/checkout")
async def checkout(request: Request) -> dict:
    body = await request.json()
    item_id = body.get("item_id")
    quantity = body.get("quantity", 1)

    # Correct: price always comes from the server-side catalog, client fields ignored.
    catalog_price = CATALOG.get(item_id, 0)
    amount = catalog_price * quantity

    return {"id": f"pi_{uuid.uuid4().hex[:16]}", "amount": amount, "currency": "usd"}


@app.post("/webhook")
async def webhook(request: Request) -> dict:
    body = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    parts = dict(p.split("=", 1) for p in sig_header.split(",") if "=" in p)
    timestamp, signature = parts.get("t"), parts.get("v1")
    if not timestamp or not signature:
        raise HTTPException(status_code=400, detail="Missing or malformed Stripe-Signature header.")

    expected = hmac.new(
        WEBHOOK_SECRET.encode(), f"{timestamp}.".encode() + body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=400, detail="Signature verification failed.")

    event = await request.json()
    return {"received": True, "type": event.get("type")}
