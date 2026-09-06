"""A deliberately broken demo checkout, so PaymentGuard has something to catch.

Runs on :8010. Trusts client-supplied price fields and accepts any webhook event
with no signature verification at all.
"""
from __future__ import annotations

import uuid

from fastapi import FastAPI, Request

app = FastAPI(title="Vulnerable Demo Shop")

CATALOG = {"premium_widget": 100000}  # real price: $1000.00, in cents


@app.post("/checkout")
async def checkout(request: Request) -> dict:
    body = await request.json()
    item_id = body.get("item_id")
    quantity = body.get("quantity", 1)
    catalog_price = CATALOG.get(item_id, 0)

    # BUG: if the client sends its own price, trust it instead of the catalog.
    for field in ("unit_price", "price", "amount", "total"):
        if field in body:
            amount = int(body[field]) * quantity if field == "unit_price" else int(body[field])
            break
    else:
        amount = catalog_price * quantity

    return {"id": f"pi_{uuid.uuid4().hex[:16]}", "amount": amount, "currency": "usd"}


@app.post("/webhook")
async def webhook(request: Request) -> dict:
    # BUG: no Stripe-Signature verification whatsoever.
    event = await request.json()
    return {"received": True, "type": event.get("type")}
