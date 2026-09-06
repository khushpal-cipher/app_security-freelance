"""Probe the app's own checkout/order endpoint for client-trusted pricing."""
from __future__ import annotations

import httpx

from app.detect.classify import classify_price_tamper
from app.models import Finding

CHECKOUT_PATH = "/checkout"
TAMPER_PRICE_CENTS = 100  # attacker offers $1.00 regardless of the real item price


def _extract_amount(payload: dict) -> int | None:
    for key in ("amount", "amount_total", "total", "charged_amount"):
        if key in payload and isinstance(payload[key], (int, float)):
            return int(payload[key])
    return None


async def run_price_tamper_check(client: httpx.AsyncClient, app_base_url: str) -> Finding:
    url = app_base_url.rstrip("/") + CHECKOUT_PATH
    baseline_amount: int | None = None
    tampered_amount: int | None = None

    try:
        baseline_resp = await client.post(url, json={"item_id": "premium_widget", "quantity": 1})
        baseline_resp.raise_for_status()
        baseline_amount = _extract_amount(baseline_resp.json())
    except (httpx.HTTPError, ValueError):
        baseline_amount = None

    try:
        tampered_resp = await client.post(
            url,
            json={
                "item_id": "premium_widget",
                "quantity": 1,
                # Try every field name a lazily-built checkout might read the price from.
                "unit_price": TAMPER_PRICE_CENTS,
                "price": TAMPER_PRICE_CENTS,
                "amount": TAMPER_PRICE_CENTS,
                "total": TAMPER_PRICE_CENTS,
            },
        )
        tampered_resp.raise_for_status()
        tampered_amount = _extract_amount(tampered_resp.json())
    except (httpx.HTTPError, ValueError):
        tampered_amount = None

    return classify_price_tamper(baseline_amount, tampered_amount, TAMPER_PRICE_CENTS)
