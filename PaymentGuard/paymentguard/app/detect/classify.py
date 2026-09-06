"""Pure evidence -> Finding classifiers. No I/O here, so they're trivially unit-testable."""
from __future__ import annotations

from app.models import Finding


def classify_price_tamper(
    baseline_amount: int | None,
    tampered_amount: int | None,
    requested_tamper_amount: int,
) -> Finding:
    """
    baseline_amount: amount (cents) the server charged for an honest order.
    tampered_amount: amount (cents) the server charged when the client also sent a
                      lower attacker-chosen price alongside the same line item.
    requested_tamper_amount: the attacker-supplied price (cents) sent in the tamper request.
    """
    evidence = [
        f"Baseline order (no tamper fields) -> server charged {baseline_amount} cents.",
        f"Tampered order (client sent price={requested_tamper_amount} cents) -> server charged {tampered_amount} cents.",
    ]

    if baseline_amount is None or tampered_amount is None:
        return Finding(
            check="price_tamper",
            severity="ERROR",
            title="Could not complete price-tamper check",
            evidence=evidence + ["One or both checkout requests failed or returned no amount."],
            remediation="Ensure the checkout endpoint returns a JSON amount field and accepts the test payloads.",
        )

    if tampered_amount == requested_tamper_amount and tampered_amount != baseline_amount:
        return Finding(
            check="price_tamper",
            severity="CRITICAL",
            title="Server trusts client-supplied price",
            evidence=evidence + [
                "The resulting charge exactly matches the attacker-supplied price, not the catalog price.",
                "An attacker can pay any amount they choose for any order.",
            ],
            remediation=(
                "Never accept price/amount/unit_price from the client. Look up the item's price "
                "server-side from your product catalog/database and recompute the order total "
                "before creating the PaymentIntent."
            ),
        )

    if tampered_amount != baseline_amount:
        return Finding(
            check="price_tamper",
            severity="CRITICAL",
            title="Server-computed amount shifts with client-supplied price fields",
            evidence=evidence + [
                "Charged amount changed when attacker-controlled price fields were added, "
                "even though it doesn't exactly equal the requested amount.",
            ],
            remediation=(
                "Recompute order totals entirely server-side from a trusted catalog. Ignore any "
                "price/amount/unit_price fields present in the client request body."
            ),
        )

    return Finding(
        check="price_tamper",
        severity="PASS",
        title="Server ignores client-supplied price fields",
        evidence=evidence + ["Charged amount was identical in both requests: server recomputes price itself."],
        remediation="No action needed for this check.",
    )


def classify_webhook_forgery(attempts: list[dict]) -> Finding:
    """
    attempts: list of {"variant": str, "status_code": int | None, "error": str | None}
    """
    evidence = []
    accepted = []
    for a in attempts:
        if a.get("error"):
            evidence.append(f"{a['variant']}: request failed ({a['error']}).")
            continue
        status = a["status_code"]
        evidence.append(f"{a['variant']}: server responded HTTP {status}.")
        if 200 <= status < 300:
            accepted.append(a["variant"])

    if accepted:
        return Finding(
            check="webhook_forge",
            severity="CRITICAL",
            title="Webhook endpoint accepts forged events",
            evidence=evidence + [
                f"Accepted forged event variant(s): {', '.join(accepted)}.",
                "An attacker can POST a fake 'payment_intent.succeeded' event and have it treated as a real payment.",
            ],
            remediation=(
                "Verify the Stripe-Signature header on every webhook request using your endpoint's "
                "signing secret (e.g. stripe.Webhook.construct_event) and reject any request that "
                "fails verification with a 400, before acting on the event."
            ),
        )

    return Finding(
        check="webhook_forge",
        severity="PASS",
        title="Webhook endpoint rejects unsigned/forged events",
        evidence=evidence,
        remediation="No action needed for this check.",
    )
