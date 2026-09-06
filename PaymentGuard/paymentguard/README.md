# PaymentGuard

Tests a Stripe-based checkout for two specific, common bugs:

1. **Price tampering** — does the server trust a price the client sends, instead of
   recomputing it from the product catalog?
2. **Webhook forgery** — does the app's Stripe webhook endpoint accept an event that
   isn't actually signed by Stripe?

## Why this matters

If a checkout endpoint trusts a client-supplied price, an attacker can open dev tools,
edit the request body, and pay **$1 for a $1,000 order** — no exploit needed, just a
modified `fetch` call.

If a webhook endpoint doesn't verify the `Stripe-Signature` header, an attacker can skip
paying entirely: they POST a fake `payment_intent.succeeded` event straight to the
webhook URL and the app marks the order paid, because it never checked that the event
actually came from Stripe.

Both are one-line fixes (recompute server-side; verify the signature) and both are
common in vibe-coded checkouts because the happy path — quantity × displayed price,
webhook payload has a `type` field — works perfectly in every manual test. Nobody
manually tests with a forged request.

PaymentGuard automates sending exactly those two attacks at your own test-mode setup
and tells you which one lands.

## Scope (read this before trusting a PASS)

PaymentGuard checks **only** the two categories above. It is not a general security
scanner: it does not test authentication, authorization, injection, rate limiting,
infrastructure, or any pricing logic beyond client-trust-of-price. A PASS means those
two specific things are handled — nothing more. This scope note is also printed on
every generated report.

## Architecture

```
paymentguard/
  app/
    main.py            FastAPI app: POST /check, GET /report/{id}, rate limiting,
                        structured logging, key redaction, test-mode enforcement
    checks/
      price_tamper.py   sends an honest order + a tampered order, compares amounts
      webhook_forge.py  sends 3 forged webhook variants (no sig / garbage sig / wrong-secret sig)
    detect/
      classify.py       pure evidence -> Finding logic (unit tested, no I/O)
    report/
      render.py         renders the HTML report
    models.py           CheckRequest / Finding / Report (pydantic)
  demo_target/
    vulnerable.py       intentionally broken demo shop (trusts price, no webhook auth)
    secure.py           correctly-built demo shop (server-side pricing, HMAC verification)
  tests/
    test_classify.py    unit tests for the classifier logic
```

**How the checks work:**

- `price_tamper`: POSTs `{item_id, quantity}` to `<app_base_url>/checkout` (baseline),
  then POSTs the same request plus `unit_price`/`price`/`amount`/`total` fields set to
  100 cents (tamper attempt). If the resulting charge tracks the attacker's number
  instead of staying at the catalog price, that's `CRITICAL`.
- `webhook_forge`: POSTs a fake `payment_intent.succeeded` event to `<webhook_url>`
  three ways — no `Stripe-Signature` header, a garbage one, and a well-formed HMAC
  signed with the wrong secret. Any `2xx` response is `CRITICAL`.

## Safety

- Refuses to run with any key starting `sk_live` (validated before any request is made).
- If a `stripe_test_key` is supplied, PaymentGuard confirms with Stripe's own API
  (`GET /v1/balance`) that the key is `livemode: false` before using it.
- Requires `authorized: true` in every request.
- Never creates a real charge — it only calls your own app's endpoints, never Stripe's
  charge/PaymentIntent-creation APIs directly.
- Logs are structured JSON and never contain the raw Stripe key (only a redacted
  `sk_test_...abcd` form).
- Simple in-memory rate limit: 10 checks/minute per client IP.

## Setup

Requires Python 3.11+.

```bash
cd paymentguard
python3.11 -m venv .venv   # or: uv venv --python 3.11 .venv
.venv/bin/pip install -r requirements.txt
```

## Run

Three processes: the two demo targets (so you have something to point PaymentGuard at)
and the PaymentGuard scanner itself.

```bash
# Terminal 1 — intentionally vulnerable demo shop
.venv/bin/uvicorn demo_target.vulnerable:app --port 8012

# Terminal 2 — correctly-built demo shop
.venv/bin/uvicorn demo_target.secure:app --port 8011

# Terminal 3 — PaymentGuard scanner
.venv/bin/uvicorn app.main:app --port 8000
```

Open http://localhost:8000 — the form defaults to the vulnerable demo target
(`http://localhost:8012`). Check the "authorized" box and click **Run check** to see
two `CRITICAL` findings. Change the URL to `http://localhost:8011` (and webhook URL to
`http://localhost:8011/webhook`) to see the same checks `PASS` against the correctly-built
demo.

Or drive it directly:

```bash
curl -X POST http://localhost:8000/check \
  -H "Content-Type: application/json" \
  -d '{
    "app_base_url": "http://localhost:8012",
    "webhook_url": "http://localhost:8012/webhook",
    "authorized": true
  }'
# -> {"id": "...", "findings": [...]}
# open http://localhost:8000/report/<id> for the HTML report
```

To point PaymentGuard at your **own** app instead of the demo targets, just change
`app_base_url` / `webhook_url` to your app's checkout and webhook endpoints — as long as
`/checkout` accepts `{item_id, quantity}` (plus optional tamper fields) and returns an
`amount`/`amount_total`/`total` field, or adapt `checks/price_tamper.py`'s field names
to match your actual endpoint's request/response shape.

## Tests

```bash
.venv/bin/pytest tests/ -v
```

7 unit tests cover the classifier logic (`detect/classify.py`) against mocked
Stripe/HTTP evidence: exact-price-match tampering, partial-shift tampering, correct
recomputation, missing data, and all three webhook-forgery accept/reject combinations.
