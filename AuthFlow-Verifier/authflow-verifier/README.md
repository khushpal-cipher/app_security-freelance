# AuthFlow-Verifier

**"Protected" and "returns 401 when you have no token" are not the same claim — and a lot of vibe-coded APIs only satisfy the first one by accident.** AuthFlow-Verifier finds the gap by running the exact same request twice — once with no credentials, once with a real logged-in user's token — and diffing what comes back.

## The bug this catches, in plain English

A route "checks auth" if it rejects a request with no token. But two more subtle bugs produce a *working-looking* app while leaving the door open:

1. **Auth bypass** — the endpoint has no check at all. An anonymous request gets a `200` and the real data, same as a logged-in user would get.
2. **Inverted policy** — the endpoint *does* branch on auth, but the branches are backwards: `if user: return my_rows() else: return all_rows()` instead of `else: reject()`. The unauthenticated caller ends up seeing *more* than the authenticated one — every real Supabase RLS/Postgres policy mistake in the wild looks exactly like this: the default-deny got flipped to default-allow somewhere.

Comparing status codes alone misses #2 entirely — an inverted endpoint often still returns `200` for both identities, so you have to compare *how much data* came back, not just whether the call "succeeded."

## How it works

```
                         endpoints.yaml (path, method, expects_auth)
                                        │
                                        ▼
                        ┌───────────────────────────────┐
 base_url ─────────────▶│      for each endpoint:        │
 user_token ────────────▶│  1. request with NO auth header│
                        │  2. request WITH user_token    │
                        └───────────────┬───────────────┘
                                        ▼
                         compare: status code + record count
                                        │
                ┌───────────────────────┼───────────────────────┐
                ▼                       ▼                       ▼
        anon 2xx & anon         anon 2xx (any other      anon 401/403
        count > authed count    shape)                   
                ▼                       ▼                       ▼
      CRITICAL inverted_policy   CRITICAL auth_bypass         pass
```

Every probe is a `GET` by default. Write methods (`POST`/`PUT`/`PATCH`/`DELETE`) are refused unless the caller explicitly opts in **and** the endpoint carries a `zero_match_filter` — a query param guaranteed to hit zero real rows — so a differential run can never accidentally mutate or delete real data.

## Safety design

- **Read-only by default.** Write methods are skipped unless `allow_write: true` is set on the request *and* the endpoint spec sets `zero_match_filter`. Both gates must be true — one alone isn't enough.
- **Host validation + SSRF guard.** Only `http`/`https` schemes are accepted, and every hostname is resolved and checked against private/loopback/link-local/reserved/multicast ranges before any request is sent (`app/runner/differential.py::validate_base_url`). A dev-only escape hatch (`AUTHFLOW_ALLOW_PRIVATE_HOSTS=1`) exists solely so this can be pointed at a local demo API — it's off by default.
- **Rate limited.** A shared async limiter caps outbound probing at 5 req/s per run, independent of the `10/minute` limit on the `/verify` and `/verify/report` endpoints themselves.
- **Tokens are never logged.** The only things written to logs are the endpoint path and an error *type* (`timeout`, `request_failed`) — never headers, never the token value, never response bodies.
- **Timeouts + backoff.** Each probe gets a 10s timeout and up to 2 retries with exponential backoff before it's recorded as a failure (never silently treated as a "pass").
- **Schema-validated spec.** `endpoints.yaml` is parsed and validated against a Pydantic schema before anything runs; a malformed spec is rejected with a clear error, not a stack trace.

## Tech stack

Python 3.11+, FastAPI, httpx (async), Pydantic v2, PyYAML, Jinja2. SQLite/DB-free — this tool has no state to persist between runs.

## Project layout

```
authflow-verifier/
  app/
    main.py                # FastAPI app: /, /verify (JSON), /verify/report (HTML)
    models.py               # Pydantic models: EndpointSpec, ProbeOutcome, Finding, ...
    spec/loader.py          # parse + schema-validate endpoints.yaml
    runner/differential.py  # SSRF guard, rate limiter, anon+authed probing
    detect/classify.py      # the differential classifier — the core logic
    report/render.py        # Jinja2 HTML report
    templates/              # index.html, report.html, base.html
  demo/vulnerable_api.py    # deliberately broken target API for the demo
  endpoints.example.yaml    # spec matching the demo API
  tests/
    test_classify.py        # classifier tested against mocked ProbeOutcomes
    test_loader.py           # YAML schema validation
  requirements.txt
```

## Setup

```bash
cd authflow-verifier
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Run the tests

```bash
python -m pytest -q
```

## Run the demo end-to-end

Terminal 1 — the deliberately broken target API:
```bash
source venv/bin/activate
uvicorn demo.vulnerable_api:app --port 8091
```

Terminal 2 — AuthFlow-Verifier itself (the `AUTHFLOW_ALLOW_PRIVATE_HOSTS=1` is only needed because the demo target is on localhost — a real target wouldn't need it):
```bash
source venv/bin/activate
AUTHFLOW_ALLOW_PRIVATE_HOSTS=1 uvicorn app.main:app --port 8090
```

Then open **http://127.0.0.1:8090** and submit the form with:
- Base URL: `http://127.0.0.1:8091`
- Valid user token: `demo-valid-user-token`
- Endpoint spec: pre-filled from `endpoints.example.yaml`

Or hit the JSON API directly:
```bash
python3 -c "
import json, urllib.request
payload = {
    'base_url': 'http://127.0.0.1:8091',
    'user_token': 'demo-valid-user-token',
    'endpoints_yaml': open('endpoints.example.yaml').read(),
}
req = urllib.request.Request(
    'http://127.0.0.1:8090/verify',
    data=json.dumps(payload).encode(),
    headers={'Content-Type': 'application/json'},
)
print(urllib.request.urlopen(req).read().decode())
"
```

Expected findings against the demo API:

| Endpoint | Classification | Why |
|---|---|---|
| `GET /api/admin/users` | **auth_bypass** (critical) | No auth check at all — anon and authed get identical `200` + full user list. |
| `GET /api/orders` | **inverted_policy** (critical) | Anon sees 5 orders (everyone's); the authed user sees only their own 2. |
| `GET /api/users/me` | pass | Anon correctly gets `401`. |
| `GET /api/public/health` | info | Not marked `expects_auth`, recorded as baseline. |
| `DELETE /api/users/42` | skipped | Write method, `allow_write` not set — never sent. |

## Sample endpoint spec

```yaml
endpoints:
  - path: /api/public/health
    method: GET
    expects_auth: false

  - path: /api/orders
    method: GET
    expects_auth: true

  - path: /api/users/42
    method: DELETE
    expects_auth: true
    zero_match_filter: "id=999999999"   # only tested if allow_write: true is also sent
```
