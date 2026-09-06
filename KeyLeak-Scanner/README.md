# KeyLeak Scanner

**A leaked service-role key is full database access for anyone who finds it.**

Client-side JS bundles ship to every browser that loads the page — anyone can view-source, unminify, and read them. Teams routinely paste server-only credentials (Stripe secret keys, Supabase service-role JWTs, cloud access keys) into frontend config, where they end up baked into a public `.js` file or its `.map`. A Supabase service-role key in particular bypasses Row Level Security entirely: whoever has it can read and write every row in every table, not just their own. This tool finds that class of mistake before an attacker does — by scanning exactly what a browser downloads, nothing more.

## How it works

```
 URL ──▶ fetch HTML ──▶ extract <script src> ──▶ fetch each JS bundle
                                                        │
                                                        ▼
                                          //# sourceMappingURL comment?
                                                        │
                                                        ▼
                                              fetch the .map file too
                                                        │
                                                        ▼
                                   run every asset's text through the detectors
                                                        │
                        ┌───────────────────────────────┼───────────────────────────┐
                        ▼                               ▼                           ▼
                 named regex rules              JWT payload decode          entropy + keyword
              (stripe/openai/AWS)          (role == service_role?)        proximity scoring
                        │                               │                           │
                        └───────────────────────────────┼───────────────────────────┘
                                                        ▼
                                     rank by severity, mask secrets, render report
```

Everything here is a **passive GET request** — the same requests a browser makes to render the page. No login, no write requests, no interaction with the target beyond reading its public assets. A cumulative 20MB download cap, a 30-asset cap, and a scheme + private-IP validation on every URL fetched (blocking `localhost`/RFC1918/link-local targets) keep it from being usable as an SSRF or DoS vector against arbitrary hosts.

### Why regex *and* entropy, not just one

Named regex patterns (`sk_live_...`, `AKIA...`) catch *known* key formats with zero false positives — if it matches `sk_live_[A-Za-z0-9]{24,}`, it's a Stripe live key, full stop. But regex only catches secrets whose format you already know. Minified JS is full of long random-looking identifiers (hashes, chunk IDs, base64 assets) that aren't secrets at all, so entropy alone floods the report with noise.

The fix used here: **Shannon entropy is only trusted near a keyword.** A string scores as a candidate secret only if it's 20+ characters, has entropy > 4.0 bits/char (`shannon_entropy()` in `entropy.py`), *and* sits within 40 characters of `key`/`token`/`secret`/`password`/`api`/`auth`/`credential`. That proximity gate is what makes the generic tier usable instead of a wall of false positives — it's the same reasoning a human reviewer uses when skimming a diff: a random-looking string next to `apiSecret =` is worth a second look; the same string as a webpack chunk hash isn't.

### The one finding that outranks everything else

Any JWT found (`eyJ...`) gets its payload base64url-decoded — no signature verification needed, since we're not authenticating, just reading what the token claims. If `payload.role == "service_role"`, that's flagged **critical** with an explicit "bypasses Row Level Security, full database access" reason, and it's the finding classify.py exists to surface loudest: an RLS-bypassing key is strictly worse than any single API key, because it's not scoped to one provider's API — it's the entire database.

## Detection rules

| Rule | Pattern | Severity |
|---|---|---|
| `stripe_live` | `sk_live_[A-Za-z0-9]{24,}` | critical |
| `supabase_service_role_jwt` | any JWT decoding to `role: service_role` | critical |
| `openai` | `sk-[A-Za-z0-9]{20,}` | high |
| `aws_access` | `AKIA[0-9A-Z]{16}` | high |
| `generic_high_entropy` | 20+ chars, entropy > 4.0, near a key/token/secret keyword | medium |

All secrets are masked before they ever reach a `Finding` object — only the first 6 characters are shown, so a full key is never stored, logged, or rendered anywhere.

## Setup

Requires Python 3.11+ (built/tested on 3.12).

```bash
cd keyleak-scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
uvicorn app.main:app --port 8000
```

Open `http://127.0.0.1:8000/` and paste a public URL. Or hit the JSON API directly:

```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

Response shape:

```json
{
  "url": "https://example.com",
  "assets_scanned": 3,
  "bytes_scanned": 45210,
  "findings": [
    {
      "provider": "stripe_live",
      "severity": "critical",
      "snippet_masked": "sk_liv****...",
      "location": "https://example.com/app.js",
      "reason": "Stripe live secret key — grants full account access to charges, customers, and payouts."
    }
  ],
  "errors": []
}
```

## Demo

A seeded "vulnerable" site is included at `demo/vulnerable-app/` with fake (non-functional) planted secrets covering all five detection rules — Stripe live key, OpenAI key, AWS access key, a Supabase `service_role` JWT, and an unlabeled high-entropy token — split across an HTML page, a JS bundle, and its source map.

```bash
# Terminal 1 — serve the demo target
cd demo/vulnerable-app && python3 -m http.server 8001

# Terminal 2 — run the scanner (KEYLEAK_ALLOW_PRIVATE_HOSTS=1 is demo-only —
# it's the one thing that lets the scanner point at 127.0.0.1; never set it
# in a real deployment, since it disables the SSRF guard)
KEYLEAK_ALLOW_PRIVATE_HOSTS=1 uvicorn app.main:app --port 8000

# Then scan http://127.0.0.1:8001/index.html from the UI or via curl.
```

## Tests

```bash
pytest tests/ -v
```

Covers entropy scoring, keyword-proximity gating, each named rule against the fixture bundle, JWT role decoding (both service_role and non-service_role paths), and secret masking.

## Production notes

- **Timeouts**: 10s per asset fetch.
- **Size cap**: 20MB total per scan, streamed and truncated rather than buffered whole.
- **Asset cap**: 30 scripts max per scan.
- **SSRF guard**: rejects non-http(s) schemes and any URL resolving to a private/loopback/link-local/reserved IP, checked for the entry URL *and* every discovered script/map URL (redirects and cross-host script tags included).
- **Rate limiting**: 10 requests/minute per client IP, in-memory.
- **Logging**: structured, and never logs a full secret, request body, or unmasked finding — only asset counts, byte counts, and host names.
