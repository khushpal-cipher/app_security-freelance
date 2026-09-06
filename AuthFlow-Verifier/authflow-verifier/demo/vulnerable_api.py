"""A deliberately broken demo API to verify AuthFlow-Verifier against.

Run:  uvicorn demo.vulnerable_api:app --port 8001
Valid user token: demo-valid-user-token

Bugs on purpose (this is the fixture, not something to "fix" here):
- /api/admin/users has NO auth check at all           -> auth_bypass
- /api/orders returns MORE rows with no token than with one -> inverted_policy
- /api/users/me is correctly protected                 -> pass, for contrast
"""

from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="Demo Vulnerable API")

VALID_TOKEN = "demo-valid-user-token"

ALL_USERS = [
    {"id": 1, "email": "alice@example.com", "role": "user"},
    {"id": 2, "email": "bob@example.com", "role": "user"},
    {"id": 3, "email": "carol@example.com", "role": "admin"},
]

ALL_ORDERS = [
    {"id": 101, "user_id": 1, "item": "keyboard"},
    {"id": 102, "user_id": 2, "item": "monitor"},
    {"id": 103, "user_id": 2, "item": "webcam"},
    {"id": 104, "user_id": 3, "item": "desk"},
    {"id": 105, "user_id": 1, "item": "chair"},
]


def _bearer_token(authorization: str | None) -> str | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    return authorization.removeprefix("Bearer ")


@app.get("/api/public/health")
def health():
    return {"status": "ok"}


@app.get("/api/users/me")
def users_me(authorization: str | None = Header(default=None)):
    if _bearer_token(authorization) != VALID_TOKEN:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"id": 1, "email": "alice@example.com"}


@app.get("/api/admin/users")
def admin_users(authorization: str | None = Header(default=None)):
    # BUG: no auth check whatsoever — every visitor gets the full user list.
    return {"users": ALL_USERS}


@app.get("/api/orders")
def orders(authorization: str | None = Header(default=None)):
    token = _bearer_token(authorization)
    if token == VALID_TOKEN:
        # "logged in": scoped to the caller's own orders (user_id 1) — 2 rows.
        return {"orders": [o for o in ALL_ORDERS if o["user_id"] == 1]}
    # BUG: no/invalid token falls through to "return everything" — 5 rows,
    # more than the authenticated user sees. Inverted policy.
    return {"orders": ALL_ORDERS}
