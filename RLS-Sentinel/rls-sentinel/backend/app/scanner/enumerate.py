import httpx

from .safety import RateLimiter


class SchemaDiscoveryError(Exception):
    """Raised when the anon key cannot list tables via PostgREST's root spec.

    Some Supabase projects now restrict GET {base_url}/rest/v1/ (the OpenAPI
    schema listing every table) to the service_role key. Anon-key callers get
    a 401 UNAUTHORIZED_INVALID_API_KEY_TYPE even though per-table access still
    works fine. There's no anon-safe way to enumerate tables in that case —
    the caller must supply table names explicitly.
    """


async def list_tables(
    client: httpx.AsyncClient,
    base_url: str,
    anon_key: str,
    rate_limiter: RateLimiter,
    timeout: float,
) -> list[str]:
    """Discover table names via PostgREST's root OpenAPI/Swagger document.

    GET {base_url}/rest/v1/ with the anon key returns an OpenAPI spec whose
    `paths` keys are `/table_name` for every table exposed to PostgREST.
    """
    await rate_limiter.acquire()
    headers = {"apikey": anon_key, "Authorization": f"Bearer {anon_key}"}
    response = await client.get(
        f"{base_url}/rest/v1/", headers=headers, timeout=timeout
    )
    if response.status_code == 401:
        raise SchemaDiscoveryError(
            "This Supabase project blocks anon-key schema discovery "
            "(only service_role can list tables here). Supply table_names "
            "explicitly to scan it."
        )
    response.raise_for_status()
    spec = response.json()
    paths = spec.get("paths", {})
    tables = sorted(
        path.lstrip("/")
        for path in paths
        if path.startswith("/") and path.lstrip("/") and "/" not in path.lstrip("/")
    )
    return tables
