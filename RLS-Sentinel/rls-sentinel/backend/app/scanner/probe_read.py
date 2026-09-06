from dataclasses import dataclass

import httpx

from .safety import RateLimiter


@dataclass
class ReadResult:
    table_name: str
    status_code: int | None
    accepted: bool
    columns: list[str]
    sample_id: str | None = None
    sample_row: dict | None = None
    error: str | None = None


async def probe_read(
    client: httpx.AsyncClient,
    base_url: str,
    anon_key: str,
    table_name: str,
    rate_limiter: RateLimiter,
    timeout: float,
) -> ReadResult:
    """GET one row from `table_name` with the anon key. Read-only, no mutation."""
    await rate_limiter.acquire()
    headers = {"apikey": anon_key, "Authorization": f"Bearer {anon_key}"}
    try:
        response = await client.get(
            f"{base_url}/rest/v1/{table_name}",
            params={"select": "*", "limit": "1"},
            headers=headers,
            timeout=timeout,
        )
    except httpx.TimeoutException:
        return ReadResult(table_name, None, False, [], error="timeout")
    except httpx.ConnectError:
        return ReadResult(table_name, None, False, [], error="connection_error")
    except httpx.HTTPError as exc:
        return ReadResult(table_name, None, False, [], error=str(exc))

    accepted = response.status_code < 400
    columns: list[str] = []
    sample_id: str | None = None
    sample_row: dict | None = None
    if accepted:
        try:
            body = response.json()
            if isinstance(body, list) and body and isinstance(body[0], dict):
                columns = list(body[0].keys())
                sample_row = body[0]
                raw_id = sample_row.get("id")
                if raw_id is not None:
                    sample_id = str(raw_id)
        except ValueError:
            pass
    return ReadResult(
        table_name, response.status_code, accepted, columns, sample_id, sample_row
    )
