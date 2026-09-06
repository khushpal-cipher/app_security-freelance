from app.models import Classification, EndpointSpec, Finding, ProbeOutcome, Severity

FIX_PROMPTS = {
    Classification.auth_bypass: (
        "Add an authentication check to {method} {path} — it currently returns a "
        "successful response with no Authorization header at all. In FastAPI, add "
        "`Depends(get_current_user)`; in Express, add auth middleware before the "
        "route handler; if backed by Supabase/Postgres, enable Row Level Security "
        "and add a policy that requires `auth.uid()` to be set."
    ),
    Classification.inverted_policy: (
        "{method} {path} returns MORE records with no Authorization header "
        "({anon_count}) than it does for a valid authenticated user ({authed_count}) — "
        "the authorization check is inverted or missing a scoping WHERE clause. Look "
        "for a code path like `if not user: return all_rows()`, and check for an RLS "
        "policy that defaults to allow when the caller isn't authenticated."
    ),
}


def _build_finding(
    ep: EndpointSpec,
    anon: ProbeOutcome,
    authed: ProbeOutcome,
    classification: Classification,
    severity: Severity,
    reason: str,
    fix_prompt: str | None = None,
) -> Finding:
    return Finding(
        path=ep.path,
        method=ep.method,
        expects_auth=ep.expects_auth,
        classification=classification,
        severity=severity,
        anon=anon,
        authed=authed,
        reason=reason,
        fix_prompt=fix_prompt,
    )


def build_skipped_finding(ep: EndpointSpec, reason: str) -> Finding:
    empty = ProbeOutcome()
    return _build_finding(ep, empty, empty, Classification.skipped, Severity.info, reason)


def classify(ep: EndpointSpec, anon: ProbeOutcome, authed: ProbeOutcome) -> Finding:
    """The differential check: same request, two identities, compare outcomes.

    For an endpoint marked expects_auth:
      - anon gets a 2xx AND sees more records than authed -> CRITICAL inverted_policy
      - anon gets a 2xx (any other case)                  -> CRITICAL auth_bypass
      - anon gets 401/403                                  -> pass
      - anon errors out or gets anything else               -> warn/error, needs a human look
    """
    if anon.error or authed.error:
        return _build_finding(
            ep, anon, authed, Classification.error, Severity.warning,
            f"Request failed (anon={anon.error}, authed={authed.error}); could not verify this endpoint.",
        )

    if not ep.expects_auth:
        return _build_finding(
            ep, anon, authed, Classification.info, Severity.info,
            "Endpoint not marked as requiring auth; recorded as baseline only.",
        )

    if anon.status_code is not None and 200 <= anon.status_code < 300:
        if (
            anon.record_count is not None
            and authed.record_count is not None
            and anon.record_count > authed.record_count
        ):
            reason = (
                f"Unauthenticated request returned {anon.record_count} record(s) vs "
                f"{authed.record_count} for the authenticated user (HTTP {anon.status_code} both) "
                "— broader access with no token than with one."
            )
            fix_prompt = FIX_PROMPTS[Classification.inverted_policy].format(
                method=ep.method.value,
                path=ep.path,
                anon_count=anon.record_count,
                authed_count=authed.record_count,
            )
            return _build_finding(
                ep, anon, authed, Classification.inverted_policy, Severity.critical, reason, fix_prompt
            )

        reason = f"Unauthenticated request to a protected endpoint succeeded (HTTP {anon.status_code})."
        fix_prompt = FIX_PROMPTS[Classification.auth_bypass].format(method=ep.method.value, path=ep.path)
        return _build_finding(
            ep, anon, authed, Classification.auth_bypass, Severity.critical, reason, fix_prompt
        )

    if anon.status_code in (401, 403):
        return _build_finding(
            ep, anon, authed, Classification.pass_, Severity.pass_,
            f"Unauthenticated request correctly rejected (HTTP {anon.status_code}).",
        )

    return _build_finding(
        ep, anon, authed, Classification.warn, Severity.warning,
        f"Unexpected status for an unauthenticated request (HTTP {anon.status_code}); review manually.",
    )


SEVERITY_ORDER = {Severity.critical: 0, Severity.warning: 1, Severity.info: 2, Severity.pass_: 3}


def rank_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])
