from enum import Enum

from pydantic import BaseModel, Field, field_validator


class Method(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


WRITE_METHODS = {Method.POST, Method.PUT, Method.PATCH, Method.DELETE}


class EndpointSpec(BaseModel):
    path: str
    method: Method = Method.GET
    expects_auth: bool = True
    zero_match_filter: str | None = Field(
        default=None,
        description=(
            "A 'key=value' query param guaranteed to match zero real records. "
            "Required (in addition to allow_write) before a write method is ever tested."
        ),
    )

    @field_validator("path")
    @classmethod
    def _path_starts_with_slash(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("endpoint path must start with '/'")
        return v


class EndpointsFile(BaseModel):
    endpoints: list[EndpointSpec]


class Classification(str, Enum):
    auth_bypass = "auth_bypass"
    inverted_policy = "inverted_policy"
    pass_ = "pass"
    warn = "warn"
    skipped = "skipped"
    error = "error"
    info = "info"


class Severity(str, Enum):
    critical = "critical"
    warning = "warning"
    info = "info"
    pass_ = "pass"


class ProbeOutcome(BaseModel):
    status_code: int | None = None
    record_count: int | None = None
    body_size: int = 0
    error: str | None = None


class Finding(BaseModel):
    path: str
    method: Method
    expects_auth: bool
    classification: Classification
    severity: Severity
    anon: ProbeOutcome
    authed: ProbeOutcome
    reason: str
    fix_prompt: str | None = None


class VerifyRequest(BaseModel):
    base_url: str = Field(..., description="Base URL of the API under test")
    user_token: str = Field(..., description="A valid, currently-active user JWT/bearer token")
    endpoints_yaml: str = Field(..., description="YAML endpoint spec, see endpoints.example.yaml")
    allow_write: bool = Field(
        default=False,
        description="Opt-in to testing write methods (POST/PUT/PATCH/DELETE). Requires zero_match_filter per endpoint.",
    )


class VerifyResponse(BaseModel):
    base_url: str
    endpoints_tested: int
    findings: list[Finding]
