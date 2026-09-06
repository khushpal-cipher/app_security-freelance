from ..models import AccessType, Severity
from .probe_read import ReadResult

SENSITIVE_COLUMN_MARKERS = (
    "email",
    "phone",
    "token",
    "password",
    "secret",
    "ssn",
    "api_key",
    "apikey",
    "credit_card",
    "card_number",
    "address",
)


class Classification:
    def __init__(
        self,
        table_name: str,
        access_type: AccessType,
        severity: Severity,
        description: str,
    ):
        self.table_name = table_name
        self.access_type = access_type
        self.severity = severity
        self.description = description


def has_sensitive_columns(columns: list[str]) -> list[str]:
    hits = []
    for col in columns:
        lowered = col.lower()
        if any(marker in lowered for marker in SENSITIVE_COLUMN_MARKERS):
            hits.append(col)
    return hits


def classify_read(result: ReadResult) -> Classification | None:
    if not result.accepted or not result.columns:
        # An empty 200 response is what a correctly RLS-protected table
        # returns to every anon caller — indistinguishable, without a
        # privileged view, from "no policy grants this row." Reporting it
        # as a finding would flag every properly secured table as a false
        # positive, which is the exact opposite of what this tool proves.
        return None
    sensitive = has_sensitive_columns(result.columns)
    if sensitive:
        cols = ", ".join(sensitive)
        return Classification(
            result.table_name,
            AccessType.READ,
            Severity.HIGH,
            f"Table '{result.table_name}' is readable by anyone with the anon key "
            f"and exposes sensitive column(s): {cols}.",
        )
    return Classification(
        result.table_name,
        AccessType.READ,
        Severity.MEDIUM,
        f"Table '{result.table_name}' is readable by anyone with the anon key.",
    )


def classify_write_advisory(result: ReadResult) -> Classification | None:
    """Flag write/delete as worth checking manually — never by testing it live.

    Supabase does not reliably honor PostgREST's `tx=rollback` dry-run
    preference, so a live write/delete probe can permanently mutate real
    data with no way to undo it — confirmed by an actual, unrecoverable
    write during this tool's own testing. There is no way to verify write
    access from the anon key alone without risking exactly that, so this
    tool never attempts one. Instead: if a table's rows are visible to
    anyone, its default write/delete grants are worth a manual look, since
    Supabase grants INSERT/UPDATE/DELETE broadly by default and RLS is
    normally the only thing standing between anon and a real mutation.
    """
    if not result.accepted or not result.columns:
        return None
    return Classification(
        result.table_name,
        AccessType.WRITE,
        Severity.MEDIUM,
        f"Table '{result.table_name}' is readable by anyone with the anon key. "
        "Write and delete access were not actively tested — Supabase does not "
        "reliably honor a safe dry-run for those operations, so testing them live "
        "risks real data loss. Manually check this table's INSERT/UPDATE/DELETE "
        "policies in the Supabase dashboard; if none exist, anonymous write "
        "access is likely also unprotected.",
    )
