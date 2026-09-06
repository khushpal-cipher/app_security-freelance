from ..models import AccessType

_READ_PROMPT = """Enable Row Level Security on the `{table}` table and restrict SELECT to owners only:

alter table {table} enable row level security;

create policy "Users can view own rows"
on {table} for select
to authenticated
using (auth.uid() = user_id);

-- If {table} has no owner column, decide who should be able to read it,
-- then write a policy that encodes exactly that rule. Do not leave it
-- policy-less: with RLS enabled and no policy, all access is denied by
-- default, which is the safe starting point."""

_WRITE_PROMPT = """Enable Row Level Security on the `{table}` table and restrict INSERT/UPDATE to owners only:

alter table {table} enable row level security;

create policy "Users can modify own rows"
on {table} for {op}
to authenticated
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

-- Replace user_id with whatever column ties a row to its owner."""

_DELETE_PROMPT = """Enable Row Level Security on the `{table}` table immediately \
-- this table currently accepts anonymous DELETE requests:

alter table {table} enable row level security;

create policy "Users can delete own rows"
on {table} for delete
to authenticated
using (auth.uid() = user_id);

-- Replace user_id with whatever column ties a row to its owner.
-- Until a policy exists, RLS alone blocks all deletes, which is safe."""


def build_fix_prompt(table_name: str, access_type: AccessType) -> str:
    if access_type == AccessType.READ:
        return _READ_PROMPT.format(table=table_name)
    if access_type == AccessType.DELETE:
        return _DELETE_PROMPT.format(table=table_name)
    return _WRITE_PROMPT.format(table=table_name, op="insert, update")
