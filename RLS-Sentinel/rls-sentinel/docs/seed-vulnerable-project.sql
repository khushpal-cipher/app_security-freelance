-- Seed a THROWAWAY Supabase project with known-bad tables so RLS-Sentinel
-- has something to find. Never run this against a project with real data.
-- Paste into Supabase Studio -> SQL Editor -> Run.

-- 1. CRITICAL + HIGH: no RLS at all. Anon can read, insert, update, delete.
--    Sensitive columns (email, phone) push the read finding to HIGH.
create table public.customers (
  id uuid primary key default gen_random_uuid(),
  full_name text,
  email text,
  phone text
);
insert into public.customers (full_name, email, phone)
values ('Ada Lovelace', 'ada@example.com', '+1-555-0100');
-- RLS deliberately left OFF.

-- 2. MEDIUM: RLS on, but a permissive SELECT policy for anon. Read-only leak,
--    no sensitive column names.
create table public.blog_posts (
  id uuid primary key default gen_random_uuid(),
  title text,
  body text
);
alter table public.blog_posts enable row level security;
create policy "public read" on public.blog_posts for select to anon using (true);
insert into public.blog_posts (title, body) values ('Hello', 'World');

-- 3. Clean control: RLS on, no anon policies. Should produce zero findings.
create table public.internal_notes (
  id uuid primary key default gen_random_uuid(),
  note text
);
alter table public.internal_notes enable row level security;
insert into public.internal_notes (note) values ('nothing to see here');
