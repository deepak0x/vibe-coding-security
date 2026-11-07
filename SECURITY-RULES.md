# Security rules for AI-built apps (Supabase / Lovable)

Follow these on every edit. They prevent the CVE-2025-48757 class of leaks.

## Database (RLS)
1. Enable RLS on every table, always: `ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;` in the same migration that creates it.
2. Never write a policy with `USING (true)` for the `anon` role. Anon gets no table access unless the data is truly public.
3. Every SELECT/UPDATE/DELETE policy must filter rows, normally by `auth.uid() = user_id`.
4. Write separate policies per operation (select, insert, update, delete). No catch-all.
5. After adding a table, verify: `SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname='public' AND rowsecurity=false;` must return zero rows.

## Secrets
6. The Supabase anon key and URL may live in client code. Nothing else may.
7. Never put the `service_role` key, API tokens, or passwords in client code, `VITE_`/`NEXT_PUBLIC_` env vars, or database tables readable by anon.
8. Third-party API calls (e.g. impact.com) go through edge functions / server routes only. Never return the raw token to the browser.
9. Never commit `.env` files.

## Auth
10. Access checks happen server-side (edge function or RLS), never only in React state or client-side routing. A hidden page is not a protected page.
11. Any shared password gate must be verified on the server, and every data endpoint must require the resulting session — not just the page.
12. Edge functions keep `verify_jwt = true` unless the function is intentionally public and returns no private data.

## Storage
13. Buckets are private by default. A public bucket needs an explicit reason written in the code review.
14. Signed URLs must expire and must be scoped to one object.

## Before every publish
15. Test the real thing: query each table over the REST API with only the anon key and no login. Any rows returned from a private table = stop and fix.
