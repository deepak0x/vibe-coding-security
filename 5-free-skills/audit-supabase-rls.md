---
name: audit-supabase-rls
description: Detect disabled Row Level Security (RLS) and misconfigured Supabase policies that expose data to unauthorized roles. Checks for the CVE-2025-48757 pattern affecting 170+ Lovable apps.
trigger: "supabase rls" | "row level security" | "rls disabled" | "anon role access"
category: auth
severity: critical
---

# Audit Supabase RLS Policies

## Why this matters

Supabase ships with RLS off. That's not a bug. It's a deliberate default so you can prototype without writing policies first. The problem is that Lovable, v0, and Bolt generate apps with that default intact and then deploy them. CVE-2025-48757 (disclosed May 2025, CVSS 9.3) is what happens next: in a sample of 1,645 Lovable apps, 170 had tables readable or writable through the public anon key — about one in ten. Moltbook (February 2026) was the same mistake on a larger dataset: 1.5M API tokens and 35K emails, pulled with a single curl. Escape.tech's October 2025 scan of 5,600 vibe-coded apps reported 2,038 critical vulnerabilities across 1,400 of them, and missing or broken RLS is one of the most common. The anon key is public by design. Your RLS policies are what stand between that key and your users' data.

## Detection steps

1. **Check which tables have RLS disabled:**
 ```sql
 SELECT tablename, rowsecurity 
 FROM pg_tables 
 WHERE schemaname = 'public' 
 AND rowsecurity = false;
 ```
 Any table returning `rowsecurity = false` is unprotected.

2. **List all policies (should be many for each table):**
 ```sql
 SELECT schemaname, tablename, policyname, qual, permissive 
 FROM pg_policies 
 WHERE schemaname = 'public' 
 ORDER BY tablename;
 ```
 If result is empty or sparse, RLS is not enforced.

3. **Find anon-role overexposure (most critical):**
 ```sql
 SELECT tablename, policyname, roles 
 FROM pg_policies 
 WHERE schemaname = 'public' 
 AND 'anon'::regrole = ANY(roles);
 ```
 Any policy with `anon` in roles needs scrutiny.

4. **Check for SELECT policies without WHERE clauses:**
 ```sql
 SELECT tablename, policyname, qual 
 FROM pg_policies 
 WHERE schemaname = 'public' 
 AND qual IS NULL 
 AND permissive = true;
 ```
 Null `qual` on SELECT = no row filter = entire table readable.

5. **Inspect Supabase table definitions in schema:**
 Look in your codebase for schema migrations or `.sql` files:
 ```bash
 grep -r "CREATE TABLE" --include="*.sql" \
 | grep -v "ENABLE ROW LEVEL SECURITY"
 ```
 Any CREATE TABLE without `ENABLE ROW LEVEL SECURITY` is a red flag.

6. **Verify auth.users.id is in SELECT policies:**
 ```sql
 SELECT tablename, policyname, qual 
 FROM pg_policies 
 WHERE schemaname = 'public' 
 AND qual LIKE '%auth.uid%';
 ```
 Good policies reference `auth.uid()` to filter by user. Missing this = shared data.

## Severity rubric

- **CRITICAL**. RLS disabled on table with PII/secrets (users, emails, tokens). Anon role can SELECT. Affects >1 table.
- **HIGH**. RLS enabled but policies allow anon SELECT without WHERE. RLS on <50% of tables. Weak qual (e.g., `1=1`).
- **MEDIUM**. RLS enabled, policies use auth.uid(), but UPDATE/DELETE policies missing or overpermissive. Admin roles unchecked.

## Remediation

**Step 1: Enable RLS on the table**
```sql
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;
```

**Step 2: Drop old permissive policies (if any)**
```sql
DROP POLICY IF EXISTS "users_read" ON public.users;
DROP POLICY IF EXISTS "users_write" ON public.users;
```

**Step 3: Create auth-bound SELECT policy**
```sql
CREATE POLICY "users_read_own" 
ON public.users 
FOR SELECT 
USING (auth.uid() = id);
```

**Step 4: Create authenticated INSERT policy (user creates own row)**
```sql
CREATE POLICY "users_insert_own" 
ON public.users 
FOR INSERT 
WITH CHECK (auth.uid() = id);
```

**Step 5: Create UPDATE policy (user updates only own row)**
```sql
CREATE POLICY "users_update_own" 
ON public.users 
FOR UPDATE 
USING (auth.uid() = id) 
WITH CHECK (auth.uid() = id);
```

**Step 6: Deny DELETE or restrict to admin**
```sql
CREATE POLICY "users_delete_admin" 
ON public.users 
FOR DELETE 
USING (
 EXISTS (
 SELECT 1 FROM public.users 
 WHERE id = auth.uid() 
 AND role = 'admin'
 )
);
```

**Step 7: Verify (re-run detection queries)**
```sql
SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public';
SELECT policyname, tablename, permissive FROM pg_policies WHERE schemaname = 'public';
```

## Reference
- [CVE-2025-48757: Lovable RLS Misconfig](https://www.superblocks.com/blog/lovable-vulnerabilities)
- [Moltbook: 1.5M tokens exposed](https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys)
- [Escape.tech, October 2025: 5,600 vibe-coded apps scanned (methodology)](https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/)
- [Escape.tech: 2,038 critical vulnerabilities and 400+ leaked secrets across 1,400 apps (findings)](https://escape.tech/state-of-security-of-vibe-coded-apps)
- [Supabase RLS Docs](https://supabase.com/docs/guides/auth/row-level-security)
