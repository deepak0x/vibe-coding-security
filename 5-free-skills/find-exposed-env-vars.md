---
name: find-exposed-env-vars
description: Detect exposed environment variables in production builds, client bundles, and deployed code. Flags NEXT_PUBLIC_ leaks that expose sensitive API keys and tokens.
trigger: "exposed env vars" | "env variable leak" | "NEXT_PUBLIC leaked" | "environment variable in client"
category: secrets
severity: critical
---

# Find Exposed Environment Variables

## Why this matters

`NEXT_PUBLIC_` is not a naming convention. It's a build instruction. Anything prefixed with it gets compiled directly into your client JavaScript. Publicly readable by anyone who opens DevTools. The Moltbook breach (February 2026) is the cautionary tale: the Supabase publishable key sat in the client bundle for anyone to grep, and combined with no RLS that exposed 1.5M API tokens and 35K email addresses — pulled with a single curl. The anon/publishable key in client JS is fine *if RLS is on*; the danger is when a real secret rides along under the same `NEXT_PUBLIC_` prefix. Escape.tech's October 2025 scan of 5,600 vibe-coded apps reported 400+ leaked secrets, Stripe, OpenAI and Supabase keys among them, sitting in frontend bundles ([findings](https://escape.tech/state-of-security-of-vibe-coded-apps)). The key rotation you do after the fact doesn't undo the window where anyone could read them.

See: https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys

## Detection steps

1. Check build output for any NEXT_PUBLIC_ or VITE_ variables with key-like values:
 ```bash
 grep -rE "(NEXT_PUBLIC_|VITE_).*=(sk-|pk-|AKIA|ghp_|hf_|sb-|supabase)" .next/static/ dist/ build/
 ```

2. Scan source code for accidental secrets prefixed with NEXT_PUBLIC_:
 ```bash
 grep -rE "NEXT_PUBLIC_(SUPABASE|STRIPE|OPENAI|ANTHROPIC|DATABASE)" . --include="*.env*" --include="*.ts" --include="*.tsx"
 ```

3. Extract all env keys from built JS bundles:
 ```bash
 grep -oE "[a-z]+_[A-Z_]+(KEY|TOKEN|SECRET|URL|PASSWORD)" .next/static/**/*.js | sort | uniq
 ```

4. Check git history for leaked .env files in prior commits:
 ```bash
 git log --all --full-history -p -- ".env*" | grep -E "^(\+|-).*(sk_|pk_|AKIA|ghp_)" | head -20
 ```

5. Use ripgrep to find high-entropy secrets in node_modules/.next output:
 ```bash
 rg -i "(api.key|secret.key|auth.token)" .next/ --max-count 5
 ```

6. Check for service role keys in client bundles (should never appear):
 ```bash
 grep -r "SUPABASE_SERVICE_ROLE_KEY\|STRIPE_SECRET_KEY\|OPENAI_API_KEY" .next/static/ && echo "CRITICAL: Service key in client bundle"
 ```

## Severity rubric

- **CRITICAL**. Service role keys (supabase_service_role, STRIPE_SECRET_KEY, sk_live_, ANTHROPIC_API_KEY) in client bundles or .next/static/. Immediate revocation required.
- **HIGH**. NEXT_PUBLIC_ prefixed with real token (sk-, pk-, akia-, ghp_). Key rotation needed within 24 hours.
- **MEDIUM**. Database connection strings or Supabase anon keys exposed (if RLS is misconfigured, escalate to CRITICAL).

## Remediation

### Fix: Never use NEXT_PUBLIC_ for secrets

```ts
// ❌ WRONG. This will be in client JS
export const NEXT_PUBLIC_SUPABASE_KEY = "eyJhbG...";

// ✅ RIGHT. Server-only (removed from build)
export const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
```

### Fix: .env.local structure (Next.js)

```bash
# .env.local (server-only secrets)
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
STRIPE_SECRET_KEY=sk_live_<REDACTED_EXAMPLE>
OPENAI_API_KEY=sk-proj-...
DATABASE_URL=postgresql://...

# .env.local (safe to expose, but use anon key with RLS)
NEXT_PUBLIC_SUPABASE_URL=https://xxxxx.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbG... (with RLS enabled)
```

### Fix: Verify post-rotation in build

```bash
# After rotating keys, rebuild and verify no secrets in output
rm -rf .next
npm run build
grep -rE "(sk_live_|sk-proj-|supabase.*service)" .next/static/ && echo "LEAK DETECTED" || echo "Clean"
```

## Reference

- https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys. Moltbook 1.5M token leak
- https://dev.to/starkprince/we-got-hacked-how-cve-2025-55182-turned-our-next-js-app-into-a-crypto-mine-3oce. CVE-2025-55182 crypto mining via leaked vars
- https://nextjs.org/docs/basic-features/environment-variables#exposing-variables-to-the-browser. Next.js NEXT_PUBLIC_ docs
