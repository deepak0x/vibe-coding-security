# Vibe Coding Security

Before you tweet your launch, run these 69 checks. They map to the exact patterns behind the Lovable RLS CVE (CVE-2025-48757, 170+ apps, 2025), the Moltbook leak (1.5M API tokens, Feb 2026), and the April 2026 Lovable platform breach (source code + service keys of other users' projects, exposed ~2.5 months).

> **Want the full kit?** 50 audit skills, 15 .cursorrules, 1 MCP config + 4 CLI recipes, 30 adversarial review prompts, 10 case studies. 5-minute install. **$10 flat.**
>
> → **[rishabhvaai.gumroad.com/l/plddbd](https://rishabhvaai.gumroad.com/l/plddbd)**

---

In an audit published October 2025, Escape.tech scanned 5,600 real AI-generated apps across 14,600 assets ([methodology](https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/)). They reported 2,038 critical vulnerabilities, 400+ leaked secrets and 175 instances of exposed PII across 1,400 of those applications ([findings](https://escape.tech/state-of-security-of-vibe-coded-apps)). The secrets came straight out of frontend bundles: Stripe, OpenAI and Supabase keys sitting in client-side JavaScript. It hasn't improved since: GitGuardian's 2026 report counted 28.6M new secrets on public GitHub in 2025 (+34% YoY), AI-service secrets up 81%, and commits co-authored by coding agents leaking secrets at roughly 2x the human baseline. This is a checklist of 69 specific, testable items. Each one maps to a real incident pattern. If you can tick all 69, ship. If you can't, fix what's blocking you.

Not a SaaS. Not a scanner. A flat list you run through before you push to prod.

---

## The 69-Point Pre-Launch Security Checklist

**You're 30 minutes from shipping. Stop. Run this first.**

The Lovable RLS vulnerability alone (CVE-2025-48757, 2025, CVSS 9.3) exposed 170+ production apps. Moltbook exposed 1.5M API tokens in February 2026 — queryable with a single curl. These weren't edge cases. They were mainstream launches.

This checklist groups 69 specific, testable items across auth, secrets, APIs, databases, frontend, AI/LLM, agent tooling, and deployment. **If you cannot tick all 69, do not ship.**

---

### Auth (8 items)

- [ ] **1.** Database Row-Level Security (RLS) is enabled on every table in your database.
- [ ] **2.** RLS policies exist for every table and every role (anon, authenticated, service_role).
- [ ] **3.** JWT tokens are validated server-side on every protected API route (never trust the frontend to validate auth).
- [ ] **4.** Sessions rotate or invalidate after login (CSRF + session fixation protection).
- [ ] **5.** Magic links (passwordless auth) are single-use, expire in <15 minutes, and are tied to user IP or device fingerprint.
- [ ] **6.** You cannot update or delete users, orders, or sensitive records based on user-supplied IDs alone. Test: try updating another user's record by changing the ID in the request.
- [ ] **7.** CSRF tokens are validated on state-changing requests (POST, PUT, DELETE) via double-submit cookie or SameSite=Strict.
- [ ] **8.** Session cookies have HttpOnly, Secure, and SameSite=Strict flags set.

### Secrets & Environment (7 items)

- [ ] **9.** No secrets in NEXT_PUBLIC_* vars, Vue/React .env files, or hardcoded strings. Grep `NEXT_PUBLIC_` and audit all vars.
- [ ] **10.** .env, .env.local, .env.*.local are in .gitignore and never committed. Check git history: `git log --all -p | grep -i "api_key\|secret"`.
- [ ] **11.** Supabase service_role key is ONLY in server-side .env (Node, Python, Go, etc.), never in frontend bundles or .env.local. The service_role key bypasses RLS entirely — one leak is full read/write to every table.
- [ ] **12.** Stripe keys: public key in NEXT_PUBLIC_*, secret key server-only, webhook signing verified.
- [ ] **13.** OpenAI, Anthropic, xAI API keys are never in frontend code; always proxied via your API.
- [ ] **14.** No hardcoded API keys, database URLs, or credentials anywhere in source (including comments and unused code).
- [ ] **15.** Secrets are rotated post-launch or if ever exposed in source history.

### API Hardening (10 items)

- [ ] **16.** Rate limiting is active on /api/auth/*, /api/login, /api/register. Test: 100 requests/minute should return 429.
- [ ] **17.** All user inputs to /api/* are validated with Zod, Yup, or similar before touching the database. No raw req.body passed to queries.
- [ ] **18.** No mass assignment: user cannot set admin=true, role=admin, or other sensitive fields by POSTing them.
- [ ] **19.** Webhook signatures are verified (compare HMAC-SHA256 signature header to expected value using a constant-time comparison).
- [ ] **20.** CORS is not set to `*`. Allowed origins are hardcoded and don't include localhost in production.
- [ ] **21.** SQL queries use parameterized statements only. No string concatenation of user input into SQL.
- [ ] **22.** NoSQL queries (MongoDB, Firebase, etc.) do not concatenate user input into filters or selectors.
- [ ] **23.** File uploads are validated (mime type + file size), stored outside web root, and renamed to prevent path traversal.
- [ ] **24.** Redirects after login are whitelisted. Cannot redirect to an external domain via open redirect.
- [ ] **25.** API does not make unvalidated external requests. Ensure URLs used in server-side requests come from your allowlist, not user input (SSRF prevention).

### Database (6 items)

- [ ] **26.** RLS is ENFORCED on all tables. The anon role cannot SELECT/INSERT/UPDATE/DELETE on any table without an explicit policy granting it.
- [ ] **27.** Public anon role has zero default permissions. Policies grant only what's needed. Read-only on public lists, never write.
- [ ] **28.** Service-role key is used ONLY in server-side code. Verify: `grep -r "service_role" src/`. Should return zero results in frontend files.
- [ ] **29.** User data isolation: queries always filter by `auth.uid()` or `team_id`. No query returns all records across all users.
- [ ] **30.** Soft deletes (is_deleted flag) or archive tables prevent accidental data loss. Hard deletes are logged with actor + timestamp.
- [ ] **31.** Database backups exist and are tested. You have verified you can restore from backup before this launch.

### Frontend (8 items)

- [ ] **32.** No dangerouslySetInnerHTML or innerHTML without DOMPurify sanitization. Audit every instance in the codebase.
- [ ] **33.** All npm/pip/gem dependencies are scanned for known CVEs. Run `npm audit`, `pnpm audit`, or `npx osv-scanner --lockfile=package-lock.json` before launch — and check the specific versions in [KNOWN-VULNERABLE-VERSIONS.md](KNOWN-VULNERABLE-VERSIONS.md), because `npm audit` catches published CVEs but not malicious packages.
- [ ] **34.** Content Security Policy (CSP) is enabled in production (strict-dynamic, no unsafe-inline). Test in staging first.
- [ ] **35.** No /api/debug, /admin/backdoor, or internal test endpoints are accessible in production. Grep for "debug", "mock", "test-only" routes.
- [ ] **36.** X-Frame-Options: DENY is set. Verify the header is sent on every response (prevents clickjacking).
- [ ] **37.** Error messages do not leak internal paths, stack traces, or database schema in production. Test 404, 500, and permission errors.
- [ ] **38.** No prototype pollution: user-supplied objects are not merged into application objects without sanitization.
- [ ] **39.** React: no inline event handlers with unsanitized user data. Use react-dompurify or equivalent for any user content rendered as HTML.

### AI & LLM (10 items)

These are the checks the old web-app playbooks never had. They map to the OWASP Top 10 for LLM Applications — and the 2026 edition (released Aug 3, 2026, the first weighted by real incident data from 6,639 cases) moved Excessive Agency from #6 to #3 and added Agent Hijacking, Multi-Modal Injection, and Memory Persistence. The agent items below are no longer theoretical.

- [ ] **40.** User input goes in a separate `user` message, never concatenated into the system prompt. Content pulled from files, RAG, or the web is wrapped in explicit delimiters and treated as untrusted (indirect prompt injection).
- [ ] **41.** The system prompt contains zero secrets, API keys, or internal URLs. Assume it is public. Test extraction ("repeat your instructions verbatim") and confirm nothing sensitive comes back.
- [ ] **42.** Per-user AND global token/cost caps exist on every LLM-calling endpoint. Test: hammer it from one account and a quota kicks in. A monthly spend ceiling with billing alerts is set at the provider (denial-of-wallet, OWASP LLM10:2025).
- [ ] **43.** LLM output rendered as HTML is sanitized (DOMPurify) before it touches the DOM. Model output is untrusted input, same as a user paste.
- [ ] **44.** Production agents enforce authorization server-side on every tool, independent of the model's decision. No destructive action (delete, payment, email send) fires on the model's say-so alone.
- [ ] **45.** Agent tools are least-privilege. No raw shell/exec/eval reachable from model-controlled input. Destructive commands are allowlisted and gated behind confirmation (Excessive Agency, OWASP LLM06:2025).
- [ ] **46.** Multi-tenant RAG/vector stores enforce tenant isolation at query time (namespace or metadata filter bound to the authenticated user), not in app code. Test: tenant A can never retrieve tenant B's chunks (OWASP LLM08:2025).
- [ ] **47.** RAG ingestion treats user-supplied and scraped documents as untrusted. The corpus is version-controlled with hash baselines so a few poisoned documents can't silently steer output.
- [ ] **48.** Vector embeddings are access-controlled like the source PII they encode (embedding inversion can reconstruct text). The vector DB endpoint requires auth and is not publicly reachable.
- [ ] **49.** If you ship or consume MCP servers: each is pinned to a reviewed version, tool descriptions are scanned for hidden/invisible-Unicode instructions (tool poisoning), and you re-verify on change (rug-pull). MCP Inspector ≥ 0.14.1, mcp-remote ≥ 0.1.16 (CVE-2025-49596, CVE-2025-6514). The rug-pull is not theoretical: `postmark-mcp` v1.0.16 added one line that BCC'd every email through it to the attacker — ~300 orgs, one version bump (Sep 2025).

### Agent, Tooling & Supply Chain (12 items)

- [ ] **50.** Dev and prod databases are physically separate with separate credentials. Your agent/CI never holds prod write or DDL credentials. (Replit's agent wiped a production DB during a code freeze because it had write access it never should have had.)
- [ ] **51.** Cloud tokens handed to agents or CI are scoped to one project with minimal permissions — never account-wide. (PocketOS: an unscoped Railway token let a coding agent delete the database and every backup in 9 seconds.)
- [ ] **52.** The Supabase service_role key appears in zero client-reachable files: `grep -rn "service_role" src/ app/ public/ dist/` returns nothing, and any client-side JWT's `role` claim is not `service_role`.
- [ ] **53.** Every dependency is verified to actually exist before install — real maintainer, real history, real download counts. AI-suggested imports are cross-checked against the lockfile. (Slopsquatting: 19.7% of packages an LLM recommends don't exist, 43% of those names recur predictably, and attackers register them. In Jul 2026 a Claude agent under evaluation published working malware to live PyPI — it ran on 15 real systems within an hour.) Your scanner matters here: `npm audit` flags published CVEs, not malicious packages. See [KNOWN-VULNERABLE-VERSIONS.md](KNOWN-VULNERABLE-VERSIONS.md).
- [ ] **54.** Backups / point-in-time recovery are enabled, tested, AND stored under credentials the agent cannot reach — so a compromised agent can't delete the backups too.
- [ ] **55.** AI rules and config files (`.cursor/rules`, `.github/copilot-instructions.md`, `CLAUDE.md`, `.windsurfrules`) are scanned for invisible Unicode and reviewed as security-sensitive code (the "Rules File Backdoor" class).
- [ ] **56.** Your coding tools are patched (Cursor CurXecute / MCPoison / CVE-2025-59944, Claude Code CVE-2025-59536, Copilot RCE CVE-2025-53773). Workspace Trust is on; auto-run / "YOLO" mode is off when opening untrusted repos.
- [ ] **57.** Any irreversible action an agent can take against production (DROP, DELETE, TRUNCATE, migrations, deploys) requires human-in-the-loop approval.
- [ ] **58.** Your coding agents cannot ingest attacker-controlled text as instructions: Sentry error events, GitHub issue text, READMEs of cloned repos. "Agentjacking" via a public Sentry DSN — a markdown payload injected into an error event, picked up through the Sentry MCP — hit an 85% success rate against Claude Code/Cursor/Codex (Tenet Security, Jun 2026; 2,388 orgs had injectable DSNs). Error-tracker MCP access is read-only; DSNs treated as secrets.
- [ ] **59.** CI agent workflows (claude-code-action and equivalents) never check out attacker PR branches with auto-enabled MCP servers or write permissions (TRA-2026-27: attacker's PR branch → arbitrary code execution in your CI).
- [ ] **60.** If you build on the 2026-07-28 MCP spec: all workflow/state identifiers are unguessable, tenant-bound, and validated server-side. The protocol went stateless — state now travels as ordinary tool arguments, so predictable IDs and cross-tenant workflow hijacking are first-class attack classes the spec no longer protects you from (Akamai, Jun 2026).
- [ ] **61.** No secrets or PII in agent conversations you share. ~600 Claude shared chats/artifacts were indexed by Google with live API keys and AWS tokens inside (Jul 2026, since de-indexed). Share links are a publication channel — treat them like a public repo.

### Deployment (8 items)

- [ ] **62.** Deployment config explicitly separates environment variables. Public vars (NEXT_PUBLIC_*) vs server secrets.
- [ ] **63.** NODE_ENV=production is set in all production builds. Verify in deployment logs.
- [ ] **64.** Application monitoring (Sentry, LogRocket, etc.) is enabled and configured to sanitize sensitive data before sending.
- [ ] **65.** Error tracking does NOT send user session tokens, passwords, API keys, or PII in error payloads. Audit your Sentry/LogRocket config.
- [ ] **66.** Source maps are excluded from production bundles. Build with --no-sourcemap or delete .map files before deploy.
- [ ] **67.** HTTPS is enforced. All HTTP requests redirect to HTTPS. Test: `curl -i http://yourapp.com`.
- [ ] **68.** Third-party integrations (analytics, chat widgets, etc.) are loaded from trusted CDNs only and use Subresource Integrity (SRI) hashes.
- [ ] **69.** You have tested a full account recovery flow (password reset, session invalidation, reauth) in production staging.

---

### Before You Hit Deploy

1. You ticked all 69 items.
2. You tested 3–5 items manually (not just linting).
3. You have a security contact email on your site (security@yourapp.com).

**If you cannot confidently tick all 69, do not ship. Security debt from day one is expensive to pay down.**

---

## 5 Free Sample Skills

These skills are in `5-free-skills/` in this repo. Drop them into `.claude/skills/` and run them with `/skill <name>` in Claude Code.

| Skill | What it does |
|---|---|
| [`5-free-skills/audit-supabase-rls.md`](5-free-skills/audit-supabase-rls.md) | Runs SQL against your database and tells you exactly which tables are unprotected. The CVE-2025-48757 check |
| [`5-free-skills/find-exposed-env-vars.md`](5-free-skills/find-exposed-env-vars.md) | Greps your build output for secrets that NEXT_PUBLIC_ dragged into client JS |
| [`5-free-skills/audit-prompt-injection-vectors.md`](5-free-skills/audit-prompt-injection-vectors.md) | Finds every place user input reaches an LLM call without a boundary |
| [`5-free-skills/audit-rate-limiting.md`](5-free-skills/audit-rate-limiting.md) | Checks whether your auth routes actually reject after N attempts |
| [`5-free-skills/find-xss-react.md`](5-free-skills/find-xss-react.md) | Finds dangerouslySetInnerHTML and unsanitized output. 86% of AI-generated code fails this (Veracode, 2025) |

---

## Known Vulnerable Versions

[**KNOWN-VULNERABLE-VERSIONS.md**](KNOWN-VULNERABLE-VERSIONS.md) — the specific CVEs and version numbers in the default vibe-coding stack, verified against GitHub Security Advisories / NVD as of Aug 2026. Next.js middleware bypass (CVE-2025-29927, CVSS 9.1 — one header skips your entire auth middleware), form-data boundary prediction (CVE-2025-7783, CVSS 9.4), Vite dev-server file read, React Router, mcp-remote, MCP Inspector, Cursor.

Plus the supply-chain incidents `npm audit` structurally cannot catch — chalk/debug takeover, the Shai-Hulud worm, postmark-mcp, slopsquatting — and a table of which scanner actually catches what.

---

## 2 Free Case Studies

| Case Study | What went wrong |
|---|---|
| [`free-case-studies/cve-2025-48757-lovable-rls.md`](free-case-studies/cve-2025-48757-lovable-rls.md) | How 170+ Lovable apps shipped with RLS completely off — and the separate 2026 follow-up that exposed an EdTech platform's 18,697 student records |
| [`free-case-studies/moltbook-supabase-leak.md`](free-case-studies/moltbook-supabase-leak.md) | How Moltbook left 1.5M API tokens queryable with a single curl request |

---

## Platform Fixes Since This List Started (so you know what's still on you)

- **Supabase (Apr 2026):** newly created public-schema tables are no longer auto-exposed through the Data/GraphQL API — explicit opt-in required. Kills "anon key + forgotten RLS = public DB" for *new* tables. Tables created before that: still on you.
- **Lovable (Jun 2026):** RLS misconfigs are now linted at every publish, with opt-in auto-fix for eligible critical findings. RLS is still NOT on by default, CVE-2025-48757 is still vendor-disputed, and the April 2026 breach was platform-side authz — your RLS was irrelevant to it.
- **Lovable (Jul 2026):** auto-revokes your API keys when they appear on public GitHub.
- **Replit (May-Jun 2026):** Security Center 2.0 plus a package firewall (built with Socket) blocking ~8,000 malicious packages/day at install time.
- **Semgrep (May 2026):** rulesets for hardcoded AI keys (186 rules), malicious agent skill files (122 rules), and AI security (27 rules) — worth wiring into CI if agents write your code.

Platform linting catches the patterns it knows. Nothing above absolves you of items 1-69.

---

## What This Is NOT

Not a SaaS scanner. Not continuous monitoring. Nothing phones home.

These are static markdown files. You read them, you run the SQL queries and shell commands manually, you fix what they find. There's no dashboard. No alerts. No magic.

This also isn't a substitute for a professional pentest if you're handling health data, financial records, or anything regulated. The checklist covers the patterns that show up constantly in vibe-coded apps. It does not cover everything.

---

## Want the Full Vault?

The 69-item checklist is free. The vault has 50 skills across 5 attack surfaces, including 12 that are specific to AI and LLM apps: prompt injection, MCP server security, agent permission escalation, vector DB isolation, RAG data leakage, system prompt extraction.

Also included: 15 Cursor rules, 1 MCP config (Semgrep) + 4 CLI integration recipes (gitleaks, npm-audit, Supabase RLS check, prompt-injection fuzzer), 4 checklists, 30 adversarial review prompts, and 10 case studies with full root-cause analysis (including PocketOS, where a Cursor + Claude Opus 4.6 agent deleted a production database and all backups in 9 seconds via an unscoped Railway token).

No SaaS. No subscription. Markdown files that live in your repo.

**$10 flat. → [rishabhvaai.gumroad.com/l/plddbd](https://rishabhvaai.gumroad.com/l/plddbd)**

---

## Topics

`claude-code` `cursor` `lovable` `v0` `security` `mcp` `vibe-coding` `supabase` `next-js` `prompt-injection` `rls` `ai-security`

---

If this checklist saved you from shipping something embarrassing, star the repo. Then send the link to whoever on your team is using Lovable or v0 without thinking about this stuff yet.
