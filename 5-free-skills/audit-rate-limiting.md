---
name: audit-rate-limiting
description: Audit rate limiting on authentication endpoints. Detect missing or misconfigured rate limits on /api/auth, /api/login, /api/forgot-password using Upstash/Vercel patterns.
trigger: "rate limiting" | "rate limit" | "brute force" | "upstash" | "api throttle"
category: api
severity: critical
---

# Audit Rate Limiting

## Why this matters

No rate limit on `/api/login` means an attacker can try every password in a leaked credential list against your users until something works. No rate limit on `/api/forgot-password` means they can spam password reset emails to enumerate which addresses are registered, then pivot to phishing. AI code generators almost never add rate limiting because it requires a Redis instance or an external service, and the model optimizes for "working app" not "app that survives contact with the internet." 67% of audited vibe-coded apps had no rate limiting on auth endpoints at all. The fix is about 20 lines with Upstash. The breach is not.

## Detection steps

1. **Find auth-related endpoints:**
 ```bash
 grep -rE "api/auth|api/login|api/register|api/forgot|api/reset|api/otp" \
 --include="*.ts" --include="*.js" | head -20
 ```

2. **Check for rate limiting middleware/decorator:**
 ```bash
 grep -rE "rateLimit|RateLimit|Ratelimit|throttle|limiter" \
 --include="*.ts" | grep -v "test"
 ```
 If auth endpoints exist but no rate limiting found, flag as CRITICAL.

3. **Audit Upstash/Vercel rate limit configuration:**
 ```bash
 grep -rE "Ratelimit|upstash" --include="*.ts" \
 -A 5 | grep -E "requests|window|interval"
 ```
 Check for: `new Ratelimit({ requests: 5, window: '1 m' })`.

4. **Check rate limit scope (per-IP vs per-user):**
 ```bash
 grep -B 5 -A 5 "rateLimit\|Ratelimit" --include="*.ts" \
 | grep -E "ip|userId|identifier|key"
 ```
 Should be per-IP for login, per-user for forgot-password.

5. **Look for response status on rate limit hit:**
 ```bash
 grep -E "429|too many requests|rate.*limit" \
 --include="*.ts" -i
 ```
 Should return HTTP 429 (Too Many Requests).

6. **Check environment variables:**
 ```bash
 grep -rE "RATELIMIT|RATE_LIMIT|THROTTLE" --include=".env*" \
 | grep -v ".env.example"
 ```

## Severity rubric

- **CRITICAL**. No rate limiting on /api/login, /api/auth, /api/forgot-password. Unlimited requests per second. No distinction between IP/user scope. Returns 200 on every request (no rejection).
- **HIGH**. Rate limit exists but threshold too high (>100 req/min). No per-IP tracking. Same limit for all auth endpoints. Returns 200 on rate limit hit (should be 429).
- **MEDIUM**. Rate limit per-endpoint but centralized (doesn't account for endpoint sensitivity). Limit reset logic has gaps. Monitoring/alerting not in place.

## Remediation

**Vercel Rate Limiting (Edge Function):**
```ts
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const redis = Redis.fromEnv();
const ratelimit = new Ratelimit({
 redis,
 requests: 5,
 window: '15 m',
});

export async function POST(req: Request) {
 // Get client IP
 const ip = req.headers.get('x-forwarded-for') || 'unknown';
 
 // Rate limit by IP
 const { limit, reset, remaining } = await ratelimit.limit(ip);
 
 if (!limit) {
 return new Response(
 JSON.stringify({ error: 'Too many login attempts' }),
 {
 status: 429,
 headers: {
 'Retry-After': Math.ceil(reset / 1000).toString(),
 },
 }
 );
 }
 
 // Process login
 const { email, password } = await req.json();
 
 // ... authentication logic
 
 return new Response(
 JSON.stringify({ success: true }),
 { status: 200 }
 );
}
```

**Express with express-rate-limit:**
```ts
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import { createClient } from 'redis';

const redisClient = createClient();

const loginLimiter = rateLimit({
 store: new RedisStore({
 client: redisClient,
 prefix: 'login-limit:',
 }),
 keyGenerator: (req) => req.ip, // Per-IP
 windowMs: 15 * 60 * 1000, // 15 minutes
 max: 5, // 5 attempts
 message: 'Too many login attempts',
 standardHeaders: true, // Send RateLimit-* headers
 legacyHeaders: false,
});

const forgotPasswordLimiter = rateLimit({
 store: new RedisStore({
 client: redisClient,
 prefix: 'forgot-limit:',
 }),
 keyGenerator: (req) => req.body.email, // Per-email
 windowMs: 60 * 60 * 1000, // 1 hour
 max: 3, // 3 attempts
});

app.post('/api/login', loginLimiter, async (req, res) => {
 // Login logic
});

app.post('/api/forgot-password', forgotPasswordLimiter, async (req, res) => {
 // Reset logic
});
```

**Custom Rate Limiter (Redis):**
```ts
import { Redis } from '@upstash/redis';

const redis = Redis.fromEnv();

export async function checkRateLimit(
 identifier: string,
 endpoint: string,
 limit: number,
 windowMinutes: number
) {
 const key = `ratelimit:${endpoint}:${identifier}`;
 const current = await redis.incr(key);
 
 if (current === 1) {
 // First request, set expiry
 await redis.expire(key, windowMinutes * 60);
 }
 
 if (current > limit) {
 return {
 allowed: false,
 remaining: 0,
 resetIn: await redis.ttl(key),
 };
 }
 
 return {
 allowed: true,
 remaining: limit - current,
 };
}

// Usage in handler
export async function POST(req: Request) {
 const ip = req.headers.get('x-forwarded-for') || 'unknown';
 const rateCheck = await checkRateLimit(ip, '/api/login', 5, 15);
 
 if (!rateCheck.allowed) {
 return new Response(
 JSON.stringify({ error: 'Too many attempts' }),
 { status: 429 }
 );
 }
 
 // ... rest of handler
}
```

**Multi-Endpoint Strategy:**
```ts
const RATE_LIMIT_CONFIG = {
 '/api/login': {
 windowMinutes: 15,
 max: 5,
 scope: 'ip', // Per IP
 },
 '/api/forgot-password': {
 windowMinutes: 60,
 max: 3,
 scope: 'email', // Per email
 },
 '/api/register': {
 windowMinutes: 60,
 max: 5,
 scope: 'ip',
 },
 '/api/verify-otp': {
 windowMinutes: 1,
 max: 3,
 scope: 'ip+email',
 },
};
```

## Reference
- [OWASP: Brute Force Attack](https://owasp.org/www-community/attacks/Brute_force_attack)
- [Upstash Rate Limiting](https://upstash.com/docs/redis/features/ratelimiting)
- [Vercel Rate Limiting Guide](https://vercel.com/docs/concepts/edge-functions/edge-middleware)
- [CWE-307: Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/307.html)
