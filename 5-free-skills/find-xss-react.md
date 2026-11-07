---
name: find-xss-react
description: Detect XSS vulnerabilities in React via dangerouslySetInnerHTML, innerHTML assignment, unescaped LLM output rendered as HTML, and iframe srcDoc abuse.
trigger: "xss" | "dangerouslySetInnerHTML" | "innerHTML" | "cross-site scripting" | "html injection" | "iframe srcDoc"
category: frontend-runtime
severity: critical
---

# Find XSS Vulnerabilities in React

## Why this matters

React escapes text by default. The moment you use `dangerouslySetInnerHTML`, you've opted out of that. 86% of AI-generated code fails basic XSS prevention (Veracode, 2025). Partly because models reach for `dangerouslySetInnerHTML` whenever they need to render formatted content, and they don't add DOMPurify because nothing in the prompt asked for it. The risk compounds in AI apps: an LLM's output is untrusted input too. Rendering a model's response straight to the DOM (or anything it generated from user input) is the same XSS hole as rendering a raw user paste. If your app renders anything a user typed, or anything an LLM produced, and you're using `dangerouslySetInnerHTML`, check this first.

## Detection steps

1. **Find all `dangerouslySetInnerHTML` usage:**
 ```bash
 grep -rE "dangerouslySetInnerHTML" --include="*.tsx" --include="*.ts" --include="*.jsx" --include="*.js"
 ```
 Every instance must be audited. Flag any that accept user input or LLM output.

2. **Check for innerHTML assignment:**
 ```bash
 grep -rE "\.innerHTML\s*=" --include="*.tsx" --include="*.ts" --include="*.jsx" --include="*.js"
 ```
 Direct DOM assignment is a critical XSS vector. Look for patterns like:
 ```ts
 element.innerHTML = userInput; // VULNERABLE
 element.innerHTML = apiResponse.content; // VULNERABLE
 ```

3. **Audit each `dangerouslySetInnerHTML` for sanitization:**
 ```bash
 grep -B 5 -A 2 "dangerouslySetInnerHTML" --include="*.tsx" \
 | grep -v "DOMPurify\|sanitize\|htmlspecialchars"
 ```
 If the value is not wrapped in DOMPurify or equivalent, it's vulnerable.

4. **Check iframe srcDoc attribute:**
 ```bash
 grep -rE "srcDoc\s*=" --include="*.tsx" --include="*.ts" \
 | grep -v "createObjectURL\|blob:"
 ```
 iframes with user-controlled srcDoc can break out of sandbox via HTML/JS.

5. **Find unescaped LLM output rendering:**
 ```bash
 grep -rE "(chat|message|response|content).*dangerouslySetInnerHTML|innerHTML" \
 --include="*.tsx" --include="*.ts"
 ```
 Look for patterns where API responses or LLM output go directly to DOM:
 ```ts
 <div dangerouslySetInnerHTML={{ __html: chatMessage.content }} /> // VULNERABLE
 ```

6. **Check for missing `<script>` tag allowlist:**
 Verify that if DOMPurify is used, it blocks `<script>` tags:
 ```bash
 grep -A 3 "DOMPurify.sanitize" --include="*.tsx" --include="*.ts"
 ```
 Should see `ALLOWED_TAGS` config that excludes `script`, `iframe`, `object`.

## Severity rubric

- **CRITICAL** , `dangerouslySetInnerHTML` or `innerHTML` assigned user input, LLM output, or API response without DOMPurify. Affects >3 components.
- **HIGH**. DOMPurify used but whitelist includes dangerous tags (`script`, `iframe`, `object`). Or unescaped HTML in template strings.
- **MEDIUM**. Unescaped text interpolation (React auto-escapes by default, but string templates don't). Or iframe sandbox attribute missing.

## Remediation

**Before: Vulnerable**
```tsx
// Unsafe: renders user HTML directly
function ChatMessage({ message }) {
 return <div dangerouslySetInnerHTML={{ __html: message.content }} />;
}

// Unsafe: direct DOM manipulation
function renderHTML(html) {
 const el = document.getElementById('output');
 el.innerHTML = html; // XSS
}
```

**After: Sanitized with DOMPurify**
```tsx
import DOMPurify from 'dompurify';

function ChatMessage({ message }) {
 const sanitized = DOMPurify.sanitize(message.content, {
 ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'code', 'pre', 'p', 'br'],
 ALLOWED_ATTR: ['href', 'target', 'rel'],
 });
 
 return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
}

// Safe: DOM manipulation with sanitization
function renderHTML(html) {
 const el = document.getElementById('output');
 el.innerHTML = DOMPurify.sanitize(html);
}
```

**For iframe srcDoc with content:**
```tsx
// Vulnerable
function IframeViewer({ content }) {
 return <iframe srcDoc={content} />; // User can inject <script>
}

// Safe: blob URL with strict sandbox
function IframeViewer({ content }) {
 const sanitized = DOMPurify.sanitize(content);
 const blob = new Blob([sanitized], { type: 'text/html' });
 const url = URL.createObjectURL(blob);
 
 return (
 <iframe 
 srcDoc={sanitized}
 sandbox="allow-same-origin" // Restrict capabilities
 title="preview"
 />
 );
}
```

**package.json dependency:**
```json
{
 "dependencies": {
 "dompurify": "^3.0.6"
 }
}
```

## Reference
- [Veracode: 86% XSS Prevention Failures](https://www.veracode.com/research)
- [OWASP LLM Top 10 2025 — Improper Output Handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)
- [OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [DOMPurify Configuration](https://github.com/cure53/DOMPurify)
