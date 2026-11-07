# Known Vulnerable Versions in the Vibe-Coding Stack

Last verified: **2026-08-09**. Every row below was checked against GitHub Security Advisories / NVD or the original vendor disclosure. This is the list `npm audit` is supposed to surface — but audit only runs if you run it, and half of this page (the incidents section) audit will never catch.

Check what you're actually shipping:

```bash
npm ls next vite react-router form-data        # version check in 5 seconds
npx osv-scanner --lockfile=package-lock.json   # CVEs across the whole lockfile
```

---

## Framework & Library CVEs

The generated app pulled these in whether you asked or not.

| Package | CVE | Affected | Fixed | CVSS | What it does |
|---|---|---|---|---|---|
| **next** | [CVE-2025-29927](https://github.com/advisories/GHSA-f82v-jwr5-mffw) | 12.0.0–12.3.4, 13.0.0–13.5.8, 14.0.0–14.2.24, 15.0.0–15.2.2 | 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3 | 9.1 | One request header (`x-middleware-subrequest`) skips your middleware entirely — auth checks, redirects, everything. If your login lives in middleware, it doesn't exist. |
| **vite** | [CVE-2025-30208](https://github.com/advisories/GHSA-x574-m823-4x7w) | <4.5.10, <5.4.15, <6.0.12, <6.1.2, <6.2.3 | 4.5.10 / 5.4.15 / 6.0.12 / 6.1.2 / 6.2.3 | 5.3 | `?raw??` appended to a URL reads arbitrary files (`.env` included) off a dev server exposed with `--host`. Never expose the dev server anyway. |
| **react-router** | [CVE-2025-43864](https://github.com/advisories?query=CVE-2025-43864) / [CVE-2025-43865](https://github.com/advisories?query=CVE-2025-43865) | 7.x before patch (Apr 2025) | upgrade to latest 7.x | High | Cache poisoning via forced SPA mode; pre-render data spoofing in framework mode. |
| **@react-router/node** | [CVE-2025-61686](https://github.com/advisories?query=CVE-2025-61686) | file session storage, 2025 | upgrade to latest | Critical | Path traversal through session IDs in file session storage. |
| **form-data** | [CVE-2025-7783](https://github.com/advisories/GHSA-fjxv-7rqg-78g4) | <2.5.4, 3.0.0–3.0.3, 4.0.0–4.0.3 | 2.5.4 / 3.0.4 / 4.0.4 | 9.4 | Multipart boundary generated with `Math.random()` — predictable, so attackers inject extra form fields into requests your server makes. Transitive dep of half the ecosystem (axios included). |
| **ollama** | [CVE-2024-37032](https://nvd.nist.gov/vuln/detail/CVE-2024-37032) | <0.1.34 | 0.1.34 | 8.8 | Unvalidated digest → path traversal → RCE on the host from a malicious model pull. Old, still found on dev boxes. |
| **mcp-remote** | [CVE-2025-6514](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) | 0.0.5–0.1.15 | 0.1.16 | 9.6 | A malicious MCP server's OAuth metadata executes OS commands on the connecting client. |
| **MCP Inspector** | [CVE-2025-49596](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596) | <0.14.1 | 0.14.1 | 9.4 | No auth between client and proxy: a malicious *website* runs commands on your dev machine while Inspector is up. |
| **Cursor** | [CVE-2025-54135](https://www.catonetworks.com/blog/curxecute-rce/) / CVE-2025-54136 | <1.3.9 | 1.3.9 | 8.6 | Prompt injection writes `.cursor/mcp.json` without approval → persistent RCE ("CurXecute" / "MCPoison"). |

---

## Supply-Chain Incidents (npm audit will never flag these)

These shipped malware through perfectly normal `npm install` runs. No CVE, no audit warning — the package was simply malicious for a window of time.

- **chalk / debug takeover (Sep 8, 2025)** — phishing took over a maintainer account; packages with ~2B combined weekly downloads shipped a crypto-clipper for a few hours. If you installed that day, your lockfile remembers.
- **Shai-Hulud worm + 2.0 (Sep + Nov–Dec 2025)** — self-replicating npm malware spreading via stolen publish tokens; 25,000+ repos affected across both waves. The worm published from *victims'* accounts, so "trusted maintainer" meant nothing.
- **postmark-mcp v1.0.16 (Sep 2025)** — one added line BCC'd every email through it to the attacker. ~300 orgs. Pulled after 8 days.
- **anthropic-toolkit (MAL-2026-6673)** — typosquat of `@anthropic-ai/sdk` with a postinstall payload. Check your package.json spelling of every AI SDK.
- **Slopsquatting (ongoing, 2026)** — [19.7% of packages AI assistants recommend don't exist](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks), and 43% of the hallucinated names recur predictably — so attackers register them. In July 2026 a Claude agent under evaluation [published working malware to live PyPI](https://socket.dev/blog/anthropic-claude-pypi-malware); it ran on 15 real systems within an hour. Verify every agent-suggested package exists and has history *before* install.

---

## What Your Scanner Actually Catches

| Tool | Known CVEs | Malicious packages | Note |
|---|---|---|---|
| `npm audit` / `pnpm audit` | yes | **no** | Only matches published advisories. The incidents above were invisible to it while live. |
| [OSV-Scanner](https://google.github.io/osv-scanner/) | yes | partial (OSV MAL-* records, after the fact) | `npx osv-scanner --lockfile=package-lock.json` |
| [Socket](https://socket.dev) | yes | **yes** (behavioral: postinstall scripts, network calls, obfuscation) | `npx socket npm install <pkg>` wraps installs |
| Replit Package Firewall | — | yes | Platform-side, blocks ~8,000 malicious packages/day (Jun 2026, built with Socket) |

Minimum viable setup: commit your lockfile, run `npm audit` + `osv-scanner` in CI, and set `npm config set ignore-scripts true` on dev machines (re-enable per-package only when a dependency genuinely needs its postinstall — most don't).

---

Rows I deliberately left out: several 2026 vector-DB and agent-framework CVEs circulating on secondary blogs (Qdrant, Chroma, LangGraph deserialization) could not be verified on NVD/GHSA at the time of writing. When they verify, they go in. Nothing lands on this page from a tweet.
