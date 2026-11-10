# AI Web Vulnerability Scanner

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org)
[![Electron](https://img.shields.io/badge/electron-45-47848F.svg)](https://www.electronjs.org)
[![Platform](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey.svg)](#requirements)
[![Version](https://img.shields.io/badge/version-2.2.1-blue.svg)](CHANGELOG.md)

An authorised red-team **reconnaissance and detection** desktop tool built with
Electron and React. It crawls one origin, ranks the pages that expose the most
input surface, and validates findings with proof-of-concept evidence rather than
just pattern-matching a single page.

> **Authorised use only.** Scans send crafted requests to the target (quote
> characters, a benign XSS marker, traversal sequences, canary URLs). Only run
> this against systems you own or have written permission to test. The desktop
> app refuses to start a scan until the authorisation checkbox is ticked, and the
> main process re-checks that flag before touching the network.
>
> **Detection, not exploitation.** No exploitation, no persistence, no brute
> force, no evasion, no mass scanning. Probes are read-only and stop at proof.

## Contents

- [What it actually does](#what-it-actually-does)
- [Scanner modules](#scanner-modules)
- [Scan profiles](#scan-profiles)
- [Safety limits](#safety-limits)
- [Requirements](#requirements)
- [Setup](#setup)
- [CLI example](#cli-example)
- [The desktop UI](#the-desktop-ui)
- [Exploitation & validation playbooks](#exploitation--validation-playbooks)
- [Authenticated scanning](#authenticated-scanning)
- [Attack-surface discovery](#attack-surface-discovery)
- [Request console](#request-console)
- [Blind detection](#blind-detection)
- [Importing external findings](#importing-external-findings)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Analysis engine](#analysis-engine)
- [Reports](#reports)
- [Limitations](#limitations)
- [License](#license)

## What it actually does

1. **Crawls** the target's own origin (breadth-first, same-host only, forms are
   never submitted). Redirecting links keep their own entry, so
   `/go?next=...` stays visible to the redirect check instead of disappearing
   into the page it forwards to.
2. **Expands the attack surface** before probing: `robots.txt`, `sitemap.xml`,
   OpenAPI/Swagger documents and endpoint strings inside same-origin JavaScript
   bundles are added as crawl seeds.
3. **Scans authenticated areas** when you supply a cookie, extra headers or Basic
   credentials. Credentials are attached only to the target origin, and a
   redirect that leaves it is not followed.
4. **Ranks pages per scanner.** Each probe scanner declares which parameter
   names it cares about (`url`, `file`, `q`, `next`, ...), so SSRF lands on the
   page with a `url=` parameter and traversal lands on the download endpoint.
5. **Runs every scanner through a small concurrency pool**, streaming findings to
   the UI as they are confirmed.
6. **Merges per scanner** so the counts in the UI and the report are honest, and
   deduplicates the same flaw found on ten pages into one finding.

### Scanner modules

| Scanner | What it checks |
| --- | --- |
| `Header Analyzer` | Missing/misconfigured `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`; technology headers |
| `Information Disclosure Scanner` | Stack traces, database errors, source-map references, hard-coded credentials, internal IPs, directory listings, debug endpoints, plus config-supplied patterns |
| `Sensitive File Scanner` | 16 signature-checked paths: `.env`, `.git/config`, `.git/HEAD`, `.svn/entries`, `.aws/credentials`, `.htaccess`, `web.config`, `docker-compose.yml`, `phpinfo.php`, `server-status`, `actuator/env`, `debug/vars`, `.DS_Store`, `config.php.bak`, ... A `200` alone is not a finding — the body must match a content signature, and secret values are redacted in the evidence |
| `CORS Analyzer` | Reflects an arbitrary `Origin`, trusts the literal `null` origin, and whether `Access-Control-Allow-Credentials: true` is combined with it |
| `HTTP Method Analyzer` | Advertised `Allow` header (`PUT`/`DELETE`/`PATCH`/`CONNECT`/`TRACE`) and a live `TRACE` echo confirmation |
| `SSL/TLS Analyzer` | Live TLS handshake: protocol version, cipher strength, certificate expiry/validation, HTTPS enforcement |
| `XSS Detector` | Reflected XSS on discovered and guessed parameters, plus `javascript:` URIs, risky DOM sinks and inline handlers |
| `SQL Injection Detector` | Error-based SQLi using non-destructive quote probes; optional time-based blind confirmation (three capped delay payloads, each repeated) |
| `CSRF Detector` | State-changing POST forms without a visible anti-CSRF token; session cookies without `SameSite` |
| `Authentication Checker` | Credentials over cleartext, login page on HTTP, missing cookie flags, session ID in URL, HTTP Basic auth, missing autocomplete hints |
| `Directory Traversal Finder` | Read-only traversal payloads on file-like parameters, confirming out-of-root file signatures such as `/etc/passwd` |
| `Open Redirect Finder` | Injects an off-site canary URL into redirect-like parameters and confirms a `30x` whose `Location` points at the canary |
| `SSRF Detector` | Opens a short-lived canary listener on the LAN interface, points `url=`/`fetch=`-style parameters at it, and confirms SSRF only when the unique token calls back |

Every finding carries a CWE and OWASP Top 10 reference, added centrally in
`TYPE_META` so scanners cannot drift apart.

### Scan profiles

| Profile | Pages crawled | Probe pages per scanner | Concurrency | Delay |
| --- | --- | --- | --- | --- |
| Quick | 6 | 2 | 3 | 60 ms |
| Standard | 12 | 4 | 3 | 40 ms |
| Deep | 30 | 8 | 4 | 25 ms |

### Safety limits

- **Authorisation gate.** `start-scan` in the main process rejects any request
  whose `options.authorized` is not `true`, independently of the renderer.
- **Same-origin crawl.** Links are filtered to the entry origin; subdomains and
  third-party hosts are never scanned.
- **Global rate limit.** Every request in the process goes through
  `fetchPage()`'s throttle (default 40 ms), so all thirteen scanners share one
  politeness budget.
- **Per-scanner caps.** Probe-heavy scanners declare `pageLimit`; the engine caps
  findings per type at 12 and parameters per page at 4–6.
- **Destructive payloads are removed.** SQL payloads matching
  `DROP`/`DELETE`/`TRUNCATE`/`INSERT`/`UPDATE`/`WAITFOR DELAY`/`SLEEP()`/
  `BENCHMARK()` are filtered at load time, and traversal payloads targeting
  Windows `SAM`/`SYSTEM` are never sent.
- **No form submission.** Forms are parsed for tokens and parameters only; the
  scanner never POSTs them.
- **Credential scoping.** Authentication is applied inside `fetchPage()` only when
  the request origin equals the scanned origin. Redirects crossing that boundary
  are stopped, so cookies and `Authorization` headers cannot leak to a third
  party.
- **No credentials in URLs.** A target like `http://user:pass@host/` is rejected
  with a pointer to the auth fields, so the secret can never reach `urlScanned`,
  evidence or a report filename.
- **Report redaction.** Header values for `Authorization`, `Cookie`,
  `Set-Cookie`, API keys and bearer tokens, plus URL userinfo, are replaced with
  `[redacted]` in JSON, HTML and text reports as a last line of defence.
- **Read-only request console.** Manual replay accepts `GET`, `HEAD` and
  `OPTIONS` only, is refused while a scan is running, and only targets the origin
  of the last *completed* scan.
- **Blind probes are capped.** Time-based SQLi runs on at most two pages with
  three payloads each, is serialised across worker threads, has a 30 s per-page
  deadline, skips servers whose baseline exceeds 6 s, and requires the delay to
  reproduce twice.

## Requirements

- Node.js 18 or newer (developed on Node 26 / Electron 45)
- Windows, macOS or Linux — the app is Electron, no external browser needed

## Setup

```powershell
git clone https://github.com/Playmanu30/-WebVulnScanner.git
cd '-WebVulnScanner'
npm install
npm run build      # bundles the React UI into dist/
npm start          # launches the Electron app
```

The repository deliberately ignores `node_modules/` and `dist/`, so the build
step is required after cloning. `npm start` loads `dist/index.html`; `npm run
dev` builds in development mode and launches in one step.

### Project scripts

| Script | Purpose |
| --- | --- |
| `npm start` | Launch the Electron desktop app from `dist/` |
| `npm run build` | Production webpack build (`dist/`, content-hashed bundle) |
| `npm run build:dev` | Development build with source maps |
| `npm run dev` | Development build, then launch Electron |
| `npm run scan:test -- <url>` | Headless CLI scan; writes JSON + HTML reports to the project root |
| `npm run scan:test -- <url> --no-report` | CLI scan without writing report files |
| `npm run check` | `node --check` over every `.js` module under `src/` |

The CLI is intentionally *not* gated by the authorisation checkbox — it is a
developer/automation tool. The Electron IPC path is gated.

## CLI example

```powershell
npm run scan:test -- http://127.0.0.1:8099/ --no-report
```

Against a local deliberately-vulnerable test server this finds 27 issues across
all thirteen scanners, including `.env` exposure, reflected XSS, error-based
SQLi, path traversal, open redirect, CORS origin reflection and an SSRF
confirmed by canary callback. (The vulnerable server is not bundled — point the
CLI at a target you are authorised to test.)

```
=== Scan Complete ===
HTTP status       : 200
Scanners completed: 13/13
Findings          : 27
  - critical: 2
  - high    : 10
  - medium  : 9
  - low     : 6
Security score    : 0/100 (risk: High)
```

## The desktop UI

- Sidebar lists all thirteen scanners with a live per-scanner finding count and
  active/error state.
- An authorisation checkbox gates the **Start scan** button; a profile selector
  chooses how far to crawl.
- **Authenticated scan** panel: cookie header, extra headers, Basic auth, and the
  opt-in blind-SQLi switch.
- A progress bar reports the crawl phase and the current scanner.
- **Live findings** stream in as each probe is confirmed.
- **Crawled pages** are listed with status and depth.
- Findings are sorted by severity; each card expands to show raw evidence, the
  probed URL, CWE/OWASP chips, the exploitation/validation playbook and the
  remediation list.
- Each finding has **Request console** (read-only replay with editable headers)
  and **Copy as curl**.
- **Import ZAP/nuclei** merges external results into the current session.
- **Export JSON** / **Export HTML** open a native save dialog; reports include
  `pagesScanned`, authentication state, CWE/OWASP, playbooks and the finding's
  source page.

The renderer is fully sandboxed: `contextIsolation: true`, `nodeIntegration:
false`, and a preload bridge (`window.scannerAPI`) exposes only
`startScan`, `stopScan`, `getScanners`, `exportReport`, `replayRequest`,
`importFindings`, `appInfo` and `onProgress`. The page ships a strict CSP.

## Exploitation & validation playbooks

Every finding card has an **Exploitation & validation guide**. It explains how
the flaw actually works, how to reproduce it and how to prove impact, tailored to
the finding type (XSS, SQLi, CSRF, traversal, SSRF, open redirect, CORS, HTTP
methods, exposed files, headers, auth, TLS, info disclosure).

Each guide follows the same shape:

1. **Summary** — the mechanism in one or two sentences.
2. **Numbered steps** — what to send, what to observe, and which response proves
   the flaw (for example: the marker reflected unencoded, the `302` `Location`
   header, the canary callback, the boolean true/false difference).
3. **Impact** — what an attacker gains, so the finding can be prioritised.
4. **Boundary block** — the same rule everywhere: stop at proof.

The guides are deliberately constrained:

- read-only probes; no data dumping, no writes, no file uploads
- no credential use or reuse, no brute force or credential stuffing
- no persistence, no evasion, no payload obfuscation
- no cloud-metadata requests (SSRF stops at a canary you control)
- no action against real users or third-party systems

Guides are available in the expanded finding card in the desktop UI and in the
exported JSON (`finding.playbook`) and HTML reports (collapsible section). They
are defined once in `src/core/playbooks.js`, with a `Default` guide for any new
finding type.

## Authenticated scanning

Open **Authenticated scan & blind detection** under the authorisation gate and
supply any of:

- **Cookie header** — e.g. `session=abc123; csrftoken=...`
- **Extra headers** — one `Name: value` per line (`X-Api-Key`, `X-Environment`, ...)
- **Username / password** — converted to a Basic `Authorization` header

The engine calls `setAuth()` once and every scanner inherits it. The origin is
recorded at scan start; headers are attached only to requests for that origin.
Redirect handling is manual, so a `302` to another host stops the chain instead
of forwarding credentials. Credentials live in memory only and are never written
to a report.

This is what makes authenticated coverage real: the crawler, probe scanners,
CSRF checker and request console all see the logged-in navigation instead of the
login page.

## Attack-surface discovery

Before the breadth-first crawl, the engine seeds the queue from:

- `robots.txt` — `Sitemap:` references and `Allow`/`Disallow` paths;
- `sitemap.xml` — `<loc>` entries (sitemap indexes included);
- OpenAPI/Swagger — `/openapi.json`, `/swagger.json`, `/api-docs/swagger.json`,
  `/v3/api-docs`, `/api/openapi.json`; every documented path is added (templated
  `{id}` segments become `1`);
- JavaScript bundles — quoted path strings such as `"/api/orders"` found in
  same-origin `<script src>` files.

All seeds stay same-origin and count against the normal page budget, so a Quick
scan does not silently turn into a broad crawl.

## Request console

Every finding with a URL has **Request console** and **Copy as curl** buttons.

The console replays the finding's request with an editable URL and extra headers,
and shows the raw status, response headers and body. It is intentionally
read-only — `GET`, `HEAD` and `OPTIONS` only — and the main process rejects any
URL outside the last scanned origin. Auth headers from the scan are added
automatically, so you can test what the authenticated session actually returns.

## Blind detection

**Blind time-based SQLi** (opt-in) sends three non-destructive delay payloads
(MySQL `SLEEP`, PostgreSQL `pg_sleep`, MSSQL `WAITFOR`) against one parameter and
requires the delay to reproduce twice before reporting. It is capped at two pages
per scan, so the cost is predictable. Nothing is read or written; a confirmed
timing difference is the whole proof.

## Importing external findings

**Import ZAP/nuclei** reads exported results and merges them into the current
session, so one report can show built-in and external engines together:

- ZAP JSON reports (`site[].alerts[]`)
- nuclei JSONL (`-jsonl` output)
- a plain JSON `{ "findings": [...] }` array

Imported findings are mapped onto the same finding model (severity, CWE, OWASP,
type), get the matching playbook, and are exported with the rest of the scan.
Import only — the app never executes the external tool, so template choice and
scope stay with the operator.

## Architecture

```
src/
├── main.js                    Electron main process, IPC + authorisation gate
├── preload.js                 contextBridge -> window.scannerAPI
├── core/
│   ├── scanner-engine.js      crawl -> task plan -> pool -> stream -> merge
│   ├── crawler.js             same-origin BFS, discovery seeds, manual redirects
│   ├── params.js              parameter wordlists (common/redirect/url/file)
│   ├── playbooks.js           lab-safe exploitation & validation guides
│   ├── importers.js           ZAP / nuclei / JSON finding import
│   ├── config-loader.js       resolves config/ from the project root
│   └── report-generator.js    JSON / HTML / text output with HTML escaping
├── scanners/
│   ├── utils.js               fetchPage, throttle, finding(), parameter helpers
│   ├── headers.js
│   ├── information-disclosure.js
│   ├── sensitive-files.js
│   ├── cors.js
│   ├── http-methods.js
│   ├── ssl-tls.js
│   ├── xss.js
│   ├── sql-injection.js
│   ├── csrf.js
│   ├── authentication.js
│   ├── directory-traversal.js
│   ├── open-redirect.js
│   └── ssrf.js
├── ai/
│   └── analysis-engine.js     deterministic scoring + correlation (no model calls)
├── ui/
│   ├── renderer.jsx           the whole React app
│   └── public/index.html      HTML template + CSS + CSP meta
└── test/
    ├── quick-scan.js          CLI wrapper
    └── check-syntax.js        `npm run check`
```

### Result contract

Every scanner returns the same shape:

```js
{
  url, status: 'complete' | 'error', scanner,
  vulnerabilities: [{
    type, severity, category, description,
    evidence, url, confidence, recommendations: [],
    cwe, owasp
  }],
  details: { /* scanner-specific facts */ },
  scanTime
}
```

Scanners that should run more than once per scan set `runsPerPage = true` and a
`pageLimit`; the rest run once against the entry point. The engine adds
`pagesScanned`, `severityBreakdown`, `statusCode`, `finalUrl`, `errors` and the
`aiAnalysis` block.

## Configuration

Patterns live in `config/*.json`. Files are resolved relative to the project
root, never the current working directory, so launching Electron from another
folder still works. Change the location with `VULN_CONFIG_DIR`.

Each file wraps its list in a key — `patterns`, `payloads` or `cipherSuites` —
and the loader unwraps it automatically. Missing or malformed files fall back to
built-in defaults with a console warning instead of throwing.

| File | Key | Used by |
| --- | --- | --- |
| `header-patterns.json` | `patterns` | Header Analyzer |
| `info-disclosure-patterns.json` | `patterns` | Information Disclosure |
| `xss-patterns.json` | `patterns` | XSS Detector |
| `sql-patterns.json` | `payloads` | SQL Injection Detector |
| `csrf-patterns.json` | `patterns` | CSRF Detector |
| `auth-patterns.json` | `patterns` | Authentication Checker |
| `ssl-patterns.json` | `cipherSuites` | SSL/TLS Analyzer |
| `traversal-patterns.json` | `payloads` | Directory Traversal Finder |
| `ai-patterns.json` | `patterns` | Analysis engine — marks input surfaces (forms, embeds, common query parameters) for its context block and "Attack Surface" insight. Never raises a finding on its own. |

## Analysis engine

No external model is called. The engine is a deterministic correlation layer:

1. Collects every finding from every scanner.
2. Applies a penalty per severity (Critical 15, High 8, Medium 3, Low 1) to
   produce a 0–100 score and a Low/Medium/High risk level.
3. Cross-references findings against page structure (forms, password fields,
   inline handlers, external scripts, iframes, inline scripts).
4. Matches the configured `ai-patterns.json` surface patterns (regex or literal)
   to report which input surfaces exist, without turning them into findings.
5. Emits plain-language insights and a severity-sorted recommendation list.

## Reports

`ReportGenerator` accepts the aggregate result and produces `json`, `html` or
`text`. All target-derived text is HTML-escaped, so a reflected payload can never
break out of the report markup.

Every finding includes severity, confidence, evidence, CWE/OWASP references, the
source page, remediation steps and the matching playbook. The metadata records
the crawled-page count and whether the scan was authenticated. Before writing,
`redactSecrets()` replaces credential headers and URL userinfo with
`[redacted]`, so an exported report is safe to share.

## Limitations

- **One origin only.** No subdomain or third-party scanning; links outside the
  entry origin are ignored by design.
- **Session import, not login automation.** You supply a cookie/header or Basic
  credentials; the scanner does not fill or submit login forms. That keeps the
  "no form submission" rule intact.
- **No JavaScript execution.** The crawler parses server-rendered HTML and static
  JS bundle strings, so routes that only exist after client-side rendering can
  still be missed.
- **Heuristics, not guarantee.** XSS and SQLi are confirmed from reflected
  markers, database errors or timing; a clean report does not prove the target
  is secure.
- **Blind SQLi is opt-in and slow.** It costs a few seconds per probed page and
  is limited to two pages per scan.
- **Out-of-band SSRF needs a reachable LAN interface.** When no non-internal
  IPv4 address exists, the SSRF probe is skipped and says so in its details
  instead of guessing.

## License

MIT © 2026 Playmanu30. See [LICENSE](LICENSE).
