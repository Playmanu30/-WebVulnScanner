# Changelog

## 2.3.0 - aggressive mode fix

Fixes the initialization bug where `--aggressive` flag wasn't being passed to scanner initialization, causing scanners to load default configs instead of advanced patterns.

### Fixed

- **Scanner initialization with options.** The `scan()` method now re-initializes scanners with fresh options (including `{aggressive: true}`) even if they already exist, ensuring aggressive mode toggles work correctly.
- **CLI flag propagation.** `quick-scan.js` now passes both `{noReport}` and `{aggressive}` flags to `run()`, so the console shows **70** XSS patterns and **2** SQLi payloads (not 15/6).

### Changed

- **Version bumped:** 2.2.1 → 2.3.0
- **Aggressive mode verified:** Higher concurrency (8-12), deeper crawl (depth 5, max pages 50), more per-page probes (12 vs 4), and advanced WAF-bypass patterns for XSS/SQLi detection all work correctly.

## 2.2.1 - guardrail hardening

Turns the safety claims into enforced behaviour and tests them.

### Fixed

- **Request console scope.** The replay origin is recorded only after a scan
  completes, so a failed or cancelled attempt cannot authorise replay. Replay is
  refused while a scan is running, rejects URLs containing `user:pass@`, and
  stays `GET`/`HEAD`/`OPTIONS` only.
- **Blind probe budget.** The SQLi scanner now enforces its own two-page,
  three-payload budget, serialises blind probes so the concurrency pool cannot
  double the cost, caps each request timeout at 12 s, adds a 30 s per-page
  deadline, and skips timing analysis when the baseline itself is slower than
  6 s.
- **Credentials in target URLs are rejected.** Use the Basic-auth fields instead,
  so the secret can never be copied into `urlScanned`, evidence or a filename.
- **Report redaction.** `Authorization`, `Cookie`, `Set-Cookie`, API-key and
  bearer-style header values plus URL userinfo are replaced with `[redacted]` in
  descriptions, evidence, URLs, pages and recommendations across JSON, HTML and
  text reports.
- Verified end to end that a scan run with a cookie and `X-Api-Key` contains
  neither value in the result object or in any exported format.

## 2.2.0 - reach and validation release

Adds the capabilities that decide whether a scan sees the real application:
authentication, hidden endpoints, blind confirmation, manual replay and external
result import. Still detection-only: the request console is read-only and the
scanner never submits forms.

### Added

- **Authenticated scanning.** Cookie header, extra headers and Basic credentials
  are applied centrally in `fetchPage()`, scoped to the scanned origin.
  Redirects are followed by hand so credentials are never forwarded off-origin.
- **Attack-surface discovery.** The crawler seeds from `robots.txt`
  (`Sitemap:`/`Allow`/`Disallow`), `sitemap.xml`, five common OpenAPI/Swagger
  locations, and quoted endpoint strings inside same-origin JS bundles.
- **Request console.** Per-finding replay with an editable URL and headers, raw
  response view, and **Copy as curl**. Read-only (`GET`/`HEAD`/`OPTIONS`) and
  bound to the last scanned origin.
- **Blind time-based SQLi.** Opt-in MySQL/PostgreSQL/MSSQL delay probes, each
  repeated before a finding is raised, capped at two pages.
- **External finding import.** ZAP JSON reports, nuclei JSONL and plain JSON
  finding arrays are mapped onto the shared finding model, given playbooks and
  merged into the session/report.
- New IPC handlers `replay-request` and `import-findings`, exposed through the
  preload bridge.

### Changed

- `fetchPage()` now follows redirects manually and supports authenticated
  requests without leaking headers across origins.
- Result aggregate includes `authenticated`; reports show it in metadata.
- `start-scan` validates and length-caps auth input and enables blind mode.

## 2.1.0 - red-team recon release

Turns the single-page scanner into a crawled, evidence-first detection tool.
Still detection only: no exploitation, persistence, brute force, evasion or mass
scanning.

### Added

- **Same-origin crawler** (`src/core/crawler.js`): breadth-first, honours a page
  and depth budget, never submits a form. Redirects are followed manually so the
  redirecting URL keeps its own entry and stays probeable.
- **Five new scanners**: `SensitiveFileScanner` (16 signature-checked paths with
  secret redaction), `CORSAnalyzer` (reflected origin, `null` origin, credentials
  combination), `HTTPMethodAnalyzer` (advertised `Allow`, live `TRACE` echo),
  `OpenRedirectFinder` (canary `Location` confirmation) and `SSRFDetector`
  (out-of-band canary listener with per-probe tokens).
- **Per-scanner page ranking**: each probe scanner declares `pageInterest`, so
  SSRF probes the `url=` endpoint and traversal probes the download endpoint
  instead of whatever page happened to be crawled first.
- **Live finding stream** in the UI (`status: 'finding'` progress events) plus a
  crawled-pages panel and CWE/OWASP chips.
- **Scan profiles** (Quick/Standard/Deep) for crawl breadth, probe pages,
  concurrency and delay.
- **Global rate limit** in `fetchPage()` (default 40 ms) shared by all scanners.
- **Authorisation gate** enforced in `src/main.js` IPC (`options.authorized`
  must be `true`) and surfaced as a required checkbox in the UI.
- **CWE/OWASP metadata** (`TYPE_META`) propagated to findings, JSON/HTML reports
  and the UI.
- **Exploitation & validation playbooks** (`src/core/playbooks.js`): per-finding
  guides covering mechanism, numbered validation steps, impact and a fixed
  lab-safety boundary. Rendered in the expanded finding card, in exported JSON
  (`finding.playbook`) and as a collapsible section in HTML reports.

### Changed

- `ScannerEngine` rewritten: crawl -> task plan -> concurrency pool -> stream ->
  merge per scanner -> aggregate, with `pages`/`pagesScanned` in the result.
- The eleven probe scanners now discover parameters with
  `parametersToTest()`: parameters already on the page first, then a small
  wordlist (`src/core/params.js`).
- `fetchPage()` supports `method`, `body` and `redirect: false` for redirect and
  method checks.
- HTML report lists crawled-page count and each finding's CWE reference.

### Fixed

- Probe scanners previously ran only against the entry page because
  `runsPerPage` was missing; the engine now reports `13 scanners (7 per-page)`.
- XSS/SQLi/traversal tested their findings against `page.finalUrl`, which for a
  redirecting URL is the destination. They now use the probed URL.
- Open-redirect and SSRF scanner notes no longer claim a callback was attempted
  when redirects were deliberately not followed.

### Housekeeping

- Removed twelve stale design/status documents that predated the 2.0.0 repair
  pass and contradicted the current README. `README.md` and `CHANGELOG.md` are
  now the only docs.
- Removed the unused `src/scanners/index.js` barrel, which still exported only
  the original eight scanners.
- Dropped nine unused dependencies (`express`, `jsdom`, `dompurify`,
  `node-fetch`, `puppeteer-core`, `react-router-dom`, `socket.io-client`,
  `concurrently`, `css-loader`/`style-loader`) and pruned 227 packages.
- Webpack now bundles only `src/ui/renderer.jsx`. The Electron main process is
  no longer pulled into the browser bundle, which shrank from ~590 KB to
  ~162 KB.

## 2.0.0 - repair pass

This release fixes a set of defects that made the previous 2.0.0 build unable to
produce findings or talk to the UI.

### Fixed

- **Config files were parsed as objects, not arrays.** Eight scanners did
  `JSON.parse(...)` and iterated the whole `{ patterns: [...] , version }`
  object, which threw `x is not iterable`. Added `src/core/config-loader.js`,
  which resolves `config/` from the project root and unwraps `patterns`,
  `payloads` or `cipherSuites` (falling back to the first array-valued key).
- **Config paths were CWD-relative.** `process.env.VULN_CONFIG_PATH || 'config/...'`
  broke whenever Electron started from another directory. Paths now come from
  the project root; `VULN_CONFIG_DIR` overrides the directory.
- **Every scanner returned zero vulnerabilities.** All eight were rewritten
  around a shared `src/scanners/utils.js` and a consistent result contract.
  Removed the out-of-scope `response` reference in XSS and the invalid
  `action.toLowerCase().some(...)` call in the auth checker.
- **The UI was a mock.** The inline Babel app in `index.html` rendered
  hard-coded demo data and never called the backend. The UI now lives in
  `src/ui/renderer.jsx`, is bundled by webpack, and drives real scans through
  `window.scannerAPI`.
- **Channel name mismatch.** The main process emitted `scan-complete` while the
  renderer listened for something else. Both sides now use `scan-progress`.
- **Webpack emitted an empty bundle.** The entry pointed at a file that no
  longer held the app; it now points at `src/ui/renderer.jsx` via
  `HtmlWebpackPlugin`.
- **`ScannerEngine is not a constructor` in the main process.** `main.js`
  required the module namespace instead of destructuring `{ ScannerEngine }`.
- **Duplicate `src/main-process.js`.** Deleted, along with a stale
  `src/package.json` (its `main` field pointed at the deleted file) and an
  ad-hoc `src/test/debug-auth.js` scratch script.
- **Unsafe report output.** HTML reports interpolated target-derived strings
  directly. Everything is now escaped.

### Changed

- `config/ai-patterns.json` is no longer dead config. The analysis engine loads
  it, matches the patterns against the page and URL (regex first, literal
  substring fallback so entries like `?id=` work), and reports the result as
  `context.inputSurfaces` plus an "Attack Surface" insight. It never raises a
  finding and never changes the score.
- The engine fetches the target once and passes the shared page to every
  scanner, instead of eight identical requests.
- Progress events carry the scanner name, index, total and a percentage;
  `stop-scan` sets a cancel flag that is honoured between scanners.
- `ai/analysis-engine.js` is no longer heuristic guesswork: it is a documented,
  deterministic correlation layer with penalty weights
  `{Critical: 15, High: 8, Medium: 3, Low: 1}` and a `Low/Medium/High` risk level.
- Electron hardening: `contextIsolation: true`, `nodeIntegration: false`, a
  narrow `contextBridge` API, strict CSP, and navigation/window-open blocked in
  favour of opening real links in the system browser.
- React and `lucide-react` now load from `node_modules` instead of a public CDN.
- Reports support `json`, `html` and `text`, and the UI saves them through a
  native dialog.

### Security

- Destructive SQL payloads (`DROP`, `DELETE`, `SLEEP`, `WAITFOR DELAY`, …) are
  filtered out before any probe is sent; only quote-based probes remain.
- Traversal payloads aimed at Windows `SAM`/`SYSTEM` are filtered out; probes
  target readable proof files only.
- Probe volume is capped per scan.

### Removed

- `src/main-process.js`, `src/package.json`, `src/test/debug-auth.js`
- The inline demo app previously embedded in `src/ui/public/index.html`

### Verified

- CLI scan against a locally hosted deliberately-vulnerable page:
  19 findings (1 critical, 6 high, 6 medium, 6 low), score 13/100.
- End-to-end Electron run driven through the real UI: 8 scanner rows, 19 finding
  cards, 5 insights, 20 recommendations, no error banner.
- Report generation in all three formats; HTML escapes the injected XSS payload.
- Production webpack build completes without warnings.
