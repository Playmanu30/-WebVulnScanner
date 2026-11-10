const { XSSDetector } = require('../scanners/xss');
const { SQLInjectionDetector } = require('../scanners/sql-injection');
const { CSRFDetector } = require('../scanners/csrf');
const { AuthenticationChecker } = require('../scanners/authentication');
const { SSLTLSAnalyzer } = require('../scanners/ssl-tls');
const { DirectoryTraversalFinder } = require('../scanners/directory-traversal');
const { InformationDisclosureScanner } = require('../scanners/information-disclosure');
const { HeaderAnalyzer } = require('../scanners/headers');
const { SensitiveFileScanner } = require('../scanners/sensitive-files');
const { CORSAnalyzer } = require('../scanners/cors');
const { HTTPMethodAnalyzer } = require('../scanners/http-methods');
const { OpenRedirectFinder } = require('../scanners/open-redirect');
const { SSRFDetector } = require('../scanners/ssrf');
const { AIAnalysisEngine } = require('../ai/analysis-engine');
const { Crawler } = require('./crawler');
const { fetchPage, normalizeSeverity, setRequestDelay, setAuth, clearAuth } = require('../scanners/utils');

// Standard identifiers, filled in when a scanner did not set them itself.
const TYPE_META = {
  XSS: { cwe: 'CWE-79', owasp: 'A03:2021 Injection' },
  'SQL Injection': { cwe: 'CWE-89', owasp: 'A03:2021 Injection' },
  CSRF: { cwe: 'CWE-352', owasp: 'A01:2021 Broken Access Control' },
  'Directory Traversal': { cwe: 'CWE-22', owasp: 'A01:2021 Broken Access Control' },
  'Information Disclosure': { cwe: 'CWE-200', owasp: 'A01:2021 Broken Access Control' },
  Header: { cwe: 'CWE-693', owasp: 'A05:2021 Security Misconfiguration' },
  Authentication: { cwe: 'CWE-287', owasp: 'A07:2021 Identification and Authentication Failures' },
  'SSL/TLS': { cwe: 'CWE-319', owasp: 'A02:2021 Cryptographic Failures' },
  'Open Redirect': { cwe: 'CWE-601', owasp: 'A01:2021 Broken Access Control' },
  SSRF: { cwe: 'CWE-918', owasp: 'A10:2021 Server-Side Request Forgery' },
  'CORS Misconfiguration': { cwe: 'CWE-942', owasp: 'A05:2021 Security Misconfiguration' },
  'HTTP Method Misconfiguration': { cwe: 'CWE-650', owasp: 'A05:2021 Security Misconfiguration' },
  'Sensitive File Exposure': { cwe: 'CWE-538', owasp: 'A01:2021 Broken Access Control' }
};

const MAX_FINDINGS_PER_TYPE = 12;
const DEFAULT_CONCURRENCY = 3;

/** Run `handler` over `items` with a fixed number of workers. */
async function runPool(items, limit, handler) {
  const results = new Array(items.length);
  let cursor = 0;

  const worker = async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await handler(items[index], index);
    }
  };

  const workers = Array.from({ length: Math.min(limit, items.length) }, worker);
  await Promise.all(workers);
  return results;
}

/**
 * Where a page exposes input: its own query string, path segments, and the
 * fields of its forms. A page's *own* parameters are worth more than a form it
 * merely contains, because that is where the parameter actually takes effect.
 */
function pageSurface(page) {
  const urlNames = new Set();
  const pathTokens = new Set();
  try {
    const parsed = new URL(page.url);
    for (const [name] of parsed.searchParams) urlNames.add(name);
    for (const token of parsed.pathname.split(/[^a-z0-9]+/i)) {
      if (token) pathTokens.add(token);
    }
  } catch {
    // malformed URL; the html is still inspected below
  }

  const formNames = new Set();
  const inputRe = /<(?:input|select|textarea)[^>]*\bname\s*=\s*["']?([a-z0-9_.\-[\]]+)/gi;
  let match;
  while ((match = inputRe.exec(page.html || '')) !== null) formNames.add(match[1]);

  return {
    ownNames: [...urlNames, ...pathTokens],
    formNames: [...formNames]
  };
}

/**
 * Pages worth spending probe traffic on: parameterised first, then pages with
 * forms, then the entry point. `interest` is a scanner's regex for the names it
 * cares about (url, file, q, ...), so an SSRF probe lands on the page that
 * actually accepts a URL rather than the marketing home page.
 */
function selectProbePages(pages, limit, interest) {
  const scored = pages.map((page, index) => {
    let score = index === 0 ? 2 : 0;
    try {
      const parsed = new URL(page.url);
      if ([...parsed.searchParams].length > 0) score += 3;
    } catch {
      // malformed page URL, still scannable via its cached body
    }
    if (/<form/i.test(page.html || '')) score += 2;
    if (/<form[^>]*method\s*=\s*["']?post/i.test(page.html || '')) score += 1;
    if (/type\s*=\s*["']?password/i.test(page.html || '')) score += 2;
    if (/<(input|textarea|select)/i.test(page.html || '')) score += 1;
    if (/[?&][a-z0-9_]+=/i.test(page.url)) score += 1;

    if (interest) {
      const { ownNames, formNames } = pageSurface(page);
      if (ownNames.some((name) => interest.test(name))) score += 8;
      else if (formNames.some((name) => interest.test(name))) score += 3;
    }

    return { page, index, score };
  });

  return scored
    .sort((a, b) => b.score - a.score || a.index - b.index)
    .slice(0, Math.max(1, limit))
    .map((entry) => entry.page);
}

class ScannerEngine {
  constructor() {
    this.name = 'AI Web Vulnerability Scanner Engine';
    this.version = '2.2.1';
    this.scanners = [];
    this.aiEngine = new AIAnalysisEngine();
    this.crawler = new Crawler();
    this.onProgressCallback = null;
    this.cancelled = false;
    this.requestsSent = 0;
  }

  cancel() {
    this.cancelled = true;
  }

  async initialize() {
    this.scanners = [
      new HeaderAnalyzer(),
      new InformationDisclosureScanner(),
      new SensitiveFileScanner(),
      new CORSAnalyzer(),
      new HTTPMethodAnalyzer(),
      new SSLTLSAnalyzer(),
      new XSSDetector(),
      new SQLInjectionDetector(),
      new CSRFDetector(),
      new AuthenticationChecker(),
      new DirectoryTraversalFinder(),
      new OpenRedirectFinder(),
      new SSRFDetector()
    ];

    for (const scanner of this.scanners) {
      await scanner.initialize();
    }
    await this.aiEngine.initialize();
    console.log(
      `[engine] initialized with ${this.scanners.length} scanners ` +
        `(${this.scanners.filter((s) => s.runsPerPage).length} per-page)`
    );
    return this.scanners.length;
  }

  emit(progress) {
    if (typeof this.onProgressCallback !== 'function') return;
    try {
      this.onProgressCallback(progress);
    } catch (error) {
      console.error('[engine] progress callback failed:', error.message);
    }
  }

  async scan(url, options = {}) {
    if (this.scanners.length === 0) await this.initialize();

    this.cancelled = false;
    this.requestsSent = 0;

    // Per-scan budgets (blind probes, canaries) must not leak between runs.
    for (const scanner of this.scanners) {
      if (typeof scanner.beginScan !== 'function') continue;
      try {
        scanner.beginScan();
      } catch (error) {
        console.warn(`[engine] ${scanner.name} beginScan failed: ${error.message}`);
      }
    }

    const startedAt = Date.now();
    setRequestDelay(options.delayMs ?? 40);

    // Credentials apply to every scanner through fetchPage(), always scoped to
    // the target origin.
    const targetOrigin = new URL(url).origin;
    if (options.auth && (options.auth.cookies || Object.keys(options.auth.headers || {}).length > 0)) {
      setAuth({
        origin: targetOrigin,
        cookies: options.auth.cookies,
        headers: options.auth.headers
      });
    } else {
      clearAuth();
    }

    const maxPages = Number(options.maxPages) > 0 ? Number(options.maxPages) : 12;
    this.emit({ status: 'section', phase: 'crawl', url, percent: 0, scanner: 'Crawler' });

    let pages;
    try {
      pages = await this.crawler.crawl(url, {
        maxPages,
        maxDepth: options.depth ?? options.maxDepth ?? 2,
        timeout: options.timeout || 15000,
        isCancelled: () => this.cancelled,
        onPage: (page, index, total) => {
          this.requestsSent += 1;
          this.emit({
            status: 'section',
            phase: 'crawl',
            scanner: 'Crawler',
            url: page.url,
            index,
            total,
            percent: Math.min(10, Math.round((index / Math.max(total, 1)) * 10))
          });
        }
      });
    } catch (error) {
      throw new Error(`Could not reach ${url}: ${error.message}`);
    }

    const reachable = pages.filter((page) => page.status > 0);
    if (reachable.length === 0) {
      throw new Error(`Could not reach ${url}: ${pages[0]?.error || 'no response'}`);
    }

    const root = pages[0];
    if (root.status >= 400) {
      console.warn(`[engine] entry point returned HTTP ${root.status}; continuing with what loaded`);
    }

    const tasks = this.buildTasks(pages, options);
    const total = tasks.length;
    let completed = 0;
    const collected = [];

    this.emit({
      status: 'section',
      phase: 'scan',
      scanner: 'Discovery complete',
      url: root.url,
      pages: reachable.length,
      percent: 10
    });

    try {
      await runPool(tasks, Number(options.concurrency) > 0 ? Number(options.concurrency) : DEFAULT_CONCURRENCY, async (task) => {
        if (this.cancelled) return null;

        const { scanner, page } = task;
        // A redirecting URL is probed as-is: /go?next=... must keep its own
        // path and parameter, not the page it forwards to.
        const target = page.redirectTo ? page.url : page.finalUrl || page.url;

        this.emit({
          status: 'running',
          scanner: scanner.name,
          url: target,
          index: completed,
          total,
          percent: 10 + Math.round((completed / total) * 90)
        });

        let result;
        try {
          result = await scanner.scan(target, { ...options, page });
        } catch (error) {
          result = {
            url: target,
            status: 'error',
            scanner: scanner.name,
            vulnerabilities: [],
            error: error.message,
            scanTime: 0
          };
        }

        const enriched = {
          ...result,
          page: page.url,
          vulnerabilities: (result.vulnerabilities || []).map((item) => this.enrich(item))
        };
        collected.push(enriched);

        for (const item of enriched.vulnerabilities) {
          this.emit({
            status: 'finding',
            scanner: scanner.name,
            url: target,
            finding: item
          });
        }

        completed += 1;
        this.emit({
          status: 'complete',
          scanner: scanner.name,
          url: target,
          index: completed,
          total,
          percent: 10 + Math.round((completed / total) * 90),
          findings: enriched.vulnerabilities.length
        });

        return enriched;
      });
    } finally {
      await this.disposeScanners();
      clearAuth();
    }

    const merged = this.mergeResults(collected, root.url);
    const aiAnalysis = await this.aiEngine.analyze(root.url, root.html, merged);

    return this.aggregate(url, merged, aiAnalysis, {
      startedAt,
      statusCode: root.status,
      finalUrl: root.finalUrl,
      pages,
      authenticated: Boolean(options.auth && (options.auth.cookies || Object.keys(options.auth.headers || {}).length > 0)),
      errors: merged.filter((result) => result.status === 'error').map((result) => ({
        scanner: result.scanner,
        error: result.error
      }))
    });
  }

  /**
   * Global scanners run once against the entry point. Probe-heavy scanners run
   * against a handful of representative pages, capped by their own pageLimit.
   */
  buildTasks(pages, options) {
    const root = pages[0];
    const perPageLimit = Number(options.perPageLimit) > 0 ? Number(options.perPageLimit) : 4;
    const tasks = [];

    for (const scanner of this.scanners) {
      if (!scanner.runsPerPage) {
        tasks.push({ scanner, page: root });
        continue;
      }

      // Each probe scanner gets its own ranking, biased towards the parameters
      // it can actually act on.
      const ceiling = Math.max(1, perPageLimit);
      let wanted = Math.min(scanner.pageLimit ?? ceiling, ceiling);
      if (scanner.name === 'SQL Injection Detector' && options.blind === true) {
        // Time-based probes cost seconds each; two representative pages is the cap.
        wanted = Math.min(2, ceiling);
      }
      const pagesForScanner = selectProbePages(pages, wanted, scanner.pageInterest);

      for (const page of pagesForScanner) {
        tasks.push({ scanner, page });
      }
    }

    return tasks;
  }

  enrich(item) {
    const meta = TYPE_META[item.type] || {};
    return {
      cwe: null,
      owasp: null,
      ...meta,
      ...item,
      severity: normalizeSeverity(item.severity)
    };
  }

  /**
   * Collapse the per-page results into one result per scanner, so the UI and
   * reports show scanner-level counts instead of page-level duplicates.
   */
  mergeResults(results, rootUrl) {
    const byScanner = new Map();

    for (const result of results) {
      if (!byScanner.has(result.scanner)) {
        byScanner.set(result.scanner, {
          url: rootUrl,
          status: 'complete',
          scanner: result.scanner,
          vulnerabilities: [],
          details: {},
          pagesScanned: 0,
          errors: [],
          scanTime: 0
        });
      }

      const merged = byScanner.get(result.scanner);
      merged.scanTime += result.scanTime || 0;
      merged.pagesScanned += 1;

      if (result.status === 'error') {
        merged.errors.push(result.error);
        if (merged.pagesScanned === 1) merged.status = 'error';
        continue;
      }

      merged.status = 'complete';
      for (const item of result.vulnerabilities || []) {
        merged.vulnerabilities.push({ ...item, page: result.page });
      }
      if (Object.keys(merged.details || {}).length === 0 && result.details) {
        merged.details = result.details;
      }
    }

    for (const merged of byScanner.values()) {
      merged.vulnerabilities = this.dedupeAcrossPages(merged.vulnerabilities);
      if (merged.errors.length > 0 && merged.status === 'complete') {
        merged.details = { ...merged.details, pageErrors: merged.errors.slice(0, 3) };
      }
      delete merged.errors;
    }

    return [...byScanner.values()];
  }

  dedupeAcrossPages(findings) {
    const seen = new Set();
    const perType = new Map();
    const result = [];

    for (const item of findings) {
      // Description mentions the parameter/header but not the URL, so the same
      // flaw on ten pages collapses into one finding.
      const key = `${item.type}|${item.category}|${item.description}`;
      if (seen.has(key)) continue;

      const count = perType.get(item.type) || 0;
      if (count >= MAX_FINDINGS_PER_TYPE) continue;

      seen.add(key);
      perType.set(item.type, count + 1);
      result.push(item);
    }

    return result;
  }

  async disposeScanners() {
    for (const scanner of this.scanners) {
      if (typeof scanner.dispose !== 'function') continue;
      try {
        await scanner.dispose();
      } catch (error) {
        console.warn(`[engine] ${scanner.name} dispose failed: ${error.message}`);
      }
    }
  }

  async scanSingle(url, options = {}) {
    return this.scan(url, options);
  }

  async scanWithAI(url, options = {}) {
    return this.scan(url, options);
  }

  async scanMultiple(urls, options = {}) {
    const aggregated = [];
    for (const url of urls) {
      try {
        aggregated.push(await this.scan(url, options));
      } catch (error) {
        aggregated.push({ url, status: 'error', error: error.message, scannerResults: [] });
      }
    }

    return {
      urls,
      status: 'complete',
      totalScans: aggregated.reduce((sum, item) => sum + (item.scannerResults?.length || 0), 0),
      totalVulnerabilities: aggregated.reduce((sum, item) => sum + (item.totalVulnerabilities || 0), 0),
      severityBreakdown: {
        critical: aggregated.reduce((s, i) => s + (i.severityBreakdown?.critical || 0), 0),
        high: aggregated.reduce((s, i) => s + (i.severityBreakdown?.high || 0), 0),
        medium: aggregated.reduce((s, i) => s + (i.severityBreakdown?.medium || 0), 0),
        low: aggregated.reduce((s, i) => s + (i.severityBreakdown?.low || 0), 0)
      },
      results: aggregated
    };
  }

  aggregate(url, scannerResults, aiAnalysis, meta) {
    const breakdown = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    let totalVulnerabilities = 0;

    for (const result of scannerResults) {
      for (const item of result.vulnerabilities || []) {
        totalVulnerabilities += 1;
        const key = String(item.severity || 'medium').toLowerCase();
        if (breakdown[key] !== undefined) breakdown[key] += 1;
        else breakdown.low += 1;
      }
    }

    return {
      url,
      status: 'complete',
      scannerVersion: this.version,
      startedAt: new Date(meta.startedAt).toISOString(),
      scanTime: Date.now() - meta.startedAt,
      statusCode: meta.statusCode,
      finalUrl: meta.finalUrl,
      pagesScanned: meta.pages.length,
      authenticated: Boolean(meta.authenticated),
      pages: meta.pages.map((page) => ({
        url: page.url,
        status: page.status,
        depth: page.depth
      })),
      totalScans: scannerResults.filter((r) => r.status === 'complete').length,
      totalVulnerabilities,
      severityBreakdown: breakdown,
      scannerResults,
      aiAnalysis,
      recommendations: aiAnalysis.recommendations,
      errors: meta.errors
    };
  }
}

module.exports = { ScannerEngine, TYPE_META, runPool, selectProbePages };
