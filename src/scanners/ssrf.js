const http = require('http');
const {
  fetchPage,
  finding,
  collectParameters,
  guessParameters,
  setParameter,
  getLanAddress,
  sleep,
  dedupeFindings
} = require('./utils');
const { URL_PARAMS } = require('../core/params');

const URLISH = /(url|uri|link|src|source|dest|destination|target|host|site|domain|feed|callback|webhook|image|img|fetch|load|proxy|api|endpoint|redirect|return|next|request)/i;

/**
 * Server-side request forgery, confirmed out-of-band.
 *
 * A short-lived HTTP listener is opened on the LAN interface. The scanner then
 * asks the target to fetch a unique token URL on that listener. A callback is
 * proof that the server made the request on our behalf; without one the
 * parameter is only reported as unconfirmed in the scan details.
 */
class SSRFDetector {
  constructor() {
    this.name = 'SSRF Detector';
    this.description =
      'Points URL-like parameters at a local canary listener and confirms SSRF from the inbound callback.';
    this.version = '2.2.1';
    this.runsPerPage = true;
    this.pageLimit = 2;
    this.pageInterest = /^(url|uri|link|src|source|dest|destination|target|host|site|domain|feed|callback|webhook|image|img|imageurl|fetch|load|proxy|api|endpoint|redirect|return|next|request)$/i;
    this.host = null;
    this.canary = null;
    this.hits = new Map();
  }

  async initialize() {
    this.host = getLanAddress();
    console.log(
      this.host
        ? `[ssrf] canary will use ${this.host}`
        : '[ssrf] no LAN address found; out-of-band confirmation disabled'
    );
  }

  async ensureCanary() {
    if (this.canary) return this.canary;
    if (!this.host) return null;

    const server = http.createServer((req, res) => {
      const token = String(req.url || '').split('/').filter(Boolean)[0];
      if (token) this.hits.set(token, Date.now());
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
    });

    try {
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '0.0.0.0', resolve);
      });
    } catch (error) {
      console.warn(`[ssrf] could not start canary listener: ${error.message}`);
      return null;
    }

    this.canary = { server, port: server.address().port };
    console.log(`[ssrf] canary listening on ${this.host}:${this.canary.port}`);
    return this.canary;
  }

  async scan(url, options = {}) {
    const started = Date.now();
    const page = options.page || (await fetchPage(url, options));
    const html = page.html || '';
    const baseUrl = url;

    const found = collectParameters(baseUrl, html, 8);
    const existing = found.filter((param) => URLISH.test(param.name));
    const guessed = guessParameters(
      baseUrl,
      found.map((param) => param.name),
      URL_PARAMS,
      6
    );
    const candidates = [...existing, ...guessed].slice(0, 6);

    if (candidates.length === 0) {
      return {
        url,
        status: 'complete',
        scanner: this.name,
        vulnerabilities: [],
        details: { note: 'No URL-like parameter was found or guessable.' },
        scanTime: Date.now() - started
      };
    }

    const canary = await this.ensureCanary();
    if (!canary) {
      return {
        url,
        status: 'complete',
        scanner: this.name,
        vulnerabilities: [],
        details: {
          parametersTested: candidates.map((param) => param.name),
          note:
            'Out-of-band confirmation needs a LAN address for the target to call back to. None was available, so no SSRF probe was sent.'
        },
        scanTime: Date.now() - started
      };
    }

    const probes = [];
    for (const param of candidates) {
      const token = `ssrf${Math.random().toString(36).slice(2, 10)}`;
      const payload = `http://${this.host}:${canary.port}/${token}`;
      const target = setParameter(baseUrl, param.name, payload);
      probes.push({ parameter: param.name, token, target, payload });

      try {
        await fetchPage(target, { timeout: options.timeout || 8000, maxRedirects: 0 });
      } catch {
        // A failing probe does not rule out SSRF: the server may fetch the URL
        // after responding, or drop the connection.
      }
    }

    // Give the target a moment to make the callback, then check the canary.
    const deadline = Date.now() + 3000;
    while (Date.now() < deadline) {
      if (probes.every((probe) => this.hits.has(probe.token))) break;
      await sleep(200);
    }

    const vulnerabilities = [];
    for (const probe of probes) {
      if (!this.hits.has(probe.token)) continue;
      vulnerabilities.push(
        finding({
          type: 'SSRF',
          severity: 'High',
          category: 'Server-Side Request Forgery',
          description: `Parameter "${probe.parameter}" made the server issue a request to ${this.host}:${canary.port}, which we control. With internal reachability this can be used to hit cloud metadata endpoints and internal services.`,
          evidence: `GET ${probe.target}\n-> canary received a callback for token ${probe.token} at ${new Date(
            this.hits.get(probe.token)
          ).toISOString()}`,
          url: probe.target,
          confidence: 0.95,
          recommendations: [
            'Validate user-supplied URLs against an allowlist of schemes and hosts.',
            'Block requests to private, link-local and metadata address ranges.',
            'Route outbound fetches through an egress proxy that resolves DNS itself.'
          ],
          cwe: 'CWE-918',
          owasp: 'A10:2021 Server-Side Request Forgery'
        })
      );
    }

    return {
      url,
      status: 'complete',
      scanner: this.name,
      vulnerabilities: dedupeFindings(vulnerabilities),
      details: {
        parametersTested: probes.map((probe) => probe.parameter),
        canary: `${this.host}:${canary.port}`,
        callbacksReceived: vulnerabilities.length,
        note:
          vulnerabilities.length > 0
            ? 'Confirmed by out-of-band callback. Every payload used a unique token.'
            : 'No callback arrived within 3 seconds. The target may block outbound requests, or the parameter may not be fetchable.'
      },
      scanTime: Date.now() - started
    };
  }

  async dispose() {
    if (!this.canary) return;
    const { server } = this.canary;
    this.canary = null;
    try {
      await new Promise((resolve) => server.close(resolve));
      console.log('[ssrf] canary listener closed');
    } catch {
      // already closed
    }
  }

  async scanMultiple(urls) {
    const results = [];
    for (const url of urls) results.push(await this.scan(url));
    return results;
  }
}

module.exports = { SSRFDetector };
