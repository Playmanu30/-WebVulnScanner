const { fetchPage, finding, dedupeFindings } = require('./utils');

const RISKY_METHODS = ['PUT', 'DELETE', 'PATCH', 'CONNECT', 'TRACE'];

class HTTPMethodAnalyzer {
  constructor() {
    this.name = 'HTTP Method Analyzer';
    this.description =
      'Inspects the advertised Allow header and tests whether the TRACE method is enabled.';
    this.version = '2.2.1';
    this.runsPerPage = false;
    this.pageLimit = 1;
  }

  async initialize() {
    console.log('[http-methods] ready');
  }

  async scan(url, options = {}) {
    const started = Date.now();
    const vulnerabilities = [];
    let allowed = null;

    try {
      const optionsResponse = await fetchPage(url, {
        method: 'OPTIONS',
        timeout: options.timeout || 10000,
        maxRedirects: 0
      });
      const header = optionsResponse.headers.allow || optionsResponse.headers.Allow;
      if (header) {
        allowed = String(header)
          .split(',')
          .map((method) => method.trim().toUpperCase())
          .filter(Boolean);
      }
    } catch {
      // OPTIONS is often blocked; that is fine, absence of a finding here
      // means "not advertised", not "not supported".
    }

    if (allowed && allowed.length > 0) {
      const risky = allowed.filter((method) => RISKY_METHODS.includes(method));

      if (risky.length > 0) {
        vulnerabilities.push(
          finding({
            type: 'HTTP Method Misconfiguration',
            severity: risky.includes('PUT') || risky.includes('DELETE') ? 'Medium' : 'Low',
            category: 'Risky Methods Advertised',
            description: `The server advertises ${risky.join(
              ', '
            )} for this resource. Write methods on a content endpoint usually mean an upload or edit path worth reviewing.`,
            evidence: `Allow: ${allowed.join(', ')}`,
            url,
            confidence: 0.6,
            recommendations: [
              'Advertise only the methods the endpoint actually implements.',
              'Require authentication and authorisation on PUT/PATCH/DELETE.',
              'Disable the TRACE method at the server level.'
            ],
            cwe: 'CWE-650',
            owasp: 'A05:2021 Security Misconfiguration'
          })
        );
      }

      if (allowed.includes('TRACE')) {
        const traceFinding = await this.confirmTrace(url, options);
        if (traceFinding) vulnerabilities.push(traceFinding);
      }
    }

    return {
      url,
      status: 'complete',
      scanner: this.name,
      vulnerabilities: dedupeFindings(vulnerabilities),
      details: {
        allow: allowed,
        note: allowed
          ? 'Only OPTIONS and TRACE requests were sent; no state-changing method was used.'
          : 'The server did not return an Allow header for OPTIONS.'
      },
      scanTime: Date.now() - started
    };
  }

  async confirmTrace(url, options) {
    try {
      const response = await fetchPage(url, {
        method: 'TRACE',
        timeout: options.timeout || 10000,
        maxRedirects: 0
      });
      const body = response.html || '';
      const echoesRequest = /TRACE\s+\/\S*\s+HTTP\/1\.[01]/i.test(body);

      if (response.status !== 200 || !echoesRequest) return null;

      return finding({
        type: 'HTTP Method Misconfiguration',
        severity: 'Medium',
        category: 'TRACE Method Enabled',
        description:
          'The TRACE method is enabled and echoes the request back. Combined with a scripting flaw, this enables Cross-Site Tracing to read headers that would otherwise be protected.',
        evidence: `TRACE ${new URL(url).pathname} -> HTTP 200, request line echoed in the body`,
        url,
        confidence: 0.9,
        recommendations: ['Disable TRACE (Apache: TraceEnable off; nginx: ignore TRACE in the server block).'],
        cwe: 'CWE-693',
        owasp: 'A05:2021 Security Misconfiguration'
      });
    } catch {
      return null;
    }
  }

  async scanMultiple(urls) {
    const results = [];
    for (const url of urls) results.push(await this.scan(url));
    return results;
  }
}

module.exports = { HTTPMethodAnalyzer };
