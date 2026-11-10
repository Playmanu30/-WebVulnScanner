const { loadList } = require('../core/config-loader');
const { finding } = require('./utils');

// Which headers we require, with the risk of leaving each one out.
const HEADER_SPEC = {
  'Content-Security-Policy': {
    severity: 'High',
    description:
      'No Content-Security-Policy header. Without CSP the browser has no restriction on which scripts may run, so an injected script is far more likely to execute.',
    recommendation: "Add a Content-Security-Policy such as default-src 'self'; object-src 'none'; base-uri 'self'."
  },
  'Strict-Transport-Security': {
    severity: 'Medium',
    description:
      'No Strict-Transport-Security header. Browsers will happily use plain HTTP for the first request, which opens the door to SSL-stripping.',
    recommendation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains (HTTPS only).'
  },
  'X-Frame-Options': {
    severity: 'Medium',
    description:
      'No X-Frame-Options header (and no frame-ancestors directive was found). The page can be embedded in an attacker-controlled iframe, enabling clickjacking.',
    recommendation: 'Add X-Frame-Options: SAMEORIGIN, or use CSP frame-ancestors \'self\'.'
  },
  'X-Content-Type-Options': {
    severity: 'Medium',
    description:
      'No X-Content-Type-Options: nosniff header. Browsers may MIME-sniff responses and execute content that is not actually JavaScript.',
    recommendation: 'Add X-Content-Type-Options: nosniff.'
  },
  'Referrer-Policy': {
    severity: 'Low',
    description:
      'No Referrer-Policy header. Full URLs may leak to third parties through the Referer header.',
    recommendation: 'Add Referrer-Policy: strict-origin-when-cross-origin.'
  },
  'Permissions-Policy': {
    severity: 'Low',
    description:
      'No Permissions-Policy header. Powerful browser features (camera, microphone, geolocation) are not explicitly restricted.',
    recommendation:
      'Add a Permissions-Policy such as geolocation=(), microphone=(), camera=().'
  }
};

const INFO_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator'];

class HeaderAnalyzer {
  constructor() {
    this.name = 'Header Analyzer';
    this.description =
      'Checks HTTP response headers for missing security controls and technology disclosure.';
    this.version = '2.2.1';
    this.requiredHeaders = [];
    this.configSource = 'defaults';
  }

  async initialize() {
    const { values, source } = loadList(
      'header-patterns.json',
      ['patterns'],
      Object.keys(HEADER_SPEC)
    );
    // Only keep names we have a check for; unknown names are ignored.
    this.requiredHeaders = values.filter((name) => HEADER_SPEC[name]);
    this.configSource = source;
    console.log(
      `[headers] ${this.requiredHeaders.length} required headers (config: ${this.configSource})`
    );
  }

  async scan(url, options = {}) {
    const started = Date.now();
    const page = options.page || (await require('./utils').fetchPage(url, options));
    const headers = page.headers || {};
    const lower = Object.fromEntries(
      Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value])
    );
    const vulnerabilities = [];

    for (const name of this.requiredHeaders) {
      const value = lower[name.toLowerCase()];
      const spec = HEADER_SPEC[name];

      if (!value) {
        vulnerabilities.push(
          finding({
            type: 'Header',
            severity: spec.severity,
            category: 'Missing Security Header',
            description: `${spec.description}`,
            evidence: `${name}: (absent)`,
            url,
            confidence: 0.95,
            recommendations: [spec.recommendation]
          })
        );
        continue;
      }

      if (name === 'X-Frame-Options' && !/sameorigin|deny/i.test(String(value))) {
        vulnerabilities.push(
          finding({
            type: 'Header',
            severity: 'Medium',
            category: 'Misconfigured Security Header',
            description: `X-Frame-Options has an unsafe value ("${value}"). It should be SAMEORIGIN or DENY.`,
            evidence: `X-Frame-Options: ${value}`,
            url,
            confidence: 0.9,
            recommendations: ["Set X-Frame-Options: SAMEORIGIN (or DENY)."]
          })
        );
      }

      if (name === 'X-Content-Type-Options' && !/nosniff/i.test(String(value))) {
        vulnerabilities.push(
          finding({
            type: 'Header',
            severity: 'Medium',
            category: 'Misconfigured Security Header',
            description: `X-Content-Type-Options is present but not "nosniff" ("${value}"), so MIME sniffing is still allowed.`,
            evidence: `X-Content-Type-Options: ${value}`,
            url,
            confidence: 0.9,
            recommendations: ['Set X-Content-Type-Options: nosniff.']
          })
        );
      }

      if (name === 'Content-Security-Policy' && /unsafe-inline|unsafe-eval/i.test(String(value))) {
        vulnerabilities.push(
          finding({
            type: 'Header',
            severity: 'Medium',
            category: 'Weak Content Security Policy',
            description:
              'The Content-Security-Policy allows unsafe-inline/unsafe-eval, which largely defeats its XSS protection.',
            evidence: `Content-Security-Policy: ${value}`,
            url,
            confidence: 0.85,
            recommendations: [
              'Remove unsafe-inline/unsafe-eval and use nonces or hashes for inline scripts.'
            ]
          })
        );
      }
    }

    // Technology disclosure is informational on its own, but helps an attacker.
    for (const name of INFO_HEADERS) {
      if (!lower[name]) continue;
      const onlyVersionLeak = name === 'server' && !/\d/.test(String(lower[name]));
      if (onlyVersionLeak) continue;

      vulnerabilities.push(
        finding({
          type: 'Information Disclosure',
          severity: 'Low',
          category: 'Technology Disclosure',
          description: `The ${name} header reveals the server stack${
            /\d/.test(String(lower[name])) ? ' and its version' : ''
          }, which helps an attacker pick exploits.`,
          evidence: `${name}: ${lower[name]}`,
          url,
          confidence: 0.8,
          recommendations: [
            'Remove or genericise technology headers (nginx: server_tokens off; Apache: ServerTokens Prod; Node/Express: app.disable("x-powered-by")).'
          ]
        })
      );
    }

    const missing = this.requiredHeaders.filter((name) => !lower[name.toLowerCase()]);

    return {
      url,
      status: 'complete',
      scanner: this.name,
      vulnerabilities,
      details: {
        statusCode: page.status,
        headerCount: Object.keys(headers).length,
        requiredHeaders: this.requiredHeaders,
        missingHeaders: missing
      },
      scanTime: Date.now() - started
    };
  }

  async scanMultiple(urls) {
    const results = [];
    for (const url of urls) {
      try {
        results.push(await this.scan(url));
      } catch (error) {
        results.push({ url, status: 'error', scanner: this.name, error: error.message });
      }
    }
    return results;
  }
}

module.exports = { HeaderAnalyzer };
