const { loadList } = require('../core/config-loader');
const { fetchPage, finding, dedupeFindings } = require('./utils');

// Targeted checks that produce far fewer false positives than the old
// "does the HTML contain the word database" approach.
const SOURCE_CHECKS = [
  {
    id: 'stack-trace',
    test: /(Traceback \(most recent call last\)|at [\w$.]+\([\w$.]+\.java:\d+\)|Unhandled Exception|Stack trace:)/,
    severity: 'Medium',
    description: 'A server-side stack trace or exception was rendered into the page.',
    recommendation: 'Render generic error pages and log stack traces server-side only.'
  },
  {
    id: 'sql-error',
    test: /(SQL syntax.*MySQL|Warning.*\bmysqli?_|PostgreSQL.*ERROR|SQLite3::|ORA-\d{5}|Microsoft OLE DB Provider)/i,
    severity: 'Medium',
    description: 'A database error message was rendered into the page.',
    recommendation: 'Disable detailed database errors in production responses.'
  },
  {
    id: 'source-map',
    test: /\/\/[#@]\s*sourceMappingURL=/,
    severity: 'Low',
    description: 'The page references JavaScript source maps, which can expose original source code.',
    recommendation: 'Do not publish .map files (or restrict them to internal networks).'
  },
  {
    id: 'secret-token',
    test: /(AIza[0-9A-Za-z_-]{35}|sk_live_[0-9A-Za-z]{16,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)/,
    severity: 'Critical',
    description: 'A hard-coded credential or private key pattern was found in the page source.',
    recommendation: 'Revoke the exposed key and move secrets to server-side configuration.'
  },
  {
    id: 'internal-ip',
    test: /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/,
    severity: 'Low',
    description: 'An internal IP address is exposed in the page source.',
    recommendation: 'Remove internal network details from client-facing content.'
  },
  {
    id: 'directory-listing',
    test: /<title>\s*Index of \/|<h1>\s*Index of \//i,
    severity: 'Medium',
    description: 'A directory listing page is publicly reachable.',
    recommendation: 'Disable directory auto-indexing on the web server.'
  },
  {
    id: 'debug-endpoint',
    test: /(\/_profiler\/|\/actuator\/env|\/actuator\/health|\/debug\/vars|\/phpinfo\.php)/,
    severity: 'Medium',
    description: 'A debugging or diagnostics endpoint is referenced by the page.',
    recommendation: 'Disable diagnostics endpoints in production or restrict them to trusted networks.'
  }
];

const CONFIG_SEVERITY = {
  'X-Powered-By:': 'Low',
  'X-AspNet-Version:': 'Low',
  'X-AspNetMvc-Version:': 'Low',
  'Traceback': 'Medium',
  'Stack Trace': 'Medium',
  'Exception:': 'Low'
};

class InformationDisclosureScanner {
  constructor() {
    this.name = 'Information Disclosure Scanner';
    this.description =
      'Looks for leaked stack traces, credentials, internal addresses, source maps and verbose headers.';
    this.version = '2.2.1';
    this.sensitivePatterns = [];
    this.configSource = 'defaults';
  }

  async initialize() {
    const { values, source } = loadList(
      'info-disclosure-patterns.json',
      ['patterns'],
      Object.keys(CONFIG_SEVERITY)
    );
    this.sensitivePatterns = values;
    this.configSource = source;
    console.log(
      `[info-disclosure] ${this.sensitivePatterns.length} patterns (config: ${this.configSource})`
    );
  }

  async scan(url, options = {}) {
    const started = Date.now();
    const page = options.page || (await fetchPage(url, options));
    const html = page.html || '';
    const vulnerabilities = [];

    for (const check of SOURCE_CHECKS) {
      const match = html.match(check.test);
      if (!match) continue;
      vulnerabilities.push(
        finding({
          type: 'Information Disclosure',
          severity: check.severity,
          category: check.id,
          description: check.description,
          evidence: this.redact(String(match[0])),
          url,
          confidence: 0.8,
          recommendations: [check.recommendation]
        })
      );
    }

    // Config patterns are literal strings; keep them as an extra safety net but
    // never let a bare word such as "database" raise a finding.
    for (const pattern of this.sensitivePatterns) {
      if (typeof pattern !== 'string' || pattern.length < 8) continue;
      if (!pattern.includes(':') && !pattern.includes('<') && !pattern.includes('\\')) continue;
      let regex;
      try {
        regex = new RegExp(pattern, 'i');
      } catch {
        continue;
      }
      const match = html.match(regex);
      if (!match) continue;
      const severity = CONFIG_SEVERITY[pattern] || 'Low';
      vulnerabilities.push(
        finding({
          type: 'Information Disclosure',
          severity,
          category: 'Configured Pattern',
          description: `Configured disclosure pattern matched: ${pattern}`,
          evidence: this.redact(String(match[0]).slice(0, 160)),
          url,
          confidence: 0.6,
          recommendations: ['Remove the disclosed value from the response.']
        })
      );
    }

    const configMatches = vulnerabilities.filter((v) => v.category === 'Configured Pattern').length;

    return {
      url,
      status: 'complete',
      scanner: this.name,
      vulnerabilities: dedupeFindings(vulnerabilities),
      details: {
        statusCode: page.status,
        htmlLength: html.length,
        configMatches
      },
      scanTime: Date.now() - started
    };
  }

  redact(value) {
    // Keep evidence useful without copying whole secrets into the report.
    return value.length > 120 ? `${value.slice(0, 117)}...` : value;
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

module.exports = { InformationDisclosureScanner };
