const { fetchPage, finding, dedupeFindings } = require('./utils');

const EVIL_ORIGIN = 'https://vlnsx7.example';

class CORSAnalyzer {
  constructor() {
    this.name = 'CORS Analyzer';
    this.description =
      'Checks whether the server reflects arbitrary Origin headers or allows credentials to any origin.';
    this.version = '2.2.1';
    this.runsPerPage = false;
    this.pageLimit = 1;
  }

  async initialize() {
    console.log('[cors] ready');
  }

  async scan(url, options = {}) {
    const started = Date.now();
    const vulnerabilities = [];
    const observations = [];

    const probes = [
      { origin: EVIL_ORIGIN, label: 'arbitrary origin' },
      { origin: 'null', label: 'null origin (sandboxed iframe / data: URL)' }
    ];

    for (const probe of probes) {
      let response;
      try {
        response = await fetchPage(url, {
          timeout: options.timeout || 10000,
          headers: { Origin: probe.origin }
        });
      } catch {
        continue;
      }

      const allowOrigin = response.headers['access-control-allow-origin'];
      const allowCredentials = String(response.headers['access-control-allow-credentials'] || '')
        .toLowerCase() === 'true';

      observations.push({
        origin: probe.origin,
        allowOrigin: allowOrigin || null,
        allowCredentials
      });

      if (!allowOrigin) continue;

      const reflected = allowOrigin === probe.origin;

      if (reflected) {
        vulnerabilities.push(
          finding({
            type: 'CORS Misconfiguration',
            severity: allowCredentials ? 'High' : 'Medium',
            category: reflected && probe.origin === 'null' ? 'Null Origin Trusted' : 'Arbitrary Origin Reflected',
            description: allowCredentials
              ? `The server reflects the ${probe.label} in Access-Control-Allow-Origin and also allows credentials. Any website can read authenticated responses from this endpoint.`
              : `The server reflects the ${probe.label} in Access-Control-Allow-Origin, so any site can read responses from this endpoint.`,
            evidence: `Origin: ${probe.origin}\nAccess-Control-Allow-Origin: ${allowOrigin}\nAccess-Control-Allow-Credentials: ${
              allowCredentials ? 'true' : '(absent)'
            }`,
            url,
            confidence: 0.95,
            recommendations: [
              'Validate Origin against a strict allowlist before echoing it.',
              'Never combine a reflected origin with Access-Control-Allow-Credentials: true.',
              'Do not trust the literal "null" origin.'
            ],
            cwe: 'CWE-942',
            owasp: 'A05:2021 Security Misconfiguration'
          })
        );
        continue;
      }

      if (allowOrigin === '*') {
        vulnerabilities.push(
          finding({
            type: 'CORS Misconfiguration',
            severity: allowCredentials ? 'Medium' : 'Low',
            category: 'Wildcard Origin Allowed',
            description: allowCredentials
              ? 'The endpoint returns Access-Control-Allow-Origin: * together with Allow-Credentials: true. Browsers reject this combination, but it signals a broken CORS policy.'
              : 'The endpoint allows any origin to read its responses. This is safe only for genuinely public, unauthenticated data.',
            evidence: 'Access-Control-Allow-Origin: *',
            url,
            confidence: 0.7,
            recommendations: [
              'Restrict Access-Control-Allow-Origin to known front-end origins.',
              'Remove Access-Control-Allow-Credentials unless it is required.'
            ],
            cwe: 'CWE-942',
            owasp: 'A05:2021 Security Misconfiguration'
          })
        );
      }
    }

    return {
      url,
      status: 'complete',
      scanner: this.name,
      vulnerabilities: dedupeFindings(vulnerabilities),
      details: { probes: observations },
      scanTime: Date.now() - started
    };
  }

  async scanMultiple(urls) {
    const results = [];
    for (const url of urls) results.push(await this.scan(url));
    return results;
  }
}

module.exports = { CORSAnalyzer };
