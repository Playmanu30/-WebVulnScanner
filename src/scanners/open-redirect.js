const { fetchPage, finding, collectParameters, guessParameters, setParameter, dedupeFindings } = require('./utils');
const { REDIRECT_PARAMS } = require('../core/params');

const CANARY_HOST = 'vlnsx7.example';
const PAYLOADS = [`https://${CANARY_HOST}/poc`, `//${CANARY_HOST}/poc`];

const URLISH = /(redirect|url|uri|next|return|returnto|dest|destination|goto|continue|target|link|out|checkout|callback)/i;

class OpenRedirectFinder {
  constructor() {
    this.name = 'Open Redirect Finder';
    this.description =
      'Injects an off-site URL into redirect-like parameters and confirms a 30x pointing at the canary host.';
    this.version = '2.2.1';
    this.runsPerPage = true;
    this.pageLimit = 4;
    this.pageInterest = /^(redirect|redirect_uri|redirect_url|url|uri|next|return|returnurl|return_url|dest|destination|goto|continue|target|link|out|r|u|checkout_url|callback_url)$/i;
  }

  async initialize() {
    console.log('[open-redirect] ready');
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
      REDIRECT_PARAMS,
      6
    );
    const candidates = [...existing, ...guessed].slice(0, 8);

    const vulnerabilities = [];
    const attempts = [];

    for (const param of candidates) {
      for (const payload of PAYLOADS) {
        const target = setParameter(baseUrl, param.name, payload);
        attempts.push({ parameter: param.name, source: param.source });

        let response;
        try {
          response = await fetchPage(target, {
            timeout: options.timeout || 10000,
            redirect: false
          });
        } catch {
          continue;
        }

        const location = response.headers.location;
        const isRedirect = [301, 302, 303, 307, 308].includes(response.status);
        if (!isRedirect || !location) continue;
        if (!String(location).includes(CANARY_HOST)) continue;

        vulnerabilities.push(
          finding({
            type: 'Open Redirect',
            severity: 'Medium',
            category: 'Unvalidated Redirect',
            description: `Parameter "${param.name}" controls the redirect target. An attacker can craft a link on the trusted domain that sends victims to an arbitrary site, which is a strong phishing primitive and can leak OAuth or reset tokens.`,
            evidence: `GET ${target}\n-> HTTP ${response.status}\nLocation: ${location}`,
            url: target,
            confidence: 0.95,
            recommendations: [
              'Only allow relative paths, or validate the destination against an allowlist of hosts.',
              'Reject protocol-relative values beginning with //.',
              'Do not carry "next"/"return" URLs through login flows without signing them.'
            ],
            cwe: 'CWE-601',
            owasp: 'A01:2021 Broken Access Control'
          })
        );
        break;
      }
    }

    return {
      url,
      status: 'complete',
      scanner: this.name,
      vulnerabilities: dedupeFindings(vulnerabilities),
      details: {
        parametersTested: attempts.length,
        parameters: [...new Set(attempts.map((attempt) => attempt.parameter))],
        note:
          candidates.length === 0
            ? 'No redirect-like parameters were found or guessable.'
            : 'Redirects were not followed: the Location header is the evidence, and the canary host is never contacted.'
      },
      scanTime: Date.now() - started
    };
  }

  async scanMultiple(urls) {
    const results = [];
    for (const url of urls) results.push(await this.scan(url));
    return results;
  }
}

module.exports = { OpenRedirectFinder };
