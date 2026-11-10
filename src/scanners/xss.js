const { loadList } = require('../core/config-loader');
const {
  fetchPage,
  finding,
  parametersToTest,
  setParameter,
  dedupeFindings
} = require('./utils');
const { COMMON_PARAMS } = require('../core/params');

const REFLECTION_MARKER = 'vlnsx7';
const REFLECTION_PAYLOAD = `${REFLECTION_MARKER}<svg/onload=alert(1)>`;

class XSSDetector {
  constructor() {
    this.name = 'XSS Detector';
    this.description =
      'Tests query/form parameters for reflected Cross-Site Scripting and flags risky inline script usage.';
    this.version = '2.2.1';
    this.staticPatterns = [];
    this.configSource = 'defaults';
    this.maxParams = 6;
    this.runsPerPage = true;
    this.pageLimit = 4;
    this.pageInterest = /^(q|s|search|query|keyword|term|name|email|comment|message|id|page|cat|category|product|item|user|username|ref)$/i;
  }

  async initialize() {
    const { values, source } = loadList('xss-patterns.json', ['patterns'], []);
    this.staticPatterns = values;
    this.configSource = source;
    console.log(`[xss] ${this.staticPatterns.length} static patterns (config: ${this.configSource})`);
  }

  async scan(url, options = {}) {
    const started = Date.now();
    const page = options.page || (await fetchPage(url, options));
    const html = page.html || '';
    const vulnerabilities = [];

    // --- Reflected XSS: inject a harmless marker+handler and see if it is echoed
    const params = parametersToTest(url, html, {
      limit: this.maxParams,
      wordlist: COMMON_PARAMS,
      guessCount: 4
    });
    const tested = [];

    for (const param of params) {
      const target = setParameter(url, param.name, REFLECTION_PAYLOAD);
      tested.push(param.name);
      try {
        const response = await fetchPage(target, { timeout: options.timeout || 15000 });
        const body = response.html || '';
        const rawHandler = body.includes('<svg/onload=alert(1)>');
        const rawMarker = body.includes(`${REFLECTION_MARKER}<svg`);

        if (rawHandler || rawMarker) {
          // Confirm it is not merely echoed back inside an escaped text node.
          const unescaped = body.replace(/&lt;|&#60;|%3C/gi, '<');
          const confirmed = unescaped.includes('<svg/onload=alert(1)>');
          vulnerabilities.push(
            finding({
              type: 'XSS',
              severity: confirmed ? 'High' : 'Medium',
              category: 'Reflected XSS',
              description: `Parameter "${param.name}" reflects attacker-controlled input into the response without encoding, so a crafted link can execute script in the victim's browser.`,
              evidence: `GET ${target} -> payload reflected${confirmed ? ' unencoded' : ' (encoding needs manual review)'}`,
              url: target,
              confidence: confirmed ? 0.9 : 0.6,
              recommendations: [
                'Encode output contextually (HTML entity encoding, attribute encoding).',
                "Add a restrictive Content-Security-Policy (no 'unsafe-inline').",
                'Validate/sanitise input server-side and use auto-escaping templates.'
              ]
            })
          );
          break; // one confirmed reflection is enough for this scanner
        }
      } catch {
        // network hiccup on a probe: ignore, the page itself was reachable
      }
    }

    // --- Static checks (low noise): javascript: URLs and eval-like inline code
    const jsUrlMatches = html.match(/(?:href|src|action)\s*=\s*["']\s*javascript:[^"']*/gi) || [];
    for (const match of jsUrlMatches.slice(0, 3)) {
      vulnerabilities.push(
        finding({
          type: 'XSS',
          severity: 'Medium',
          category: 'Dangerous URI Scheme',
          description:
            'The page contains javascript: URIs. If such a value ever contains user input it becomes a script injection primitive.',
          evidence: match.slice(0, 160),
          url,
          confidence: 0.6,
          recommendations: [
            'Replace javascript: links with event handlers that call named functions.',
            'Validate any user-controlled URL with an allowlist of schemes.'
          ]
        })
      );
    }

    const evalSinks = [
      { regex: /document\.write\s*\(/g, label: 'document.write(' },
      { regex: /\.innerHTML\s*=\s*[^;]{0,80}(location|document\.URL|search|hash|referrer)/gi, label: 'innerHTML = (URL-derived value)' },
      { regex: /eval\s*\(\s*(location|document\.|window\.name)/gi, label: 'eval( on browser input)' }
    ];
    for (const sink of evalSinks) {
      if (sink.regex.test(html)) {
        sink.regex.lastIndex = 0;
        vulnerabilities.push(
          finding({
            type: 'XSS',
            severity: 'Low',
            category: 'Risky DOM Sink',
            description: `A potentially dangerous DOM sink was found in inline code (${sink.label}). Review whether user-controlled data can reach it.`,
            evidence: sink.label,
            url,
            confidence: 0.5,
            recommendations: [
              'Use textContent / safe templating instead of HTML sinks.',
              'Sanitise untrusted markup with DOMPurify if HTML is required.'
            ]
          })
        );
      }
      sink.regex.lastIndex = 0;
    }

    return {
      url,
      status: 'complete',
      scanner: this.name,
      vulnerabilities: dedupeFindings(vulnerabilities),
      details: {
        statusCode: page.status,
        htmlLength: html.length,
        parametersTested: tested,
        reflectionProbes: tested.length
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

module.exports = { XSSDetector };
