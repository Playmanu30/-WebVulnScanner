const { loadList } = require('../core/config-loader');
const {
  fetchPage,
  finding,
  parametersToTest,
  setParameter,
  dedupeFindings
} = require('./utils');
const { FILE_PARAMS } = require('../core/params');

// Signatures that prove a file outside the web root was returned.
const FILE_SIGNATURES = [
  { regex: /root:[x*]?:0:0:/, label: 'Linux /etc/passwd contents' },
  { regex: /\[extensions\][\s\S]{0,200}\[fonts\]/i, label: 'Windows win.ini contents' },
  { regex: /; for 16-bit app support/i, label: 'Windows system.ini contents' },
  { regex: /\[boot loader\]/i, label: 'Windows boot.ini contents' },
  { regex: /daemon:[x*]:1:1:/, label: 'Linux passwd entry' }
];

class DirectoryTraversalFinder {
  constructor() {
    this.name = 'Directory Traversal Finder';
    this.description =
      'Probes file/path parameters with traversal payloads and looks for out-of-root file signatures.';
    this.version = '2.2.1';
    this.testPayloads = [];
    this.configSource = 'defaults';
    this.maxParams = 4;
    this.runsPerPage = true;
    this.pageLimit = 4;
    this.pageInterest = /^(file|filename|path|dir|folder|page|doc|download|template|include|view|img|image|load|read|src|resource|asset|theme|lang|layout)$/i;
  }

  async initialize() {
    const { values, source } = loadList(
      'traversal-patterns.json',
      ['payloads', 'patterns'],
      ['../../../../etc/passwd', '..%2f..%2f..%2f..%2fetc%2fpasswd', '..\\..\\..\\..\\windows\\win.ini']
    );
    // Only keep payloads that target a readable proof file, never SAM/SYSTEM
    // (those are locked and would only produce noise).
    this.testPayloads = values.filter(
      (payload) => typeof payload === 'string' && !/sam|system32\/config/i.test(payload)
    );
    if (this.testPayloads.length === 0) this.testPayloads = ['../../../../etc/passwd'];
    this.configSource = source;
    console.log(
      `[directory-traversal] ${this.testPayloads.length} payloads (config: ${this.configSource})`
    );
  }

  async scan(url, options = {}) {
    const started = Date.now();
    const page = options.page || (await fetchPage(url, options));
    const html = page.html || '';
    const params = parametersToTest(url, html, {
      limit: this.maxParams,
      wordlist: FILE_PARAMS,
      guessCount: 3
    });
    const vulnerabilities = [];
    const probes = [];

    // Only probe parameters that look like they could address a file.
    const fileParams = params.filter((p) =>
      /(file|path|dir|folder|page|doc|download|template|include|view|img|image|load|read)/i.test(p.name)
    );
    const candidates = fileParams.length > 0 ? fileParams : params.slice(0, 2);

    outer: for (const param of candidates) {
      for (const payload of this.testPayloads) {
        const target = setParameter(url, param.name, payload);
        probes.push({ parameter: param.name, payload });
        try {
          const response = await fetchPage(target, { timeout: options.timeout || 15000 });
          const body = response.html || '';
          const hit = FILE_SIGNATURES.find((sig) => sig.regex.test(body));
          if (hit) {
            vulnerabilities.push(
              finding({
                type: 'Directory Traversal',
                severity: 'Critical',
                category: 'Path Traversal',
                description: `Parameter "${param.name}" accepts traversal sequences and returned ${hit.label}. An attacker can read arbitrary files.`,
                evidence: `GET ${target} -> ${hit.label}`,
                url: target,
                confidence: 0.9,
                recommendations: [
                  'Never build filesystem paths from user input; resolve against an allowlisted root and verify the result stays inside it.',
                  'Use opaque identifiers instead of file names in parameters.',
                  'Run the web server with the least privileges and keep sensitive files outside the web root.'
                ]
              })
            );
            break outer;
          }
        } catch {
          // probe failed; keep going
        }
      }
    }

    return {
      url,
      status: 'complete',
      scanner: this.name,
      vulnerabilities: dedupeFindings(vulnerabilities),
      details: {
        statusCode: page.status,
        parametersDiscovered: params.map((p) => p.name),
        probesSent: probes.length,
        note:
          candidates.length === 0
            ? 'No parameters were available to probe for path traversal.'
            : 'Only read-only payloads targeting /etc/passwd and win.ini were sent.'
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

module.exports = { DirectoryTraversalFinder };
