const { loadList } = require('../core/config-loader');
const {
  fetchPage,
  finding,
  parametersToTest,
  setParameter,
  dedupeFindings
} = require('./utils');
const { COMMON_PARAMS } = require('../core/params');

const SQL_ERROR_SIGNATURES =
  /(SQL syntax[^<]{0,80}MySQL|You have an error in your SQL syntax|Warning:\s*mysqli?_|Warning:\s*pg_|PostgreSQL[^<]{0,40}ERROR|SQLite3?::|unrecognized token:|ORA-\d{5}|Microsoft OLE DB Provider for SQL Server|Microsoft SQL Native Client error|ODBC SQL Server Driver|Incorrect syntax near|Unclosed quotation mark after the character string|quoted string not properly terminated|SQLSTATE\[\d+\])/i;

const DESTRUCTIVE = /(drop\s+table|delete\s+from|truncate|insert\s+into|update\s+\w+\s+set|waitfor\s+delay|sleep\s*\(|benchmark\s*\()/i;

class SQLInjectionDetector {
  constructor() {
    this.name = 'SQL Injection Detector';
    this.description =
      'Probes URL and GET-form parameters with quote payloads and looks for database error leakage.';
    this.version = '2.2.1';
    this.testPayloads = [];
    this.configSource = 'defaults';
    this.maxParams = 5;
    this.runsPerPage = true;
    this.pageLimit = 4;
    this.pageInterest = /^(q|s|search|query|keyword|term|name|email|id|page|cat|category|product|item|user|username|ref|sort|filter)$/i;
    // Hard budget for blind probing, enforced here as well as in the engine.
    this.blindPages = 0;
    this.maxBlindPages = 2;
    this.maxBlindPayloads = 3;
    this.blindRunning = false;
  }

  beginScan() {
    this.blindPages = 0;
    this.blindRunning = false;
  }

  async initialize() {
    const { values, source } = loadList(
      'sql-patterns.json',
      ['payloads', 'patterns'],
      ["'", '"', "'\""]
    );
    // Never send destructive payloads (DROP/DELETE/SLEEP/WAITFOR) to a live target.
    // Only quote-based probes are used; the rest of the config is kept for reference.
    this.testPayloads = values.filter((p) => typeof p === 'string' && !DESTRUCTIVE.test(p));
    if (this.testPayloads.length === 0) this.testPayloads = ["'", '"'];
    this.configSource = source;
    console.log(
      `[sql-injection] ${this.testPayloads.length} safe quote probes (config: ${this.configSource})`
    );
  }

  async scan(url, options = {}) {
    const started = Date.now();
    const page = options.page || (await fetchPage(url, options));
    const html = page.html || '';
    const params = parametersToTest(url, html, {
      limit: this.maxParams,
      wordlist: COMMON_PARAMS,
      guessCount: 4
    });
    const vulnerabilities = [];
    const tested = [];

    for (const param of params) {
      for (const payload of this.testPayloads) {
        const target = setParameter(url, param.name, payload);
        tested.push({ parameter: param.name, payload });
        try {
          const response = await fetchPage(target, { timeout: options.timeout || 15000 });
          const body = response.html || '';
          const match = body.match(SQL_ERROR_SIGNATURES);
          const baselineHasError = Boolean((html || '').match(SQL_ERROR_SIGNATURES));

          if (match && !baselineHasError) {
            vulnerabilities.push(
              finding({
                type: 'SQL Injection',
                severity: 'High',
                category: 'Error-Based SQL Injection',
                description: `Parameter "${param.name}" causes a database error when a quote character is supplied, which strongly suggests user input is concatenated into SQL.`,
                evidence: `GET ${target} -> ${String(match[0]).slice(0, 140)}`,
                url: target,
                confidence: 0.85,
                recommendations: [
                  'Use parameterised queries / prepared statements for every query.',
                  'Disable verbose database errors in production.',
                  'Apply least-privilege database accounts.'
                ]
              })
            );
            break;
          }
        } catch {
          // probe failed: ignore, keep testing other parameters
        }
      }
      if (vulnerabilities.length > 0) break;
    }

    if (vulnerabilities.length === 0 && options.blind === true) {
      const blind = await this.blindProbe(url, params, options);
      if (blind) vulnerabilities.push(blind);
    }

    return {
      url,
      status: 'complete',
      scanner: this.name,
      vulnerabilities: dedupeFindings(vulnerabilities),
      details: {
        statusCode: page.status,
        parametersDiscovered: params.map((p) => p.name),
        probesSent: tested.length,
        blindProbed: options.blind === true,
        note:
          params.length === 0
            ? 'No query or GET-form parameters were found, so no injection probe could be sent.'
            : options.blind === true
              ? 'Quote probes plus a capped time-based blind check were sent.'
              : 'Only non-destructive quote probes were sent.'
      },
      scanTime: Date.now() - started
    };
  }

  /**
   * Time-based blind SQLi confirmation. One parameter, three payloads, every
   * probe repeated once: a response that is consistently ~3 s slower than the
   * baseline is the signal. Nothing is written and no data is read.
   */
  async blindProbe(url, params, options) {
    if (this.blindPages >= this.maxBlindPages) return null;
    // Only one blind probe may run at a time, even with a concurrency pool.
    if (this.blindRunning) return null;

    const param = params[0];
    if (!param) return null;

    this.blindRunning = true;
    this.blindPages += 1;

    try {
      const payloads = [
        { label: 'MySQL SLEEP', value: `1' AND SLEEP(3)-- ` },
        { label: 'PostgreSQL pg_sleep', value: `1' AND pg_sleep(3)-- ` },
        { label: 'MSSQL WAITFOR', value: `1'; WAITFOR DELAY '0:0:3'-- ` }
      ].slice(0, this.maxBlindPayloads);

      const timeout = Math.min(Math.max(options.timeout || 15000, 8000), 12000);
      const deadline = Date.now() + 30000;

      const timeRequest = async (target) => {
        if (Date.now() > deadline) return null;
        const started = Date.now();
        try {
          await fetchPage(target, { timeout });
        } catch {
          return null;
        }
        return Date.now() - started;
      };

      const baselineTarget = setParameter(url, param.name, '1');
      const baseline = await timeRequest(baselineTarget);
      // A slow/loaded server makes timing evidence worthless; do not guess.
      if (baseline === null || baseline > 6000) return null;

      for (const payload of payloads) {
        if (Date.now() > deadline) break;
        const target = setParameter(url, param.name, payload.value);
        const first = await timeRequest(target);
        if (first === null || first - baseline < 2500) continue;

        const second = await timeRequest(target);
        if (second === null || second - baseline < 2500) continue;

        return finding({
          type: 'SQL Injection',
          severity: 'High',
          category: 'Blind Time-Based SQL Injection',
          description: `Parameter "${param.name}" delayed the database twice in a row when a ${payload.label} payload was supplied. That behaviour is only possible if the value is executed as SQL.`,
          evidence: `GET ${target}\nbaseline ${baseline} ms · probe 1 ${first} ms · probe 2 ${second} ms (confirmed twice)`,
          url: target,
          confidence: 0.8,
          recommendations: [
            'Use parameterised queries / prepared statements for every query.',
            'Apply a statement timeout so injected delays cannot consume worker time.',
            'Apply least-privilege database accounts.'
          ]
        });
      }

      return null;
    } finally {
      this.blindRunning = false;
    }
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

module.exports = { SQLInjectionDetector };
