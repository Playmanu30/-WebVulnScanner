const path = require('path');
const { version } = require('../../package.json');
const { ScannerEngine } = require('../core/scanner-engine');
const { ReportGenerator } = require('../core/report-generator');

class QuickScan {
  constructor() {
    this.engine = new ScannerEngine();
    this.reporter = new ReportGenerator();
  }

  async run(url, options = {}) {
    console.log(`\n=== AI Web Vulnerability Scanner v${version} (CLI) ===`);
    console.log(`Target: ${url}\n`);

    // Pass scanOptions to initialize() so scanners are created with the correct config first
    const scanOptions = {
      timeout: options.timeout || 20000,
      maxPages: Number(options.maxPages) > 0 ? Number(options.maxPages) : (options.aggressive === true ? 50 : 12),
      perPageLimit: Number(options.perPageLimit) > 0 ? Number(options.perPageLimit) : (options.aggressive === true ? 12 : 4),
      depth: options.depth ?? (options.aggressive === true ? 5 : 2),
      concurrency: Number(options.concurrency) > 0 ? Number(options.concurrency) : (options.aggressive === true ? 12 : 3),
      delayMs: options.delayMs ?? (options.aggressive === true ? 0 : 40),
      aggressive: options.aggressive === true,
      ...options
    };

    await this.engine.initialize(scanOptions);

    let lastScanner = null;
    this.engine.onProgressCallback = (progress) => {
      if (progress.status === 'running' && progress.scanner !== lastScanner) {
        lastScanner = progress.scanner;
        console.log(`  [${progress.percent}%] ${progress.scanner}`);
      } else if (progress.status === 'complete' && progress.findings > 0) {
        console.log(`         -> ${progress.findings} finding(s)`);
      }
    };

    const results = await this.engine.scan(url, scanOptions);

    console.log('\n=== Scan Complete ===');
    console.log(`HTTP status       : ${results.statusCode}`);
    console.log(`Scanners completed: ${results.totalScans}/${results.scannerResults.length}`);
    console.log(`Findings          : ${results.totalVulnerabilities}`);
    for (const [severity, count] of Object.entries(results.severityBreakdown)) {
      console.log(`  - ${severity.padEnd(8)}: ${count}`);
    }
    if (results.aiAnalysis) {
      console.log(
        `Security score    : ${Math.round(results.aiAnalysis.securityScore * 100)}/100 (risk: ${
          results.aiAnalysis.riskLevel
        })`
      );
    }

    const details = results.scannerResults
      .flatMap((scannerResult) =>
        (scannerResult.vulnerabilities || []).map((item) => ({
          scanner: scannerResult.scanner,
          ...item
        }))
      )
      .sort((a, b) => ['Critical', 'High', 'Medium', 'Low', 'Info'].indexOf(a.severity) -
        ['Critical', 'High', 'Medium', 'Low', 'Info'].indexOf(b.severity));

    if (details.length > 0) {
      console.log('\n--- Findings ---');
      for (const item of details) {
        console.log(`\n[${item.severity}] ${item.type} · ${item.category}`);
        console.log(`  ${item.description}`);
        if (item.evidence) console.log(`  Evidence: ${item.evidence}`);
      }
    }

    if (!options.noReport) {
      const outputDir = path.join(__dirname, '..', '..');
      const json = await this.reporter.generateToFile(url, results, 'json', outputDir);
      const html = await this.reporter.generateToFile(url, results, 'html', outputDir);

      if (json.savedFile) console.log(`\nJSON report: ${json.savedFile}`);
      if (html.savedFile) console.log(`HTML report: ${html.savedFile}`);
      if (json.error) console.log(`JSON report failed: ${json.error}`);
      if (html.error) console.log(`HTML report failed: ${html.error}`);
    }

    const failed = results.scannerResults.filter((scannerResult) => scannerResult.status === 'error');
    if (failed.length > 0) {
      console.log('\n--- Scanner errors ---');
      for (const item of failed) console.log(`  ! ${item.scanner}: ${item.error}`);
    }

    return results;
  }
}

async function main() {
  const args = process.argv.slice(2);
  const noReport = args.includes('--no-report');
  const aggressive = args.includes('--aggressive');
  const target = args.find((arg) => /^https?:\/\//i.test(arg)) || 'https://example.com';
  const scanner = new QuickScan();

  try {
    // Pass both noReport and aggressive flags to run()
    const results = await scanner.run(target, { noReport, aggressive });
    process.exitCode = 0;
  } catch (error) {
    console.error(`\nScan failed: ${error.message}`);
    if (/Could not reach/i.test(error.message)) {
      console.error('Check that the target is online and reachable from this machine.');
    }
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main();
}

module.exports = { QuickScan };
