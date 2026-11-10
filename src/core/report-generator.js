const fs = require('fs');
const path = require('path');
const { getPlaybook, LAB_NOTICE } = require('./playbooks');

const SEVERITY_CLASS = {
  Critical: 'critical',
  High: 'high',
  Medium: 'medium',
  Low: 'low',
  Info: 'info'
};

function escapeHtml(value) {
  return String(value === undefined || value === null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Last line of defence: even if a scanner or an imported report carries a
 * credential, it must not be serialised into a report file.
 */
function redactSecrets(value) {
  if (value === undefined || value === null) return value;
  return String(value)
    .replace(
      /\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-access-token)\b\s*[:=]\s*[^\r\n]+/gi,
      '$1: [redacted]'
    )
    .replace(/(\b[a-z][a-z0-9+.-]*:\/\/)[^\s/?#@]+@/gi, '$1[redacted]@');
}

class ReportGenerator {
  constructor() {
    this.name = 'Report Generator';
    this.version = '2.2.1';
    this.outputFormats = ['json', 'html', 'text'];
  }

  /**
   * @param {string|string[]} url
   * @param {object|object[]} results  an aggregate scan result or an array of scanner results
   * @param {'json'|'html'|'text'} format
   */
  async generate(url, results, format = 'json') {
    try {
      const data = this.createReportData(url, results);
      let content;

      switch (String(format).toLowerCase()) {
        case 'html':
          content = this.generateHtml(data);
          break;
        case 'text':
        case 'txt':
          content = this.generateText(data);
          break;
        case 'json':
        default:
          content = JSON.stringify(data, null, 2);
      }

      return {
        status: 'success',
        format: String(format).toLowerCase() === 'txt' ? 'text' : String(format).toLowerCase(),
        content,
        size: Buffer.byteLength(content)
      };
    } catch (error) {
      return { status: 'error', error: error.message };
    }
  }

  async generateToFile(url, results, format = 'json', directory = process.cwd()) {
    const report = await this.generate(url, results, format);
    if (report.status !== 'success') return report;

    const extension = report.format === 'text' ? 'txt' : report.format;
    const filename = `scan-report-${Date.now()}.${extension}`;
    const filePath = path.join(directory, filename);

    try {
      fs.writeFileSync(filePath, report.content);
      return { ...report, savedFile: filePath };
    } catch (error) {
      return { ...report, status: 'error', error: error.message };
    }
  }

  createReportData(url, results) {
    const aggregate = this.normalizeResults(url, results);
    const scannerResults = aggregate.scannerResults;
    const findings = [];

    for (const result of scannerResults) {
      for (const item of result.vulnerabilities || []) {
        findings.push({
          id: `F-${findings.length + 1}`.padStart(6, '0'),
          scanner: result.scanner,
          type: item.type,
          severity: item.severity,
          category: item.category || 'General',
          cwe: item.cwe || null,
          owasp: item.owasp || null,
          description: redactSecrets(item.description || ''),
          evidence: item.evidence ? redactSecrets(item.evidence) : null,
          url: redactSecrets(item.url || result.url || null),
          page: redactSecrets(item.page || null),
          confidence: item.confidence ?? null,
          recommendations: (item.recommendations || []).map((rec) => redactSecrets(rec)),
          playbook: getPlaybook(item.type)
        });
      }
    }

    const severityBreakdown = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const item of findings) {
      const key = String(item.severity || 'medium').toLowerCase();
      if (severityBreakdown[key] !== undefined) severityBreakdown[key] += 1;
      else severityBreakdown.low += 1;
    }

    return {
      reportMetadata: {
        title: 'AI Web Vulnerability Scan Report',
        tool: 'AI Web Vulnerability Scanner',
        generatedAt: new Date().toISOString(),
        scannerVersion: this.version,
        urlScanned: (Array.isArray(url) ? url : [url]).map((entry) => redactSecrets(entry)),
        finalUrl: redactSecrets(aggregate.finalUrl || null),
        httpStatus: aggregate.statusCode ?? null,
        pagesScanned: aggregate.pagesScanned ?? 1,
        authenticated: Boolean(aggregate.authenticated)
      },
      summary: {
        totalScanners: scannerResults.length,
        completedScanners: scannerResults.filter((r) => r.status === 'complete').length,
        failedScanners: scannerResults.filter((r) => r.status === 'error').length,
        totalFindings: findings.length,
        severityBreakdown,
        securityScore: aggregate.aiAnalysis?.securityScore ?? null,
        riskLevel: aggregate.aiAnalysis?.riskLevel ?? null,
        scanTimeMs: aggregate.scanTime ?? null
      },
      context: aggregate.aiAnalysis?.context || {},
      scanErrors: scannerResults
        .filter((r) => r.status === 'error')
        .map((r) => ({ scanner: r.scanner, error: r.error })),
      findings,
      insights: aggregate.aiAnalysis?.insights || [],
      recommendations: aggregate.aiAnalysis?.recommendations || []
    };
  }

  normalizeResults(url, results) {
    if (results && !Array.isArray(results) && Array.isArray(results.scannerResults)) {
      return results;
    }

    const scannerResults = Array.isArray(results) ? results : results ? [results] : [];
    let totalVulnerabilities = 0;
    const severityBreakdown = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

    for (const result of scannerResults) {
      for (const item of result.vulnerabilities || []) {
        totalVulnerabilities += 1;
        const key = String(item.severity || 'medium').toLowerCase();
        if (severityBreakdown[key] !== undefined) severityBreakdown[key] += 1;
        else severityBreakdown.low += 1;
      }
    }

    return {
      url: Array.isArray(url) ? url : [url],
      finalUrl: null,
      statusCode: null,
      scanTime: scannerResults.reduce((sum, r) => sum + (r.scanTime || 0), 0),
      totalVulnerabilities,
      severityBreakdown,
      scannerResults,
      aiAnalysis: null
    };
  }

  generateHtml(data) {
    const { summary, reportMetadata } = data;
    const badges = ['critical', 'high', 'medium', 'low', 'info'];

    const summaryCards = badges
      .map(
        (key) => `
        <div class="card ${key}">
          <div class="label">${key}</div>
          <div class="number">${summary.severityBreakdown[key] || 0}</div>
        </div>`
      )
      .join('');

    const findingsHTML = data.findings
      .map(
        (item) => `
        <article class="finding ${SEVERITY_CLASS[item.severity] || 'low'}">
          <header>
            <span class="type">${escapeHtml(item.type)} · ${escapeHtml(item.category)}</span>
            <span class="badge ${SEVERITY_CLASS[item.severity] || 'low'}">${escapeHtml(item.severity)}</span>
          </header>
          <p>${escapeHtml(item.description)}</p>
          ${item.evidence ? `<pre>${escapeHtml(item.evidence)}</pre>` : ''}
          <dl>
            <dt>Scanner</dt><dd>${escapeHtml(item.scanner)}</dd>
            <dt>Confidence</dt><dd>${item.confidence ? `${Math.round(item.confidence * 100)}%` : 'n/a'}</dd>
            ${item.cwe ? `<dt>Reference</dt><dd>${escapeHtml(item.cwe)}${
              item.owasp ? ` · ${escapeHtml(item.owasp)}` : ''
            }</dd>` : ''}
            ${item.url ? `<dt>URL</dt><dd>${escapeHtml(item.url)}</dd>` : ''}
          </dl>
          ${
            item.playbook
              ? `<details class="playbook">
                   <summary>Exploitation &amp; validation guide <span class="tag">lab-safe</span></summary>
                   <p>${escapeHtml(item.playbook.summary)}</p>
                   <ol>${item.playbook.steps
                     .map(
                       (step) =>
                         `<li><strong>${escapeHtml(step.title)}.</strong> ${escapeHtml(step.detail)}</li>`
                     )
                     .join('')}</ol>
                   <p><strong>Impact:</strong> ${escapeHtml(item.playbook.impact)}</p>
                   <p class="limits">${escapeHtml(LAB_NOTICE)}</p>
                 </details>`
              : ''
          }
          ${
            item.recommendations.length > 0
              ? `<ul class="recs">${item.recommendations
                  .map((rec) => `<li>${escapeHtml(rec)}</li>`)
                  .join('')}</ul>`
              : ''
          }
        </article>`
      )
      .join('');

    const insightsHTML = data.insights
      .map(
        (insight) => `
        <li><strong>${Math.round((insight.confidence || 0) * 100)}% · ${escapeHtml(
          insight.category || 'Insight'
        )}:</strong> ${escapeHtml(insight.insight)}</li>`
      )
      .join('');

    const recommendationsHTML = data.recommendations
      .map(
        (rec) => `
        <li><span class="badge ${SEVERITY_CLASS[rec.priority] || 'low'}">${escapeHtml(
          rec.priority || 'Info'
        )}</span> ${escapeHtml(rec.detail)}</li>`
      )
      .join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(reportMetadata.title)}</title>
<style>
  :root { color-scheme: light; }
  body { margin: 0; padding: 32px; background: #f5f7fb; font-family: 'Segoe UI', Tahoma, sans-serif; color: #1f2937; }
  .container { max-width: 1100px; margin: 0 auto; }
  h1 { margin: 0 0 4px; font-size: 26px; }
  .meta { color: #6b7280; font-size: 13px; margin-bottom: 24px; }
  .meta code { background: #e5e7eb; padding: 2px 6px; border-radius: 4px; }
  .score { background: #fff; border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,.08); display: flex; gap: 32px; flex-wrap: wrap; }
  .score div strong { display: block; font-size: 12px; text-transform: uppercase; color: #6b7280; margin-bottom: 4px; }
  .score div span { font-size: 22px; font-weight: 700; }
  .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 24px; }
  .card { background: #fff; border-radius: 10px; padding: 16px; text-align: center; border-top: 4px solid #d1d5db; }
  .card.critical { border-color: #dc2626; } .card.high { border-color: #ea580c; }
  .card.medium { border-color: #2563eb; } .card.low { border-color: #16a34a; } .card.info { border-color: #6b7280; }
  .card .label { text-transform: uppercase; font-size: 11px; letter-spacing: .5px; color: #6b7280; }
  .card .number { font-size: 28px; font-weight: 700; }
  h2 { margin: 28px 0 12px; font-size: 18px; }
  .finding { background: #fff; border-radius: 10px; padding: 16px 18px; margin-bottom: 12px; box-shadow: 0 1px 3px rgba(0,0,0,.06); border-left: 4px solid #d1d5db; }
  .finding.critical { border-color: #dc2626; } .finding.high { border-color: #ea580c; }
  .finding.medium { border-color: #2563eb; } .finding.low { border-color: #16a34a; }
  .finding header { display: flex; justify-content: space-between; gap: 12px; align-items: center; }
  .finding .type { font-weight: 700; }
  .finding p { color: #374151; font-size: 14px; }
  .finding pre { background: #0f172a; color: #e2e8f0; padding: 10px 12px; border-radius: 8px; font-size: 12px; white-space: pre-wrap; word-break: break-word; }
  .finding dl { display: grid; grid-template-columns: 100px 1fr; gap: 4px 12px; font-size: 12px; color: #4b5563; margin: 8px 0; }
  .finding dt { font-weight: 600; }
  .finding dd { margin: 0; word-break: break-word; }
  .recs { margin: 8px 0 0; padding-left: 20px; font-size: 13px; color: #374151; }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 11px; font-weight: 700; text-transform: uppercase; color: #fff; background: #6b7280; }
  .badge.critical { background: #dc2626; } .badge.high { background: #ea580c; }
  .badge.medium { background: #2563eb; } .badge.low { background: #16a34a; }
  ul.insights, ul.recs-top { background: #fff; border-radius: 10px; padding: 16px 16px 16px 36px; box-shadow: 0 1px 3px rgba(0,0,0,.06); font-size: 14px; }
  ul.insights li, ul.recs-top li { margin-bottom: 8px; }
  .empty { color: #16a34a; font-weight: 600; }
  details.playbook { margin-top: 12px; padding: 10px 12px; border: 1px solid #e0e7ff; border-left: 3px solid #6366f1; border-radius: 6px; background: #f8faff; font-size: 13px; line-height: 1.6; }
  details.playbook summary { cursor: pointer; font-weight: 700; color: #3730a3; }
  details.playbook .tag { margin-left: 8px; padding: 1px 7px; border-radius: 999px; background: #e0e7ff; color: #4338ca; font-size: 10px; font-weight: 700; text-transform: uppercase; }
  details.playbook ol { padding-left: 20px; }
  details.playbook li { margin-bottom: 6px; }
  details.playbook .limits { padding: 7px 9px; border-radius: 6px; background: #fffbeb; color: #92400e; font-size: 12px; }
  footer { margin-top: 32px; color: #9ca3af; font-size: 12px; }
  @media (max-width: 760px) { .summary { grid-template-columns: repeat(2, 1fr); } }
</style>
</head>
<body>
<div class="container">
  <h1>${escapeHtml(reportMetadata.title)}</h1>
  <p class="meta">
    Generated ${escapeHtml(reportMetadata.generatedAt)} · Scanner v${escapeHtml(reportMetadata.scannerVersion)} ·
    Target <code>${escapeHtml(reportMetadata.urlScanned.join(', '))}</code>
    ${reportMetadata.httpStatus ? ` · HTTP ${escapeHtml(reportMetadata.httpStatus)}` : ''}
    ${reportMetadata.pagesScanned > 1 ? ` · ${reportMetadata.pagesScanned} pages crawled` : ''}
    ${reportMetadata.authenticated ? ' · authenticated scan' : ''}
  </p>

  <section class="score">
    <div><strong>Security score</strong><span>${summary.securityScore === null ? 'n/a' : Math.round(summary.securityScore * 100) + ' / 100'}</span></div>
    <div><strong>Risk level</strong><span>${escapeHtml(summary.riskLevel || 'n/a')}</span></div>
    <div><strong>Findings</strong><span>${summary.totalFindings}</span></div>
    <div><strong>Scanners</strong><span>${summary.completedScanners} / ${summary.totalScanners}</span></div>
    <div><strong>Duration</strong><span>${summary.scanTimeMs === null ? 'n/a' : Math.round(summary.scanTimeMs) + ' ms'}</span></div>
  </section>

  <section class="summary">${summaryCards}</section>

  <h2>Findings</h2>
  ${findingsHTML || '<p class="empty">No vulnerabilities were detected in this pass.</p>'}

  ${data.insights.length > 0 ? `<h2>Analysis insights</h2><ul class="insights">${insightsHTML}</ul>` : ''}
  ${data.recommendations.length > 0 ? `<h2>Prioritised recommendations</h2><ul class="recs-top">${recommendationsHTML}</ul>` : ''}
  ${
    data.scanErrors.length > 0
      ? `<h2>Scanner errors</h2><ul class="insights">${data.scanErrors
          .map((e) => `<li><strong>${escapeHtml(e.scanner)}:</strong> ${escapeHtml(e.error)}</li>`)
          .join('')}</ul>`
      : ''
  }

  <footer>Generated by AI Web Vulnerability Scanner v${escapeHtml(reportMetadata.scannerVersion)}. Findings are heuristic indications — verify manually before acting.</footer>
</div>
</body>
</html>`;
  }

  generateText(data) {
    const lines = [];
    lines.push('==============================================');
    lines.push(' AI WEB VULNERABILITY SCAN REPORT');
    lines.push('==============================================');
    lines.push(`Target     : ${data.reportMetadata.urlScanned.join(', ')}`);
    lines.push(`Generated  : ${data.reportMetadata.generatedAt}`);
    lines.push(`Scanners   : ${data.summary.completedScanners}/${data.summary.totalScanners} completed`);
    lines.push(
      `Score      : ${
        data.summary.securityScore === null ? 'n/a' : Math.round(data.summary.securityScore * 100) + '/100'
      } (risk: ${data.summary.riskLevel || 'n/a'})`
    );
    lines.push('');
    lines.push(
      `Findings   : ${data.summary.totalFindings}  (` +
        Object.entries(data.summary.severityBreakdown)
          .map(([key, value]) => `${key}:${value}`)
          .join(', ') +
        ')'
    );
    lines.push('');

    if (data.findings.length === 0) {
      lines.push('No vulnerabilities were detected in this pass.');
    } else {
      data.findings.forEach((item, index) => {
        lines.push(`[${index + 1}] ${item.severity.toUpperCase()} - ${item.type} (${item.category})`);
        lines.push(`    ${item.description}`);
        if (item.evidence) lines.push(`    Evidence : ${item.evidence}`);
        if (item.url) lines.push(`    URL      : ${item.url}`);
        lines.push(`    Scanner  : ${item.scanner}`);
        item.recommendations.forEach((rec) => lines.push(`    - ${rec}`));
        lines.push('');
      });
    }

    if (data.insights.length > 0) {
      lines.push('--- Insights ---');
      data.insights.forEach((insight) =>
        lines.push(`* [${Math.round((insight.confidence || 0) * 100)}%] ${insight.insight}`)
      );
      lines.push('');
    }

    if (data.scanErrors.length > 0) {
      lines.push('--- Scanner errors ---');
      data.scanErrors.forEach((error) => lines.push(`! ${error.scanner}: ${error.error}`));
    }

    return lines.join('\n');
  }
}

module.exports = { ReportGenerator };
