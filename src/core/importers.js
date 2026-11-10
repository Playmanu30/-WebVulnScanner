// Import findings from other authorised testing engines (ZAP JSON, nuclei
// JSONL). Import only: this never runs the external tool, so template choice,
// scope and authorisation stay with the operator.

const SEVERITY_MAP = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Info',
  info: 'Info'
};

function normalizeSeverity(value) {
  return SEVERITY_MAP[String(value || '').trim().toLowerCase()] || 'Medium';
}

/** Best-effort mapping onto the scanner's finding types so playbooks apply. */
function inferType(text) {
  const name = String(text || '');
  if (/cross[- ]site scripting|\bxss\b/i.test(name)) return 'XSS';
  if (/sql injection|\bsqli\b/i.test(name)) return 'SQL Injection';
  if (/server[- ]side request forgery|\bssrf\b/i.test(name)) return 'SSRF';
  if (/path traversal|directory traversal|local file inclusion|\blfi\b/i.test(name)) return 'Directory Traversal';
  if (/open redirect/i.test(name)) return 'Open Redirect';
  if (/cross[- ]origin|\bcors\b/i.test(name)) return 'CORS Misconfiguration';
  if (/csrf|cross[- ]site request forgery/i.test(name)) return 'CSRF';
  if (/exposed|\.env|\.git|backup file|sensitive file/i.test(name)) return 'Sensitive File Exposure';
  if (/security header|content-security-policy|x-frame-options|hsts/i.test(name)) return 'Header';
  if (/\btls\b|\bssl\b|certificate|weak cipher/i.test(name)) return 'SSL/TLS';
  if (/information disclosure|version disclosure|stack trace/i.test(name)) return 'Information Disclosure';
  if (/authentication|session cookie|login/i.test(name)) return 'Authentication';
  if (/http method|trace method|put method/i.test(name)) return 'HTTP Method Misconfiguration';
  return 'Imported Finding';
}

function findingFrom(source, fields) {
  return {
    type: inferType(fields.title),
    severity: normalizeSeverity(fields.severity),
    category: fields.category || 'Imported',
    description: fields.description || fields.title || 'Imported finding',
    evidence: fields.evidence || null,
    url: fields.url || null,
    confidence: fields.confidence ?? 0.6,
    recommendations: fields.recommendations || [],
    cwe: fields.cwe || null,
    owasp: fields.owasp || null,
    source
  };
}

function parseZap(content) {
  const report = typeof content === 'string' ? JSON.parse(content) : content;
  const findings = [];
  const sites = Array.isArray(report.site) ? report.site : report.site ? [report.site] : [];

  for (const site of sites) {
    for (const alert of site.alerts || []) {
      const instances = Array.isArray(alert.instances) ? alert.instances : [];
      const first = instances[0] || {};
      const cweId = alert.cweid && String(alert.cweid) !== '-1' ? `CWE-${alert.cweid}` : null;
      findings.push(
        findingFrom('ZAP', {
          title: alert.alert || alert.name,
          severity: alert.riskdesc ? String(alert.riskdesc).split(' ')[0] : alert.riskcode,
          category: alert.pluginid ? `ZAP plugin ${alert.pluginid}` : 'ZAP',
          description: alert.desc ? String(alert.desc).replace(/<[^>]+>/g, ' ').slice(0, 600) : '',
          evidence: first.evidence
            ? `param=${first.param || '—'} ${first.method || 'GET'} ${first.uri || ''}\n${first.evidence}`.trim()
            : first.uri || null,
          url: first.uri || site['@name'] || null,
          confidence: alert.confidence === 'High' ? 0.9 : alert.confidence === 'Low' ? 0.6 : 0.75,
          recommendations: alert.solution ? [String(alert.solution).replace(/<[^>]+>/g, ' ').trim()] : [],
          cwe: cweId
        })
      );
    }
  }

  return findings;
}

function parseNuclei(content) {
  const lines = String(content)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const findings = [];
  for (const line of lines) {
    let item;
    try {
      item = JSON.parse(line);
    } catch {
      continue;
    }

    const info = item.info || {};
    const classification = info.classification || {};
    const cweIds = Array.isArray(classification['cwe-id'])
      ? classification['cwe-id']
      : classification['cwe-id']
        ? [classification['cwe-id']]
        : [];

    findings.push(
      findingFrom('nuclei', {
        title: info.name || item['template-id'] || item['template'] || 'nuclei finding',
        severity: info.severity,
        category: item['template-id'] || 'nuclei',
        description: info.description || '',
        evidence: [item['matched-at'] || item.host, item['matcher-name'], item['extracted-results']]
          .filter(Boolean)
          .join(' · '),
        url: item['matched-at'] || item.host || null,
        confidence: 0.75,
        recommendations: info.remediation ? [String(info.remediation)] : [],
        cwe: cweIds.length > 0 ? `CWE-${String(cweIds[0]).replace(/^CWE-/i, '')}` : null,
        owasp: Array.isArray(classification['owasp-top-10'])
          ? String(classification['owasp-top-10'][0])
          : classification['owasp-top-10'] || null
      })
    );
  }

  return findings;
}

/** Detect ZAP JSON, nuclei JSONL, or a bare JSON array of findings. */
function parseImport(content, filename = '') {
  const text = String(content || '').trim();
  if (!text) return { source: 'unknown', findings: [] };

  const lower = filename.toLowerCase();
  if (lower.endsWith('.jsonl') || lower.endsWith('.ndjson') || (text.startsWith('{') && text.includes('\n{'))) {
    const findings = parseNuclei(text);
    if (findings.length > 0) return { source: 'nuclei', findings: findings.slice(0, 300) };
  }

  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return { source: 'unknown', findings: [] };
  }

  if (data && Array.isArray(data.findings)) {
    const findings = data.findings.map((item) =>
      findingFrom('JSON', {
        title: item.title || item.type || item.name,
        severity: item.severity,
        category: item.category || 'Imported',
        description: item.description,
        evidence: item.evidence,
        url: item.url,
        confidence: item.confidence,
        recommendations: item.recommendations,
        cwe: item.cwe,
        owasp: item.owasp
      })
    );
    return { source: 'json', findings: findings.slice(0, 300) };
  }

  if (data && (data.site || data['@version'])) {
    return { source: 'zap', findings: parseZap(data).slice(0, 300) };
  }

  if (Array.isArray(data)) {
    const findings = data
      .filter((item) => item && typeof item === 'object')
      .map((item) =>
        findingFrom('JSON', {
          title: item.title || item.type || item.name,
          severity: item.severity,
          category: item.category || 'Imported',
          description: item.description,
          evidence: item.evidence,
          url: item.url,
          confidence: item.confidence,
          recommendations: item.recommendations,
          cwe: item.cwe,
          owasp: item.owasp
        })
      );
    return { source: 'json', findings: findings.slice(0, 300) };
  }

  return { source: 'unknown', findings: [] };
}

module.exports = { parseImport, parseZap, parseNuclei, inferType, normalizeSeverity };
