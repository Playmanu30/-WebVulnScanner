const cheerio = require('cheerio');
const { loadList } = require('../core/config-loader');

const SEVERITY_PENALTY = { Critical: 15, High: 8, Medium: 3, Low: 1, Info: 0 };

// config/ai-patterns.json entries are a mix of regex fragments and plain
// strings ("?id=" is not a valid regex). Try a regex first, then a literal
// substring search so either style works.
function patternMatches(haystack, pattern) {
  if (typeof pattern !== 'string' || pattern === '') return false;
  try {
    return new RegExp(pattern, 'i').test(haystack);
  } catch {
    return haystack.toLowerCase().includes(pattern.toLowerCase());
  }
}

// Turn a config regex into something a human can read in the report.
function describeSurface(pattern) {
  if (/method\s*=\s*"(POST|PUT|DELETE)"/i.test(pattern)) return 'state-changing form';
  if (/<form/i.test(pattern)) return 'form';
  if (/<iframe/i.test(pattern)) return 'embedded frame';
  if (/<object|<embed/i.test(pattern)) return 'embedded object';
  if (/<input|<textarea|<select/i.test(pattern)) return 'input field';
  if (/<script/i.test(pattern)) return 'inline script';
  if (/^\?/.test(pattern)) return `"${pattern}" parameter`;
  return pattern.replace(/[\\^$*+?.()|[\]{}]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 24);
}

/**
 * Heuristic analysis layer (no external model calls).
 * It correlates scanner findings with structural facts about the page to produce
 * a single risk score, plain-language insights and prioritised recommendations.
 */
class AIAnalysisEngine {
  constructor() {
    this.name = 'AI Vulnerability Analysis Engine';
    this.version = '2.2.1';
    this.surfacePatterns = [];
    this.configSource = 'defaults';
  }

  async initialize() {
    // Patterns that mark an "input surface": forms, embeds, common query
    // parameters. They never raise a finding on their own — they tell the
    // report which parts of the page deserve the most attention.
    const { values, source } = loadList(
      'ai-patterns.json',
      ['patterns'],
      ['<form[^>]*action', '<input', '<iframe[^>]*src=', '?id=', 'method="POST"']
    );
    this.surfacePatterns = values;
    this.configSource = source;
    console.log(`[analysis] ${this.surfacePatterns.length} surface patterns (config: ${this.configSource})`);
    return true;
  }

  async analyze(url, html, scannerResults = []) {
    const $ = cheerio.load(html || '');
    const findings = scannerResults.flatMap((result) => result.vulnerabilities || []);
    const haystack = `${url || ''}\n${html || ''}`;

    const matchedSurfaces = this.surfacePatterns.filter((pattern) =>
      patternMatches(haystack, pattern)
    );

    const context = {
      forms: $('form').length,
      passwordFields: $('input[type="password"]').length,
      inlineEventHandlers: $('*')
        .toArray()
        .reduce((count, el) => {
          const attribs = (el.attribs && Object.keys(el.attribs)) || [];
          return count + attribs.filter((name) => /^on[a-z]+$/i.test(name)).length;
        }, 0),
      externalScripts: $('script[src]').filter((i, el) => {
        const src = $(el).attr('src') || '';
        return /^https?:\/\//i.test(src);
      }).length,
      iframes: $('iframe').length,
      inlineScripts: $('script:not([src])').length,
      inputSurfaces: matchedSurfaces.length,
      inputSurfacePatterns: matchedSurfaces.slice(0, 8)
    };

    const penalty = findings.reduce(
      (total, item) => total + (SEVERITY_PENALTY[item.severity] ?? 5),
      0
    );
    const securityScore = Math.max(0, Math.min(100, 100 - penalty)) / 100;
    const riskLevel =
      securityScore >= 0.85 ? 'Low' : securityScore >= 0.6 ? 'Medium' : 'High';

    const insights = [];
    const addInsight = (insight, confidence, category) =>
      insights.push({ insight, confidence, category });

    if (findings.length === 0) {
      addInsight(
        'No issues were detected by the passive checks in this pass. Active payload tests only cover parameters exposed on this page.',
        0.6,
        'Coverage'
      );
    } else {
      addInsight(
        `${findings.length} finding(s) were confirmed or strongly indicated across ${
          scannerResults.filter((r) => (r.vulnerabilities || []).length > 0).length
        } scanner(s).`,
        0.9,
        'Correlation'
      );
    }

    if (context.passwordFields > 0 && !/^https:/i.test(url)) {
      addInsight(
        'A password field is present on a page served over HTTP. Credentials are exposed in transit.',
        0.95,
        'Authentication'
      );
    }

    if (context.forms > 0 && findings.some((f) => f.type === 'CSRF')) {
      addInsight(
        `${context.forms} form(s) were found and at least one state-changing form lacks a visible anti-CSRF token.`,
        0.75,
        'CSRF'
      );
    }

    if (context.inlineEventHandlers > 25) {
      addInsight(
        `${context.inlineEventHandlers} inline event handler attributes were found. Heavy inline JavaScript makes CSP hardening and code review harder.`,
        0.7,
        'Client-Side'
      );
    }

    if (context.externalScripts > 10) {
      addInsight(
        `${context.externalScripts} third-party scripts are loaded. Each one is a supply-chain trust decision.`,
        0.65,
        'Supply Chain'
      );
    }

    if (context.inputSurfaces >= 2) {
      const sample = [...new Set(matchedSurfaces.map(describeSurface))].slice(0, 4).join(', ');
      addInsight(
        `${context.inputSurfaces} input surface(s) were detected (${sample}). ${
          findings.length > 0
            ? 'These are the code paths most likely to share the flaws above, so review them first.'
            : 'Each one accepts user-controlled data that the automated probes only partially exercised.'
        }`,
        0.7,
        'Attack Surface'
      );
    }

    if (findings.some((f) => f.type === 'XSS' && f.category === 'Reflected XSS')) {
      addInsight(
        'A parameter reflects unencoded input. Any page sharing that template is likely to have the same flaw.',
        0.85,
        'Injection'
      );
    }

    if (findings.some((f) => f.type === 'SQL Injection')) {
      addInsight(
        'A database error was triggered by a quote character. Assume the underlying query is string-concatenated and audit every endpoint on that code path.',
        0.9,
        'Injection'
      );
    }

    const recommendations = [];
    const seen = new Set();
    for (const item of findings) {
      for (const text of item.recommendations || []) {
        if (seen.has(text)) continue;
        seen.add(text);
        recommendations.push({
          title: `${item.type} – ${item.category}`,
          priority: item.severity,
          detail: text
        });
      }
    }

    const priorityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    recommendations.sort(
      (a, b) => (priorityOrder[a.priority] ?? 9) - (priorityOrder[b.priority] ?? 9)
    );

    return {
      engine: `${this.name} v${this.version}`,
      method: 'Deterministic heuristic correlation (no external model calls)',
      riskLevel,
      securityScore,
      context,
      surfacePatterns: this.surfacePatterns.length,
      insights,
      recommendations: recommendations.slice(0, 20)
    };
  }
}

module.exports = { AIAnalysisEngine };
