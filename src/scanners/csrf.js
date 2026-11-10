const cheerio = require('cheerio');
const { loadList } = require('../core/config-loader');
const { fetchPage, finding, dedupeFindings } = require('./utils');

const TOKEN_NAME_RE = /(csrf|xsrf|_token|authenticity_token|__requestverificationtoken|nonce)/i;
const SENSITIVE_ACTION_RE = /(delete|remove|update|edit|change|profile|settings|account|admin|transfer|payment|checkout|subscribe)/i;
const LOGIN_ACTION_RE = /(login|signin|sign-in|register|signup|sign-up|auth)/i;
const SESSION_COOKIE_RE = /(session|sessid|sid|auth|token|jwt)/i;

class CSRFDetector {
  constructor() {
    this.name = 'CSRF Detector';
    this.description =
      'Audits state-changing forms for anti-CSRF tokens and inspects session cookies for SameSite protection.';
    this.version = '2.2.1';
    this.csrfPatterns = [];
    this.configSource = 'defaults';
    this.runsPerPage = true;
    this.pageLimit = 4;
  }

  async initialize() {
    const { values, source } = loadList(
      'csrf-patterns.json',
      ['patterns'],
      ['csrf', 'xsrf', '_token', 'authenticity_token']
    );
    this.csrfPatterns = values;
    this.configSource = source;
    console.log(`[csrf] ${this.csrfPatterns.length} token patterns (config: ${this.configSource})`);
  }

  async scan(url, options = {}) {
    const started = Date.now();
    const page = options.page || (await fetchPage(url, options));
    const html = page.html || '';
    const vulnerabilities = [];

    let analysis = { totalForms: 0, postForms: 0, protectedForms: 0, unprotectedForms: 0, hasMetaToken: false };
    try {
      analysis = this.analyzeForms(html);
    } catch (error) {
      return { url, status: 'error', scanner: this.name, error: error.message };
    }

    for (const form of analysis.unprotected) {
      const isLogin = LOGIN_ACTION_RE.test(form.action);
      const sensitive = !isLogin && SENSITIVE_ACTION_RE.test(`${form.action} ${form.fields.join(' ')}`);
      const severity = sensitive ? 'High' : 'Medium';
      vulnerabilities.push(
        finding({
          type: 'CSRF',
          severity,
          category: isLogin ? 'Login Form Without Anti-CSRF Token' : 'Missing Anti-CSRF Token',
          description: `A ${
            form.method
          } form${sensitive ? ' that appears to change account state' : isLogin ? ' that authenticates a user' : ''} has no visible anti-CSRF token.${
            isLogin
              ? ' This enables login-CSRF, where a victim is silently signed into an attacker account.'
              : " A cross-site request could submit it with the victim's cookies."
          }`,
          evidence: `${form.method} ${form.action} (fields: ${form.fields.join(', ') || 'none'})`,
          url,
          confidence: sensitive ? 0.8 : 0.6,
          recommendations: [
            'Issue a per-session, unpredictable CSRF token and validate it server-side.',
            'Set SameSite=Lax or Strict on session cookies.',
            'Verify the Origin/Referer header on state-changing requests.'
          ]
        })
      );
    }

    const cookies = [].concat(page.headers['set-cookie'] || []);
    for (const cookie of cookies) {
      const name = String(cookie).split('=')[0].trim();
      if (!SESSION_COOKIE_RE.test(name)) continue;
      if (/samesite\s*=\s*(lax|strict)/i.test(cookie)) continue;
      vulnerabilities.push(
        finding({
          type: 'CSRF',
          severity: 'Low',
          category: 'Session Cookie Without SameSite',
          description: `Session cookie "${name}" does not set SameSite=Lax/Strict, so it can be attached to cross-site requests in browsers that do not default to Lax.`,
          evidence: `${name}=... (no SameSite attribute)`,
          url,
          confidence: 0.65,
          recommendations: ['Add SameSite=Lax (or Strict) to session cookies.']
        })
      );
    }

    if (analysis.postForms > 0 && analysis.protectedForms === 0 && analysis.unprotected.length === 0) {
      vulnerabilities.push(
        finding({
          type: 'CSRF',
          severity: 'Low',
          category: 'CSRF Protection Not Verifiable',
          description:
            'POST forms exist but no token inputs were visible. Protection may be enforced through a header or cookie that cannot be verified from a single page.',
          evidence: `${analysis.postForms} POST form(s) observed`,
          url,
          confidence: 0.4,
          recommendations: ['Confirm server-side CSRF validation for every state-changing endpoint.']
        })
      );
    }

    return {
      url,
      status: 'complete',
      scanner: this.name,
      vulnerabilities: dedupeFindings(vulnerabilities),
      details: {
        statusCode: page.status,
        totalForms: analysis.totalForms,
        postForms: analysis.postForms,
        protectedForms: analysis.protectedForms,
        unprotectedForms: analysis.unprotectedForms,
        metaTokenPresent: analysis.hasMetaToken,
        cookiesObserved: cookies.length
      },
      scanTime: Date.now() - started
    };
  }

  analyzeForms(html) {
    const $ = cheerio.load(html);
    const hasMetaToken =
      $('meta[name*="csrf" i], meta[name*="xsrf" i]').length > 0 ||
      html.toLowerCase().includes('csrf-token');

    const forms = [];
    $('form').each((i, form) => {
      const method = ($(form).attr('method') || 'GET').toUpperCase();
      const action = $(form).attr('action') || '(same page)';
      const fields = [];
      let hasToken = false;

      $(form)
        .find('input[name], textarea[name], select[name]')
        .each((j, field) => {
          const name = $(field).attr('name');
          if (!name) return;
          fields.push(name);
          if (TOKEN_NAME_RE.test(name)) hasToken = true;
        });

      const tokenInForm = hasToken || $(form).find('input[type="hidden"]').toArray().some((el) => {
        const value = String($(el).attr('value') || '');
        return value.length >= 20 && /^[A-Za-z0-9+/=_-]+$/.test(value) && TOKEN_NAME_RE.test($(el).attr('name') || '');
      });

      forms.push({ method, action, fields, hasToken: tokenInForm });
    });

    const postForms = forms.filter((f) => f.method === 'POST');
    const protectedForms = forms.filter((f) => f.hasToken);
    const unprotected = postForms.filter((f) => !f.hasToken);

    return {
      totalForms: forms.length,
      postForms: postForms.length,
      protectedForms: protectedForms.length,
      unprotectedForms: unprotected.length,
      unprotected,
      hasMetaToken
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

module.exports = { CSRFDetector };
