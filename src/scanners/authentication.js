const cheerio = require('cheerio');
const { fetchPage, finding, dedupeFindings } = require('./utils');

const SESSION_COOKIE_RE = /(session|sessid|sid|auth|token|jwt|remember)/i;

class AuthenticationChecker {
  constructor() {
    this.name = 'Authentication Checker';
    this.description =
      'Reviews login forms, session cookies and transport security for authentication weaknesses.';
    this.version = '2.2.1';
    this.authPatterns = [];
    this.configSource = 'defaults';
    this.runsPerPage = true;
    this.pageLimit = 4;
  }

  async initialize() {
    const { loadList } = require('../core/config-loader');
    const { values, source } = loadList(
      'auth-patterns.json',
      ['patterns'],
      ['HttpOnly', 'Secure', 'SameSite']
    );
    this.authPatterns = values;
    this.configSource = source;
    console.log(`[authentication] ${this.authPatterns.length} patterns (config: ${this.configSource})`);
  }

  async scan(url, options = {}) {
    const started = Date.now();
    const page = options.page || (await fetchPage(url, options));
    const html = page.html || '';
    const vulnerabilities = [];
    const isHttps = /^https:/i.test(url);

    let formInfo;
    try {
      formInfo = this.analyzeForms(html, url);
    } catch (error) {
      return { url, status: 'error', scanner: this.name, error: error.message };
    }

    // 1. Credentials posted over plain HTTP
    if (formInfo.hasPasswordField && formInfo.insecureAction) {
      vulnerabilities.push(
        finding({
          type: 'Authentication',
          severity: 'High',
          category: 'Credentials Over Cleartext',
          description:
            'A form containing a password field submits to an http:// URL. Credentials would travel unencrypted.',
          evidence: `form action: ${formInfo.insecureAction}`,
          url,
          confidence: 0.95,
          recommendations: ['Serve the login form and its action over HTTPS only.']
        })
      );
    }

    // 2. The page itself is served over HTTP and contains a password field
    if (!isHttps && formInfo.hasPasswordField) {
      vulnerabilities.push(
        finding({
          type: 'Authentication',
          severity: 'High',
          category: 'Login Page Over HTTP',
          description:
            'The login page is served over plain HTTP. Passwords and session cookies can be intercepted or modified in transit.',
          evidence: `Page URL: ${url}`,
          url,
          confidence: 0.95,
          recommendations: ['Force HTTPS for the whole site and redirect HTTP requests.']
        })
      );
    }

    // 3. Session cookie flags
    const cookies = [].concat(page.headers['set-cookie'] || []);
    for (const raw of cookies) {
      const cookie = String(raw);
      const name = cookie.split('=')[0].trim();
      if (!SESSION_COOKIE_RE.test(name)) continue;

      const missing = [];
      if (!/httponly/i.test(cookie)) missing.push('HttpOnly');
      if (!/;\s*secure/i.test(cookie) && isHttps) missing.push('Secure');
      if (!/samesite/i.test(cookie)) missing.push('SameSite');

      if (missing.length === 0) continue;
      vulnerabilities.push(
        finding({
          type: 'Authentication',
          severity: missing.includes('HttpOnly') ? 'Medium' : 'Low',
          category: 'Insecure Session Cookie',
          description: `Session cookie "${name}" is missing the ${missing.join(', ')} flag(s), which exposes it to script access, plaintext transport or cross-site sending.`,
          evidence: `${name}=... (missing: ${missing.join(', ')})`,
          url,
          confidence: 0.8,
          recommendations: [
            'Set HttpOnly, Secure and SameSite=Lax/Strict on all session cookies.'
          ]
        })
      );
    }

    // 4. Session identifier carried in the URL
    if (/(?:^|[?&;])(phpsessid|jsessionid|sessionid|sessid|aspsessionid)=/i.test(url)) {
      vulnerabilities.push(
        finding({
          type: 'Authentication',
          severity: 'High',
          category: 'Session ID In URL',
          description:
            'The session identifier is part of the URL. URLs leak through Referer headers, logs and shared links.',
          evidence: url.replace(/((?:^|[?&;])(?:phpsessid|jsessionid|sessionid|sessid|aspsessionid)=)[^&;]*/i, '$1[redacted]'),
          url,
          confidence: 0.9,
          recommendations: ['Keep session identifiers in cookies only.']
        })
      );
    }

    // 5. HTTP Basic authentication
    if (page.status === 401 && /basic/i.test(String(page.headers['www-authenticate'] || ''))) {
      vulnerabilities.push(
        finding({
          type: 'Authentication',
          severity: 'Medium',
          category: 'HTTP Basic Authentication',
          description:
            'The server uses HTTP Basic authentication. Credentials are only encoded, not encrypted, and cannot be revoked per session.',
          evidence: `WWW-Authenticate: ${page.headers['www-authenticate']}`,
          url,
          confidence: 0.85,
          recommendations: [
            'Use a session-based login flow over HTTPS, or a proper SSO/OIDC provider.'
          ]
        })
      );
    }

    // 6. Password field without autocomplete hints (minor)
    if (formInfo.hasPasswordField && formInfo.passwordAutocompleteMissing) {
      vulnerabilities.push(
        finding({
          type: 'Authentication',
          severity: 'Low',
          category: 'Password Manager Hints Missing',
          description:
            'The password input has no autocomplete attribute, which discourages password managers from filling strong credentials.',
          evidence: formInfo.passwordFieldEvidence,
          url,
          confidence: 0.6,
          recommendations: ['Add autocomplete="current-password" (login) or "new-password" (registration).']
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
        hasLoginForm: formInfo.hasPasswordField,
        formCount: formInfo.formCount,
        passwordFieldCount: formInfo.passwordFields,
        cookiesObserved: cookies.length
      },
      scanTime: Date.now() - started
    };
  }

  analyzeForms(html, baseUrl) {
    const $ = cheerio.load(html);
    const passwordInputs = $('input[type="password"]');
    const loginForm = passwordInputs.first().closest('form');
    let insecureAction = null;
    let passwordAutocompleteMissing = false;

    if (passwordInputs.length > 0) {
      const first = passwordInputs.first();
      const autocomplete = String(first.attr('autocomplete') || '');
      passwordAutocompleteMissing = autocomplete !== 'current-password' && autocomplete !== 'new-password';
    }

    const action = loginForm.attr('action');
    if (action && /^http:\/\//i.test(action)) insecureAction = action;

    return {
      formCount: $('form').length,
      passwordFields: passwordInputs.length,
      hasPasswordField: passwordInputs.length > 0,
      passwordAutocompleteMissing,
      passwordFieldEvidence: passwordInputs.first().attr('name')
        ? `input[name="${passwordInputs.first().attr('name')}"] has no usable autocomplete attribute`
        : 'password input without autocomplete attribute',
      insecureAction
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

module.exports = { AuthenticationChecker };
