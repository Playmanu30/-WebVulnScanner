const axios = require('axios');
const cheerio = require('cheerio');
const os = require('os');

const DEFAULT_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ' +
  'Chrome/120.0 Safari/537.36 AI-VulnScanner/2.2.1';

const DEFAULT_HEADERS = {
  'User-Agent': DEFAULT_UA,
  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9'
};

// A shared, global rate limit. Every request in the process goes through
// fetchPage(), so this keeps a scan polite without threading a limiter through
// twelve scanners.
let requestDelayMs = 40;
let lastRequestAt = 0;

function setRequestDelay(ms) {
  requestDelayMs = Math.max(0, Number(ms) || 0);
}

async function throttle() {
  if (requestDelayMs <= 0) return;
  const wait = lastRequestAt + requestDelayMs - Date.now();
  if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
  lastRequestAt = Date.now();
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
}

// Authentication is applied centrally so every scanner inherits it. Credentials
// are only attached to requests whose origin matches the scan target, and a
// redirect that leaves that origin is not followed (no credential leak).
let authState = { origin: null, headers: {}, cookies: '' };

function setAuth(auth = {}) {
  const headers = {};
  for (const [name, value] of Object.entries(auth.headers || {})) {
    if (typeof value === 'string') headers[name] = value;
  }
  authState = {
    origin: auth.origin || null,
    headers,
    cookies: typeof auth.cookies === 'string' ? auth.cookies.trim() : ''
  };
}

function clearAuth() {
  authState = { origin: null, headers: {}, cookies: '' };
}

function getAuth() {
  return { ...authState, headers: { ...authState.headers } };
}

function authApplies(url) {
  if (!authState.origin) return false;
  try {
    return new URL(url).origin === authState.origin;
  } catch {
    return false;
  }
}

function requestHeaders(url, extra) {
  const headers = { ...DEFAULT_HEADERS, ...(extra || {}) };
  if (!authApplies(url)) return headers;

  for (const [name, value] of Object.entries(authState.headers)) {
    if (!Object.keys(headers).some((existing) => existing.toLowerCase() === name.toLowerCase())) {
      headers[name] = value;
    }
  }
  if (authState.cookies && !Object.keys(headers).some((name) => name.toLowerCase() === 'cookie')) {
    headers.Cookie = authState.cookies;
  }
  return headers;
}

/**
 * Fetch a page without throwing on 4xx/5xx so header/cookie checks still work.
 * Pass `redirect: false` (or maxRedirects: 0) when a 30x Location header is the
 * interesting part, as with open-redirect testing.
 *
 * Redirects are followed by hand so an authenticated scan never forwards its
 * Cookie/Authorization header to another origin.
 */
async function fetchPage(url, options = {}) {
  const started = Date.now();
  const noRedirect = options.redirect === false;
  const maxRedirects = noRedirect ? 0 : options.maxRedirects === undefined ? 5 : options.maxRedirects;
  const method = (options.method || 'GET').toUpperCase();

  let currentUrl = url;
  let currentMethod = method;
  let currentBody = options.body;
  let response = null;

  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    await throttle();
    const headers = requestHeaders(currentUrl, options.headers);
    if (hop > 0 && currentMethod === 'GET') {
      // A redirect that turned the request into a GET has no payload.
      delete headers['Content-Type'];
      delete headers['content-type'];
    }

    response = await axios.request(currentUrl, {
      method: currentMethod,
      data: currentBody,
      timeout: options.timeout || 15000,
      maxRedirects: 0,
      headers,
      responseType: 'text',
      transformResponse: [(data) => data],
      validateStatus: () => true,
      maxContentLength: 5 * 1024 * 1024,
      maxBodyLength: 5 * 1024 * 1024
    });

    const location = response.headers.location;
    const isRedirect = [301, 302, 303, 307, 308].includes(response.status) && location;
    if (noRedirect || !isRedirect || hop === maxRedirects) break;

    let nextUrl;
    try {
      nextUrl = new URL(location, currentUrl).toString();
    } catch {
      break;
    }

    // Never carry credentials or the scan off the target origin.
    if (authState.origin) {
      let nextOrigin = null;
      try {
        nextOrigin = new URL(nextUrl).origin;
      } catch {
        nextOrigin = null;
      }
      if (nextOrigin !== authState.origin) break;
    }

    if (response.status === 303 || ((response.status === 301 || response.status === 302) && currentMethod !== 'HEAD')) {
      currentMethod = 'GET';
      currentBody = undefined;
    }
    currentUrl = nextUrl;
  }

  const html = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
  return {
    url,
    finalUrl: currentUrl,
    status: response.status,
    headers: response.headers || {},
    html: html || '',
    timeMs: Date.now() - started
  };
}

/** First non-internal IPv4 address, used for out-of-band SSRF canaries. */
function getLanAddress() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const address of interfaces[name] || []) {
      if (address.family !== 'IPv4' || address.internal) continue;
      if (/^169\.254\./.test(address.address)) continue;
      return address.address;
    }
  }
  return null;
}


function finding(fields) {
  return {
    type: 'Vulnerability',
    severity: 'Medium',
    category: 'General',
    description: '',
    evidence: null,
    url: null,
    confidence: 0.75,
    recommendations: [],
    ...fields
  };
}

function toArray(value) {
  return Array.isArray(value) ? value : [];
}

/**
 * Collect parameters worth probing: those already in the URL plus GET form inputs.
 */
function collectParameters(url, html, limit = 5) {
  const seen = new Set();
  const params = [];

  const add = (name, value, source) => {
    if (!name || seen.has(name)) return;
    seen.add(name);
    params.push({ name, value: value === undefined ? '1' : value, source });
  };

  try {
    const parsed = new URL(url);
    for (const [name, value] of parsed.searchParams) add(name, value, 'url');
  } catch {
    // ignore malformed URLs, axios will surface the error
  }

  if (html) {
    try {
      const $ = cheerio.load(html);
      $('form').each((i, form) => {
        const method = ($(form).attr('method') || 'GET').toUpperCase();
        if (method !== 'GET') return;
        $(form)
          .find('input[name], select[name], textarea[name]')
          .each((j, input) => {
            const type = ($(input).attr('type') || 'text').toLowerCase();
            if (['submit', 'button', 'image', 'reset', 'file', 'password'].includes(type)) return;
            add($(input).attr('name'), $(input).attr('value') || '1', 'form');
          });
      });
    } catch {
      // non-HTML body
    }
  }

  return params.slice(0, limit);
}

function setParameter(url, name, value) {
  const parsed = new URL(url);
  parsed.searchParams.set(name, value);
  return parsed.toString();
}

/**
 * Add parameter names that are not visible on the page. Many endpoints accept
 * a parameter the UI never renders, which is exactly where parsers and
 * reflected values hide.
 */
function guessParameters(url, existingNames, wordlist, count = 4) {
  const taken = new Set(existingNames);
  const guessed = [];

  for (const name of wordlist) {
    if (guessed.length >= count) break;
    if (taken.has(name)) continue;
    taken.add(name);
    guessed.push({ name, value: '1', source: 'guessed' });
  }

  return guessed;
}

/** Every parameter to test: found ones first, then a few guesses. */
function parametersToTest(url, html, options = {}) {
  const limit = options.limit ?? 6;
  const found = collectParameters(url, html, limit);
  if (options.guess === false) return found;

  const wordlist = options.wordlist || [];
  const guessCount = Math.max(0, Math.min(options.guessCount ?? 4, limit - found.length));
  const guessed = guessParameters(url, found.map((p) => p.name), wordlist, guessCount);

  return [...found, ...guessed];
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];

function normalizeSeverity(value) {
  const candidate = String(value || '').toLowerCase();
  const match = SEVERITY_ORDER.find((s) => s.toLowerCase() === candidate);
  return match || 'Medium';
}

/**
 * Merge findings that are identical (same type + evidence) to keep counts honest.
 */
function dedupeFindings(findings) {
  const seen = new Set();
  const result = [];
  for (const item of findings) {
    const key = `${item.type}|${item.severity}|${item.evidence || ''}|${item.description || ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(item);
  }
  return result;
}

module.exports = {
  DEFAULT_HEADERS,
  fetchPage,
  finding,
  toArray,
  collectParameters,
  guessParameters,
  parametersToTest,
  setParameter,
  escapeRegExp,
  normalizeSeverity,
  dedupeFindings,
  setRequestDelay,
  setAuth,
  clearAuth,
  getAuth,
  getLanAddress,
  sleep,
  SEVERITY_ORDER
};
