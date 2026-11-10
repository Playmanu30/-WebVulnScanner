const cheerio = require('cheerio');
const { fetchPage } = require('../scanners/utils');

// Things that are never useful to a scanner and just generate traffic.
const SKIP_EXTENSIONS =
  /\.(?:jpe?g|png|gif|svg|webp|ico|bmp|css|js|mjs|map|woff2?|ttf|eot|pdf|zip|rar|7z|gz|tar|mp4|mp3|avi|mov|webm|wav|ogg|docx?|xlsx?|pptx?)$/i;

const SKIP_PATHS = /\/(?:logout|log-out|signout|sign-out|delete|remove)\b/i;

/**
 * Breadth-first, same-origin crawler.
 *
 * It exists so the probe scanners can test parameters that only appear on
 * inner pages. It deliberately stays on one origin, honours a page budget and
 * never submits a form.
 */
class Crawler {
  constructor() {
    this.name = 'Crawler';
    this.version = '2.2.1';
    this.fetchedScripts = new Set();
  }

  normalize(rawUrl, baseUrl) {
    try {
      const url = new URL(rawUrl, baseUrl);
      url.hash = '';
      return url;
    } catch {
      return null;
    }
  }

  isInScope(candidate, origin) {
    if (!candidate) return false;
    if (!/^https?:$/.test(candidate.protocol)) return false;
    return candidate.origin === origin;
  }

  isWorthFetching(candidate) {
    if (SKIP_EXTENSIONS.test(candidate.pathname)) return false;
    if (SKIP_PATHS.test(candidate.pathname)) return false;
    return true;
  }

  extractLinks(html, baseUrl, origin) {
    const $ = cheerio.load(html || '');
    const found = [];
    const seen = new Set();

    const add = (raw) => {
      const candidate = this.normalize(raw, baseUrl);
      if (!candidate) return;
      if (!this.isInScope(candidate, origin)) return;
      if (!this.isWorthFetching(candidate)) return;
      const key = candidate.toString();
      if (seen.has(key)) return;
      seen.add(key);
      found.push(candidate);
    };

    $('a[href]').each((i, el) => add($(el).attr('href')));
    $('form[action]').each((i, el) => add($(el).attr('action')));

    return found;
  }

  /**
   * Seeds the crawler with endpoints the HTML never links to: robots.txt
   * entries, sitemap.xml locations and an OpenAPI/Swagger document. All are
   * same-origin GETs and count against the normal page budget.
   */
  async discoverSeeds(start, options = {}) {
    const origin = start.origin;
    const seeds = new Map();

    const add = (raw) => {
      const candidate = this.normalize(raw, start.toString());
      if (!candidate) return;
      if (!this.isInScope(candidate, origin)) return;
      if (!this.isWorthFetching(candidate)) return;
      seeds.set(candidate.toString(), candidate);
    };

    const get = async (path) => {
      try {
        return await fetchPage(new URL(path, origin).toString(), {
          timeout: Math.min(options.timeout || 15000, 10000),
          maxRedirects: 2
        });
      } catch {
        return null;
      }
    };

    // robots.txt: sitemap references and allow/disallow paths.
    const robots = await get('/robots.txt');
    const sitemaps = [];
    if (robots && robots.status === 200 && !/<html/i.test(robots.html.slice(0, 200))) {
      for (const line of robots.html.split(/\r?\n/)) {
        const match = /^\s*(sitemap|allow|disallow)\s*:\s*(\S+)/i.exec(line);
        if (!match) continue;
        const [, directive, value] = match;
        if (directive.toLowerCase() === 'sitemap') {
          if (/^https?:/i.test(value)) sitemaps.push(value);
          continue;
        }
        if (value === '/' || value === '' || value.includes('*')) continue;
        add(value);
      }
    }
    sitemaps.push(new URL('/sitemap.xml', origin).toString());

    // sitemap.xml: <loc> entries, including nested sitemap indexes.
    for (const sitemap of [...new Set(sitemaps)].slice(0, 3)) {
      if (new URL(sitemap).origin !== origin) continue;
      const response = await get(sitemap);
      if (!response || response.status !== 200) continue;
      const locs = [...response.html.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)]
        .map((match) => match[1].replace(/&amp;/g, '&'))
        .slice(0, 25);
      for (const loc of locs) add(loc);
    }

    // Common OpenAPI/Swagger locations.
    const specPaths = [
      '/openapi.json',
      '/swagger.json',
      '/api-docs/swagger.json',
      '/v3/api-docs',
      '/api/openapi.json'
    ];
    for (const specPath of specPaths) {
      const response = await get(specPath);
      if (!response || response.status !== 200) continue;
      let spec;
      try {
        spec = JSON.parse(response.html);
      } catch {
        continue;
      }
      const base = this.openApiBase(spec, origin);
      if (!base) break;
      for (const apiPath of Object.keys(spec.paths || {}).slice(0, 40)) {
        add(new URL(apiPath.replace(/\{[^}]+\}/g, '1'), base).toString());
      }
      break;
    }

    return [...seeds.values()].slice(0, 25);
  }

  openApiBase(spec, origin) {
    const serverUrl = spec.servers && spec.servers[0] && spec.servers[0].url;
    if (serverUrl) {
      try {
        const parsed = new URL(serverUrl, origin);
        if (parsed.origin === origin) return parsed;
      } catch {
        return null;
      }
    }
    if (typeof spec.basePath === 'string' && spec.basePath.startsWith('/')) {
      return new URL(spec.basePath, origin);
    }
    return new URL('/', origin);
  }

  /**
   * Endpoint strings embedded in same-origin JavaScript bundles. SPAs keep their
   * API routes there, and the crawler would otherwise never see them.
   */
  async discoverFromScripts(html, baseUrl, origin, budget) {
    const $ = cheerio.load(html || '');
    const found = [];
    const seen = new Set();

    const scripts = $('script[src]')
      .map((i, el) => $(el).attr('src'))
      .get()
      .map((src) => this.normalize(src, baseUrl))
      .filter((url) => url && url.origin === origin)
      .slice(0, budget);

    for (const script of scripts) {
      const key = script.toString();
      if (this.fetchedScripts.has(key)) continue;
      this.fetchedScripts.add(key);

      let response;
      try {
        response = await fetchPage(key, { timeout: 10000, maxRedirects: 2 });
      } catch {
        continue;
      }
      if (response.status !== 200) continue;

      for (const match of response.html.matchAll(/["'`](\/[a-z0-9][a-z0-9\-_/]{2,}(?:\?[^"'`\s]*)?)["'`]/gi)) {
        const raw = match[1];
        if (/\.(?:png|jpe?g|gif|svg|css|woff2?|ttf|ico)$/i.test(raw)) continue;
        const candidate = this.normalize(raw, origin);
        if (!candidate || candidate.origin !== origin) continue;
        if (!this.isWorthFetching(candidate)) continue;
        const candidateKey = candidate.toString();
        if (seen.has(candidateKey)) continue;
        seen.add(candidateKey);
        found.push(candidate);
      }
    }

    return found.slice(0, 20);
  }

  async crawl(startUrl, options = {}) {
    const maxPages = Math.max(1, options.maxPages ?? 12);
    const maxDepth = Math.max(0, options.maxDepth ?? 2);
    const start = new URL(startUrl);
    const origin = start.origin;

    const queue = [{ url: start, depth: 0 }];
    const visited = new Set([start.toString()]);
    const pages = [];
    this.fetchedScripts = new Set();

    if (options.discovery !== false) {
      let seeds = [];
      try {
        seeds = await this.discoverSeeds(start, options);
      } catch (error) {
        console.warn(`[crawler] discovery failed: ${error.message}`);
      }
      for (const seed of seeds) {
        const key = seed.toString();
        if (visited.has(key)) continue;
        visited.add(key);
        queue.push({ url: seed, depth: 1 });
      }
      if (seeds.length > 0) console.log(`[crawler] ${seeds.length} endpoint(s) from robots/sitemap/openapi`);
    }

    while (queue.length > 0 && pages.length < maxPages) {
      if (options.isCancelled && options.isCancelled()) break;

      const current = queue.shift();
      const currentUrl = current.url.toString();
      let page;
      try {
        // Redirects are followed by hand so the redirecting URL keeps its own
        // entry. That URL is usually the interesting one: /go?next=..., /out?url=...
        page = await fetchPage(currentUrl, {
          timeout: options.timeout || 15000,
          redirect: false
        });
      } catch (error) {
        pages.push({
          url: currentUrl,
          finalUrl: currentUrl,
          status: 0,
          headers: {},
          html: '',
          depth: current.depth,
          error: error.message
        });
        continue;
      }

      if (page.status >= 300 && page.status < 400 && page.headers.location) {
        const target = this.normalize(page.headers.location, currentUrl);

        pages.push({
          url: currentUrl,
          finalUrl: target ? target.toString() : currentUrl,
          status: page.status,
          headers: page.headers,
          html: '',
          depth: current.depth,
          redirectTo: target ? target.toString() : null,
          timeMs: page.timeMs
        });

        if (typeof options.onPage === 'function') {
          options.onPage(pages[pages.length - 1], pages.length, maxPages);
        }

        // Follow the destination at the same depth, so a redirect hop does not
        // consume the crawl budget.
        if (target && this.isInScope(target, origin) && this.isWorthFetching(target)) {
          const key = target.toString();
          if (!visited.has(key)) {
            visited.add(key);
            queue.unshift({ url: target, depth: current.depth });
          }
        }
        continue;
      }

      const contentType = String(page.headers['content-type'] || '');
      const isHtml = contentType === '' || /text\/html|application\/xhtml/i.test(contentType);

      pages.push({
        url: currentUrl,
        finalUrl: page.finalUrl,
        status: page.status,
        headers: page.headers,
        html: isHtml ? page.html : '',
        depth: current.depth,
        timeMs: page.timeMs
      });

      if (typeof options.onPage === 'function') {
        options.onPage(pages[pages.length - 1], pages.length, maxPages);
      }

      if (!isHtml || current.depth >= maxDepth) continue;

      const links = this.extractLinks(page.html, currentUrl, origin);

      if (options.discovery !== false && this.fetchedScripts.size < 12) {
        try {
          const scriptLinks = await this.discoverFromScripts(page.html, currentUrl, origin, 2);
          links.push(...scriptLinks);
        } catch (error) {
          console.warn(`[crawler] script discovery failed: ${error.message}`);
        }
      }

      for (const link of links) {
        const key = link.toString();
        if (visited.has(key)) continue;
        visited.add(key);
        queue.push({ url: link, depth: current.depth + 1 });
      }
    }

    return pages;
  }
}

module.exports = { Crawler };
