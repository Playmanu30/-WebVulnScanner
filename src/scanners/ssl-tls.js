const tls = require('tls');
const { loadList } = require('../core/config-loader');
const { fetchPage, finding, dedupeFindings } = require('./utils');

const WEAK_CIPHER_RE = /(RC4|3DES|DES_CBC|NULL|EXPORT|MD5)/i;
const WEAK_PROTOCOLS = ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'];

class SSLTLSAnalyzer {
  constructor() {
    this.name = 'SSL/TLS Analyzer';
    this.description =
      'Inspects the live TLS handshake: certificate validity, protocol version, cipher strength and HTTPS enforcement.';
    this.version = '2.2.1';
    this.cipherSuites = [];
    this.configSource = 'defaults';
  }

  async initialize() {
    const { values, source } = loadList('ssl-patterns.json', ['cipherSuites', 'patterns'], []);
    this.cipherSuites = values;
    this.configSource = source;
    console.log(`[ssl-tls] ${this.cipherSuites.length} known ciphers (config: ${this.configSource})`);
  }

  async scan(url, options = {}) {
    const started = Date.now();
    const vulnerabilities = [];
    const parsed = new URL(url);

    if (parsed.protocol !== 'https:') {
      vulnerabilities.push(
        finding({
          type: 'SSL/TLS',
          severity: 'High',
          category: 'No Transport Encryption',
          description:
            'The target is served over plain HTTP. Traffic, cookies and credentials can be read or modified by anyone on the path.',
          evidence: url,
          url,
          confidence: 0.95,
          recommendations: [
            'Serve the site over HTTPS with a valid certificate and redirect all HTTP traffic.'
          ]
        })
      );

      const redirect = await this.checkHttpsRedirect(url, options);
      if (redirect && redirect.redirectsToHttps) {
        vulnerabilities.push(
          finding({
            type: 'SSL/TLS',
            severity: 'Low',
            category: 'HTTPS Redirect Present',
            description: `Plain HTTP redirects to ${redirect.location}, but the initial request is still unencrypted.`,
            evidence: `HTTP ${redirect.status} -> ${redirect.location}`,
            url,
            confidence: 0.9,
            recommendations: ['Add Strict-Transport-Security once HTTPS is enforced.']
          })
        );
      }

      return {
        url,
        status: 'complete',
        scanner: this.name,
        vulnerabilities,
        details: { protocol: 'http', tls: null },
        scanTime: Date.now() - started
      };
    }

    let handshake;
    try {
      handshake = await this.inspectTls(parsed.hostname, parsed.port ? Number(parsed.port) : 443, options.timeout);
    } catch (error) {
      return {
        url,
        status: 'error',
        scanner: this.name,
        error: `TLS handshake failed: ${error.message}`,
        scanTime: Date.now() - started
      };
    }

    const { protocol, cipher, cert, authorized, authorizationError } = handshake;

    if (WEAK_PROTOCOLS.includes(protocol)) {
      vulnerabilities.push(
        finding({
          type: 'SSL/TLS',
          severity: 'High',
          category: 'Obsolete TLS Version',
          description: `The server negotiated ${protocol}, which is deprecated and has known weaknesses.`,
          evidence: `negotiated protocol: ${protocol}`,
          url,
          confidence: 0.95,
          recommendations: ['Disable TLS 1.0/1.1 and SSLv3; require TLS 1.2 or newer (ideally 1.3).']
        })
      );
    }

    if (cipher && WEAK_CIPHER_RE.test(cipher.name || '')) {
      vulnerabilities.push(
        finding({
          type: 'SSL/TLS',
          severity: 'High',
          category: 'Weak Cipher Suite',
          description: `The negotiated cipher ${cipher.name} uses a weak primitive.`,
          evidence: `cipher: ${cipher.name} (${cipher.version || protocol})`,
          url,
          confidence: 0.9,
          recommendations: ['Restrict the server to AEAD suites (AES-GCM or ChaCha20-Poly1305) with ECDHE.']
        })
      );
    }

    if (cert && cert.valid_to) {
      const expires = new Date(cert.valid_to);
      const daysLeft = Math.floor((expires.getTime() - Date.now()) / 86400000);
      if (Number.isNaN(expires.getTime())) {
        // ignore unparseable dates
      } else if (daysLeft < 0) {
        vulnerabilities.push(
          finding({
            type: 'SSL/TLS',
            severity: 'High',
            category: 'Expired Certificate',
            description: `The TLS certificate expired on ${expires.toISOString().slice(0, 10)}. Browsers show a full-page warning, so users are trained to click through.`,
            evidence: `valid_to: ${cert.valid_to}`,
            url,
            confidence: 0.99,
            recommendations: ['Renew the certificate and automate renewal.']
          })
        );
      } else if (daysLeft <= 30) {
        vulnerabilities.push(
          finding({
            type: 'SSL/TLS',
            severity: 'Medium',
            category: 'Certificate Expiring Soon',
            description: `The TLS certificate expires in ${daysLeft} day(s) (${expires.toISOString().slice(0, 10)}).`,
            evidence: `valid_to: ${cert.valid_to}`,
            url,
            confidence: 0.95,
            recommendations: ['Automate certificate renewal (ACME) and alert before expiry.']
          })
        );
      }
    }

    if (authorized === false) {
      vulnerabilities.push(
        finding({
          type: 'SSL/TLS',
          severity: 'High',
          category: 'Certificate Validation Failed',
          description: `Node rejected the certificate chain (${authorizationError}). This usually means a self-signed, incomplete or mismatched certificate.`,
          evidence: `authorizationError: ${authorizationError}`,
          url,
          confidence: 0.85,
          recommendations: ['Install the full intermediate chain and a certificate matching the hostname.']
        })
      );
    }

    return {
      url,
      status: 'complete',
      scanner: this.name,
      vulnerabilities: dedupeFindings(vulnerabilities),
      details: {
        protocol,
        cipher: cipher ? { name: cipher.name, version: cipher.version } : null,
        subject: cert?.subject?.CN || null,
        issuer: cert?.issuer?.CN || null,
        validFrom: cert?.valid_from || null,
        validTo: cert?.valid_to || null,
        authorized,
        authorizationError: authorizationError || null
      },
      scanTime: Date.now() - started
    };
  }

  inspectTls(hostname, port, timeout = 10000) {
    return new Promise((resolve, reject) => {
      const socket = tls.connect(
        { host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout },
        () => {
          const cert = socket.getPeerCertificate() || {};
          resolve({
            protocol: socket.getProtocol(),
            cipher: socket.getCipher(),
            cert,
            authorized: socket.authorized,
            authorizationError: socket.authorizationError
          });
          socket.end();
        }
      );

      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('connection timed out'));
      });
      socket.on('error', (error) => {
        socket.destroy();
        reject(error);
      });
    });
  }

  async checkHttpsRedirect(url, options) {
    try {
      const secure = url.replace(/^http:/i, 'https:');
      const response = await fetchPage(url, { ...options, maxRedirects: 0 });
      const location = response.headers.location || response.headers.Location;
      if ([301, 302, 307, 308].includes(response.status) && location && /^https:/i.test(location)) {
        return { status: response.status, location, redirectsToHttps: true };
      }
      // Some servers redirect straight to the https variant of the same URL.
      if ([301, 302, 307, 308].includes(response.status) && location && location === secure) {
        return { status: response.status, location, redirectsToHttps: true };
      }
      return { status: response.status, location: location || null, redirectsToHttps: false };
    } catch {
      return null;
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

module.exports = { SSLTLSAnalyzer };
