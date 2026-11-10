const { fetchPage, finding, dedupeFindings } = require('./utils');

// Each entry must have a content signature: a 200 response alone proves
// nothing, since many apps return 200 with a friendly "not found" page.
const TARGETS = [
  {
    path: '/.env',
    severity: 'Critical',
    category: 'Exposed Environment File',
    signature: /^\s*[A-Z][A-Z0-9_]{2,}\s*=\s*\S+/m,
    description:
      'A .env file is publicly readable. It usually contains database credentials, API keys and application secrets.',
    recommendation: 'Serve only the public directory, and block dotfiles at the web-server level.'
  },
  {
    path: '/.git/config',
    severity: 'High',
    category: 'Exposed Git Repository',
    signature: /\[core\]/i,
    description:
      'The .git directory is served publicly. The full source history — including deleted secrets — can be reconstructed from it.',
    recommendation: 'Block /.git/ in the web server and deploy without the repository metadata.'
  },
  {
    path: '/.git/HEAD',
    severity: 'Medium',
    category: 'Exposed Git Repository',
    signature: /^ref:\s+refs\//m,
    description: 'Git metadata is reachable, confirming the repository is deployed and downloadable.',
    recommendation: 'Block /.git/ in the web server.'
  },
  {
    path: '/.svn/entries',
    severity: 'Medium',
    category: 'Exposed SVN Metadata',
    signature: /^\d+\s*$/m,
    description: 'Subversion metadata is exposed, which can leak source files and repository paths.',
    recommendation: 'Block /.svn/ in the web server.'
  },
  {
    path: '/.aws/credentials',
    severity: 'Critical',
    category: 'Exposed Cloud Credentials',
    signature: /aws_access_key_id/i,
    description: 'An AWS credential file is publicly readable.',
    recommendation: 'Remove the file from the document root and rotate the affected keys immediately.'
  },
  {
    path: '/.htaccess',
    severity: 'Low',
    category: 'Exposed Server Config',
    signature: /(RewriteEngine|AuthType|Require\s+valid-user)/i,
    description: 'The Apache .htaccess file is downloadable, leaking rewrite and access-control rules.',
    recommendation: 'Deny access to dotfiles in the web-server configuration.'
  },
  {
    path: '/web.config',
    severity: 'High',
    category: 'Exposed Server Config',
    signature: /<configuration[\s>]/i,
    description: 'The IIS web.config file is downloadable and may contain connection strings.',
    recommendation: 'Deny access to web.config and move secrets out of it.'
  },
  {
    path: '/docker-compose.yml',
    severity: 'High',
    category: 'Exposed Deployment Config',
    signature: /^services:/m,
    description: 'A Docker Compose file is served, exposing service topology, image tags and environment variables.',
    recommendation: 'Deploy build artefacts only; never ship compose files to the document root.'
  },
  {
    path: '/phpinfo.php',
    severity: 'Medium',
    category: 'Exposed Debug Page',
    signature: /PHP Version\s*=>/i,
    description: 'A phpinfo() page is reachable and discloses paths, modules and environment variables.',
    recommendation: 'Delete diagnostic pages from production.'
  },
  {
    path: '/info.php',
    severity: 'Medium',
    category: 'Exposed Debug Page',
    signature: /PHP Version\s*=>/i,
    description: 'A phpinfo() page is reachable and discloses paths, modules and environment variables.',
    recommendation: 'Delete diagnostic pages from production.'
  },
  {
    path: '/server-status',
    severity: 'Medium',
    category: 'Exposed Server Status',
    signature: /Apache Server Status/i,
    description: 'Apache mod_status is public, exposing live request URLs, client IPs and internal paths.',
    recommendation: 'Restrict /server-status to localhost or remove mod_status.'
  },
  {
    path: '/server-info',
    severity: 'Medium',
    category: 'Exposed Server Info',
    signature: /Apache Server Information/i,
    description: 'Apache mod_info is public, disclosing the full module and configuration summary.',
    recommendation: 'Restrict /server-info to localhost or remove mod_info.'
  },
  {
    path: '/actuator/env',
    severity: 'High',
    category: 'Exposed Actuator Endpoint',
    signature: /"propertySources"/i,
    description: 'A Spring Boot actuator endpoint is public and can leak configuration and datasource credentials.',
    recommendation: 'Expose only health/info, and require authentication on the actuator base path.'
  },
  {
    path: '/debug/vars',
    severity: 'Medium',
    category: 'Exposed Debug Endpoint',
    signature: /"cmdline"\s*:/i,
    description: 'A Go expvar debug endpoint is public, disclosing runtime counters and command-line flags.',
    recommendation: 'Disable expvar or bind the debug listener to localhost.'
  },
  {
    path: '/.DS_Store',
    severity: 'Low',
    category: 'Exposed Directory Metadata',
    signature: /Bud1/,
    description: 'A macOS .DS_Store file is downloadable and reveals the directory listing.',
    recommendation: 'Block dotfiles and exclude .DS_Store from deployment.'
  },
  {
    path: '/config.php.bak',
    severity: 'High',
    category: 'Exposed Backup File',
    signature: /<\?php/i,
    description: 'A PHP source backup is downloadable as plain text, exposing credentials and logic.',
    recommendation: 'Never leave editor or deployment backups in the document root.'
  }
];

class SensitiveFileScanner {
  constructor() {
    this.name = 'Sensitive File Scanner';
    this.description =
      'Probes for exposed dotfiles, repository metadata, debug endpoints and deployment configs.';
    this.version = '2.2.1';
    this.runsPerPage = false;
    this.pageLimit = 1;
    this.targets = TARGETS;
  }

  async initialize() {
    console.log(`[sensitive-files] ${this.targets.length} paths queued`);
  }

  async scan(url, options = {}) {
    const started = Date.now();
    const base = new URL(url);
    const vulnerabilities = [];
    const probed = [];

    for (const target of this.targets) {
      const probeUrl = new URL(target.path, base.origin).toString();
      probed.push(target.path);

      let response;
      try {
        response = await fetchPage(probeUrl, {
          timeout: options.timeout || 10000,
          maxRedirects: 0,
          headers: { Accept: '*/*' }
        });
      } catch {
        continue;
      }

      // A redirect to a login page is not an exposure.
      if (response.status !== 200) continue;
      const body = response.html || '';
      const match = body.match(target.signature);
      if (!match) continue;

      vulnerabilities.push(
        finding({
          type: 'Sensitive File Exposure',
          severity: target.severity,
          category: target.category,
          description: target.description,
          evidence: `${probeUrl} -> HTTP 200, matched ${this.describeMatch(body, match[0])}`,
          url: probeUrl,
          confidence: 0.9,
          recommendations: [target.recommendation],
          cwe: 'CWE-538',
          owasp: 'A01:2021 Broken Access Control'
        })
      );
    }

    return {
      url,
      status: 'complete',
      scanner: this.name,
      vulnerabilities: dedupeFindings(vulnerabilities),
      details: {
        pathsProbed: probed.length,
        note: 'Only GET requests were sent; no files were modified.'
      },
      scanTime: Date.now() - started
    };
  }

  /** Show enough to prove the finding without copying a secret into a report. */
  describeMatch(body, matched) {
    const line = String(matched).trim();

    // KEY=value style: keep the key, redact the value.
    const assignment = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (assignment && assignment[2].length > 0) {
      return `${assignment[1]}=***`;
    }

    const trimmed = line.length > 60 ? `${line.slice(0, 57)}...` : line;
    return `"${trimmed.replace(/[\r\n]+/g, ' ')}"`;
  }

  async scanMultiple(urls) {
    const results = [];
    for (const url of urls) results.push(await this.scan(url));
    return results;
  }
}

module.exports = { SensitiveFileScanner };
