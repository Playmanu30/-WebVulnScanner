// Lab-safe exploitation guides, keyed by finding type.
//
// The goal is to explain *how* a flaw is exploited and how to prove it, not to
// provide a weapon. Every step assumes a system you are authorised to test and
// stops at proof: no data dumping, no credential use, no persistence, no
// evasion, no action against third parties.

const LAB_NOTICE =
  'Authorised labs only. Stop at proof: no data dumping, no credential reuse, no persistence, no evasion, and never run these steps against third-party systems or real users.';

const PLAYBOOKS = {
  XSS: {
    summary:
      'The application writes attacker-controlled input into the HTML response without context-aware encoding, so the browser treats it as markup and executes it as script in the target origin.',
    impact:
      'Script runs with the site origin: it can read the DOM, perform actions as the victim, phish inside the trusted page, and steal session tokens when cookies lack HttpOnly.',
    steps: [
      {
        title: 'Confirm the reflection',
        detail:
          'Open the URL from the evidence and inspect the response around your marker. If the marker appears unencoded (for example inside <p>, an attribute, or a script block), the page is reflecting input rather than escaping it.'
      },
      {
        title: 'Prove execution in your lab browser',
        detail:
          'Replace the marker with a harmless alert such as <svg/onload=alert(document.domain)>. If the dialog shows the target domain, the payload executed in the site origin. That single dialog is the whole proof; nothing further is needed.'
      },
      {
        title: 'Identify the context',
        detail:
          'Check whether the value lands in text, an attribute, a URL, or a <script> block. The context determines which characters survive filtering and is what the fix must address. Compare the evidence URLs across pages to see if several parameters are affected.'
      },
      {
        title: 'Check what the script could reach',
        detail:
          'In DevTools, read document.cookie and the response headers. A session cookie without HttpOnly is script-readable, which is why the same flaw escalates from "alert box" to account takeover.'
      },
      {
        title: 'Write the finding up with the minimum payload',
        detail:
          'Keep the alert payload in the report as reproduction evidence. Do not develop a cookie exfiltration or phishing chain; the impact statement plus the alert is enough for a client to prioritise the fix.'
      }
    ]
  },

  'SQL Injection': {
    summary:
      'User input reaches a SQL query without parameterisation, so quote characters change the query structure and the database reports syntax errors or behaves differently.',
    impact:
      'An attacker can read arbitrary tables, bypass authentication, and in some configurations modify or delete data.',
    steps: [
      {
        title: 'Reproduce the error',
        detail:
          'Request the evidence URL and compare it with the same parameter set to a harmless value. The baseline should render normally; the quote probe should return a database error, a 500, or a visibly different page.'
      },
      {
        title: 'Confirm with a boolean pair (read-only)',
        detail:
          'In a lab, compare a condition that is true with one that is false, for example "... AND 1=1" versus "... AND 1=2". A stable difference in content or status proves the input is interpreted as SQL rather than text. Do not progress to UNION, stacked queries, or file writes.'
      },
      {
        title: 'Note the database fingerprint',
        detail:
          'The error text usually names the engine and version ("MySQL server version", "ORA-", "SQLSTATE"). Record it; it tells the developer which driver and which parameterisation API to use.'
      },
      {
        title: 'Check for authentication bypass only if in scope',
        detail:
          'If the same parameter backs a login form, a lab account can show whether " OR 1=1 -- style input skips the password check. Test against your own test account, never a real user, and do not retain any session you obtain.'
      },
      {
        title: 'Report the proof, not a dump',
        detail:
          'The error message and the true/false difference are sufficient evidence. Dumping tables or extracting password hashes turns a validation exercise into a data breach; the fix is the same either way.'
      }
    ]
  },

  CSRF: {
    summary:
      'A state-changing request is accepted based only on ambient cookies, with no unpredictable token tied to the user session. Another site can therefore make the victim\'s browser send it.',
    impact:
      'Account changes, privilege changes, deletions, or login-CSRF (silently signing the victim into the attacker\'s account) performed without the victim\'s intent.',
    steps: [
      {
        title: 'Map the request',
        detail:
          'From the form, list the action URL, method, and every field. Confirm in DevTools that the browser sends session cookies automatically on that request.'
      },
      {
        title: 'Build a local proof page',
        detail:
          'Save a small HTML page on your machine containing a form with method="POST", action pointing at the target, and the same fields pre-filled with your test values. This page is the CSRF primitive; nothing needs to be hosted publicly.'
      },
      {
        title: 'Run it against your own test account',
        detail:
          'Log in to the lab account, open the local page, and submit. If the server accepts the request without a token, the state changes. Use a reversible action on an account you own and undo it afterwards.'
      },
      {
        title: 'Check the cookie defences',
        detail:
          'Inspect SameSite on the session cookie. SameSite=Lax/Strict blocks most cross-site POSTs; its absence is what makes the proof page work. Note that a token is still the primary defence.'
      },
      {
        title: 'Stop at the state change',
        detail:
          'The observed change on your own account is the evidence. Do not target real accounts, and do not chain the request into a worm or mass action.'
      }
    ]
  },

  'Directory Traversal': {
    summary:
      'A file-like parameter is concatenated into a filesystem path without normalisation or a root check, so "../" sequences escape the intended directory.',
    impact:
      'Read access to configuration files, source code, private keys, and credential stores outside the web root.',
    steps: [
      {
        title: 'Establish the baseline',
        detail:
          'Request the parameter with a normal value and note the response length and content type. This is your reference for spotting a successful read.'
      },
      {
        title: 'Request a known readable file',
        detail:
          'Send a traversal sequence targeting /etc/passwd on Linux or win.ini on Windows. A response containing a passwd line ("root:x:0:0:") or the win.ini sections is proof that the path left the web root.'
      },
      {
        title: 'Try only the proof file',
        detail:
          'Do not walk the filesystem or pull application configs, .env files, keys, or database dumps. The one file that proves traversal is enough to prioritise the fix.'
      },
      {
        title: 'Note the traversal depth that worked',
        detail:
          'Record how many "../" segments were needed. That indicates the working directory relative to the web root and helps the developer verify their fix with the same input.'
      }
    ]
  },

  'Open Redirect': {
    summary:
      'A parameter controls the destination of a redirect and is not restricted to relative paths or an allowlist, so the trusted domain can send users anywhere.',
    impact:
      'Convincing phishing links on the real domain, OAuth or password-reset token leakage when the redirect carries a code, and bypass of allowlists that trust the domain name alone.',
    steps: [
      {
        title: 'Inspect the hop',
        detail:
          'Send the parameter with an absolute URL pointing at a domain you control (or the scanner canary). Disable redirect following in DevTools or use curl -I so you can read the raw 302 and its Location header.'
      },
      {
        title: 'Confirm there is no interstitial',
        detail:
          'A warning page ("you are leaving this site") breaks the primitive. A direct 302 to the supplied host is the finding.'
      },
      {
        title: 'Test the variants that matter',
        detail:
          'Try a protocol-relative value (//host) and an absolute https URL. If only one is filtered, the policy is incomplete. Do not test javascript: or data: schemes; those are a different bug class and risk script execution.'
      },
      {
        title: 'Demonstrate the phishing flow in a lab',
        detail:
          'The evidence is the crafted link plus the Location header. Do not send it to anyone, and do not build a fake login page; the redirect itself proves the impact.'
      }
    ]
  },

  SSRF: {
    summary:
      'A parameter that accepts a URL is fetched server-side without validation, so the server can be made to issue requests to hosts the attacker cannot reach directly.',
    impact:
      'Reach internal services, cloud metadata endpoints and admin interfaces, and use the server as a proxy that bypasses network controls.',
    steps: [
      {
        title: 'Confirm out-of-band',
        detail:
          'Point the parameter at a canary listener you control and watch for the callback. The scanner already does this with a unique token; a callback is definitive proof that the server made the request.'
      },
      {
        title: 'Test an internal address you own',
        detail:
          'In a lab, use a second local listener on 127.0.0.1 or a Docker service and observe whether the response body or timing changes. This shows internal reachability without touching anything sensitive.'
      },
      {
        title: 'Do not aim at cloud metadata',
        detail:
          'Requests to 169.254.169.254 can return live credentials. Do not make them. If the client needs proof of that risk, describe it in the report and let them test in an isolated account.'
      },
      {
        title: 'Record the redirect and scheme behaviour',
        detail:
          'Check whether the server follows redirects and whether non-HTTP schemes are accepted. Those determine how the fix must be written (allowlist host and scheme, resolve DNS, block private ranges).'
      }
    ]
  },

  'CORS Misconfiguration': {
    summary:
      'The server echoes an arbitrary Origin (or the literal "null") in Access-Control-Allow-Origin, sometimes with credentials allowed, instead of validating against an allowlist.',
    impact:
      'Any website can read authenticated responses from the endpoint, exposing profile data, tokens, and API results to a malicious origin.',
    steps: [
      {
        title: 'Reproduce the header',
        detail:
          'Send the request with Origin: https://example.invalid and read Access-Control-Allow-Origin and Access-Control-Allow-Credentials in the response. The evidence already contains both; confirm they change with the Origin you supply.'
      },
      {
        title: 'Prove readability in a lab',
        detail:
          'Serve a page from a different local port that runs fetch(target, { credentials: "include" }) and reads the JSON body. If the browser hands you the response, the origin check is broken. Without credentials, data exposure is limited to unauthenticated responses.'
      },
      {
        title: 'Check the null origin',
        detail:
          'A sandboxed iframe or a data: URL sends Origin: null. If that is reflected, an attacker can host the page anywhere without owning a domain.'
      },
      {
        title: 'Do not collect real user data',
        detail:
          'Run the proof with your own test account. The header pair plus a successful fetch is the finding; exfiltrating another user\'s data is out of scope.'
      }
    ]
  },

  'HTTP Method Misconfiguration': {
    summary:
      'The server advertises or accepts methods the endpoint does not need, such as PUT, DELETE, or TRACE.',
    impact:
      'TRACE enables Cross-Site Tracing to read headers that HttpOnly would otherwise protect; writable methods can expose upload or edit paths that were never meant to be public.',
    steps: [
      {
        title: 'Read the Allow header',
        detail:
          'Send OPTIONS to the endpoint and inspect Allow. The advertised list is the server\'s own statement of what it accepts.'
      },
      {
        title: 'Confirm TRACE safely',
        detail:
          'Send a TRACE request with no body. A compliant echo returns the request line in the response body, which is the proof. Do not combine it with script injection.'
      },
      {
        title: 'Do not exercise write methods on production',
        detail:
          'PUT, PATCH, and DELETE can change or remove data. In a lab, check whether they require authentication and whether they are actually implemented; on a client system, report the advertised method and let them decide.'
      }
    ]
  },

  'Sensitive File Exposure': {
    summary:
      'A file that should never be served, such as .env, .git/config, a backup, or a debug endpoint, is reachable from the web root.',
    impact:
      'Direct disclosure of credentials, API keys, source history, internal topology, and live request data. Exposed keys often grant access to cloud or third-party systems.',
    steps: [
      {
        title: 'Fetch only the reported path',
        detail:
          'Request the URL from the evidence once and confirm the signature the scanner matched. Do not enumerate neighbouring paths or brute-force backups.'
      },
      {
        title: 'Classify the secret without using it',
        detail:
          'Note what kind of value is exposed (database password, cloud key, signing secret) and redact it in your notes. Do not authenticate with it, and do not paste real values into tickets or chat.'
      },
      {
        title: 'Escalate for rotation',
        detail:
          'Any exposed credential should be treated as compromised: rotate it, then remove the file and block the path. If .git is exposed, assume the full history, including deleted secrets, is public.'
      },
      {
        title: 'Verify the fix',
        detail:
          'After remediation, request the same path and confirm a 403/404. Do not test bypasses such as encoded paths or alternate extensions unless the client explicitly asks for a hardening review.'
      }
    ]
  },

  Header: {
    summary:
      'A browser security header is missing or weak, so the browser applies a permissive default instead of the policy the application intended.',
    impact:
      'Clickjacking when framing is unrestricted, MIME sniffing when nosniff is absent, protocol downgrade when HSTS is missing, and a much larger blast radius for any XSS when CSP is absent.',
    steps: [
      {
        title: 'Identify what the missing header allows',
        detail:
          'Read the finding category: framing, MIME sniffing, transport, referrer leakage, or script policy. Each maps to one concrete browser behaviour.'
      },
      {
        title: 'Prove clickjacking locally',
        detail:
          'For a missing X-Frame-Options or frame-ancestors, save a local HTML page containing an iframe pointing at the target and open it. If the page renders inside the frame, framing is allowed. Do not build a full clickjacking overlay or lure real users.'
      },
      {
        title: 'Check the CSP before assuming impact',
        detail:
          'A missing CSP only matters when the site also has an injection point or third-party scripts. Note the combination rather than reporting the header in isolation.'
      },
      {
        title: 'Fix at the edge',
        detail:
          'Add the header at the reverse proxy or application layer for every response, including errors, and verify with the same request used in the scan.'
      }
    ]
  },

  Authentication: {
    summary:
      'A login or session mechanism leaks or under-protects credentials: cleartext transport, missing cookie flags, session IDs in URLs, or weak password-manager hints.',
    impact:
      'Credential interception on the network, session theft through script access, session leakage through logs and Referer headers, and account takeover.',
    steps: [
      {
        title: 'Inspect transport and storage',
        detail:
          'Submit a login on the lab account with DevTools open. Confirm whether the request is HTTP, whether the response sets Secure/HttpOnly/SameSite, and whether any token appears in the URL.'
      },
      {
        title: 'Check the cookie scope',
        detail:
          'A session cookie readable by script (no HttpOnly) turns any XSS into account takeover. A cookie without Secure can be sent over HTTP. A missing SameSite widens CSRF exposure.'
      },
      {
        title: 'Do not attack credentials',
        detail:
          'No password spraying, brute force, credential stuffing, or reuse of passwords found elsewhere. This checker reports configuration weaknesses; proving them does not require guessing a password.'
      },
      {
        title: 'Verify the fix with a fresh session',
        detail:
          'Log out, log in again, and confirm the flags on the new cookie plus HTTPS-only transport. Old sessions should be invalidated server-side after the change.'
      }
    ]
  },

  'SSL/TLS': {
    summary:
      'The transport is missing, outdated, or misconfigured: plain HTTP, a weak protocol or cipher, or an invalid/expired certificate.',
    impact:
      'Traffic, cookies, and credentials can be read or modified in transit; users cannot distinguish the real site from an impostor.',
    steps: [
      {
        title: 'Inspect the handshake',
        detail:
          'Use openssl s_client -connect host:443 -servername host to read the protocol, cipher, and certificate chain. The scanner already records these values in the finding.'
      },
      {
        title: 'Check downgrade behaviour',
        detail:
          'Request the http:// URL and see whether it redirects to https and whether HSTS is present. Without HSTS the first request is always plaintext.'
      },
      {
        title: 'Stay passive',
        detail:
          'Do not attempt to intercept traffic on networks you do not own, and do not install test certificates on client devices. A configuration finding is proven by the handshake itself.'
      },
      {
        title: 'Fix and re-test',
        detail:
          'Disable obsolete protocols, prefer modern ciphers, redirect HTTP to HTTPS, and add HSTS with a gradually increasing max-age.'
      }
    ]
  },

  'Information Disclosure': {
    summary:
      'The response leaks implementation detail: version banners, stack traces, source maps, internal paths, or debug output.',
    impact:
      'Gives an attacker the exact framework and version to research, plus internal hostnames and file paths that make other attacks easier.',
    steps: [
      {
        title: 'Read the leaked value',
        detail:
          'Compare the evidence against the page source and headers. Version strings, stack traces, and source-map links are the useful parts; note them without probing further.'
      },
      {
        title: 'Map the version to advisories',
        detail:
          'Look up the disclosed product and version in the vendor advisory list. Do not run public exploits against the client; record the affected version and the fixed version.'
      },
      {
        title: 'Check source maps and backups',
        detail:
          'A .map file can reveal the full front-end source. Treat it as a code disclosure finding and recommend removing maps from production builds.'
      }
    ]
  },

  Default: {
    summary:
      'This finding is a configuration or logic weakness. Validate it with the evidence already captured, then stop at proof.',
    impact:
      'Depends on the category: the finding description explains what an attacker gains and the recommendations list how to close it.',
    steps: [
      {
        title: 'Replay the evidence',
        detail:
          'Request the URL shown in the evidence and compare it with a benign baseline. A stable, reproducible difference is the proof.'
      },
      {
        title: 'Confirm the security impact',
        detail:
          'Ask what an attacker gains that they should not: data, access, or the ability to make a victim act. If the answer is "nothing", downgrade the finding.'
      },
      {
        title: 'Fix and verify',
        detail:
          'Apply the first recommendation, then replay the same request and confirm the difference is gone.'
      }
    ]
  }
};

function getPlaybook(type) {
  return PLAYBOOKS[type] || PLAYBOOKS.Default;
}

module.exports = { PLAYBOOKS, getPlaybook, LAB_NOTICE };
