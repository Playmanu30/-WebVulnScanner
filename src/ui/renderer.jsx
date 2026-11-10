import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Search,
  Loader2,
  Square,
  RefreshCw,
  Link2,
  Code2,
  Database,
  UserCheck,
  Lock,
  FolderOpen,
  Eye,
  Tags,
  Brain,
  Lightbulb,
  FileJson,
  FileText,
  CheckCircle2,
  AlertTriangle,
  Info,
  ChevronDown,
  ChevronRight,
  FileWarning,
  Globe,
  Network,
  ExternalLink,
  Radar,
  Radio,
  Crosshair,
  Terminal,
  Copy,
  Upload,
  Send,
  X,
  KeyRound
} from 'lucide-react';
import { getPlaybook, LAB_NOTICE } from '../core/playbooks';

function parseHeaderLines(text) {
  const headers = {};
  for (const line of String(text || '').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const index = trimmed.indexOf(':');
    if (index <= 0) continue;
    const name = trimmed.slice(0, index).trim();
    const value = trimmed.slice(index + 1).trim();
    if (!/^[A-Za-z0-9-]{1,64}$/.test(name) || value.length === 0) continue;
    headers[name] = value;
  }
  return headers;
}

function toCurl(url) {
  return `curl -i -sS ${JSON.stringify(url)}`;
}

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const SEVERITY_CLASS = {
  Critical: 'critical',
  High: 'high',
  Medium: 'medium',
  Low: 'low',
  Info: 'info'
};

const SCANNER_ICONS = {
  'Header Analyzer': Tags,
  'Information Disclosure Scanner': Eye,
  'Sensitive File Scanner': FileWarning,
  'CORS Analyzer': Globe,
  'HTTP Method Analyzer': Network,
  'SSL/TLS Analyzer': Lock,
  'XSS Detector': Code2,
  'SQL Injection Detector': Database,
  'CSRF Detector': ShieldAlert,
  'Authentication Checker': UserCheck,
  'Directory Traversal Finder': FolderOpen,
  'Open Redirect Finder': ExternalLink,
  'SSRF Detector': Radar
};

const PROFILES = {
  quick: { label: 'Quick', pages: 6, probePages: 2, concurrency: 3, delayMs: 60 },
  standard: { label: 'Standard', pages: 12, probePages: 4, concurrency: 3, delayMs: 40 },
  deep: { label: 'Deep', pages: 30, probePages: 8, concurrency: 4, delayMs: 25 }
};

const bridge = () => window.scannerAPI || null;

function severityClass(value) {
  return SEVERITY_CLASS[value] || 'info';
}

function formatScanTime(ms) {
  if (typeof ms !== 'number' || Number.isNaN(ms)) return '—';
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

function Banner({ kind, icon: Icon, children }) {
  return (
    <div className={`banner ${kind}`}>
      {Icon ? <Icon size={16} /> : null}
      <div>{children}</div>
    </div>
  );
}

function SummaryCard({ label, value, tone }) {
  return (
    <div className={`card ${tone}`}>
      <div className="card-label">{label}</div>
      <div className="card-value">{value}</div>
    </div>
  );
}

function Finding({ item, index, expanded, onToggle, onConsole, onCopyCurl }) {
  const Icon = SCANNER_ICONS[item.scanner] || Shield;
  const playbook = getPlaybook(item.type);
  return (
    <article className={`finding ${severityClass(item.severity)}`}>
      <div className="finding-head">
        <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
          <Icon size={16} style={{ marginTop: 2, color: '#6b7280', flex: '0 0 auto' }} />
          <div>
            <div className="finding-title">
              {item.type} · {item.category}
            </div>
            <div className="finding-meta">
              {item.scanner}
              {typeof item.confidence === 'number'
                ? ` · ${Math.round(item.confidence * 100)}% confidence`
                : ''}
              {item.cwe ? ` · ${item.cwe}` : ''}
            </div>
          </div>
        </div>
        <span className={`sev-badge ${severityClass(item.severity)}`}>{item.severity}</span>
      </div>

      <p className="finding-desc">{item.description}</p>

      {expanded ? (
        <div>
          {item.evidence ? <pre className="evidence">{item.evidence}</pre> : null}
          {item.url ? (
            <p className="finding-meta" style={{ wordBreak: 'break-all' }}>
              {item.url}
            </p>
          ) : null}
          {item.cwe || item.owasp ? (
            <p className="finding-meta">
              {item.cwe ? <span className="chip">{item.cwe}</span> : null}
              {item.owasp ? <span className="chip">{item.owasp}</span> : null}
            </p>
          ) : null}

          {item.url ? (
            <div className="finding-tools">
              <button type="button" className="btn-mini" onClick={() => onConsole(item)}>
                <Terminal size={13} />
                Request console
              </button>
              <button type="button" className="btn-mini" onClick={() => onCopyCurl(item)}>
                <Copy size={13} />
                Copy as curl
              </button>
            </div>
          ) : null}

          <div className="playbook">
            <div className="playbook-head">
              <Crosshair size={14} />
              Exploitation &amp; validation guide
              <span className="playbook-tag">lab-safe</span>
            </div>
            <p className="playbook-summary">{playbook.summary}</p>
            <ol className="playbook-steps">
              {playbook.steps.map((step, stepIndex) => (
                <li key={stepIndex}>
                  <b>{step.title}.</b> {step.detail}
                </li>
              ))}
            </ol>
            <p className="playbook-impact">
              <b>Impact:</b> {playbook.impact}
            </p>
            <p className="playbook-limits">{LAB_NOTICE}</p>
          </div>

          {item.recommendations && item.recommendations.length > 0 ? (
            <ul className="rec-list">
              {item.recommendations.map((rec, i) => (
                <li key={i}>{rec}</li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}

      <button className="expand" onClick={onToggle} aria-expanded={expanded} aria-controls={`finding-${index}`}>
        {expanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        {expanded ? 'Hide details' : 'Show details & remediation'}
      </button>
    </article>
  );
}

function App() {
  const [url, setUrl] = useState('https://example.com');
  const [profile, setProfile] = useState('standard');
  const [authorized, setAuthorized] = useState(false);
  const [scanners, setScanners] = useState([]);
  const [appMeta, setAppMeta] = useState(null);
  const [status, setStatus] = useState('idle'); // idle | running | done
  const [progress, setProgress] = useState({ percent: 0, scanner: null, phase: null, pages: 0 });
  const [result, setResult] = useState(null);
  const [liveFindings, setLiveFindings] = useState([]);
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null);
  const [exporting, setExporting] = useState(null);
  const [expanded, setExpanded] = useState({});
  const [bridgeMissing, setBridgeMissing] = useState(false);
  const [authOpen, setAuthOpen] = useState(false);
  const [authCookies, setAuthCookies] = useState('');
  const [authHeaders, setAuthHeaders] = useState('');
  const [authUser, setAuthUser] = useState('');
  const [authPass, setAuthPass] = useState('');
  const [blind, setBlind] = useState(false);
  const [importing, setImporting] = useState(false);
  const [consoleItem, setConsoleItem] = useState(null);
  const [consoleUrl, setConsoleUrl] = useState('');
  const [consoleMethod, setConsoleMethod] = useState('GET');
  const [consoleHeaders, setConsoleHeaders] = useState('');
  const [consoleResult, setConsoleResult] = useState(null);
  const [consoleError, setConsoleError] = useState(null);
  const [consoleBusy, setConsoleBusy] = useState(false);
  const liveRef = useRef([]);

  useEffect(() => {
    const api = bridge();
    if (!api) {
      setBridgeMissing(true);
      return undefined;
    }

    api.getScanners().then(setScanners).catch(() => setScanners([]));
    api.appInfo().then(setAppMeta).catch(() => setAppMeta(null));

    const unsubscribe = api.onProgress((update) => {
      if (update.status === 'finding' && update.finding) {
        liveRef.current = [{ ...update.finding, scanner: update.scanner, url: update.url }, ...liveRef.current].slice(
          0,
          60
        );
        setLiveFindings(liveRef.current);
        return;
      }

      setProgress((previous) => ({
        percent: typeof update.percent === 'number' ? update.percent : previous.percent,
        scanner: update.scanner || previous.scanner,
        phase: update.phase || previous.phase,
        pages: update.pages || previous.pages
      }));
    });
    return unsubscribe;
  }, []);

  useEffect(() => {
    if (!notice) return undefined;
    const timer = setTimeout(() => setNotice(null), 8000);
    return () => clearTimeout(timer);
  }, [notice]);

  const findings = useMemo(() => {
    const list = [];
    for (const scannerResult of result?.scannerResults || []) {
      for (const item of scannerResult.vulnerabilities || []) {
        list.push({ ...item, scanner: scannerResult.scanner });
      }
    }
    return list.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  }, [result]);

  const scannerRows = useMemo(() => {
    const byName = new Map();
    for (const scannerResult of result?.scannerResults || []) {
      const entry = byName.get(scannerResult.scanner) || { count: 0, status: 'complete', pages: 0 };
      entry.count += scannerResult.vulnerabilities?.length || 0;
      entry.pages += scannerResult.pagesScanned || 1;
      if (scannerResult.status === 'error') entry.status = 'error';
      byName.set(scannerResult.scanner, entry);
    }

    return scanners.map((scanner) => {
      const entry = byName.get(scanner.name);
      const count = entry?.count || 0;
      let state = 'idle';
      if (status === 'running' && progress.scanner === scanner.name) state = 'active';
      else if (entry?.status === 'error') state = 'error';
      else if (entry) state = 'done';
      return { ...scanner, count, state, pages: entry?.pages || 0 };
    });
  }, [scanners, result, progress.scanner, status]);

  const breakdown = result?.severityBreakdown || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const canStart = authorized && !bridgeMissing;

  const handleScan = useCallback(
    async (event) => {
      if (event) event.preventDefault();
      const api = bridge();
      if (!api) return;

      if (!authorized) {
        setError('Confirm you have written authorisation for this target before scanning.');
        return;
      }

      const target = url.trim();
      if (!/^https?:\/\//i.test(target)) {
        setError('Enter a target that starts with http:// or https://');
        return;
      }

      const selected = PROFILES[profile] || PROFILES.standard;

      setStatus('running');
      setError(null);
      setNotice(null);
      setResult(null);
      setLiveFindings([]);
      liveRef.current = [];
      setExpanded({});
      setProgress({ percent: 0, scanner: null, phase: 'crawl', pages: 0 });

      const authHeadersObject = parseHeaderLines(authHeaders);
      const auth =
        authCookies.trim() || Object.keys(authHeadersObject).length > 0 || authUser.trim()
          ? {
              cookies: authCookies,
              headers: authHeadersObject,
              username: authUser,
              password: authPass
            }
          : undefined;

      try {
        const response = await api.startScan(target, {
          authorized: true,
          maxPages: selected.pages,
          perPageLimit: selected.probePages,
          concurrency: selected.concurrency,
          delayMs: selected.delayMs,
          blind,
          auth
        });
        if (!response || response.success === false) {
          setError(response?.error || 'The scan failed for an unknown reason.');
          setStatus('idle');
          return;
        }
        setResult(response);
        setProgress({ percent: 100, scanner: null, phase: null, pages: response.pagesScanned || 0 });
        setStatus('done');
      } catch (scanError) {
        setError(scanError.message || String(scanError));
        setStatus('idle');
      }
    },
    [url, authorized, profile, blind, authCookies, authHeaders, authUser, authPass]
  );

  const handleStop = useCallback(() => {
    const api = bridge();
    if (api) api.stopScan();
    setNotice('Stopping after the current request finishes…');
  }, []);

  const handleExport = useCallback(
    async (format) => {
      const api = bridge();
      if (!api || !result) return;
      setExporting(format);
      try {
        const response = await api.exportReport(result, format);
        if (response?.success) {
          setNotice(`Saved report to ${response.savedFile}`);
        } else if (!response?.canceled) {
          setNotice(`Export failed: ${response?.error || 'unknown error'}`);
        }
      } catch (exportError) {
        setNotice(`Export failed: ${exportError.message}`);
      } finally {
        setExporting(null);
      }
    },
    [result]
  );

  const handleImport = useCallback(async () => {
    const api = bridge();
    if (!api || importing) return;
    setImporting(true);
    try {
      const response = await api.importFindings();
      if (!response?.success) {
        if (!response?.canceled) setNotice(`Import failed: ${response?.error || 'unknown error'}`);
        return;
      }

      setResult((previous) => {
        if (!previous) return previous;
        const scannerResult = {
          url: previous.url,
          status: 'complete',
          scanner: `Imported · ${String(response.source || 'json').toUpperCase()}`,
          vulnerabilities: response.findings,
          details: { fileName: response.fileName, imported: true },
          scanTime: 0,
          pagesScanned: 1,
          imported: true
        };
        const scannerResults = [...previous.scannerResults, scannerResult];
        const severityBreakdown = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        let total = 0;
        for (const scanner of scannerResults) {
          for (const item of scanner.vulnerabilities || []) {
            total += 1;
            const key = String(item.severity || 'medium').toLowerCase();
            if (severityBreakdown[key] !== undefined) severityBreakdown[key] += 1;
            else severityBreakdown.low += 1;
          }
        }
        return {
          ...previous,
          scannerResults,
          totalScans: scannerResults.length,
          totalVulnerabilities: total,
          severityBreakdown
        };
      });
      setNotice(`Imported ${response.findings.length} finding(s) from ${response.fileName}`);
    } catch (importError) {
      setNotice(`Import failed: ${importError.message}`);
    } finally {
      setImporting(false);
    }
  }, [importing]);

  const openConsole = useCallback((item) => {
    setConsoleItem(item);
    setConsoleUrl(item.url || '');
    setConsoleMethod('GET');
    setConsoleHeaders('');
    setConsoleResult(null);
    setConsoleError(null);
  }, []);

  const closeConsole = useCallback(() => {
    setConsoleItem(null);
    setConsoleResult(null);
    setConsoleError(null);
  }, []);

  const handleReplay = useCallback(async () => {
    const api = bridge();
    if (!api || consoleBusy) return;

    const headers = parseHeaderLines(consoleHeaders);
    const authHeaderList = parseHeaderLines(authHeaders);
    for (const [name, value] of Object.entries(authHeaderList)) {
      if (!Object.keys(headers).some((key) => key.toLowerCase() === name.toLowerCase())) {
        headers[name] = value;
      }
    }
    if (authCookies.trim() && !Object.keys(headers).some((key) => key.toLowerCase() === 'cookie')) {
      headers.Cookie = authCookies.trim();
    }

    setConsoleBusy(true);
    setConsoleError(null);
    try {
      const response = await api.replayRequest({
        authorized: true,
        url: consoleUrl.trim(),
        method: consoleMethod,
        headers
      });
      if (!response?.success) {
        setConsoleError(response?.error || 'The request failed.');
        return;
      }
      setConsoleResult(response);
    } catch (replayError) {
      setConsoleError(replayError.message);
    } finally {
      setConsoleBusy(false);
    }
  }, [consoleBusy, consoleUrl, consoleMethod, consoleHeaders, authCookies, authHeaders]);

  const handleCopyCurl = useCallback(async (item) => {
    const command = toCurl(item.url);
    try {
      await navigator.clipboard.writeText(command);
      setNotice('Copied curl command to the clipboard.');
    } catch {
      setNotice(command);
    }
  }, []);

  const progressLabel = () => {
    if (progress.phase === 'crawl') {
      return progress.pages > 0 ? `Crawling target · ${progress.pages} page(s) found` : 'Crawling target…';
    }
    return progress.scanner ? `Running ${progress.scanner}…` : 'Working…';
  };

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={22} />
          </div>
          <div>
            <div className="brand-title">VulnScanner AI</div>
            <div className="brand-sub">Authorised red-team recon</div>
          </div>
        </div>

        <div>
          <div className="nav-label">Scanner modules</div>
          <div className="scanner-list">
            {scannerRows.length === 0 ? (
              <div className="scanner-row">
                <span className="dot" />
                <span className="scanner-name">Loading modules…</span>
              </div>
            ) : (
              scannerRows.map((scanner) => (
                <div
                  key={scanner.name}
                  className={`scanner-row ${scanner.state === 'active' ? 'is-active' : ''} ${
                    scanner.state === 'error' ? 'is-error' : ''
                  }`}
                  title={scanner.description || scanner.name}
                >
                  <span className={`dot ${scanner.state === 'idle' ? '' : scanner.state}`} />
                  <span className="scanner-name">{scanner.name}</span>
                  {scanner.count > 0 ? <span className="scanner-count">{scanner.count}</span> : null}
                </div>
              ))
            )}
          </div>
        </div>

        <div className="sidebar-footer">
          <div>
            <b>Status:</b> {status === 'running' ? 'Scanning…' : status === 'done' ? 'Scan complete' : 'Ready'}
          </div>
          {appMeta ? (
            <div>
              <b>Engine:</b> v{appMeta.version} · Electron {appMeta.electron}
            </div>
          ) : null}
          <div>
            <b>Mode:</b> crawl + non-destructive probes
          </div>
        </div>
      </aside>

      <main className="main">
        <div className="topbar">
          <div>
            <h1 className="title">
              <ShieldCheck size={22} style={{ verticalAlign: '-3px', marginRight: 8, color: '#5b6ee1' }} />
              Web Vulnerability Scanner
            </h1>
            <p className="subtitle">
              Crawls one authorised origin, then validates injection, exposure and misconfiguration findings with
              proof-of-concept evidence.
            </p>
          </div>
          <div className="toolbar">
            <button className="btn btn-ghost" onClick={handleImport} disabled={importing || status === 'running'}>
              {importing ? <Loader2 size={15} className="spinner" /> : <Upload size={15} />}
              Import ZAP/nuclei
            </button>
            {result ? (
              <>
                <button className="btn btn-ghost" onClick={() => handleExport('json')} disabled={!!exporting}>
                  {exporting === 'json' ? <Loader2 size={15} className="spinner" /> : <FileJson size={15} />}
                  Export JSON
                </button>
                <button className="btn btn-ghost" onClick={() => handleExport('html')} disabled={!!exporting}>
                  {exporting === 'html' ? <Loader2 size={15} className="spinner" /> : <FileText size={15} />}
                  Export HTML
                </button>
              </>
            ) : null}
          </div>
        </div>

        {bridgeMissing ? (
          <Banner kind="error" icon={AlertTriangle}>
            The Electron bridge is unavailable. Launch the desktop app with <b>npm start</b> instead of opening
            this page in a browser.
          </Banner>
        ) : null}

        <form className="target-form" onSubmit={handleScan}>
          <div className="input-wrap">
            <Link2 size={16} />
            <input
              className="url-input"
              type="text"
              value={url}
              spellCheck={false}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://target.example.com"
              disabled={status === 'running'}
              aria-label="Target URL"
            />
          </div>

          <select
            className="profile-select"
            value={profile}
            onChange={(event) => setProfile(event.target.value)}
            disabled={status === 'running'}
            aria-label="Scan profile"
          >
            {Object.entries(PROFILES).map(([key, value]) => (
              <option key={key} value={key}>
                {value.label} · {value.pages} pages
              </option>
            ))}
          </select>

          {status === 'running' ? (
            <button type="button" className="btn btn-danger" onClick={handleStop}>
              <Square size={14} />
              Stop
            </button>
          ) : (
            <button type="submit" className="btn btn-primary" disabled={!canStart} title={canStart ? '' : 'Confirm authorisation first'}>
              <Search size={15} />
              Start scan
            </button>
          )}

          {result ? (
            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => {
                setResult(null);
                setStatus('idle');
                setLiveFindings([]);
                liveRef.current = [];
                setProgress({ percent: 0, scanner: null, phase: null, pages: 0 });
                setError(null);
              }}
            >
              <RefreshCw size={14} />
              Reset
            </button>
          ) : null}
        </form>

        <label className={`gate ${authorized ? 'is-checked' : ''}`}>
          <input
            type="checkbox"
            checked={authorized}
            onChange={(event) => setAuthorized(event.target.checked)}
            disabled={status === 'running'}
          />
          <span>
            <b>I have written authorisation to test this target.</b> Scans send crafted requests from this machine
            and are limited to the target's own origin — but the responsibility for scope is yours.
          </span>
        </label>

        <button
          type="button"
          className={`auth-toggle ${authOpen ? 'is-open' : ''}`}
          onClick={() => setAuthOpen((open) => !open)}
          aria-expanded={authOpen}
        >
          {authOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          <KeyRound size={14} />
          Authenticated scan &amp; blind detection
          <span className="auth-hint">
            cookies · headers · Basic auth · time-based SQLi
          </span>
        </button>

        {authOpen ? (
          <div className="auth-panel">
            <div className="auth-grid">
              <label>
                <span>Username (Basic auth)</span>
                <input
                  type="text"
                  value={authUser}
                  onChange={(event) => setAuthUser(event.target.value)}
                  placeholder="optional"
                  autoComplete="off"
                  spellCheck={false}
                  disabled={status === 'running'}
                />
              </label>
              <label>
                <span>Password</span>
                <input
                  type="password"
                  value={authPass}
                  onChange={(event) => setAuthPass(event.target.value)}
                  placeholder="optional"
                  autoComplete="off"
                  disabled={status === 'running'}
                />
              </label>
            </div>

            <label className="auth-block">
              <span>Cookie header</span>
              <input
                type="text"
                value={authCookies}
                onChange={(event) => setAuthCookies(event.target.value)}
                placeholder="session=abc123; csrftoken=..."
                spellCheck={false}
                autoComplete="off"
                disabled={status === 'running'}
              />
            </label>

            <label className="auth-block">
              <span>Extra headers — one per line</span>
              <textarea
                rows={3}
                value={authHeaders}
                onChange={(event) => setAuthHeaders(event.target.value)}
                placeholder={'X-Api-Key: ...\nX-Environment: staging'}
                spellCheck={false}
                disabled={status === 'running'}
              />
            </label>

            <label className="auth-blind">
              <input
                type="checkbox"
                checked={blind}
                onChange={(event) => setBlind(event.target.checked)}
                disabled={status === 'running'}
              />
              <span>
                <b>Blind time-based SQLi</b> — adds three capped delay probes per scan. Slower, but finds
                injection on pages that never print a database error.
              </span>
            </label>

            <p className="auth-note">
              Credentials stay in memory, are sent only to the scanned origin, and are never written to reports.
              Redirects that leave the origin are not followed.
            </p>
          </div>
        ) : null}

        {status === 'running' ? (
          <div className="progress">
            <div className="progress-head">
              <span>{progressLabel()}</span>
              <span>{progress.percent}%</span>
            </div>
            <div className="progress-track">
              <div className="progress-fill" style={{ width: `${Math.max(progress.percent, 3)}%` }} />
            </div>
          </div>
        ) : null}

        {error ? (
          <Banner kind="error" icon={AlertTriangle}>
            {error}
          </Banner>
        ) : null}

        {notice ? (
          <Banner kind="info" icon={Info}>
            {notice}
          </Banner>
        ) : null}

        {status === 'running' && liveFindings.length > 0 ? (
          <div className="section">
            <div className="section-head">
              <h2 className="section-title">
                <Radio size={16} style={{ verticalAlign: '-3px', marginRight: 6, color: '#dc2626' }} />
                Live findings
              </h2>
              <span className="muted">{liveFindings.length} so far</span>
            </div>
            <div className="live">
              {liveFindings.slice(0, 10).map((item, index) => (
                <div className={`live-row ${severityClass(item.severity)}`} key={`${item.scanner}-${index}`}>
                  <span className={`sev-badge ${severityClass(item.severity)}`}>{item.severity}</span>
                  <span className="live-title">
                    {item.type} · {item.category}
                  </span>
                  <span className="live-scanner">{item.scanner}</span>
                </div>
              ))}
            </div>
          </div>
        ) : null}

        {!result && !error ? (
          <div className="section">
            <div className="empty">
              <strong>No scan yet</strong>
              Enter an authorised target and start a scan. Each run:
              <ul>
                <li>Crawls the origin (same host only) and ranks pages by input surface</li>
                <li>Reviews headers, cookies, CORS policy and HTTP methods</li>
                <li>Probes for exposed dotfiles, repository metadata and debug endpoints</li>
                <li>Confirms reflected XSS, error-based SQLi and path traversal with evidence</li>
                <li>Checks CSRF tokens, session flags and authentication transport</li>
                <li>Inspects the live TLS handshake and certificate</li>
                <li>Tests redirect parameters for open redirects</li>
                <li>Confirms SSRF with an out-of-band canary callback</li>
              </ul>
              <p style={{ marginTop: 12, fontSize: 12 }}>
                Detection and validation only: no exploitation, no persistence, no brute force.
              </p>
            </div>
          </div>
        ) : null}

        {result ? (
          <>
            <div className="section">
              <div className="section-head">
                <h2 className="section-title">Overview</h2>
                <span className="muted">
                  {result.finalUrl || result.url}
                  {result.statusCode ? ` · HTTP ${result.statusCode}` : ''}
                </span>
              </div>
              <div className="score-row">
                <SummaryCard label="Critical" value={breakdown.critical || 0} tone="critical" />
                <SummaryCard label="High" value={breakdown.high || 0} tone="high" />
                <SummaryCard label="Medium" value={breakdown.medium || 0} tone="medium" />
                <SummaryCard label="Low" value={breakdown.low || 0} tone="low" />
                <SummaryCard
                  label="Security score"
                  value={
                    result.aiAnalysis?.securityScore !== undefined
                      ? `${Math.round(result.aiAnalysis.securityScore * 100)}/100`
                      : '—'
                  }
                  tone="info"
                />
              </div>
              <p className="muted" style={{ marginTop: 10 }}>
                {result.totalVulnerabilities} finding(s) across {result.totalScans}/{result.scannerResults?.length || 0}{' '}
                scanners · {result.pagesScanned || 1} page(s) crawled · duration{' '}
                {formatScanTime(result.scanTime)} · risk {result.aiAnalysis?.riskLevel || '—'}
                {result.authenticated ? ' · authenticated' : ''}
              </p>
            </div>

            <div className="section">
              <div className="section-head">
                <h2 className="section-title">Findings</h2>
                <span className="muted">Sorted by severity</span>
              </div>
              {findings.length === 0 ? (
                <div className="empty">
                  <CheckCircle2 size={22} color="#16a34a" style={{ marginBottom: 6 }} />
                  <strong style={{ color: '#166534' }}>No vulnerabilities detected in this pass</strong>
                  That does not prove the target is secure — it means these automated checks found nothing.
                </div>
              ) : (
                <div className="findings">
                  {findings.map((item, index) => (
                    <Finding
                      key={`${item.scanner}-${index}`}
                      item={item}
                      index={index}
                      expanded={!!expanded[index]}
                      onToggle={() =>
                        setExpanded((previous) => ({ ...previous, [index]: !previous[index] }))
                      }
                      onConsole={openConsole}
                      onCopyCurl={handleCopyCurl}
                    />
                  ))}
                </div>
              )}
            </div>

            {result.pages?.length > 1 ? (
              <div className="section">
                <div className="section-head">
                  <h2 className="section-title">Crawled pages</h2>
                  <span className="muted">{result.pages.length}</span>
                </div>
                <div className="live">
                  {result.pages.map((page, index) => (
                    <div className="live-row" key={`${page.url}-${index}`}>
                      <span className="live-scanner">HTTP {page.status || '—'}</span>
                      <span className="live-title" style={{ wordBreak: 'break-all' }}>
                        {page.url}
                      </span>
                      <span className="live-scanner">depth {page.depth}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            {result.aiAnalysis?.insights?.length > 0 ? (
              <div className="section">
                <div className="section-head">
                  <h2 className="section-title">
                    <Brain size={16} style={{ verticalAlign: '-3px', marginRight: 6, color: '#5b6ee1' }} />
                    Analysis insights
                  </h2>
                </div>
                <div className="insights">
                  {result.aiAnalysis.insights.map((insight, index) => (
                    <div className="insight" key={index}>
                      <Info size={15} style={{ marginTop: 1, color: '#2563eb', flex: '0 0 auto' }} />
                      <div>
                        <b>
                          {Math.round((insight.confidence || 0) * 100)}% · {insight.category}:
                        </b>{' '}
                        {insight.insight}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            {result.aiAnalysis?.recommendations?.length > 0 ? (
              <div className="section">
                <div className="section-head">
                  <h2 className="section-title">
                    <Lightbulb size={16} style={{ verticalAlign: '-3px', marginRight: 6, color: '#ca8a04' }} />
                    Prioritised recommendations
                  </h2>
                </div>
                <div className="recs-top">
                  {result.aiAnalysis.recommendations.map((rec, index) => (
                    <div className="rec" key={index}>
                      <span className={`sev-badge prio ${severityClass(rec.priority)}`}>{rec.priority}</span>
                      <div className="rec-body">
                        <span className="rec-title">{rec.title}</span>
                        <span>{rec.detail}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            {result.errors?.length > 0 ? (
              <div className="section">
                <div className="section-head">
                  <h2 className="section-title">Scanner errors</h2>
                </div>
                <div className="scanner-errors">
                  {result.errors.map((item, index) => (
                    <code key={index}>
                      {item.scanner}: {item.error}
                    </code>
                  ))}
                </div>
              </div>
            ) : null}
          </>
        ) : null}
      </main>

      {consoleItem ? (
        <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Request console">
          <div className="modal">
            <div className="modal-head">
              <div>
                <div className="modal-title">
                  <Terminal size={15} />
                  Request console
                </div>
                <div className="modal-sub">
                  Read-only replay of this finding. Edit the URL or add headers to test a hypothesis.
                </div>
              </div>
              <button type="button" className="btn-mini" onClick={closeConsole} aria-label="Close">
                <X size={14} />
              </button>
            </div>

            <div className="console-form">
              <select value={consoleMethod} onChange={(event) => setConsoleMethod(event.target.value)}>
                <option value="GET">GET</option>
                <option value="HEAD">HEAD</option>
                <option value="OPTIONS">OPTIONS</option>
              </select>
              <input
                className="console-url"
                type="text"
                value={consoleUrl}
                onChange={(event) => setConsoleUrl(event.target.value)}
                spellCheck={false}
                aria-label="Request URL"
              />
              <button type="button" className="btn btn-primary" onClick={handleReplay} disabled={consoleBusy}>
                {consoleBusy ? <Loader2 size={14} className="spinner" /> : <Send size={14} />}
                Send
              </button>
            </div>

            <label className="auth-block">
              <span>Extra headers — one per line (auth headers from the scan are added automatically)</span>
              <textarea
                rows={3}
                value={consoleHeaders}
                onChange={(event) => setConsoleHeaders(event.target.value)}
                placeholder={'Accept: application/json'}
                spellCheck={false}
              />
            </label>

            {consoleError ? (
              <Banner kind="error" icon={AlertTriangle}>
                {consoleError}
              </Banner>
            ) : null}

            {consoleResult ? (
              <div className="console-output">
                <div className="console-status">
                  HTTP {consoleResult.status} · {formatScanTime(consoleResult.timeMs)} ·{' '}
                  {consoleResult.body.length} bytes
                </div>
                <pre className="evidence">
                  {Object.entries(consoleResult.headers || {})
                    .map(([name, value]) => `${name}: ${Array.isArray(value) ? value.join(', ') : value}`)
                    .join('\n')}
                </pre>
                <pre className="evidence console-body">{consoleResult.body}</pre>
              </div>
            ) : (
              <p className="muted">
                Only GET, HEAD and OPTIONS are allowed. The target must match the origin of the last scan.
              </p>
            )}

            <p className="playbook-limits">{LAB_NOTICE}</p>
          </div>
        </div>
      ) : null}
    </div>
  );
}

const container = document.getElementById('root');
createRoot(container).render(<App />);
