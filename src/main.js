const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs');

const { ScannerEngine } = require('./core/scanner-engine');
const { ReportGenerator } = require('./core/report-generator');
const { parseImport } = require('./core/importers');
const { fetchPage } = require('./scanners/utils');

let mainWindow = null;
let scannerEngine = null;
let reportGenerator = null;
let scanInFlight = false;
let lastScanOrigin = null;

function createWindow() {
  const iconPath = path.join(__dirname, 'icon', 'base64-icon.png');
  const windowOptions = {
    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    backgroundColor: '#667eea',
    show: false,
    title: 'AI Web Vulnerability Scanner - Production Grade Security Suite',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  };

  if (fs.existsSync(iconPath)) windowOptions.icon = iconPath;

  mainWindow = new BrowserWindow(windowOptions);
  mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'));
  mainWindow.once('ready-to-show', () => mainWindow.show());

  if (process.env.NODE_ENV === 'development') {
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  }

  // The scanner UI is a single local page: block navigation and open real links
  // in the system browser instead of inside the app.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith('file://')) {
      event.preventDefault();
      if (/^https?:/i.test(url)) shell.openExternal(url);
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

async function getEngine() {
  if (scannerEngine) return scannerEngine;

  scannerEngine = new ScannerEngine();
  scannerEngine.onProgressCallback = (progress) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('scan-progress', progress);
    }
  };
  await scannerEngine.initialize();
  console.log(`[main] scanner engine ready with ${scannerEngine.scanners.length} scanners`);
  return scannerEngine;
}

function getReporter() {
  if (!reportGenerator) reportGenerator = new ReportGenerator();
  return reportGenerator;
}

function validateTarget(url) {
  if (typeof url !== 'string' || url.trim() === '') {
    return { ok: false, error: 'Please enter a target URL.' };
  }
  let parsed;
  try {
    parsed = new URL(url.trim());
  } catch {
    return { ok: false, error: 'That does not look like a valid URL.' };
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { ok: false, error: 'Only http:// and https:// targets are supported.' };
  }
  // Credentials in the URL would end up in reports and logs. Use the auth
  // fields instead, which are scoped and never serialised.
  if (parsed.username || parsed.password) {
    return {
      ok: false,
      error: 'Remove credentials from the URL. Use the username/password fields instead, so they never reach a report.'
    };
  }
  return { ok: true, url: parsed.toString() };
}

app.whenReady().then(() => {
  createWindow();
  // Warm the scanners up so the first scan does not pay the config-load cost.
  getEngine().catch((error) => console.error('[main] engine init failed:', error.message));

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

ipcMain.handle('app-info', async () => ({
  version: app.getVersion(),
  electron: process.versions.electron,
  chrome: process.versions.chrome,
  node: process.versions.node
}));

ipcMain.handle('get-scanners', async () => {
  const engine = await getEngine();
  return engine.scanners.map((scanner) => ({
    name: scanner.name,
    description: scanner.description,
    version: scanner.version,
    configSource: scanner.configSource,
    runsPerPage: scanner.runsPerPage === true
  }));
});

ipcMain.handle('start-scan', async (event, rawUrl, options = {}) => {
  const target = validateTarget(rawUrl);
  if (!target.ok) return { success: false, error: target.error };

  // Guardrail: a scan sends crafted requests to someone else's system. The UI
  // must confirm authorisation, and the main process refuses to start without
  // it even if the renderer is manipulated.
  if (options.authorized !== true) {
    return {
      success: false,
      error:
        'Authorisation not confirmed. Tick the authorisation checkbox before scanning a target you do not own.'
    };
  }

  if (scanInFlight) return { success: false, error: 'A scan is already running.' };

  scanInFlight = true;
  try {
    const engine = await getEngine();
    const numeric = (value, fallback, min, max) => {
      const parsed = Number(value);
      if (!Number.isFinite(parsed)) return fallback;
      return Math.min(max, Math.max(min, Math.round(parsed)));
    };

    const scanOptions = {
      timeout: numeric(options.timeout, 20000, 3000, 120000),
      maxPages: numeric(options.maxPages, 12, 1, 40),
      depth: numeric(options.depth, 2, 0, 4),
      perPageLimit: numeric(options.perPageLimit, 4, 1, 12),
      concurrency: numeric(options.concurrency, 3, 1, 6),
      delayMs: numeric(options.delayMs, 40, 0, 1000),
      blind: options.blind === true
    };

    // Authentication: cookies plus optional extra headers. Values are length
    // capped, header names are validated, and the engine scopes them to the
    // target origin.
    const authInput = options.auth && typeof options.auth === 'object' ? options.auth : {};
    const authHeaders = {};
    for (const [name, value] of Object.entries(authInput.headers || {})) {
      if (!/^[A-Za-z0-9-]{1,64}$/.test(name)) continue;
      if (typeof value !== 'string' || value.length === 0 || value.length > 4096) continue;
      authHeaders[name] = value;
    }
    if (typeof authInput.username === 'string' && authInput.username.length > 0) {
      const password = typeof authInput.password === 'string' ? authInput.password : '';
      authHeaders.Authorization = `Basic ${Buffer.from(`${authInput.username}:${password}`).toString('base64')}`;
    }
    const cookies = typeof authInput.cookies === 'string' ? authInput.cookies.slice(0, 8192).trim() : '';
    if (cookies || Object.keys(authHeaders).length > 0) {
      scanOptions.auth = { cookies, headers: authHeaders };
    }

    console.log(
      `[main] scanning ${target.url} (pages<=${scanOptions.maxPages}, probePages=${scanOptions.perPageLimit}, concurrency=${scanOptions.concurrency}${scanOptions.auth ? ', authenticated' : ''})`
    );
    const results = await engine.scan(target.url, scanOptions);

    // Scope for the request console is only set once a scan has actually
    // finished, so a failed or cancelled attempt cannot authorise replay.
    lastScanOrigin = new URL(target.url).origin;
    return { success: true, ...results };
  } catch (error) {
    console.error('[main] scan failed:', error.message);
    return { success: false, error: error.message };
  } finally {
    scanInFlight = false;
  }
});

ipcMain.on('stop-scan', () => {
  if (scannerEngine) scannerEngine.cancel();
});

const REPLAY_METHODS = ['GET', 'HEAD', 'OPTIONS'];

ipcMain.handle('replay-request', async (event, payload = {}) => {
  if (payload.authorized !== true) {
    return { success: false, error: 'Confirm authorisation before replaying requests.' };
  }
  if (scanInFlight) {
    return { success: false, error: 'Wait for the current scan to finish before replaying requests.' };
  }
  if (!lastScanOrigin) {
    return { success: false, error: 'Run a scan first: replay is scoped to the last scanned origin.' };
  }

  const target = validateTarget(payload.url);
  if (!target.ok) return { success: false, error: target.error };
  if (new URL(target.url).origin !== lastScanOrigin) {
    return {
      success: false,
      error: 'Replay is limited to the origin of the last scan. Start a scan for that host first.'
    };
  }

  const method = String(payload.method || 'GET').toUpperCase();
  if (!REPLAY_METHODS.includes(method)) {
    return {
      success: false,
      error: 'The request console is read-only: only GET, HEAD and OPTIONS are allowed.'
    };
  }

  const headers = {};
  for (const [name, value] of Object.entries(payload.headers || {})) {
    if (!/^[A-Za-z0-9-]{1,64}$/.test(name)) continue;
    if (/^(host|content-length|connection|transfer-encoding)$/i.test(name)) continue;
    if (typeof value !== 'string' || value.length > 4096) continue;
    headers[name] = value;
  }

  try {
    const response = await fetchPage(target.url, {
      method,
      headers,
      redirect: false,
      timeout: 15000
    });
    return {
      success: true,
      status: response.status,
      headers: response.headers,
      body: String(response.html || '').slice(0, 120000),
      timeMs: response.timeMs
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('import-findings', async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
    title: 'Import ZAP / nuclei findings',
    properties: ['openFile'],
    filters: [
      { name: 'ZAP, nuclei or JSON', extensions: ['json', 'jsonl', 'ndjson'] },
      { name: 'All files', extensions: ['*'] }
    ]
  });
  if (canceled || !filePaths || filePaths.length === 0) {
    return { success: false, canceled: true };
  }

  const file = filePaths[0];
  try {
    const stat = fs.statSync(file);
    if (stat.size > 10 * 1024 * 1024) {
      return { success: false, error: 'File is larger than 10 MB; export a smaller report.' };
    }

    const parsed = parseImport(fs.readFileSync(file, 'utf8'), file);
    if (parsed.findings.length === 0) {
      return {
        success: false,
        error: 'No findings recognised. Supported: ZAP JSON report, nuclei JSONL, or a JSON findings array.'
      };
    }

    return {
      success: true,
      source: parsed.source,
      findings: parsed.findings,
      fileName: path.basename(file)
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('export-report', async (event, payload = {}) => {
  const { results, format = 'json' } = payload;
  if (!results) return { success: false, error: 'Nothing to export yet.' };

  const normalizedFormat = ['json', 'html', 'text'].includes(String(format).toLowerCase())
    ? String(format).toLowerCase()
    : 'json';
  const extension = normalizedFormat === 'text' ? 'txt' : normalizedFormat;
  const targetUrl = Array.isArray(results.url) ? results.url[0] : results.url;
  const safeHost = String(targetUrl || 'scan')
    .replace(/^https?:\/\//, '')
    .replace(/[^a-z0-9.-]+/gi, '_')
    .slice(0, 40);
  const defaultName = `vulnscan-${safeHost}-${Date.now()}.${extension}`;

  const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
    title: 'Save scan report',
    defaultPath: path.join(app.getPath('documents'), defaultName),
    filters: [{ name: `${normalizedFormat.toUpperCase()} report`, extensions: [extension] }]
  });

  if (canceled || !filePath) return { success: false, canceled: true };

  const report = await getReporter().generate(targetUrl || 'unknown', results, normalizedFormat);
  if (report.status !== 'success') {
    return { success: false, error: report.error || 'Report generation failed.' };
  }

  try {
    fs.writeFileSync(filePath, report.content);
    return { success: true, savedFile: filePath, size: report.size };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

console.log('[main] AI Web Vulnerability Scanner initialised');
