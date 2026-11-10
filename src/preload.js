const { contextBridge, ipcRenderer } = require('electron');

// Minimal, explicit bridge. The renderer has no Node access (contextIsolation on),
// so every privileged operation is funnelled through these IPC calls.
contextBridge.exposeInMainWorld('scannerAPI', {
  startScan: (url, options) => ipcRenderer.invoke('start-scan', url, options),
  stopScan: () => ipcRenderer.send('stop-scan'),
  getScanners: () => ipcRenderer.invoke('get-scanners'),
  exportReport: (results, format) => ipcRenderer.invoke('export-report', { results, format }),
  replayRequest: (payload) => ipcRenderer.invoke('replay-request', payload),
  importFindings: () => ipcRenderer.invoke('import-findings'),
  appInfo: () => ipcRenderer.invoke('app-info'),
  onProgress: (callback) => {
    const listener = (_event, progress) => callback(progress);
    ipcRenderer.on('scan-progress', listener);
    return () => ipcRenderer.removeListener('scan-progress', listener);
  }
});

console.log('[preload] scannerAPI bridge ready');
