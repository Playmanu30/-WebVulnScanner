const fs = require('fs');
const path = require('path');

// Resolve paths relative to the project root, never the current working directory.
// This keeps the scanner working when Electron is launched from another folder.
const PROJECT_ROOT = path.join(__dirname, '..', '..');
const CONFIG_DIR = process.env.VULN_CONFIG_DIR || path.join(PROJECT_ROOT, 'config');

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

/**
 * Config files in this project look like:
 *   { "patterns": [...], "version": "2.0.0" }
 *   { "payloads": [...] }
 *   { "cipherSuites": [...] }
 * Older code assigned the whole object to a field and iterated it, which threw
 * "x is not iterable". This helper returns the array no matter the wrapper key.
 */
function extractArray(parsed, preferredKeys = []) {
  if (Array.isArray(parsed)) return parsed;
  if (!parsed || typeof parsed !== 'object') return null;

  for (const key of preferredKeys) {
    if (Array.isArray(parsed[key])) return parsed[key];
  }

  // Fall back to the first array-valued property in the document.
  for (const value of Object.values(parsed)) {
    if (Array.isArray(value)) return value;
  }
  return null;
}

/**
 * Load a pattern/payload list from config/<fileName>.
 * Returns { values, source } where source is the file path or 'defaults'.
 */
function loadList(fileName, preferredKeys, defaults = []) {
  const file = path.join(CONFIG_DIR, fileName);
  try {
    if (fs.existsSync(file)) {
      const values = extractArray(readJson(file), preferredKeys);
      if (Array.isArray(values) && values.length > 0) {
        return { values, source: file };
      }
      console.warn(`[config] ${fileName} contains no usable array, using defaults`);
    } else {
      console.warn(`[config] ${fileName} not found, using defaults`);
    }
  } catch (error) {
    console.warn(`[config] failed to read ${fileName}: ${error.message}`);
  }
  return { values: defaults.slice(), source: 'defaults' };
}

module.exports = { loadList, PROJECT_ROOT, CONFIG_DIR };
