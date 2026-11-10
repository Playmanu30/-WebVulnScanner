const { execFileSync } = require('child_process');
const { readdirSync, statSync } = require('fs');
const path = require('path');

// Syntax-check every .js file under src/. The renderer is .jsx and is covered by
// the webpack build, not by node --check.
function walk(directory) {
  const entries = readdirSync(directory);
  const files = [];
  for (const entry of entries) {
    const full = path.join(directory, entry);
    if (statSync(full).isDirectory()) files.push(...walk(full));
    else if (entry.endsWith('.js')) files.push(full);
  }
  return files;
}

const files = walk(path.join(__dirname, '..', '..', 'src'));

for (const file of files) {
  execFileSync(process.execPath, ['--check', file], { stdio: 'inherit' });
}

console.log(`syntax ok: ${files.length} files`);
