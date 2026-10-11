'use strict';
/**
 * scripts/lint.js — dependency-free linter (audit B6).
 *
 * `node --check` every first-party JS file, and count the two highest-value
 * smells so they cannot grow silently: empty catch blocks (D10) and raw
 * innerHTML sinks (D11). Exits non-zero on any syntax error. Swap in ESLint
 * (no-empty, no-undef, a raw-HTML rule) when the dependency is added.
 *
 * Run: node scripts/lint.js
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const SKIP = /(^|\/)(node_modules|\.git|dist|build|_archive|\.next|\.mimosa|coverage)(\/|$)/;

const files = [];
(function walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (SKIP.test(p)) continue;
    if (e.isDirectory()) walk(p);
    else if (/\.(js|cjs|mjs)$/.test(e.name)) files.push(p);
  }
})(ROOT);

let syntaxErrors = 0, emptyCatch = 0, innerHTML = 0;
for (const f of files) {
  let src = '';
  try { src = fs.readFileSync(f, 'utf8'); } catch (_) { continue; }
  try { execFileSync(process.execPath, ['--check', f], { stdio: 'ignore' }); }
  catch (_) { console.error('SYNTAX ' + path.relative(ROOT, f)); syntaxErrors++; }
  emptyCatch += (src.match(/catch\s*(\([^)]*\))?\s*\{\s*\}/g) || []).length;
  innerHTML  += (src.match(/\.innerHTML\s*=/g) || []).length;
}

console.log(`lint: ${files.length} files · syntax errors ${syntaxErrors} · empty catch ${emptyCatch} · innerHTML sinks ${innerHTML}`);

// Ratchet (B6): the two smell counts may go down but never up. Lower the
// numbers in scripts/lint-baseline.json as the code is cleaned; run with
// --update-baseline after a clean-up to record the new floor.
const BASELINE = path.join(__dirname, 'lint-baseline.json');
let base = null;
try { base = JSON.parse(fs.readFileSync(BASELINE, 'utf8')); } catch (_) { base = null; }
if (process.argv.includes('--update-baseline') || !base) {
  fs.writeFileSync(BASELINE, JSON.stringify({ emptyCatch, innerHTML }, null, 2) + '\n');
  console.log(`lint: baseline ${base ? 'updated' : 'created'} → empty catch ${emptyCatch}, innerHTML ${innerHTML}`);
  base = { emptyCatch, innerHTML };
}
let ratchetFail = 0;
if (emptyCatch > base.emptyCatch) { console.error(`lint: empty catch blocks rose ${base.emptyCatch} → ${emptyCatch}`); ratchetFail = 1; }
if (innerHTML > base.innerHTML)   { console.error(`lint: innerHTML sinks rose ${base.innerHTML} → ${innerHTML}`); ratchetFail = 1; }
process.exit(syntaxErrors || ratchetFail ? 1 : 0);
