'use strict';

/**
 * Defensive local vuln / secret scanner for files you own.
 * Patterns only — no exploit generation.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PATTERNS = [
  { id: 'hardcoded_aws', severity: 'high', label: 'AWS Access Key ID', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: 'hardcoded_gh', severity: 'high', label: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { id: 'private_key', severity: 'critical', label: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { id: 'eval', severity: 'medium', label: 'eval() on dynamic input', re: /\beval\s*\(/g },
  { id: 'child_exec', severity: 'high', label: 'shell exec with string', re: /\b(?:exec|execSync|spawn)\s*\(\s*[`'"]/g },
  { id: 'sql_concat', severity: 'medium', label: 'possible SQL string concat', re: /SELECT\s+.+\+\s*|WHERE\s+\w+\s*=\s*['"]\s*\+/gi },
  { id: 'http_secret', severity: 'medium', label: 'secret in URL query', re: /[?&](?:api[_-]?key|token|secret|password)=/gi },
  { id: 'dangerous_fs', severity: 'medium', label: 'rm/unlink recursive', re: /\brm\s+-rf\b|unlinkSync\s*\(|rmSync\s*\(/g },
];

function scanText(text, name = 'stdin') {
  const findings = [];
  for (const p of PATTERNS) {
    p.re.lastIndex = 0;
    const m = text.match(p.re);
    if (m && m.length) {
      findings.push({ ...p, count: m.length, sample: String(m[0]).slice(0, 24) + '…', file: name });
    }
  }
  const sev = findings.some((f) => f.severity === 'critical') ? 'CRITICAL'
    : findings.some((f) => f.severity === 'high') ? 'HIGH'
    : findings.length ? 'MEDIUM' : 'CLEAN';
  return { sev, findings, file: name, engine: 'local-static-v1' };
}

function scanFile(filePath) {
  const st = fs.statSync(filePath);
  if (st.size > 2 * 1024 * 1024) return { sev: 'SKIP', findings: [], file: filePath, note: 'file >2MB' };
  const text = fs.readFileSync(filePath, 'utf8');
  return scanText(text, path.basename(filePath));
}

function scanDir(dir, maxFiles = 200) {
  const results = [];
  let n = 0;
  const walk = (d) => {
    if (n >= maxFiles) return;
    for (const ent of fs.readdirSync(d, { withFileTypes: true })) {
      if (n >= maxFiles) return;
      if (ent.name === 'node_modules' || ent.name === '.git') continue;
      const p = path.join(d, ent.name);
      if (ent.isDirectory()) walk(p);
      else if (/\.(js|ts|py|env|json|yml|yaml|sh|pem|key)$/i.test(ent.name)) {
        try {
          results.push(scanFile(p));
          n++;
        } catch (_) {}
      }
    }
  };
  walk(dir);
  const high = results.filter((r) => r.sev === 'HIGH' || r.sev === 'CRITICAL');
  return {
    dir,
    scanned: results.length,
    highCount: high.length,
    results: results.filter((r) => r.findings.length).sort((a, b) => (b.findings.length - a.findings.length)).slice(0, 40),
    engine: 'local-static-v1',
  };
}

module.exports = { scanText, scanFile, scanDir, PATTERNS };
