'use strict';

/**
 * VulnScanner — Defensive Static Analysis for Code You Own
 * ========================================================
 *
 * This is the honest, working translation of the "ZeroDayDiscoveryEngine"
 * concept into KasbahOS's governance stack. It is DEFENSIVE only:
 *
 *   - It scans source you control to surface dangerous patterns BEFORE
 *     attackers do, with deterministic, explainable severity.
 *   - It does NOT generate exploits, fuzz third-party targets, or produce
 *     working attack payloads. Those are intentionally not implemented —
 *     see generateExploit() below, which is a governance-blocked stub.
 *
 * Design principles (matching zk-governance-proof.js's honesty):
 *   - No coin-flip "crash oracle". Findings come from real pattern matches
 *     against the bytes/text actually present.
 *   - Confidence is derived from match specificity + context, not random().
 *   - Every scan can emit a signed governance attestation via the existing
 *     GovernanceAttestation module, so results are auditable.
 *
 * RBAC: scanning requires at least ANALYST clearance; the (blocked) exploit
 * path would require OPERATOR + an explicit authorized-engagement token that
 * this product deliberately does not mint.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ── Clearance tiers (RBAC) ──────────────────────────────────────────────
const Clearance = Object.freeze({
  OBSERVER: 0,   // read-only
  ANALYST: 1,    // run defensive scans
  RESEARCHER: 2, // scan + export detailed findings
  OPERATOR: 3,   // reserved; exploit generation is NOT enabled
  DIRECTOR: 4,
});

/**
 * Dangerous-pattern catalogue. Each entry is defensive: it flags code that
 * is commonly the root cause of a vulnerability class, so an owner can fix
 * it. Patterns are language-tagged so we can scope by file extension.
 *
 * `base` is a CVSS-ish 0–10 baseline; final severity is adjusted by context.
 */
const PATTERNS = [
  // C / C++
  { id: 'c_strcpy',     lang: ['c'], cwe: 'CWE-120', base: 8.5,
    re: /\bstrcpy\s*\(/g, why: 'Unbounded string copy; use strlcpy/snprintf with a bound.' },
  { id: 'c_gets',       lang: ['c'], cwe: 'CWE-242', base: 9.5,
    re: /\bgets\s*\(/g, why: 'gets() cannot bound input and is removed from C11; use fgets().' },
  { id: 'c_sprintf',    lang: ['c'], cwe: 'CWE-787', base: 7.5,
    re: /\bsprintf\s*\(/g, why: 'Unbounded formatted write; use snprintf with a size.' },
  { id: 'c_system',     lang: ['c'], cwe: 'CWE-78', base: 7.0,
    re: /\bsystem\s*\(/g, why: 'Shell invocation; prefer execve with argv to avoid injection.' },
  { id: 'c_memcpy',     lang: ['c'], cwe: 'CWE-119', base: 6.5,
    re: /\bmemcpy\s*\(/g, why: 'Verify the length is bounded by the destination size.' },

  // JavaScript / TypeScript (most relevant to this repo)
  { id: 'js_eval',      lang: ['js', 'ts'], cwe: 'CWE-95', base: 8.0,
    re: /\beval\s*\(/g, why: 'Dynamic code execution; avoid or sandbox untrusted input.' },
  { id: 'js_function',  lang: ['js', 'ts'], cwe: 'CWE-95', base: 7.0,
    re: /\bnew\s+Function\s*\(/g, why: 'Function constructor executes strings as code.' },
  { id: 'js_child_exec', lang: ['js', 'ts'], cwe: 'CWE-78', base: 8.0,
    re: /\bchild_process\b[\s\S]{0,40}?\bexec\s*\(/g, why: 'exec() runs a shell; use execFile with an argv array.' },
  { id: 'js_exec_dynamic', lang: ['js', 'ts'], cwe: 'CWE-78', base: 8.5,
    // exec()/execSync() whose argument is built from a template ${...} OR
    // string concatenation (+) OR a bare variable — i.e. not a pure literal.
    re: /\bexec(?:Sync)?\s*\(\s*(?:[`'"][^`'"]*(?:\$\{|['"]\s*\+)|[A-Za-z_$][\w$.]*\s*[+)])/g,
    why: 'Command built from dynamic input (interpolation/concatenation/variable) — injection risk; use execFile with an argv array.' },
  { id: 'js_innerhtml', lang: ['js', 'ts'], cwe: 'CWE-79', base: 6.5,
    re: /\.innerHTML\s*=/g, why: 'Assigning to innerHTML can introduce XSS; sanitize or use textContent.' },
  { id: 'js_md5',       lang: ['js', 'ts'], cwe: 'CWE-327', base: 5.0,
    re: /createHash\s*\(\s*['"]md5['"]\s*\)/g, why: 'MD5 is broken for security; use SHA-256+.' },
  { id: 'js_math_random_secret', lang: ['js', 'ts'], cwe: 'CWE-338', base: 6.0,
    re: /Math\.random\s*\(\)/g, why: 'Math.random is not cryptographically secure; use crypto.randomBytes for secrets.' },

  // Python (ported from kasbah-os/zeroday_engine.py CWE patterns)
  { id: 'py_pickle',      lang: ['py'], cwe: 'CWE-502', base: 8.0,
    re: /\b(?:pickle|cPickle|dill|shelve)\s*\.\s*(?:loads?|load|Unpickler)\s*\(|yaml\s*\.\s*load\s*\((?![^)]*SafeLoader)/g, why: 'Deserializing untrusted data can execute code; use json or yaml.safe_load.' },
  { id: 'py_hardcoded_secret', lang: ['py'], cwe: 'CWE-798', base: 8.5,
    re: /\b(?:password|passwd|secret|api[_-]?key|aws_secret|token)\s*=\s*['"][^'"]{8,}['"]/gi, why: 'Hardcoded credential — move to env vars or a vault.' },
  { id: 'py_urlopen',     lang: ['py'], cwe: 'CWE-918', base: 6.0,
    re: /\burllib\.request\.urlopen\s*\(/g, why: 'URL fetch from code — validate the URL against an allowlist to avoid SSRF.' },

  // Shell (ported from kasbah-os/zeroday_engine.py CWE patterns)
  { id: 'sh_chmod777',    lang: ['sh'], cwe: 'CWE-732', base: 6.5,
    re: /\bchmod\s+(?:-[Rfv]*\s+)?777\b/g, why: 'World-writable permissions; use the least privilege that works.' },
];

// Context keywords that raise severity (attack surface / privilege).
const ESCALATORS = [
  { keys: ['kernel', 'syscall', 'kmalloc', 'copy_from_user'], bump: 1.5 },
  { keys: ['socket', 'recv', 'request', 'req.body', 'req.query', 'req.params'], bump: 1.0 },
  { keys: ['auth', 'password', 'token', 'credential', 'login', 'secret'], bump: 1.5 },
  { keys: ['setuid', 'setgid', 'sudo', 'root', 'admin'], bump: 2.0 },
];

const EXT_TO_LANG = {
  '.c': 'c', '.h': 'c', '.cc': 'c', '.cpp': 'c', '.hpp': 'c',
  '.js': 'js', '.mjs': 'js', '.cjs': 'js', '.jsx': 'js',
  '.ts': 'ts', '.tsx': 'ts',
  '.py': 'py', '.pyw': 'py',
  '.sh': 'sh', '.bash': 'sh', '.zsh': 'sh',
};

function langForPath(path) {
  const m = String(path).toLowerCase().match(/(\.[a-z]+)$/);
  return m ? (EXT_TO_LANG[m[1]] || null) : null;
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function lineAt(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === '\n') line++;
  }
  return line;
}

class VulnScanner {
  /**
   * @param {object} [opts]
   * @param {number} [opts.clearance] one of Clearance.* (default ANALYST)
   * @param {object} [opts.attestor]  optional GovernanceAttestation instance
   *                                  for signing scan results.
   */
  constructor(opts = {}) {
    this.clearance = opts.clearance != null ? opts.clearance : Clearance.ANALYST;
    this.attestor = opts.attestor || null;
    this.scanCount = 0;
  }

  /**
   * Scan a single source string. Pure and deterministic.
   * @param {string} source
   * @param {object} [meta] e.g. { path: 'app/x.js', lang: 'js' }
   * @returns {{findings: Array, summary: object}}
   */
  scanSource(source, meta = {}) {
    if (this.clearance < Clearance.ANALYST) {
      throw new Error('VulnScanner: ANALYST clearance required to scan');
    }
    const text = String(source);
    const lang = meta.lang || langForPath(meta.path || '') || 'js';
    const findings = [];

    for (const p of PATTERNS) {
      if (!p.lang.includes(lang)) continue;
      // Fresh regex per scan — never mutate the shared module-level pattern's
      // lastIndex, which would leak state across scanSource() calls.
      const re = new RegExp(p.re.source, 'g');
      let m;
      while ((m = re.exec(text)) !== null) {
        const idx = m.index;
        const ctx = text.slice(Math.max(0, idx - 120), idx + 120).toLowerCase();
        let severity = p.base;
        const escalators = [];
        for (const e of ESCALATORS) {
          if (e.keys.some(k => ctx.includes(k))) {
            severity += e.bump;
            escalators.push(...e.keys.filter(k => ctx.includes(k)));
          }
        }
        severity = Math.min(10, Math.round(severity * 10) / 10);
        // Confidence: specific single-token API matches are high-confidence;
        // escalator context nudges it up. Capped honestly below 1.0.
        const confidence = Math.min(0.95, 0.6 + (escalators.length * 0.1));
        findings.push({
          id: `FND-${sha256Hex(p.id + idx + (meta.path || '')).slice(0, 10)}`,
          rule: p.id,
          cwe: p.cwe,
          severity,
          confidence,
          line: lineAt(text, idx),
          match: m[0],
          why: p.why,
          escalators: [...new Set(escalators)],
          path: meta.path || null,
        });
        if (m.index === re.lastIndex) re.lastIndex++; // avoid zero-width loop
      }
    }

    findings.sort((a, b) => b.severity - a.severity);
    this.scanCount++;

    const summary = {
      path: meta.path || null,
      lang,
      findingCount: findings.length,
      maxSeverity: findings.length ? findings[0].severity : 0,
      bytesScanned: text.length,
    };
    return { findings, summary };
  }

  /**
   * Scan many files. Accepts [{ path, source }] to stay filesystem-agnostic
   * (the caller decides what to read — keeps this module side-effect free).
   */
  scanFiles(files) {
    const all = [];
    const perFile = [];
    for (const f of files) {
      const { findings, summary } = this.scanSource(f.source, { path: f.path });
      all.push(...findings);
      perFile.push(summary);
    }
    all.sort((a, b) => b.severity - a.severity);
    return {
      findings: all,
      files: perFile,
      summary: {
        filesScanned: files.length,
        findingCount: all.length,
        maxSeverity: all.length ? all[0].severity : 0,
        criticalCount: all.filter(x => x.severity >= 9).length,
        highCount: all.filter(x => x.severity >= 7 && x.severity < 9).length,
      },
    };
  }

  /** Read and scan a single file from disk. Caller is responsible for path safety. */
  scanFile(filePath) {
    const source = fs.readFileSync(filePath, 'utf8');
    return this.scanSource(source, { path: filePath });
  }

  /**
   * Walk a directory and scan every recognized source file under it. Caller
   * is responsible for path safety (this does not confine `dirPath` itself).
   */
  scanDirectory(dirPath, opts = {}) {
    const maxDepth = opts.maxDepth != null ? opts.maxDepth : 6;
    const maxFileBytes = opts.maxFileBytes != null ? opts.maxFileBytes : 2_000_000;
    const skipDirs = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'vendor', 'coverage']);
    const files = [];
    const walk = (p, depth) => {
      if (depth > maxDepth) return;
      let entries;
      try { entries = fs.readdirSync(p, { withFileTypes: true }); } catch { return; }
      for (const e of entries) {
        if (skipDirs.has(e.name)) continue;
        const full = path.join(p, e.name);
        if (e.isDirectory()) { walk(full, depth + 1); continue; }
        if (!e.isFile() || !langForPath(e.name)) continue;
        let stat;
        try { stat = fs.statSync(full); } catch { continue; }
        if (stat.size > maxFileBytes) continue;
        try { files.push({ path: full, source: fs.readFileSync(full, 'utf8') }); } catch (_) {}
      }
    };
    walk(dirPath, 0);
    return this.scanFiles(files);
  }

  /**
   * Produce a signed, witness-private attestation that a scan was run and
   * met a policy bar (e.g. "no critical findings"), without leaking the
   * source. Requires an attestor (GovernanceAttestation) to be supplied.
   */
  attestScan(scanResult, publicInput = {}) {
    if (!this.attestor) {
      throw new Error('VulnScanner: no attestor configured');
    }
    const pub = { maxAllowedSeverity: 8.999, ...publicInput };
    const witness = {
      riskScore: scanResult.summary.maxSeverity / 10,
      verb: 'STATIC_SCAN',
      piiCount: 0,
      requestCount: 0,
    };
    this.attestor.createCircuit([
      { id: 'S1', name: 'no_critical_findings',
        evaluate: (w) => (w.riskScore || 0) * 10 < (pub.maxAllowedSeverity) },
    ]);
    return this.attestor.generateProof(witness, pub);
  }

  /**
   * Governance-blocked. Exploit generation is intentionally NOT implemented.
   * A privacy-first governance product detects and constrains offensive
   * action; it does not synthesize working attacks. This stub exists so the
   * surface is explicit and auditable rather than silently absent.
   */
  generateExploit() {
    return {
      blocked: true,
      reason:
        'Exploit synthesis is disabled by governance policy. KasbahOS is a ' +
        'defensive platform; generating working exploit payloads requires a ' +
        'separately authorized engagement scope that this product does not provision.',
    };
  }
}

module.exports = { VulnScanner, Clearance, PATTERNS };
