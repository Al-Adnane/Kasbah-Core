'use strict';

/**
 * Local nomos-engine ethics — loads packages/nomos-engine when packaged.
 * Fail-soft: returns { available:false } if missing (api-server /v1/nomos still possible).
 */

const fs = require('fs');
const path = require('path');

function resolveDir() {
  const { app } = (() => { try { return require('electron'); } catch (_) { return {}; } })();
  const candidates = [
    process.resourcesPath ? path.join(process.resourcesPath, 'packages', 'nomos-engine') : null,
    path.join(__dirname, '..', '..', 'nomos-engine'),
    path.join(__dirname, '../../../packages/nomos-engine'),
    '/Users/mac/Desktop/KasbahFinal/packages/nomos-engine',
  ].filter(Boolean);
  for (const d of candidates) {
    try { if (fs.existsSync(path.join(d, 'src', 'index.js'))) return d; } catch (_) {}
  }
  return null;
}

let _mod;
function load() {
  if (_mod !== undefined) return _mod;
  const dir = resolveDir();
  if (!dir) { _mod = null; return _mod; }
  try { _mod = { dir, ...require(path.join(dir, 'src', 'index.js')) }; }
  catch (e) { _mod = { dir, error: e.message }; }
  return _mod;
}

function status() {
  const m = load();
  return {
    available: !!(m && !m.error && (m.createDefaultEngine || m.ConsensusEngine)),
    dir: m?.dir || null,
    error: m?.error || null,
    exports: m ? Object.keys(m).slice(0, 12) : [],
  };
}

function evaluate(content) {
  const m = load();
  if (!m || m.error) return { ok: false, available: false, error: m?.error || 'nomos-engine not installed' };
  try {
    const eng = m.createDefaultEngine ? m.createDefaultEngine() : null;
    if (eng?.evaluate) return { ok: true, available: true, ...eng.evaluate(String(content || '')) };
    return { ok: false, available: true, error: 'no evaluate export' };
  } catch (e) { return { ok: false, available: true, error: e.message }; }
}

function debate(content, initialVerdict, challenge) {
  const m = load();
  if (!m || m.error) return { ok: false, available: false, error: m?.error || 'nomos-engine not installed' };
  try {
    const eng = m.createDebateEngine ? m.createDebateEngine() : null;
    if (eng?.debate) return { ok: true, available: true, ...eng.debate(String(content||''), initialVerdict, String(challenge||'')) };
    return { ok: false, available: true, error: 'no debate export' };
  } catch (e) { return { ok: false, available: true, error: e.message }; }
}

module.exports = { status, evaluate, debate, resolveDir };
