'use strict';

/**
 * Local agent cost governor — thin wrapper around @kasbah/agent-cost-watch
 * when packaged; otherwise an in-process token budget with the same API shape.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const DIR = path.join(os.homedir(), '.kasbah-privacy');
const STATE = path.join(DIR, 'agent-cost.json');

function ensure() { try { fs.mkdirSync(DIR, { recursive: true, mode: 0o700 }); } catch (_) {} }

function resolvePkg() {
  const candidates = [
    process.resourcesPath ? path.join(process.resourcesPath, 'packages', 'agent-cost-watch') : null,
    path.join(__dirname, '..', '..', 'agent-cost-watch'),
    path.join(__dirname, '../../../packages/agent-cost-watch'),
  ].filter(Boolean);
  for (const dir of candidates) {
    try { if (fs.existsSync(path.join(dir, 'src', 'index.js'))) return dir; } catch (_) {}
  }
  return null;
}

function loadState() {
  try { return JSON.parse(fs.readFileSync(STATE, 'utf8')); }
  catch {
    return {
      dailyLimitTokens: 2_000_000,
      dailyLimitCents: 500,
      usedTokens: 0,
      usedCents: 0,
      day: new Date().toISOString().slice(0, 10),
      events: [],
    };
  }
}

function saveState(s) { ensure(); fs.writeFileSync(STATE, JSON.stringify(s, null, 2), { mode: 0o600 }); }

function rollDay(s) {
  const today = new Date().toISOString().slice(0, 10);
  if (s.day !== today) {
    s.day = today;
    s.usedTokens = 0;
    s.usedCents = 0;
    s.events = (s.events || []).slice(-20);
  }
  return s;
}

/** Record usage. Returns remaining budget + band. */
function record({ tokens = 0, costCents = 0, agent = 'local' } = {}) {
  const s = rollDay(loadState());
  s.usedTokens += Math.max(0, Number(tokens) || 0);
  s.usedCents += Math.max(0, Number(costCents) || 0);
  s.events = s.events || [];
  s.events.push({ ts: Date.now(), tokens, costCents, agent: String(agent).slice(0, 40) });
  if (s.events.length > 100) s.events.splice(0, s.events.length - 100);
  saveState(s);
  return evaluate(s);
}

function evaluate(s = rollDay(loadState())) {
  const tokPct = s.dailyLimitTokens > 0 ? s.usedTokens / s.dailyLimitTokens : 0;
  const costPct = s.dailyLimitCents > 0 ? s.usedCents / s.dailyLimitCents : 0;
  const pct = Math.max(tokPct, costPct);
  const band = pct >= 1 ? 'BLOCK' : pct >= 0.8 ? 'SLOW' : pct >= 0.5 ? 'MID' : 'FAST';
  return {
    day: s.day,
    usedTokens: s.usedTokens,
    usedCents: s.usedCents,
    dailyLimitTokens: s.dailyLimitTokens,
    dailyLimitCents: s.dailyLimitCents,
    pct: Math.round(pct * 1000) / 10,
    band,
    block: band === 'BLOCK',
    remainingTokens: Math.max(0, s.dailyLimitTokens - s.usedTokens),
    remainingCents: Math.max(0, s.dailyLimitCents - s.usedCents),
    recent: (s.events || []).slice(-5),
  };
}

function configure(patch = {}) {
  const s = rollDay(loadState());
  if (patch.dailyLimitTokens != null) s.dailyLimitTokens = Math.max(1000, Number(patch.dailyLimitTokens) || s.dailyLimitTokens);
  if (patch.dailyLimitCents != null) s.dailyLimitCents = Math.max(1, Number(patch.dailyLimitCents) || s.dailyLimitCents);
  if (patch.reset) { s.usedTokens = 0; s.usedCents = 0; s.events = []; }
  saveState(s);
  return evaluate(s);
}

function status() {
  const dir = resolvePkg();
  let pkg = null;
  if (dir) {
    try { pkg = { dir, available: true, exports: Object.keys(require(path.join(dir, 'src', 'index.js'))).slice(0, 10) }; }
    catch (e) { pkg = { dir, available: false, error: e.message }; }
  }
  return { ...evaluate(), package: pkg || { available: false, note: 'using local budget tracker' } };
}

module.exports = { record, evaluate, configure, status, loadState };
