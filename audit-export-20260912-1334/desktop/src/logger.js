'use strict';

/**
 * Structured logger — JSON lines to ~/.kasbah-privacy/logs/app.jsonl
 * plus tagged console. Replaces ad-hoc console.log.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const DIR = path.join(os.homedir(), '.kasbah-privacy', 'logs');
const FILE = path.join(DIR, 'app.jsonl');
const MAX = 2 * 1024 * 1024;

function ensure() {
  try {
    fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
    // mkdirSync's mode only applies when it actually creates the directory —
    // an already-existing dir (e.g. created under a looser umask before this
    // check existed) is left as-is. Tighten it explicitly every time.
    fs.chmodSync(DIR, 0o700);
  } catch (_) {}
  try { if (fs.existsSync(FILE)) fs.chmodSync(FILE, 0o600); } catch (_) {}
}

function rotate() {
  try {
    if (fs.existsSync(FILE) && fs.statSync(FILE).size > MAX) {
      fs.renameSync(FILE, FILE + '.1');
    }
  } catch (_) {}
}

function write(level, tag, msg, meta) {
  ensure();
  rotate();
  const rec = {
    ts: new Date().toISOString(),
    level,
    tag: tag || 'app',
    msg: String(msg),
    ...(meta && typeof meta === 'object' ? { meta } : {}),
  };
  try { fs.appendFileSync(FILE, JSON.stringify(rec) + '\n', { mode: 0o600 }); } catch (_) {}
  const line = `[${rec.tag}] ${rec.msg}`;
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
  return rec;
}

module.exports = {
  info: (tag, msg, meta) => write('info', tag, msg, meta),
  warn: (tag, msg, meta) => write('warn', tag, msg, meta),
  error: (tag, msg, meta) => write('error', tag, msg, meta),
  FILE,
  DIR,
};
