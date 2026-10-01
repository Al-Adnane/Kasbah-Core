'use strict';

/**
 * Dead-man / check-in switch — local only.
 * If you don't check in before deadline, mint a signed "missed check-in"
 * proof-of-protection-style receipt (so a trusted contact can see it).
 * No cloud push — poll the local state.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const DIR = path.join(os.homedir(), '.kasbah-privacy');
const STATE = path.join(DIR, 'deadman.json');
const LOG = path.join(DIR, 'deadman-log.jsonl');

function ensure() { fs.mkdirSync(DIR, { recursive: true, mode: 0o700 }); }

function load() {
  try { return JSON.parse(fs.readFileSync(STATE, 'utf8')); }
  catch { return { enabled: false, intervalHours: 24, lastCheckIn: null, graceHours: 6 }; }
}

function save(s) {
  ensure();
  fs.writeFileSync(STATE, JSON.stringify(s, null, 2), { mode: 0o600 });
  return s;
}

function checkIn(note = '') {
  const s = load();
  s.lastCheckIn = new Date().toISOString();
  s.note = note;
  if (!s.intervalHours) s.intervalHours = 24;
  save(s);
  return s;
}

function deadline(s) {
  const last = s.lastCheckIn ? new Date(s.lastCheckIn) : new Date();
  const h = (s.intervalHours || 24) + (s.graceHours || 0);
  return new Date(last.getTime() + h * 3600 * 1000);
}

function status() {
  const s = load();
  const dl = deadline(s);
  const overdue = s.enabled && Date.now() > dl.getTime();
  return {
    enabled: s.enabled,
    intervalHours: s.intervalHours,
    graceHours: s.graceHours,
    lastCheckIn: s.lastCheckIn,
    deadline: dl.toISOString(),
    overdue,
    msLeft: dl.getTime() - Date.now(),
  };
}

/** If overdue, mint a local proof event (caller may also mint POP receipt). */
function poll() {
  const st = status();
  if (st.overdue) {
    ensure();
    fs.appendFileSync(LOG, JSON.stringify({ ts: new Date().toISOString(), event: 'missed_check_in', st }) + '\n');
  }
  return st;
}

function configure({ enabled, intervalHours, graceHours, contactNote } = {}) {
  const s = load();
  if (enabled != null) s.enabled = !!enabled;
  if (intervalHours != null) s.intervalHours = Math.max(1, Number(intervalHours));
  if (graceHours != null) s.graceHours = Math.max(0, Number(graceHours));
  if (contactNote != null) s.contactNote = contactNote;
  save(s);
  return status();
}

function log() {
  try {
    return fs.readFileSync(LOG, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)).slice(-50);
  } catch { return []; }
}

module.exports = { checkIn, status, poll, configure, log, STATE };
