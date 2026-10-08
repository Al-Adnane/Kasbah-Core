'use strict';

/**
 * Microphone Sentinel — monitors which processes access the system microphone
 * on macOS and emits alerts when an unexpected process starts recording.
 *
 * Two layers:
 *   1. TCC approval list — which apps have been granted mic permission (SQLite)
 *   2. Active capture check — which permitted apps are currently recording
 *      (CoreAudio lsof heuristic + `lsof` pid cross-reference)
 *
 * When a process appears to be actively recording AND is not in the user's
 * approved list, the sentinel fires an alert via `onChange`.
 *
 * Silent-speech / subvocal input protection:
 *   Any app that accesses the microphone silently — without the user having
 *   explicitly opened it for audio — is a candidate for harvesting subvocal
 *   or near-silent speech. The sentinel's approved-list model means the user
 *   explicitly whitelist apps that should record; everything else is flagged.
 *
 * Honest scope:
 *   - On macOS 12+ reading TCC.db requires Full Disk Access. If FDA is not
 *     granted, the TCC layer gracefully skips and the sentinel falls back to
 *     the lsof heuristic alone.
 *   - lsof-based active capture detection is a heuristic: it matches processes
 *     holding open file descriptors to CoreAudio device paths. It can miss
 *     processes that use AVFoundation via XPC.
 *   - This does NOT intercept or block microphone access at the OS level —
 *     it observes and alerts. Blocking requires a kernel extension (not built).
 */

const fs       = require('fs');
const os       = require('os');
const path     = require('path');
const crypto   = require('crypto');
const { execFile, exec } = require('child_process');

const SETTINGS_DIR  = path.join(os.homedir(), '.kasbah-privacy');
const APPROVED_FILE = path.join(SETTINGS_DIR, 'mic-approved.json');
const POLL_MS       = 8000; // check every 8 s

// Known legitimate always-on audio processes — never flagged.
const SYSTEM_AUDIO_PROCS = new Set([
  'coreaudiod', 'audiod', 'AirPlayXPCHelper', 'bluetoothd',
  'Control Center', 'SystemUIServer', 'Kasbah Guard',
]);

let _timer   = null;
let _onChange = null;
let _lastAlerted = new Set();

// ─── Persistence ─────────────────────────────────────────────────────────────

function _loadApproved() {
  try { return new Set(JSON.parse(fs.readFileSync(APPROVED_FILE, 'utf8'))); }
  catch { return new Set(); }
}

function _saveApproved(set) {
  try {
    fs.mkdirSync(SETTINGS_DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(APPROVED_FILE, JSON.stringify([...set], null, 2), { mode: 0o600 });
  } catch (_) {}
}

// ─── TCC database query ───────────────────────────────────────────────────────

async function _tccPermittedApps() {
  const tccPath = path.join(
    os.homedir(), 'Library', 'Application Support', 'com.apple.TCC', 'TCC.db'
  );
  if (!fs.existsSync(tccPath)) return null;
  return new Promise((resolve) => {
    // kTCCServiceMicrophone = 'kTCCServiceMicrophone'
    execFile('sqlite3', ['-json', tccPath,
      "SELECT client, client_type, auth_value FROM access WHERE service='kTCCServiceMicrophone'"],
    { timeout: 5000 },
    (err, stdout) => {
      if (err) { resolve(null); return; }
      try {
        const rows = JSON.parse(stdout || '[]');
        // auth_value 2 = allowed, 0 = denied
        resolve(rows.filter((r) => r.auth_value === 2).map((r) => r.client));
      } catch { resolve(null); }
    });
  });
}

// ─── Active recording detection (lsof heuristic) ─────────────────────────────

async function _activeRecordingPids() {
  return new Promise((resolve) => {
    // Look for processes holding open handles to CoreAudio input device paths.
    exec("lsof 2>/dev/null | grep -iE 'AppleHDA|CoreAudio|AURemoteIO|coreaudio' | awk '{print $1,$2}' | sort -u",
    { timeout: 8000 },
    (err, stdout) => {
      if (err || !stdout) { resolve([]); return; }
      const entries = [];
      for (const line of stdout.trim().split('\n')) {
        const [name, pid] = line.trim().split(/\s+/);
        if (name && pid && /^\d+$/.test(pid)) {
          entries.push({ name, pid: parseInt(pid, 10) });
        }
      }
      resolve(entries);
    });
  });
}

// ─── Process name from PID ────────────────────────────────────────────────────
// NOTE: `ps -o comm=` truncates to 16 chars and lsof's COMMAND column to 9.
// Resolve the true executable via lsof's full-path field first.

async function _procPath(pid) {
  return new Promise((resolve) => {
    execFile('lsof', ['-p', String(pid), '-d', 'txt', '-Fn'], { timeout: 3000 }, (err, stdout) => {
      if (!err && stdout) {
        const line = stdout.split('\n').find((l) => l.startsWith('n/'));
        if (line) return resolve(line.slice(1));
      }
      execFile('ps', ['-p', String(pid), '-o', 'comm='], { timeout: 3000 }, (err2, out2) => {
        resolve(err2 ? '' : out2.trim());
      });
    });
  });
}

async function _procName(pid) {
  return new Promise((resolve) => {
    execFile('ps', ['-p', String(pid), '-o', 'comm='], { timeout: 3000 }, (err, stdout) => {
      resolve(err ? '' : stdout.trim());
    });
  });
}

// ─── Main check ───────────────────────────────────────────────────────────────

async function check() {
  const approved  = _loadApproved();
  const active    = await _activeRecordingPids();
  const tccList   = await _tccPermittedApps(); // null if no FDA

  const alerts = [];

  for (const { name, pid } of active) {
    const fullName = (await _procPath(pid)) || name || (await _procName(pid));
    if (!fullName) continue;
    const base = path.basename(fullName);

    if (SYSTEM_AUDIO_PROCS.has(base)) continue;
    // Apple platform binaries (SIP-protected /System paths) hold audio
    // handles for system sounds/loginwindow, not capture. Never alerts.
    if (/^\/System\//.test(fullName)) continue;
    const quarantined = isQuarantined(base) || isQuarantined(fullName);
    if (!quarantined && (approved.has(base) || approved.has(fullName))) continue;

    // If we have TCC data: only alert if this app has mic permission
    // (otherwise the lsof hit is likely a system service, not active capture).
    if (tccList !== null && !tccList.some((c) => c.includes(base))) continue;

    const key = `${base}:${pid}`;
    if (_lastAlerted.has(key)) continue;
    _lastAlerted.add(key);

    alerts.push({
      pid,
      name: base,
      fullPath: fullName,
      tccPermitted: tccList ? tccList.some((c) => c.includes(base)) : 'unknown',
      quarantined: !!quarantined,
      severity: quarantined ? 'quarantine' : 'unapproved',
      ts: Date.now(),
    });
  }

  // Clear stale alert dedup keys for pids that are gone.
  const activePids = new Set(active.map((e) => String(e.pid)));
  for (const key of _lastAlerted) {
    const pid = key.split(':')[1];
    if (!activePids.has(pid)) _lastAlerted.delete(key);
  }

  return { active, alerts, approved: [...approved], tccAvailable: tccList !== null };
}

// ─── Public API ───────────────────────────────────────────────────────────────

function start(onChange) {
  if (_timer) return;
  _onChange = onChange;
  _timer = setInterval(async () => {
    try {
      const result = await check();
      if (result.alerts.length && _onChange) _onChange(result);
    } catch (_) {}
  }, POLL_MS);
  // Run immediately.
  check().then((r) => { if (r.alerts.length && _onChange) _onChange(r); }).catch(() => {});
}

function stop() {
  if (_timer) { clearInterval(_timer); _timer = null; }
}

function approve(appName) {
  // Quarantine wins over approval: release first via unquarantine().
  if (isQuarantined(appName)) return [..._loadApproved()];
  const s = _loadApproved();
  s.add(appName);
  _saveApproved(s);
  return [...s];
}

function revoke(appName) {
  const s = _loadApproved();
  s.delete(appName);
  _saveApproved(s);
  return [...s];
}

function listApproved() {
  return [..._loadApproved()];
}

function clearApproved() {
  _saveApproved(new Set());
}

// ─── Monotonic quarantine ─────────────────────────────────────────────────
// A quarantined app is denied even if approved; approval cannot clear it.
// Release is an explicit logged exception (history retained), never silent.
const QUARANTINE_FILE = path.join(SETTINGS_DIR, 'mic-quarantined.json');
function _loadQuarantine() {
  try {
    const raw = fs.readFileSync(QUARANTINE_FILE, 'utf8');
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch (_) { return []; }
}
function _saveQuarantine(arr) {
  try { fs.writeFileSync(QUARANTINE_FILE, JSON.stringify(arr, null, 2), { mode: 0o600 }); } catch (_) {}
}
function isQuarantined(appName) {
  const base = path.basename(String(appName || ''));
  return _loadQuarantine().some((r) => !r.releasedAt && (r.name === appName || r.name === base));
}
function quarantine(appName, reason) {
  const name = path.basename(String(appName || ''));
  if (!name) return { ok: false, error: 'app name required' };
  const s = _loadApproved();
  s.delete(name);
  _saveApproved(s);
  const recs = _loadQuarantine();
  const existing = recs.find((r) => r.name === name && !r.releasedAt);
  if (existing) { existing.reason = String(reason || existing.reason || ''); existing.ts = Date.now(); }
  else recs.push({ name, reason: String(reason || ''), ts: Date.now(), releasedAt: null });
  _saveQuarantine(recs);
  return { ok: true, quarantined: listQuarantined() };
}
function unquarantine(appName, note) {
  const base = path.basename(String(appName || ''));
  const recs = _loadQuarantine();
  const rec = recs.find((r) => (r.name === appName || r.name === base) && !r.releasedAt);
  if (!rec) return { ok: false, error: 'not quarantined' };
  rec.releasedAt = Date.now();
  rec.releaseNote = String(note || '');
  _saveQuarantine(recs);
  return { ok: true, quarantined: listQuarantined() };
}
function listQuarantined() {
  return _loadQuarantine().filter((r) => !r.releasedAt);
}

module.exports = { start, stop, check, approve, revoke, listApproved, clearApproved, quarantine, unquarantine, isQuarantined, listQuarantined };
