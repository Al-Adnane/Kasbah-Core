'use strict';

/**
 * Camera Sentinel — monitors which processes access the system camera on
 * macOS and emits alerts when an unexpected process starts capturing video.
 *
 * This is the face-detection counterpart of mic-sentinel.js: any app that
 * accesses the camera silently — without the user having explicitly opened
 * it for video — is a candidate for harvesting face geometry, rPPG
 * (remote photoplethysmography) pulse data, and other biometric signs.
 *
 * Two layers:
 *   1. TCC approval list — which apps have been granted camera permission
 *      (kTCCServiceCamera in TCC.db, requires Full Disk Access)
 *   2. Active capture check — which permitted apps currently hold open
 *      handles to camera device paths (lsof heuristic)
 *
 * Honest scope:
 *   - Without Full Disk Access the TCC layer gracefully skips and the
 *     sentinel falls back to the lsof heuristic alone.
 *   - lsof-based capture detection is a heuristic; it can miss processes
 *     that use AVFoundation via XPC out-of-process.
 *   - This does NOT intercept or block camera access at the OS level —
 *     it observes and alerts. Blocking requires a kernel extension (not built).
 */

const fs       = require('fs');
const os       = require('os');
const path     = require('path');
const crypto   = require('crypto');
const { execFile, exec } = require('child_process');

const SETTINGS_DIR  = path.join(os.homedir(), '.kasbah-privacy');
const APPROVED_FILE = path.join(SETTINGS_DIR, 'camera-approved.json');
const POLL_MS       = 8000; // check every 8 s

// Known legitimate system camera processes — never flagged.
const SYSTEM_AUDIO_PROCS = new Set([
  'Kasbah Guard', 'Kasbah Guard Helper',
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
    // kTCCServiceCamera — camera permission grants
    execFile('sqlite3', ['-json', tccPath,
      "SELECT client, client_type, auth_value FROM access WHERE service='kTCCServiceCamera'"],
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
    // Look for processes holding open handles to camera input device paths.
    exec("lsof 2>/dev/null | grep -iE 'AVFoundation|VDC|AppleCamera|USB Camera|iSight|CoreMedia|cmio' | awk '{print $1,$2}' | sort -u",
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
    const fullName = name || (await _procName(pid));
    if (!fullName) continue;
    const base = path.basename(fullName);

    if (SYSTEM_AUDIO_PROCS.has(base)) continue;
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
const QUARANTINE_FILE = path.join(SETTINGS_DIR, 'camera-quarantined.json');
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
