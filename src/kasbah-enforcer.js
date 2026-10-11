'use strict';

/**
 * kasbah-enforcer — user-space enforcement daemon for Kasbah's biometric watch.
 *
 * Three-tier architecture (honest scope):
 *   Tier 1 (always on):   sentinels (mic/camera, TCC + lsof) — observe & alert
 *   Tier 2 (kext):        kernel-side real-time event ring — when signed & loaded
 *   Tier 3 (this module): user-space enforcement actions — real, auditable,
 *                         reversible. Actions available when ENFORCE mode is on:
 *
 *     - terminate: kill an unapproved process that is actively capturing
 *     - tcc-reset: revoke the app's TCC permission (tccutil reset <service> <bundle-id>)
 *     - alert-only: never act, just alert (default)
 *
 * Why user-space enforcement: kernel-context enforcement (killing processes or
 * dropping syscalls in-kernel) cannot be audited or undone safely. Every action
 * here is logged with a timestamp, target, and outcome in the action log so the
 * user can review exactly what the enforcer did.
 *
 * Safety rails:
 *   - The enforcer NEVER acts on Kasbah's own processes.
 *   - The enforcer NEVER acts on anything not confirmed by the sentinel
 *     (no heuristic hit alone triggers an action).
 *   - Enforce mode follows the master protection switch: protection ON means
 *     confirmed unapproved captures are physically revoked (tcc-reset default);
 *     protection OFF stands enforcement down. The user can still pick
 *     alert-only or terminate explicitly at any time.
 */

const fs        = require('fs');
const os        = require('os');
const path      = require('path');
const { execFile } = require('child_process');

const SETTINGS_DIR  = process.env.KASBAH_PRIVACY_DIR || path.join(os.homedir(), '.kasbah-privacy');
const STATE_FILE    = path.join(SETTINGS_DIR, 'enforcer-state.json');
const ACTIONS_LOG   = path.join(SETTINGS_DIR, 'enforcer-actions.log');

// Injectable command runner (T1): tests set KASBAH_ENFORCE_DRYRUN=1 so no real
// kill/tccutil is ever executed, and KASBAH_PRIVACY_DIR so state stays in a temp dir.
const DRYRUN = process.env.KASBAH_ENFORCE_DRYRUN === '1';
function _run(cmd, args, opts, cb) {
  if (DRYRUN) { setImmediate(() => cb(null, '')); return; }
  execFile(cmd, args, opts, cb);
}

const SELF_PROCS = new Set([
  'Kasbah Guard', 'Kasbah Guard Helper', 'Electron', 'electron',
  'coreaudiod', 'audiod', 'kernel_task', 'launchd', 'WindowServer',
]);

const TCC_SERVICE_BY_DEVICE = { mic: 'Microphone', camera: 'Camera' };

let _state  = { enforce: false, action: 'alert-only' };
let _onAction = null;

// ─── Persistence ─────────────────────────────────────────────────────────────

function _loadState() {
  try { return { ..._state, ...JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')) }; }
  catch { return { ..._state }; }
}

function _saveState() {
  try {
    fs.mkdirSync(SETTINGS_DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(STATE_FILE, JSON.stringify(_state, null, 2), { mode: 0o600 });
  } catch (_) {}
}

function _logAction(entry) {
  try {
    fs.mkdirSync(SETTINGS_DIR, { recursive: true, mode: 0o700 });
    fs.appendFileSync(ACTIONS_LOG, JSON.stringify(entry) + '\n', { mode: 0o600 });
  } catch (_) {}
  if (_onAction) { try { _onAction(entry); } catch (_) {} }
}

// ─── Enforcement actions ─────────────────────────────────────────────────────

function _terminate(pid, name, reason) {
  return new Promise((resolve) => {
    if (SELF_PROCS.has(name) || pid <= 1) { resolve({ ok: false, reason: 'protected process' }); return; }
    _run('kill', ['-15', String(pid)], { timeout: 5000 }, (err) => {
      const entry = { ts: new Date().toISOString(), action: 'terminate', target: name, pid, reason, ok: !err };
      _logAction(entry);
      resolve({ ok: !err, reason: err ? err.message : `SIGTERM sent to ${name} (pid ${pid})` });
    });
  });
}

function _tccReset(device, bundleId, name, reason) {
  return new Promise((resolve) => {
    const service = TCC_SERVICE_BY_DEVICE[device];
    if (!service) { resolve({ ok: false, reason: 'unknown device' }); return; }
    // tccutil reset <service> <bundle-id> — revokes the permission
    _run('tccutil', ['reset', service, bundleId], { timeout: 8000 }, (err, stdout) => {
      const entry = { ts: new Date().toISOString(), action: 'tcc-reset', device, target: name, bundleId, reason, ok: !err, output: (stdout || '').trim().slice(0, 200) };
      _logAction(entry);
      resolve({ ok: !err, reason: err ? `tccutil failed for ${bundleId}` : `${service} permission reset for ${bundleId}` });
    });
  });
}

// ─── Public API ───────────────────────────────────────────────────────────────

function status() {
  _state = _loadState();
  return {
    enforce: _state.enforce,
    action: _state.action,
    actionsLogExists: fs.existsSync(ACTIONS_LOG),
    tier: _state.enforce ? 3 : 1,
  };
}

function setEnforce(on) {
  _state = _loadState();
  _state.enforce = !!on;
  _saveState();
  _logAction({ ts: new Date().toISOString(), action: 'enforce-mode', value: _state.enforce });
  return status();
}

function setAction(action) {
  if (!['alert-only', 'terminate', 'tcc-reset'].includes(action)) {
    return { error: 'action must be alert-only | terminate | tcc-reset' };
  }
  _state = _loadState();
  _state.action = action;
  _saveState();
  _logAction({ ts: new Date().toISOString(), action: 'enforce-action', value: action });
  return status();
}

/**
 * Act on a sentinel alert. Only called with CONFIRMED alerts (never a bare
 * heuristic hit). Returns the outcome of the configured action.
 * @param {{device:'mic'|'camera', name:string, pid:number, bundleId?:string}} alert
 */
async function actOnAlert(alert) {
  _state = _loadState();
  if (!_state.enforce) return { acted: false, reason: 'enforce mode is off (alert-only)' };
  if (!alert || !alert.name || !alert.pid) return { acted: false, reason: 'invalid alert' };
  if (SELF_PROCS.has(alert.name)) return { acted: false, reason: 'protected process' };

  if (_state.action === 'terminate') {
    const r = await _terminate(alert.pid, alert.name, `unapproved ${alert.device} capture`);
    return { acted: r.ok, reason: r.reason };
  }
  if (_state.action === 'tcc-reset') {
    const bundleId = alert.bundleId || alert.name;
    const r = await _tccReset(alert.device, bundleId, alert.name, `unapproved ${alert.device} capture`);
    return { acted: r.ok, reason: r.reason };
  }
  return { acted: false, reason: 'action policy is alert-only' };
}

/** Recent enforcement actions for the UI audit view. */
function recentActions(n = 20) {
  try {
    const lines = fs.readFileSync(ACTIONS_LOG, 'utf8').trim().split('\n').filter(Boolean);
    return lines.slice(-n).map(l => { try { return JSON.parse(l); } catch { return { raw: l }; } }).reverse();
  } catch { return []; }
}

module.exports = { status, setEnforce, setAction, actOnAlert, recentActions };