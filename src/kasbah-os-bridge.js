'use strict';

/**
 * kasbah-os-bridge.js — Node adapter that wires the standalone kasbah-os Python
 * package into the running system via a stdio JSON-RPC subprocess.
 *
 * Defensive modules (governance proxy, zero-trust audit) are exposed as live
 * async methods. Offensive Mythos modules are introspection-only (see bridge.py).
 *
 * Graceful by design: if python3 or the bridge is unavailable, `available`
 * stays false and callers get a clean error instead of a crash. The Node
 * system never depends on this bridge being up.
 */

const { spawn } = require('child_process');
const path = require('path');
const readline = require('readline');

const BRIDGE_PY = path.resolve(__dirname, '..', 'kasbah-os', 'bridge.py');

class KasbahOSBridge {
  constructor(opts = {}) {
    this.python = opts.python || process.env.KASBAH_PYTHON || 'python3';
    this.timeoutMs = opts.timeoutMs || 15000;
    this.proc = null;
    this.available = false;
    this._nextId = 1;
    this._pending = new Map();
    this._starting = null;
  }

  async start() {
    if (this.available) return true;
    if (this._starting) return this._starting;
    this._starting = new Promise((resolve) => {
      let proc;
      try {
        proc = spawn(this.python, [BRIDGE_PY], { stdio: ['pipe', 'pipe', 'pipe'] });
      } catch (e) {
        this.available = false; return resolve(false);
      }
      // python3 missing → spawn emits 'error'. MUST resolve(false) here, else
      // start() never settles and every caller hangs forever (000, not 503).
      proc.on('error', () => { this.available = false; this.proc = null; resolve(false); });
      proc.on('exit', () => {
        this.available = false; this.proc = null;
        for (const { reject } of this._pending.values()) reject(new Error('bridge exited'));
        this._pending.clear();
        resolve(false);
      });
      const rl = readline.createInterface({ input: proc.stdout });
      rl.on('line', (line) => {
        let msg; try { msg = JSON.parse(line); } catch { return; }
        const p = this._pending.get(msg.id);
        if (!p) return;
        this._pending.delete(msg.id);
        clearTimeout(p.timer);
        if (msg.error) p.reject(new Error(msg.error)); else p.resolve(msg.result);
      });
      // bridge prints "ready" on stderr
      proc.stderr.once('data', () => { this.available = true; this.proc = proc; resolve(true); });
      // fallback: assume up if the process is alive; otherwise resolve(false)
      // so start() always settles (never leave callers hanging).
      setTimeout(() => {
        if (this.available) return;
        if (proc.pid) { this.available = true; this.proc = proc; resolve(true); }
        else { this.proc = null; resolve(false); }
      }, 1500);
    });
    return this._starting;
  }

  async call(method, params = {}) {
    const up = await this.start();
    if (!up || !this.proc) throw new Error('kasbah-os bridge unavailable (python3 / numpy missing?)');
    const id = this._nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this._pending.delete(id); reject(new Error('bridge timeout')); }, this.timeoutMs);
      this._pending.set(id, { resolve, reject, timer });
      try { this.proc.stdin.write(JSON.stringify({ id, method, params }) + '\n'); }
      catch (e) { clearTimeout(timer); this._pending.delete(id); reject(e); }
    });
  }

  // Convenience wrappers ------------------------------------------------------
  health() { return this.call('health'); }
  processTurn({ messages = [], tools = [], clearance = 2 } = {}) {
    return this.call('governance.process_turn', { messages, tools, clearance });
  }
  approve(actionId) { return this.call('governance.approve', { action_id: actionId }); }
  auditRecord(engine, eventType, data) { return this.call('audit.record', { engine, event_type: eventType, data }); }
  auditVerify() { return this.call('audit.verify'); }
  offensiveInfo() { return this.call('offensive.info'); }

  stop() { if (this.proc) { try { this.proc.kill(); } catch (_) {} this.proc = null; this.available = false; } }
}

// Lazy singleton.
let _singleton = null;
function getBridge() { if (!_singleton) _singleton = new KasbahOSBridge(); return _singleton; }

module.exports = { KasbahOSBridge, getBridge };
