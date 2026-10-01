'use strict';

/**
 * python-bridge.js — Node.js bridge to KasbahOS v4.0 Python core.
 *
 * Spawns packages/kasbah-core-python/bridge.py (v2.0 + v4.0 engines integrated).
 * Handles process lifecycle, timeouts, and graceful degradation.
 *
 * Usage:
 *   const bridge = new PythonBridge();
 *   await bridge.start();
 *   const result = await bridge.call('analyze_binary', { binary_hex: '...' });
 *   await bridge.stop();
 */

const { spawn } = require('child_process');
const path = require('path');

const BRIDGE_SCRIPT = path.resolve(__dirname, '..', '..', 'kasbah-core-python', 'bridge.py');
const STARTUP_TIMEOUT_MS = 10000;
const CALL_TIMEOUT_MS = 30000;

class PythonBridge {
  constructor() {
    this.process = null;
    this.ready = false;
    this._pending = new Map(); // id → { resolve, reject, timer }
    this._nextId = 1;
    this._buf = '';
  }

  async start() {
    return new Promise((resolve, reject) => {
      try {
        this.process = spawn('python3', [BRIDGE_SCRIPT], {
          stdio: ['pipe', 'pipe', 'pipe'],
          env: { ...process.env, PYTHONUNBUFFERED: '1' },
        });
      } catch (e) {
        return reject(new Error(`Failed to spawn Python bridge: ${e.message}`));
      }

      const startupTimer = setTimeout(() => {
        reject(new Error('Python bridge startup timed out'));
        this._stopProcess();
      }, STARTUP_TIMEOUT_MS);

      this.process.stdout.setEncoding('utf8');
      this.process.stdout.on('data', (chunk) => {
        this._buf += chunk;
        let nl;
        while ((nl = this._buf.indexOf('\n')) >= 0) {
          const line = this._buf.slice(0, nl).trim();
          this._buf = this._buf.slice(nl + 1);
          if (!line) continue;

          try {
            const msg = JSON.parse(line);

            // First response marks readiness (pong or any response)
            if (!this.ready) {
              this.ready = true;
              clearTimeout(startupTimer);
              resolve(msg);
              continue;
            }

            // Route response to pending call by id
            const pending = this._pending.get(msg.id);
            if (pending) {
              clearTimeout(pending.timer);
              this._pending.delete(msg.id);
              pending.resolve(msg);
            }
          } catch (_) { /* ignore parse errors */ }
        }
      });

      this.process.stderr.on('data', (data) => {
        const err = data.toString().trim();
        if (err && !err.includes('ready') && !err.includes('shut down')) {
          console.warn('[python-bridge]', err);
        }
      });

      this.process.on('error', (e) => {
        if (!this.ready) {
          clearTimeout(startupTimer);
          reject(new Error(`Python bridge process error: ${e.message}`));
        }
      });

      this.process.on('exit', (code) => {
        this.ready = false;
        for (const [id, pending] of this._pending) {
          clearTimeout(pending.timer);
          pending.reject(new Error(`Python bridge exited with code ${code}`));
          this._pending.delete(id);
        }
      });

      // Send ping to confirm readiness
      this.process.stdin.write(JSON.stringify({ id: '0', method: 'ping' }) + '\n');
    });
  }

  async call(method, params = {}) {
    if (!this.ready || !this.process) {
      throw new Error('Python bridge not ready');
    }

    return new Promise((resolve, reject) => {
      const id = String(this._nextId++);
      const timer = setTimeout(() => {
        this._pending.delete(id);
        reject(new Error(`Python bridge call '${method}' timed out`));
      }, CALL_TIMEOUT_MS);

      this._pending.set(id, { resolve, reject, timer });

      const msg = { id, method, ...params };
      try {
        this.process.stdin.write(JSON.stringify(msg) + '\n');
      } catch (e) {
        clearTimeout(timer);
        this._pending.delete(id);
        reject(new Error(`Failed to write to Python bridge: ${e.message}`));
      }
    });
  }

  /**
   * Convenience methods for common operations.
   */
  async health()           { return this.call('health'); }
  async analyzeBinary(hex, sampleId) { return this.call('analyze_binary', { binary_hex: hex, sample_id: sampleId }); }
  async runPipeline(hex)   { return this.call('run_pipeline', { binary_hex: hex }); }
  async auditReport()      { return this.call('audit_report'); }
  async recordEvent(engine, eventType, data) { return this.call('record_event', { engine, event_type: eventType, data }); }
  async keygen()           { return this.call('keygen'); }
  async pubkey(seedHex)    { return this.call('pubkey', { seed_hex: seedHex }); }
  async sign(msgHex, seedHex) { return this.call('sign', { message_hex: msgHex, seed_hex: seedHex }); }
  async verify(msgHex, sigHex, pkHex) { return this.call('verify', { message_hex: msgHex, signature_hex: sigHex, public_key_hex: pkHex }); }

  async stop() {
    if (this.process && this.ready) {
      try {
        this.process.stdin.write(JSON.stringify({ id: 'shutdown', method: 'shutdown' }) + '\n');
        // Give it a moment to flush
        await new Promise(r => setTimeout(r, 200));
      } catch (_) {}
    }
    this._stopProcess();
  }

  _stopProcess() {
    if (this.process) {
      try { this.process.kill(); } catch (_) {}
      this.process = null;
    }
    this.ready = false;
    for (const [id, pending] of this._pending) {
      clearTimeout(pending.timer);
      pending.reject(new Error('Bridge stopped'));
      this._pending.delete(id);
    }
  }

  get isReady() { return this.ready; }
}

module.exports = { PythonBridge };
