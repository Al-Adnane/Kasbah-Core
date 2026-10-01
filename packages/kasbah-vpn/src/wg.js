'use strict';

/**
 * Thin wrapper over the system WireGuard tools (wg-quick / wg).
 *
 * We deliberately do NOT reimplement the WireGuard data plane — the kernel
 * module and wireguard-go are the audited, state-of-the-art implementations.
 * This module detects them, brings tunnels up/down, and degrades to printing
 * the exact commands when the tools are missing or privileges are lacking.
 */

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

function which(cmd) {
  const r = spawnSync('which', [cmd], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : null;
}

function detect() {
  return {
    wg: which('wg'),
    wgQuick: which('wg-quick'),
    platform: process.platform,
  };
}

/**
 * Write conf to a private temp location and run wg-quick up/down.
 * Returns { ok, method, output } — method 'wg-quick' when executed,
 * 'manual' with instructions when the tools aren't available.
 */
function run(action, confText, name = 'kasbah0') {
  const tools = detect();
  const confDir = path.join(os.homedir(), '.kasbah-vpn');
  fs.mkdirSync(confDir, { recursive: true, mode: 0o700 });
  const confPath = path.join(confDir, `${name}.conf`);
  fs.writeFileSync(confPath, confText, { mode: 0o600 });

  if (!tools.wgQuick) {
    return {
      ok: false,
      method: 'manual',
      confPath,
      output:
        `wg-quick not found. Install WireGuard first:\n` +
        (process.platform === 'darwin'
          ? `  brew install wireguard-tools\n`
          : `  apt install wireguard   # or your distro's package\n`) +
        `Then: sudo wg-quick ${action} ${confPath}`,
    };
  }

  const r = spawnSync('sudo', [tools.wgQuick, action, confPath], { encoding: 'utf8' });
  return {
    ok: r.status === 0,
    method: 'wg-quick',
    confPath,
    output: (r.stdout || '') + (r.stderr || ''),
  };
}

function status() {
  const tools = detect();
  if (!tools.wg) return { ok: false, output: 'wg not installed' };
  const r = spawnSync('sudo', [tools.wg, 'show'], { encoding: 'utf8' });
  return { ok: r.status === 0, output: (r.stdout || r.stderr || '').trim() || '(no active tunnels)' };
}

module.exports = { detect, run, status };
