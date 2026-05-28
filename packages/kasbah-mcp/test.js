#!/usr/bin/env node
'use strict';
/**
 * Smoke test — must pass before `npm publish` (wired via prepublishOnly).
 *
 * Spawns the MCP server over stdio, sends an initialize + tools/list, asserts
 * the response shape. Does not require a running engine.
 */

const { spawn } = require('child_process');
const path = require('path');

const SERVER = path.join(__dirname, 'src', 'index.js');
let failed = 0;
function ok(msg)   { console.log('  \x1b[32m✓\x1b[0m ' + msg); }
function fail(msg) { console.error('  \x1b[31m✗\x1b[0m ' + msg); failed++; }

function runTest() {
  return new Promise((resolve) => {
    // Use shell pipe instead of node spawn — matches how MCP hosts actually invoke us
    const { exec } = require('child_process');
    const input = JSON.stringify({ jsonrpc:'2.0', id:1, method:'initialize', params:{} }) + '\n' +
                  JSON.stringify({ jsonrpc:'2.0', id:2, method:'tools/list', params:{} }) + '\n';
    const cmd = `(printf '%s' "${input.replace(/"/g,'\\"')}"; sleep 1) | node "${SERVER}" 2>/dev/null`;
    const p = exec(cmd, { timeout: 6000 }, (err, stdout) => {
      if (err && err.killed) { fail('timeout — server did not respond in 6s'); resolve(); return; }
      const lines = stdout.split('\n').filter(l => l.trim());
      let initOK = false, listOK = false;
      for (const line of lines) {
        try {
          const msg = JSON.parse(line);
          if (msg.id === 1 && msg.result) {
            initOK = true;
            const r = msg.result;
            if (r.protocolVersion === '2024-11-05') ok('protocolVersion 2024-11-05');
            else fail('wrong protocolVersion: ' + r.protocolVersion);
            if (r.serverInfo?.name === 'kasbah') ok('serverInfo.name = kasbah');
            else fail('wrong serverInfo.name');
            if (r.serverInfo?.version === '2.0.0') ok('serverInfo.version = 2.0.0');
            else fail('wrong version: ' + r.serverInfo?.version);
          }
          if (msg.id === 2 && msg.result) {
            listOK = true;
            const tools = msg.result.tools || [];
            const names = tools.map(t => t.name).sort();
            if (names.includes('kasbah_attest')) ok('tool: kasbah_attest');
            else fail('missing kasbah_attest');
            if (names.includes('kasbah_verify')) ok('tool: kasbah_verify');
            else fail('missing kasbah_verify');
            if (tools.length === 2) ok('exactly 2 tools');
            else fail('expected 2 tools, got ' + tools.length);
          }
        } catch (_) {}
      }
      if (!initOK) fail('no initialize response received');
      if (!listOK) fail('no tools/list response received');
      resolve();
    });
  });
}

console.log('\n@kasbah/mcp-server · smoke test\n');
runTest().then(() => {
  if (failed) { console.error(`\n\x1b[31m${failed} test(s) failed\x1b[0m\n`); process.exit(1); }
  console.log('\n\x1b[32mAll tests passed.\x1b[0m\n'); process.exit(0);
});
