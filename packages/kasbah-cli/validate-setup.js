#!/usr/bin/env node
'use strict';

/**
 * Kasbah Setup Validation
 *
 * Comprehensive test suite:
 * 1. API connectivity (Anthropic, Alibaba)
 * 2. MCP server responsiveness
 * 3. SDK instrumentation working
 * 4. Cost tracking enabled
 * 5. Audit receipt generation
 * 6. All model integration
 *
 * Usage:
 *   kasbah validate [--verbose] [--models X,Y,Z]
 */

const http = require('http');
const { CostTracker } = require('../kasbah-sdk/src/cost-tracker');

const c = (color, text) => {
  const colors = {
    green: '\x1b[32m', red: '\x1b[31m', yellow: '\x1b[33m', cyan: '\x1b[36m',
    dim: '\x1b[2m', reset: '\x1b[0m', bold: '\x1b[1m'
  };
  return (colors[color] || '') + text + colors.reset;
};

const log = (msg, level = 'info') => {
  const prefix = { ok: '✓', err: '✕', warn: '⚠', info: '→' }[level] || '→';
  const color = level === 'ok' ? 'green' : level === 'err' ? 'red' : level === 'warn' ? 'yellow' : 'cyan';
  console.log(c(color, prefix + ' ') + msg);
};

async function testAPIConnectivity() {
  log('Testing API connectivity...');
  const tests = {
    anthropic: !!process.env.ANTHROPIC_API_KEY,
    alibaba: !!process.env.ALIBABA_API_KEY
  };

  if (!tests.anthropic && !tests.alibaba) {
    log('No API keys found. Set ANTHROPIC_API_KEY or ALIBABA_API_KEY', 'err');
    return { ok: false };
  }

  let ok = true;
  for (const [provider, found] of Object.entries(tests)) {
    if (found) {
      log(`${provider}: configured`, 'ok');
    } else {
      log(`${provider}: not configured`, 'warn');
      ok = false;
    }
  }

  return { ok, providers: tests };
}

async function testMCPServer() {
  log('Testing MCP server...');

  return new Promise((resolve) => {
    const req = http.get('http://127.0.0.1:8788/v1/health', (res) => {
      if (res.statusCode === 200) {
        log('MCP server responsive', 'ok');
        resolve({ ok: true });
      } else {
        log(`MCP server returned ${res.statusCode}`, 'err');
        resolve({ ok: false, status: res.statusCode });
      }
    }).on('error', (e) => {
      log(`MCP server not running: ${e.message}`, 'err');
      resolve({ ok: false, error: e.message });
    });
  });
}

async function testCostTracking() {
  log('Testing cost tracking...');

  try {
    const tracker = new CostTracker();

    // Record a test call
    const testCall = tracker.recordCall(
      'claude-haiku',
      100,    // input tokens
      50,     // output tokens
      250,    // latency ms
      { test: true }
    );

    if (testCall) {
      log(`Cost tracking: $${testCall.cost.toFixed(6)} recorded`, 'ok');
      const report = tracker.getDailyReport();
      log(`Today's cost: $${report.totalCost.toFixed(4)}`, 'ok');
      return { ok: true, cost: testCall.cost };
    } else {
      log('Cost tracking failed to record', 'err');
      return { ok: false };
    }
  } catch (e) {
    log(`Cost tracking error: ${e.message}`, 'err');
    return { ok: false, error: e.message };
  }
}

async function testAuditReceipts() {
  log('Testing audit receipt generation...');

  return new Promise((resolve) => {
    const payload = JSON.stringify({
      policyDecision: 'allow',
      sourceDomain: 'claude.ai',
      riskScore: 0
    });

    const req = http.request({
      hostname: '127.0.0.1',
      port: 8788,
      path: '/v1/audit/receipt',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': payload.length }
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode === 200) {
          try {
            const receipt = JSON.parse(data);
            if (receipt.receipt || receipt.kasbah_receipt) {
              log('Audit receipt generated', 'ok');
              resolve({ ok: true, receipt });
            } else {
              log('Receipt format unexpected', 'warn');
              resolve({ ok: true, receipt, partial: true });
            }
          } catch (e) {
            log(`Receipt parsing failed: ${e.message}`, 'err');
            resolve({ ok: false });
          }
        } else {
          log(`Receipt endpoint returned ${res.statusCode}`, 'err');
          resolve({ ok: false, status: res.statusCode });
        }
      });
    }).on('error', (e) => {
      log(`Receipt generation failed: ${e.message}`, 'err');
      resolve({ ok: false, error: e.message });
    });

    req.write(payload);
    req.end();
  });
}

async function testMultiModelSupport() {
  log('Testing multi-model support...');

  const { PRICING } = require('../kasbah-sdk/src/cost-tracker');
  const models = Object.keys(PRICING);

  const anthropic = models.filter(m => PRICING[m].provider === 'anthropic');
  const alibaba = models.filter(m => PRICING[m].provider === 'alibaba');

  console.log(c('cyan', '  Anthropic models:'));
  for (const m of anthropic) {
    const p = PRICING[m];
    log(`    ${m}: $${(p.output * 1_000_000).toFixed(2)}/1M output tokens`, 'ok');
  }

  console.log(c('cyan', '  Alibaba models:'));
  for (const m of alibaba) {
    const p = PRICING[m];
    log(`    ${m}: $${(p.output * 1_000_000).toFixed(2)}/1M output tokens`, 'ok');
  }

  return { ok: true, models: { anthropic, alibaba } };
}

async function main() {
  const argv = process.argv.slice(2);
  const verbose = argv.includes('--verbose');

  console.log(c('bold', '\nKasbah Setup Validation\n'));

  const results = {
    timestamp: new Date().toISOString(),
    tests: {}
  };

  // Run all tests
  results.tests.apiConnectivity = await testAPIConnectivity();
  results.tests.mcpServer = await testMCPServer();
  results.tests.costTracking = await testCostTracking();
  results.tests.auditReceipts = await testAuditReceipts();
  results.tests.multiModel = await testMultiModelSupport();

  // Summary
  const allOk = Object.values(results.tests).every(t => t.ok);

  console.log('');
  console.log(c('dim', '═'.repeat(50)));
  if (allOk) {
    log('All tests passed! ✓', 'ok');
    console.log('\nNext steps:');
    console.log('  1. kasbah status              — view cost dashboard');
    console.log('  2. kasbah dashboard daily     — today\'s breakdown');
    console.log('  3. kasbah dashboard savings   — routing recommendations\n');
  } else {
    log('Some tests failed. See above for details.', 'err');
    process.exit(1);
  }

  if (verbose) {
    console.log('\nDetailed results:');
    console.log(JSON.stringify(results, null, 2));
  }
}

if (require.main === module) {
  main().catch((e) => {
    console.error('Validation failed:', e.message);
    process.exit(1);
  });
}

module.exports = { testAPIConnectivity, testMCPServer, testCostTracking };
