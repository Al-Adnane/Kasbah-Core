'use strict';

/**
 * mcp-block-loop.test.js — CLOSED-LOOP MCP block verification.
 *
 * Proves the gateway's central claim ("blocks are denied at the gateway") is
 * verified fact, not UI copy:
 *
 *   1. Block a tool via the governor (same path POST /v1/mcp/tool uses)
 *   2. Check the tool → MUST be DENIED at pre-execution
 *   3. Unblock the tool
 *   4. Check again → MUST be ALLOWED
 *
 * Run: node tests/mcp-block-loop.test.js
 */

const path = require('path');
const gov = require(path.join(__dirname, '..', 'packages', 'api-server', 'src', 'multi-mcp-governor.js'));

let passed = 0, failed = 0;
function check(name, cond, detail) {
  if (cond) { passed++; console.log(`  ✓ ${name}`); }
  else { failed++; console.log(`  ✗ ${name}${detail ? ' — ' + detail : ''}`); }
}

const SERVER = 'ensemble';
const TOOL = 'qwen3.5-plus';

console.log('\n═══ MCP Block Loop — closed-loop enforcement verification ═══\n');

// 0. Baseline: unblocked tool is allowed
{
  const v = gov.governToolCall(SERVER, TOOL);
  check('baseline unblocked → ALLOW', v.verdict === 'ALLOW' && v.allowed === true, JSON.stringify(v));
  check('baseline carries enforcedBy', v.enforcedBy === 'kasbah-mcp-governor');
}

// 1. Block the tool (same path POST /v1/mcp/tool uses)
{
  const r = gov.setToolBlocked(SERVER, TOOL, true);
  check('block registered', r.ok === true && r.blocked === true, JSON.stringify(r));
}

// 2. Pre-execution check: MUST be denied
{
  const v = gov.governToolCall(SERVER, TOOL);
  check('blocked tool → DENY verdict', v.verdict === 'DENY', JSON.stringify(v));
  check('blocked tool → allowed:false', v.allowed === false);
  check('denial states the reason', /BLOCKED by the MCP governor/.test(v.reason || ''), v.reason);
}

// 3. Block list audit reflects the state
{
  const blocks = gov.getToolBlocks().filter(b => b.serverId === SERVER && b.toolName === TOOL);
  check('block list shows the block', blocks.length === 1 && blocks[0].blocked === true, JSON.stringify(blocks));
}

// 4. Unblock → allowed again
{
  gov.setToolBlocked(SERVER, TOOL, false);
  const v = gov.governToolCall(SERVER, TOOL);
  check('unblocked → ALLOW again', v.verdict === 'ALLOW' && v.allowed === true, JSON.stringify(v));
  const blocks = gov.getToolBlocks().filter(b => b.serverId === SERVER && b.toolName === TOOL && b.blocked);
  check('block list cleared', blocks.length === 0, JSON.stringify(blocks));
}

// 5. Independent second tool is unaffected (isolation)
{
  gov.setToolBlocked(SERVER, 'qwen3-coder', true);
  const v1 = gov.governToolCall(SERVER, 'qwen3-coder');
  const v2 = gov.governToolCall(SERVER, TOOL);
  check('isolation: second tool DENIED', v1.verdict === 'DENY');
  check('isolation: first tool still ALLOWED', v2.verdict === 'ALLOW');
  gov.setToolBlocked(SERVER, 'qwen3-coder', false);
}

console.log(`\n═══ ${passed} passed, ${failed} failed ═══\n`);
process.exit(failed ? 1 : 0);