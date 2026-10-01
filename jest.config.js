'use strict';

module.exports = {
  testPathIgnorePatterns: [
    '/node_modules/',
    '/audit-export-\\d',
    '\\.kasbah-audit',
    '/\\.claude/',
    '/archive/',
    '/_archive/',
    // Standalone test runners (use node:test or custom harness, not jest)
    'packages/kasbah-vpn/test\\.js',
    'packages/kasbah-receipts/test\\.js',
    'packages/kasbah-mcp/test\\.js',
    'packages/agent-cost-watch/src/test\\.js',
    'packages/kasbah-sdk/src/test\\.js',
    'packages/wasm-kernel/test\\.js',
    'packages/control/tests/agent-security\\.test\\.js',
    'packages/api-server/tests/frontier-v4\\.test\\.js',
    'tests/integration/runtime\\.test\\.js',
    'tests/capabilities\\.test\\.js',
    'tests/capability-packages\\.test\\.js',
    // TypeScript tests without transform configured
    '\\.test\\.ts$',
  ],
  testTimeout: 30000,
  forceExit: true,
  maxWorkers: 1,
};
