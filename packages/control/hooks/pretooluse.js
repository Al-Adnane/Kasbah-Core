#!/usr/bin/env node
'use strict';

/**
 * Claude Code PreToolUse hook entry point.
 * Reads tool name + input from stdin (Claude Code hook format),
 * runs governance check, exits 0 (allow) or 1 (block).
 *
 * Configure in .claude/settings.json:
 * {
 *   "hooks": {
 *     "PreToolUse": [{
 *       "matcher": "Bash|Edit|Write",
 *       "hooks": [{ "type": "command", "command": "npx @kasbah/control" }]
 *     }]
 *   }
 * }
 */

let KasbahAgentControl;
try {
  ({ KasbahAgentControl } = require('../src/index'));
} catch {
  process.exit(0); // fail open if not configured
}

KasbahAgentControl.runAsClaudeCodeHook().catch(() => process.exit(0));
