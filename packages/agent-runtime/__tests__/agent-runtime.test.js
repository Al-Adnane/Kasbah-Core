'use strict';

/**
 * Agent Runtime — Security Invariant Tests
 *
 * These tests verify the core security guarantees of the agentic control plane.
 * Every test corresponds to a property that MUST hold, regardless of other changes.
 */

const { AgentSession, createSession, killSession, listSessions } = require('../src/index');

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeSession(overrides = {}) {
  return createSession({
    agentId: 'test-agent',
    passportId: 'test-passport',
    manifest: {
      allowedTools: ['read_file', 'search'],
      blockedTools: ['delete_file', 'bash'],
      maxTurns: 5,
      maxCostCents: 100,
      maxTokens: 1000,
    },
    ...overrides,
  });
}

// ── Blocked tool tests ────────────────────────────────────────────────────────

describe('Manifest enforcement', () => {
  test('blocked tool is denied immediately', async () => {
    const session = makeSession();
    const result = await session.governTool({ tool: 'delete_file', args: { path: '/etc/passwd' }, argsText: '/etc/passwd' });
    expect(result.ok).toBe(false);
    expect(result.verdict).toBe('DENY');
    expect(result.reason).toBe('manifest_blocked');
  });

  test('allowed tool passes manifest check', async () => {
    const session = makeSession();
    // scanContent is called for argsText — mock it to avoid network call
    session._guard.scanContent = async () => ({ verdict: 'ALLOW', threats: [] });
    const result = await session.governTool({ tool: 'read_file', args: { path: 'README.md' }, argsText: 'README.md' });
    expect(result.ok).toBe(true);
    expect(result.verdict).toBe('ALLOW');
  });

  test('tool not in allowedTools and not in blockedTools is denied', async () => {
    const session = makeSession();
    const result = await session.governTool({ tool: 'write_file', args: {}, argsText: '' });
    expect(result.ok).toBe(false);
    expect(result.verdict).toBe('DENY');
    expect(result.reason).toBe('manifest_blocked');
  });

  test('wildcard allowedTools permits any non-blocked tool', async () => {
    const session = makeSession({ manifest: { allowedTools: '*', blockedTools: ['bash'], maxTurns: 5, maxCostCents: 100, maxTokens: 1000 } });
    session._guard.scanContent = async () => ({ verdict: 'ALLOW', threats: [] });
    const result = await session.governTool({ tool: 'arbitrary_tool', args: {}, argsText: '' });
    expect(result.ok).toBe(true);
  });

  test('wildcard allowedTools still blocks blockedTools entries', async () => {
    const session = makeSession({ manifest: { allowedTools: '*', blockedTools: ['bash'], maxTurns: 5, maxCostCents: 100, maxTokens: 1000 } });
    const result = await session.governTool({ tool: 'bash', args: {}, argsText: '' });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('manifest_blocked');
  });
});

// ── Kill switch tests ─────────────────────────────────────────────────────────

describe('Kill switch', () => {
  test('killed session rejects all subsequent tool calls', async () => {
    const session = makeSession();
    await session.kill('test_kill');
    expect(session.status).toBe('killed');

    const result = await session.governTool({ tool: 'read_file', args: {}, argsText: '' });
    expect(result.ok).toBe(false);
    expect(result.verdict).toBe('DENY');
    expect(result.reason).toBe('session_killed');
  });

  test('killed session is removed from the global registry', async () => {
    const session = makeSession();
    const { sessionId } = session;
    await session.kill('test_cleanup');
    expect(listSessions().find(s => s.sessionId === sessionId)).toBeUndefined();
  });

  test('kill emits "killed" event', async () => {
    const session = makeSession();
    const events = [];
    session.on('killed', e => events.push(e));
    await session.kill('event_test');
    expect(events).toHaveLength(1);
    expect(events[0].reason).toBe('event_test');
  });

  test('killSession() by ID hard-stops the session', async () => {
    const session = makeSession();
    const { sessionId } = session;
    killSession(sessionId, 'external_kill');
    // Allow event loop to process
    await new Promise(r => setImmediate(r));
    expect(session.status).toBe('killed');
  });
});

// ── Budget enforcement tests ──────────────────────────────────────────────────

describe('Budget enforcement', () => {
  test('cost budget exceeded blocks tool call and kills session', async () => {
    const session = makeSession({ manifest: { allowedTools: '*', blockedTools: [], maxTurns: 100, maxCostCents: 10, maxTokens: 999999 } });
    // Exhaust budget
    session.budget.costCents = 10;
    const result = await session.governTool({ tool: 'search', args: {}, argsText: '' });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('budget_exceeded');
    expect(session.status).toBe('killed');
  });

  test('token budget exceeded blocks tool call and kills session', async () => {
    const session = makeSession({ manifest: { allowedTools: '*', blockedTools: [], maxTurns: 100, maxCostCents: 999999, maxTokens: 100 } });
    session.budget.totalTokens = 100;
    const result = await session.governTool({ tool: 'search', args: {}, argsText: '' });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('budget_exceeded');
  });
});

// ── Loop detection tests ──────────────────────────────────────────────────────

describe('Loop detection', () => {
  test('same tool+args repeated 4 times triggers loop block', async () => {
    const session = makeSession({ manifest: { allowedTools: ['search'], blockedTools: [], maxTurns: 100, maxCostCents: 9999, maxTokens: 999999 } });
    session._guard.scanContent = async () => ({ verdict: 'ALLOW', threats: [] });

    // First 3 calls should be ALLOW
    for (let i = 0; i < 3; i++) {
      const r = await session.governTool({ tool: 'search', args: { q: 'test' }, argsText: 'test' });
      expect(r.verdict).toBe('ALLOW');
    }

    // 4th identical call should trip loop detection
    const r = await session.governTool({ tool: 'search', args: { q: 'test' }, argsText: 'test' });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('loop_detected');
  });
});

// ── Child session policy constraints ─────────────────────────────────────────

describe('Policy-constrained child sessions', () => {
  test('child cannot have more permissive tool list than parent', () => {
    const parent = makeSession({ manifest: { allowedTools: ['read_file'], blockedTools: [], maxTurns: 10, maxCostCents: 100, maxTokens: 1000 } });
    const child = createSession({
      agentId: 'child',
      parentSessionId: parent.sessionId,
      manifest: { allowedTools: ['read_file', 'bash', 'write_file'], blockedTools: [], maxTurns: 10, maxCostCents: 100, maxTokens: 1000 },
    });

    // Child should only have the intersection with parent
    expect(child.manifest.allowedTools).toEqual(['read_file']);
    parent.complete();
    child.complete();
  });

  test('child cannot exceed parent token budget', () => {
    const parent = makeSession({ manifest: { allowedTools: '*', blockedTools: [], maxTurns: 100, maxCostCents: 100, maxTokens: 500 } });
    const child = createSession({
      agentId: 'greedy-child',
      parentSessionId: parent.sessionId,
      manifest: { allowedTools: '*', blockedTools: [], maxTurns: 100, maxCostCents: 100, maxTokens: 999999 },
    });

    expect(child.manifest.maxTokens).toBe(500);  // capped at parent's limit
    parent.complete();
    child.complete();
  });
});
