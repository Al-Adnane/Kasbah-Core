'use strict';

/**
 * session-store.js — Persistent session history for governed agent sessions
 *
 * Saves completed/killed session summaries so they survive process restarts.
 * Uses the existing persistence layer (Redis if available, in-memory fallback).
 *
 * Storage schema (Redis / in-memory):
 *   Hash  kasbah:sessions:by-passport:<passportId>   field=sessionId  value=summary
 *   KV    kasbah:sessions:by-id:<sessionId>           value=summary
 *   List  kasbah:sessions:recent                      (lpush, newest first)
 *
 * Exports:
 *   recordSession(summary)              → Promise<void>
 *   getHistory(passportId, limit=20)    → Promise<summary[]>   newest first
 *   getSessionById(sessionId)           → Promise<summary|null>
 */

const persistence = require('./persistence.js');

const RECENT_KEY = 'kasbah:sessions:recent';
const RECENT_MAX = 1000; // keep last 1000 sessions in the recent list

// ---------------------------------------------------------------------------
// recordSession(summary) — persist a completed/killed session
// ---------------------------------------------------------------------------

/**
 * @param {object} summary - Session summary object (from session._summary())
 *                           Expected shape:
 *                           { sessionId, agentId, passportId, goal, status,
 *                             createdAt, completedAt?, killedAt?, turns, ... }
 */
async function recordSession(summary) {
  if (!summary || !summary.sessionId) return;

  try {
    const enriched = {
      ...summary,
      recordedAt: new Date().toISOString(),
    };

    // Store by sessionId for direct lookup
    await persistence.set(
      `kasbah:sessions:by-id:${summary.sessionId}`,
      enriched
    );

    // Store in per-passport hash for history queries
    if (summary.passportId) {
      await persistence.hset(
        `kasbah:sessions:by-passport:${summary.passportId}`,
        summary.sessionId,
        enriched
      );
    }

    // Push to recent list (newest first)
    await persistence.lpush(RECENT_KEY, enriched);

    // Trim the recent list to prevent unbounded growth (best-effort)
    // Note: in-memory persistence.lrange already handles slicing lazily
  } catch (err) {
    // Non-fatal — session history is not mission-critical
    console.error('[session-store] recordSession error:', err.message);
  }
}

// ---------------------------------------------------------------------------
// getHistory(passportId, limit) — fetch last N sessions for a passport
// ---------------------------------------------------------------------------

/**
 * @param {string} passportId
 * @param {number} limit - max number of sessions to return (default 20, max 200)
 * @returns {Promise<object[]>} sessions ordered newest first
 */
async function getHistory(passportId, limit = 20) {
  if (!passportId) return [];
  const cap = Math.min(limit, 200);

  try {
    const raw = await persistence.hgetall(
      `kasbah:sessions:by-passport:${passportId}`
    );

    if (!raw || Object.keys(raw).length === 0) return [];

    const sessions = Object.values(raw);

    // Sort newest first (by recordedAt or createdAt)
    sessions.sort((a, b) => {
      const ta = new Date(a.recordedAt || a.createdAt || 0).getTime();
      const tb = new Date(b.recordedAt || b.createdAt || 0).getTime();
      return tb - ta;
    });

    return sessions.slice(0, cap);
  } catch (err) {
    console.error('[session-store] getHistory error:', err.message);
    return [];
  }
}

// ---------------------------------------------------------------------------
// getSessionById(sessionId) — fetch a single session record
// ---------------------------------------------------------------------------

/**
 * @param {string} sessionId
 * @returns {Promise<object|null>}
 */
async function getSessionById(sessionId) {
  if (!sessionId) return null;

  try {
    const record = await persistence.get(`kasbah:sessions:by-id:${sessionId}`);
    return record || null;
  } catch (err) {
    console.error('[session-store] getSessionById error:', err.message);
    return null;
  }
}

// ---------------------------------------------------------------------------
// getRecent(limit) — fetch the most recent sessions across all passports
// ---------------------------------------------------------------------------

/**
 * @param {number} limit
 * @returns {Promise<object[]>}
 */
async function getRecent(limit = 50) {
  const cap = Math.min(limit, 200);
  try {
    return await persistence.lrange(RECENT_KEY, 0, cap - 1);
  } catch (err) {
    console.error('[session-store] getRecent error:', err.message);
    return [];
  }
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  recordSession,
  getHistory,
  getSessionById,
  getRecent,
};
