'use strict';

/**
 * Kasbah Threat Intelligence Feed
 *
 * Stores anonymised threat pattern metadata — never the original prompt text.
 * Used for:
 *   - Real-time feed of recent threat patterns (last N)
 *   - Aggregated stats by type / day
 *   - Public leaderboard of top attack vectors this week
 */

// Max number of threat records kept in memory
const FEED_MAX = 2000;

// In-memory threat feed (newest first)
const _feed = [];

// ── recordThreat ──────────────────────────────────────────────────────────────
/**
 * Record one DENY event. Called after every DENY verdict.
 * IMPORTANT: never stores actual prompt content — only pattern metadata.
 * @param {string}   verdict     - governance verdict (should be 'DENY')
 * @param {string[]} threats     - array of threat labels from the engine
 * @param {number}   riskScore   - 0–1 normalised risk
 * @param {string}   passportId  - hashed/opaque passport identifier
 */
function recordThreat(verdict, threats, riskScore, passportId) {
  if (!threats || threats.length === 0) return;

  const entry = {
    id:         `ti_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    verdict:    verdict || 'DENY',
    // Store primary + secondary threat labels only — no raw text
    primaryType:   threats[0] || 'unknown',
    secondaryTypes: threats.slice(1, 4),   // up to 3 additional labels
    riskScore:  typeof riskScore === 'number' ? +riskScore.toFixed(4) : 0,
    // Anonymised passport hash — SHA-256 truncated to 8 hex chars
    passportHash: passportId ? require('crypto').createHash('sha256').update(String(passportId)).digest('hex').slice(0, 8) : 'anon',
    ts:         Date.now(),
    day:        new Date().toISOString().slice(0, 10),   // YYYY-MM-DD
    hour:       new Date().getUTCHours(),
  };

  _feed.unshift(entry);
  if (_feed.length > FEED_MAX) _feed.length = FEED_MAX;
}

// ── getFeed ───────────────────────────────────────────────────────────────────
/**
 * Return last N threat patterns (newest first).
 * @param {number} limit  defaults to 100, max 500
 */
function getFeed(limit = 100) {
  const n = Math.min(limit, 500);
  return _feed.slice(0, n);
}

// ── getStats ──────────────────────────────────────────────────────────────────
/**
 * Aggregated statistics: counts by type, by day, trending vectors.
 */
function getStats() {
  const byType  = {};
  const byDay   = {};
  const byHour  = {};

  for (const e of _feed) {
    // By type
    byType[e.primaryType] = (byType[e.primaryType] || 0) + 1;
    // By day
    byDay[e.day] = (byDay[e.day] || 0) + 1;
    // By hour (last 24 h bucket)
    const key = `${e.day}T${String(e.hour).padStart(2, '0')}`;
    byHour[key] = (byHour[key] || 0) + 1;
  }

  // Top 10 most common threat types
  const trending = Object.entries(byType)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([type, count]) => ({ type, count }));

  // Average risk score
  const avgRisk = _feed.length
    ? +(_feed.reduce((s, e) => s + e.riskScore, 0) / _feed.length).toFixed(4)
    : 0;

  return {
    totalRecorded: _feed.length,
    avgRiskScore:  avgRisk,
    byType,
    byDay,
    byHour,
    trending,
    timestamp:     new Date().toISOString(),
  };
}

// ── getLeaderboard ────────────────────────────────────────────────────────────
/**
 * Top attack vectors in the last 7 days — designed to be shared publicly
 * (devs can embed this in their dashboards / share on social).
 */
function getLeaderboard() {
  const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const weekFeed = _feed.filter(e => e.ts >= weekAgo);

  const counts = {};
  let total = 0;
  for (const e of weekFeed) {
    counts[e.primaryType] = (counts[e.primaryType] || 0) + 1;
    total++;
  }

  const ranked = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .map(([type, count], i) => ({
      rank:       i + 1,
      threatType: type,
      count,
      pct:        total > 0 ? +((count / total) * 100).toFixed(1) : 0,
    }));

  return {
    period:     'last_7_days',
    totalThreats: total,
    leaderboard: ranked,
    generatedAt: new Date().toISOString(),
  };
}

module.exports = { recordThreat, getFeed, getStats, getLeaderboard };
