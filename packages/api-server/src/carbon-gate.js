'use strict';

// ─── Carbon-Intensity Execution Gate ──────────────────────────────────────────
//
// Fetches grid carbon intensity from Electricity Maps (free tier) or CO2Signal,
// caches for CACHE_TTL_MS, and produces a signed attestation that can be
// embedded in a kernel ticket.  The gate checks CI ≤ threshold before issuing.
//
// Without an API token the module falls back to a static global-average
// estimate (450 gCO2eq/kWh) so the gate degrades gracefully — it marks
// estimated:true so callers can decide whether to accept it.
//
// Env vars:
//   ELECTRICITY_MAPS_TOKEN — Electricity Maps free-tier token
//   CO2SIGNAL_TOKEN        — fallback: CO2Signal API key (same provider)
//   CARBON_GATE_ZONE       — default zone, e.g. "DE", "US-CAL-CISO" (default: "DE")

const https = require('https');
const crypto = require('crypto');

const ATTEST_SECRET = process.env.KASBAH_TICKET_SECRET || crypto.randomBytes(32).toString('hex');
const CACHE_TTL_MS  = 15 * 60 * 1000; // 15 min — CI changes slowly
const GLOBAL_AVG_CI = 450;             // gCO2eq/kWh — IEA 2023 world average
const DEFAULT_ZONE  = process.env.CARBON_GATE_ZONE || 'DE';

let _cache = null; // { zone, ci, unit, source, fetchedAt, estimated, atRisk }

// ─── helpers ──────────────────────────────────────────────────────────────────

function _get(url, headers) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(body) }); }
        catch (_) { reject(new Error(`Non-JSON response from ${url}: ${body.slice(0,200)}`)); }
      });
    });
    req.on('error', reject);
    req.setTimeout(8000, () => { req.destroy(new Error('timeout')); });
  });
}

function _sign(payload) {
  return crypto.createHmac('sha256', ATTEST_SECRET)
    .update(typeof payload === 'string' ? payload : JSON.stringify(payload))
    .digest('base64url');
}

// ─── fetch ────────────────────────────────────────────────────────────────────

async function _fetchCI(zone) {
  const emToken = process.env.ELECTRICITY_MAPS_TOKEN;
  const co2Token = process.env.CO2SIGNAL_TOKEN;

  if (emToken) {
    try {
      const r = await _get(
        `https://api.electricitymap.org/v3/carbon-intensity/latest?zone=${encodeURIComponent(zone)}`,
        { 'auth-token': emToken }
      );
      if (r.status === 200 && typeof r.data.carbonIntensity === 'number') {
        return { ci: r.data.carbonIntensity, unit: 'gCO2eq/kWh', source: 'electricitymap', estimated: false };
      }
    } catch (_) { /* fall through */ }
  }

  if (co2Token) {
    try {
      const r = await _get(
        `https://api.co2signal.com/v1/latest?countryCode=${encodeURIComponent(zone.split('-')[0])}`,
        { 'auth-token': co2Token }
      );
      if (r.status === 200 && typeof r.data?.data?.carbonIntensity === 'number') {
        return { ci: r.data.data.carbonIntensity, unit: 'gCO2eq/kWh', source: 'co2signal', estimated: false };
      }
    } catch (_) { /* fall through */ }
  }

  // No token or fetch failed — return global-average estimate
  return { ci: GLOBAL_AVG_CI, unit: 'gCO2eq/kWh', source: 'static-estimate', estimated: true };
}

// ─── public API ───────────────────────────────────────────────────────────────

/**
 * Return the current carbon intensity for `zone`, with a 15-min cache.
 * Always resolves — never rejects (falls back to estimate on any error).
 */
async function current(zone = DEFAULT_ZONE) {
  if (_cache && _cache.zone === zone && (Date.now() - _cache.fetchedAt) < CACHE_TTL_MS) {
    return _cache;
  }
  let fetched;
  try { fetched = await _fetchCI(zone); }
  catch (_) { fetched = { ci: GLOBAL_AVG_CI, unit: 'gCO2eq/kWh', source: 'static-estimate', estimated: true }; }

  const entry = {
    zone,
    ci: fetched.ci,
    unit: fetched.unit,
    source: fetched.source,
    estimated: fetched.estimated,
    fetchedAt: Date.now(),
  };
  _cache = entry;
  return entry;
}

/**
 * Produce a signed attestation object for the current CI reading.
 * The sig covers zone + ci + unit + source + fetchedAt so it can't be replayed
 * with a different reading.
 */
async function attest(zone = DEFAULT_ZONE) {
  const reading = await current(zone);
  const payload = {
    zone: reading.zone,
    ci: reading.ci,
    unit: reading.unit,
    source: reading.source,
    estimated: reading.estimated,
    fetchedAt: reading.fetchedAt,
  };
  return { ...payload, sig: _sign(payload) };
}

/**
 * Gate check: resolves to { allowed, ci, threshold, zone, attestation }.
 * allowed=false means the caller must refuse resource allocation.
 * threshold=null means no gate is configured (always allowed).
 */
async function check(threshold = null, zone = DEFAULT_ZONE) {
  if (threshold === null || threshold === undefined) {
    return { allowed: true, ci: null, threshold: null, zone, attestation: null };
  }
  const attestation = await attest(zone);
  const allowed = attestation.ci <= threshold;
  return {
    allowed,
    ci: attestation.ci,
    threshold,
    zone,
    unit: attestation.unit,
    source: attestation.source,
    estimated: attestation.estimated,
    attestation,
    reason: allowed ? null : `carbon intensity ${attestation.ci} ${attestation.unit} exceeds threshold ${threshold}`,
  };
}

module.exports = { current, attest, check, DEFAULT_ZONE };
