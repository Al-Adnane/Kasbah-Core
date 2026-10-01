'use strict';

/**
 * kasbah-products.js — Detection Products Loader
 *
 * Loads the real, functional detection engines and exposes them as one module.
 * Only products that make an honest, testable claim are wired.
 *
 * Removed (2026-07): the exotic-math research toys (chronos-paradox,
 * manifold-validator, neural-witness, quantum-sentinel, botnet-radar), the
 * Forge/Nexus/Cortex trinity, multiverse-core — and, separately,
 * legal-evidence + resume-authentic. Those last two had zero test coverage,
 * zero external benchmark, and fabricated "forensic," "court-admissible,"
 * "expert witness-ready" narratives on a home-brew, unmeasured AI-authorship
 * score. A caveat string doesn't fix a report that calls itself forensic
 * evidence — that class of overclaim is gone, not just labeled.
 *
 * Removed (2026-09): DatingGuard + RelationshipGuard. Not a quality call —
 * the engines were real (regex-based pattern detection) — this is a values
 * decision that AI has no business monitoring dating/relationship content.
 *
 * Wired:
 *   - cryptoUtils        — Shamir / MMR / VDF primitives (real cryptography)
 */

// ─── Crypto utils (real cryptography, lazy) ───────────────────────────────────
let _cryptoUtils;
function getCryptoUtils() {
  if (_cryptoUtils !== undefined) return _cryptoUtils;
  try {
    _cryptoUtils = {
      shamir: require('../../crypto-utils/dist/shamir.js'),
      mmr:    require('../../crypto-utils/dist/mmr.js'),
      vdf:    require('../../crypto-utils/dist/vdf.js'),
    };
  } catch (e) { _cryptoUtils = null; }
  return _cryptoUtils;
}

function status() {
  return {
    cryptoUtils: !!getCryptoUtils(),
  };
}

module.exports = {
  get cryptoUtils() { return getCryptoUtils(); },
  status,
};
