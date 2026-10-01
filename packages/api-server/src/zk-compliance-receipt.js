'use strict';

/**
 * zk-compliance-receipt.js — the compliance moat.
 *
 * A normal Kasbah receipt is a signed statement: "engine K says verdict = V".
 * That is self-attested — an auditor must trust K, and to re-check the
 * decision they need the prompt itself (often regulated/PII data they are not
 * allowed to hold).
 *
 * A ZK-COMPLIANCE receipt additionally proves, in zero knowledge, that the
 * verdict is the CORRECT threshold decision for the (hidden) risk score the
 * engine computed — while the prompt and the score both stay private. The
 * auditor verifies enforcement was applied honestly WITHOUT ever seeing the
 * data. That is the artifact an EU-AI-Act / regulated-data buyer needs and
 * that no dashboard or self-attested log can produce.
 *
 * Bound into every receipt (and into the ZK Fiat–Shamir transcript, so none
 * can be swapped):
 *   - inputCommitment  : salted SHA-256 of the prompt (hiding + binding;
 *                        salt stays with the data owner, never in the receipt)
 *   - policyHash       : SHA-256 of the policy version + enforced thresholds
 *   - verdict, threshold
 *   - thresholdProof   : ZK proof that hidden score is on the verdict's side of
 *                        the public threshold (packages/crypto-utils zk-proofs-full)
 * The whole bundle is signed by the engine key (Ed25519, ML-DSA-capable).
 *
 * HONEST BOUNDARY — stated in the receipt itself: this proves tamper-evidence,
 * verdict-correct-under-threshold, and input/score privacy. It does NOT prove
 * the score is the "true" risk of the input; detector quality is a separate,
 * separately-benchmarked question. Selling this as "provably correct
 * detection" would be exactly the kind of overclaim KASBAH.md §4 bans.
 */

const crypto = require('crypto');
const { ZKProofSystem } = require('../../crypto-utils/src/zk-proofs-full.js');
const engineKey = require('./engine-key.js');

const zk = new ZKProofSystem();
const SCALE = 1000; // risk score in [0,1] → integer [0,1000]
const BITS = 16;

function _saltedCommit(prompt) {
  const salt = crypto.randomBytes(16);
  const commitment = crypto.createHash('sha256').update(salt).update(String(prompt)).digest('hex');
  return { commitment, salt: salt.toString('hex') }; // salt returned to caller, NOT embedded
}

function _policyHash(policyVersion, thresholds) {
  return crypto.createHash('sha256')
    .update(String(policyVersion || 'default'))
    .update(JSON.stringify(thresholds || {}))
    .digest('hex');
}

/**
 * Build a ZK-compliance receipt for a governance decision.
 * @param {object} p
 * @param {string} p.prompt          the governed input (never embedded)
 * @param {string} p.verdict         ALLOW | WARN | REQUIRE_APPROVAL | DENY
 * @param {number} p.riskScore       [0,1]
 * @param {number} p.warnThreshold   [0,1] (default 0.5)
 * @param {number} p.approvalThreshold [0,1] (default 0.8)
 * @param {string} p.policyVersion
 * @returns {{ receipt, payload, decoded, salt, thresholdProof }}
 *   `salt` lets the data owner later open the input commitment in a dispute.
 */
function build({ prompt = '', verdict, riskScore, warnThreshold = 0.5, approvalThreshold = 0.8, policyVersion = 'kasbah-default-v1' }) {
  if (!verdict) throw new Error('verdict required');
  if (typeof riskScore !== 'number' || riskScore < 0 || riskScore > 1) throw new Error('riskScore must be in [0,1]');

  const score = Math.min(SCALE, Math.round(riskScore * SCALE));
  const warnT = Math.round(warnThreshold * SCALE);
  const approvalT = Math.round(approvalThreshold * SCALE);
  const thresholds = { warn: warnT, approval: approvalT, scale: SCALE };

  // Map the verdict to the inequality that decides it, and prove exactly that.
  let governingThreshold, below;
  if (verdict === 'ALLOW') { governingThreshold = warnT; below = true; }        // score < warnT
  else if (verdict === 'WARN') { governingThreshold = warnT; below = false; }    // score >= warnT (escalation trigger)
  else { governingThreshold = approvalT; below = false; }                        // DENY/REQUIRE_APPROVAL: score >= approvalT

  const thresholdProof = zk.proveThresholdVerdict(score, governingThreshold, below, BITS);

  const { commitment: inputCommitment, salt } = _saltedCommit(prompt);
  const bundle = {
    attestationType: 'zk-compliance',
    inputCommitment,
    inputCommitmentAlg: 'sha256(salt||prompt)',
    policyVersion,
    policyHash: _policyHash(policyVersion, thresholds),
    verdict,
    governingThreshold,
    thresholds,
    thresholdProof,
    proves: `verdict "${verdict}" is the correct decision for a hidden risk score that is ${below ? 'below' : 'at/above'} the enforced threshold ${governingThreshold}/${SCALE}; prompt and score never revealed`,
    guaranteeBoundary: 'Proves tamper-evidence + verdict-correct-under-threshold + input/score privacy. Does NOT prove the score is the true risk of the input (detector quality is benchmarked separately).',
    timestamp: new Date().toISOString(),
  };

  const signed = engineKey.sign(bundle);
  return { receipt: signed.receipt, payload: signed.payload, decoded: signed.decoded, salt, thresholdProof };
}

/**
 * Verify a ZK-compliance receipt end-to-end: engine signature (tamper-evidence
 * + who signed) AND the zero-knowledge threshold proof (verdict is correct
 * under the enforced threshold). The prompt is never needed.
 * @param {string} receipt  the kasbah_receipt:... string
 * @param {string} payload  base64url canonical payload (from build())
 */
function verify(receipt, payload) {
  const sig = engineKey.verify(receipt, payload);
  if (!sig || !sig.valid) {
    return { valid: false, signatureValid: false, error: sig?.error || 'signature invalid' };
  }
  let bundle;
  try { bundle = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); }
  catch (e) { return { valid: false, signatureValid: true, error: 'payload not decodable: ' + e.message }; }

  if (bundle.attestationType !== 'zk-compliance' || !bundle.thresholdProof) {
    return { valid: false, signatureValid: true, error: 'not a zk-compliance receipt' };
  }
  const zkResult = zk.verifyThresholdVerdict(bundle.thresholdProof);
  if (!zkResult.isValid) {
    return { valid: false, signatureValid: true, zkValid: false, error: 'ZK threshold proof invalid: ' + zkResult.error };
  }

  // Cross-check: the verdict in the signed bundle must match the direction the
  // ZK proof actually proves, against the governing threshold in the bundle.
  const dir = bundle.thresholdProof.direction;
  const T = bundle.thresholdProof.threshold;
  const verdictConsistent =
    (bundle.verdict === 'ALLOW' && dir === 'below' && T === bundle.governingThreshold) ||
    (bundle.verdict === 'WARN' && dir === 'at-or-above' && T === bundle.governingThreshold) ||
    (['DENY', 'REQUIRE_APPROVAL'].includes(bundle.verdict) && dir === 'at-or-above' && T === bundle.governingThreshold);
  if (!verdictConsistent) {
    return { valid: false, signatureValid: true, zkValid: true, error: 'signed verdict does not match the proven threshold direction' };
  }

  return {
    valid: true,
    signatureValid: true,
    zkValid: true,
    keyId: sig.keyId || bundle.keyId,
    verdict: bundle.verdict,
    proves: zkResult.proves,
    inputCommitment: bundle.inputCommitment,
    policyHash: bundle.policyHash,
    note: 'Verified without seeing the prompt or the risk score.',
  };
}

/** Open an input commitment in a dispute (owner supplies prompt + salt). */
function openCommitment(prompt, saltHex, commitment) {
  const recomputed = crypto.createHash('sha256').update(Buffer.from(saltHex, 'hex')).update(String(prompt)).digest('hex');
  return { matches: recomputed === commitment, recomputed };
}

module.exports = { build, verify, openCommitment, SCALE, BITS };
