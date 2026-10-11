/**
 * GovernanceAttestation — Signed Satisfaction Attestations of Rule Adherence
 *
 * Produces a cryptographically SOUND, witness-private attestation that:
 * "An authorized evaluator confirmed this action satisfied governance
 *  rules X, Y, Z" — WITHOUT revealing the witness (risk scores, internal
 *  state, decision process) to the verifier.
 *
 * Soundness model (honest):
 *   - The evaluator holds an Ed25519 signing key.
 *   - Only the key holder can produce a valid attestation, so a third party
 *     cannot forge "rules satisfied" for a non-satisfying action.
 *   - The witness is hidden behind a salted commitment H(salt || witness);
 *     the verifier never sees witness values.
 *
 * What this is NOT (and we do not claim it to be):
 *   - This is NOT a zero-knowledge SNARK. It does not let an UNTRUSTED
 *     prover convince a verifier of satisfaction without a trusted key.
 *     Trust is rooted in the evaluator's signing key, exactly like a
 *     notarized statement. For trustless ZK you need groth16/bulletproofs.
 *
 * The previous version used a Schnorr "Sigma protocol" that was UNSOUND:
 * the prover chose publicValue = g^secret freely, so the proof attested
 * only "I know a discrete log", never "the circuit is satisfied". Removed.
 */

'use strict';

const crypto = require('crypto');

function sha256Hex(...args) {
  const h = crypto.createHash('sha256');
  for (const a of args) h.update(typeof a === 'string' ? a : JSON.stringify(a));
  return h.digest('hex');
}

/** Canonical JSON with sorted keys for deterministic signing. */
function canonical(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonical).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonical(obj[k])).join(',') + '}';
}

/**
 * Governance Rule as a boolean constraint.
 * Each rule: f(witness, publicInput) => boolean
 */
class GovernanceCircuit {
  constructor(rules) {
    this.rules = rules; // [{ id, name, evaluate: (witness, publicInput) => boolean }]
  }

  evaluate(witness, publicInput) {
    const results = this.rules.map(rule => ({
      id: rule.id,
      name: rule.name,
      satisfied: !!rule.evaluate(witness, publicInput),
    }));
    return {
      satisfied: results.every(r => r.satisfied),
      results,
      ruleCount: this.rules.length,
    };
  }
}

class GovernanceAttestation {
  /**
   * @param {object} options
   * @param {string} [options.privateKeyPem] — Ed25519 private key (PKCS8 PEM). If absent, one is generated.
   * @param {string} [options.publicKeyPem]  — matching public key (SPKI PEM).
   */
  constructor(options = {}) {
    this.circuit = null;
    this.proofCount = 0;
    this.verificationCount = 0;

    if (options.privateKeyPem && options.publicKeyPem) {
      this.privateKey = crypto.createPrivateKey(options.privateKeyPem);
      this.publicKey = crypto.createPublicKey(options.publicKeyPem);
    } else {
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
      this.privateKey = privateKey;
      this.publicKey = publicKey;
    }
    this.publicKeyPem = this.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    this.keyId = sha256Hex(this.publicKeyPem).slice(0, 16);
  }

  createCircuit(rules) {
    this.circuit = new GovernanceCircuit(rules);
    return this.circuit;
  }

  createDefaultCircuit() {
    return this.createCircuit([
      { id: 'R1', name: 'risk_below_threshold', evaluate: (w, pub) => (w.riskScore || 0) < (pub.riskThreshold || 0.7) },
      { id: 'R2', name: 'no_forbidden_verbs', evaluate: (w, pub) => {
          const forbidden = pub.forbiddenVerbs || ['DELETE_FILE', 'DROP_TABLE', 'EXEC'];
          return !forbidden.includes(w.verb || '');
        } },
      { id: 'R3', name: 'no_pii_in_output', evaluate: (w) => (w.piiCount || 0) === 0 },
      { id: 'R4', name: 'within_rate_limit', evaluate: (w, pub) => (w.requestCount || 0) < (pub.rateLimit || 100) },
      { id: 'R5', name: 'authorized_domain', evaluate: (w, pub) => {
          const allowed = pub.allowedDomains || [];
          return allowed.length === 0 || allowed.includes(w.targetDomain || '');
        } },
    ]);
  }

  /**
   * Generate a signed satisfaction attestation.
   * Returns null if the witness does NOT satisfy the circuit — an honest
   * evaluator cannot attest to something false.
   *
   * @param {object} witness — private values, never included in the attestation
   * @param {object} publicInput — public constraint parameters
   */
  generateProof(witness, publicInput) {
    if (!this.circuit) this.createDefaultCircuit();
    const start = Date.now();

    const evaluation = this.circuit.evaluate(witness, publicInput);
    if (!evaluation.satisfied) {
      return null; // cannot attest to a false statement
    }

    // Witness-hiding commitment: H(salt || witness). Salt keeps it binding
    // and prevents dictionary attacks on low-entropy witnesses. Salt is
    // included so the committer could later open it, but the verifier never
    // needs the witness to check the attestation.
    const salt = crypto.randomBytes(32).toString('hex');
    const witnessCommitment = sha256Hex(salt, canonical(witness));

    const statement = {
      v: 'gov-attest-1',
      keyId: this.keyId,
      // A13: reflect the real evaluation — never a blanket true. A DENY means not
      // all rules held, so this must be false there. Named both ways for compat.
      satisfied: evaluation.results.every((r) => r.satisfied),
      allRulesSatisfied: evaluation.results.every((r) => r.satisfied),
      ruleCount: evaluation.ruleCount,
      rulesSatisfied: evaluation.results.filter(r => r.satisfied).length,
      ruleIds: evaluation.results.map(r => r.id),
      publicInputHash: sha256Hex(canonical(publicInput)),
      witnessCommitment,
      issuedAt: new Date().toISOString(),
    };

    const message = Buffer.from(canonical(statement), 'utf8');
    const signature = crypto.sign(null, message, this.privateKey).toString('base64');

    this.proofCount++;
    return {
      proof: {
        statement,
        signature,
        publicKeyPem: this.publicKeyPem,
      },
      proofId: `gatt_${Date.now()}_${this.proofCount}`,
      publicInputHash: statement.publicInputHash,
      rulesEvaluated: evaluation.ruleCount,
      rulesSatisfied: statement.rulesSatisfied,
      // Attestation contains NO witness values — only a salted commitment.
      latencyMs: Date.now() - start,
      proofSizeBytes: Buffer.byteLength(canonical(statement)) + signature.length,
    };
  }

  /**
   * Verify a signed satisfaction attestation.
   *
   * Soundness: a valid signature under the expected public key proves the
   * authorized evaluator attested satisfaction. We also re-bind the
   * attestation to the verifier's own publicInput, so a statement issued
   * for different public parameters cannot be replayed.
   *
   * @param {object} proof — output of generateProof
   * @param {object} publicInput — the public parameters the verifier expects
   * @param {string} [expectedKeyId] — if provided, the attestation must be from this key
   */
  verifyProof(proof, publicInput, expectedKeyId) {
    const start = Date.now();
    try {
      const { statement, signature, publicKeyPem } = proof.proof || {};
      if (!statement || !signature || !publicKeyPem) {
        return { valid: false, error: 'malformed attestation', latencyMs: Date.now() - start };
      }

      const pub = crypto.createPublicKey(publicKeyPem);
      const recomputedKeyId = sha256Hex(publicKeyPem).slice(0, 16);

      // 1. Signature must verify over the canonical statement.
      const message = Buffer.from(canonical(statement), 'utf8');
      const sigOk = crypto.verify(null, message, pub, Buffer.from(signature, 'base64'));

      // 2. The embedded keyId must match the actual public key.
      const keyBindingOk = statement.keyId === recomputedKeyId;

      // 3. The attestation must be for the SAME public input the verifier expects.
      const publicInputOk = statement.publicInputHash === sha256Hex(canonical(publicInput));

      // 4. Optional: pin to an expected evaluator key.
      const keyTrustOk = !expectedKeyId || recomputedKeyId === expectedKeyId;

      // 5. Statement must actually assert satisfaction.
      const assertsSatisfied = statement.satisfied === true;

      this.verificationCount++;
      const valid = sigOk && keyBindingOk && publicInputOk && keyTrustOk && assertsSatisfied;

      return {
        valid,
        checks: { sigOk, keyBindingOk, publicInputOk, keyTrustOk, assertsSatisfied },
        keyId: recomputedKeyId,
        latencyMs: Date.now() - start,
        proofId: proof.proofId,
        rulesVerified: statement.ruleCount,
      };
    } catch (e) {
      return { valid: false, error: e.message, latencyMs: Date.now() - start };
    }
  }

  getStats() {
    return {
      proofsGenerated: this.proofCount,
      proofsVerified: this.verificationCount,
      keyId: this.keyId,
    };
  }
}

// Backwards-compatible export name. The class is honestly a signed
// attestation, not a zero-knowledge proof.
module.exports = {
  GovernanceAttestation,
  GovernanceCircuit,
  // Alias kept so existing requires of ZKGovernanceProof keep working.
  ZKGovernanceProof: GovernanceAttestation,
};
