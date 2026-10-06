'use strict';

/**
 * ZKGovernanceAdapter — Adapts GovernanceAttestation to Sentinel's expected interface
 * 
 * The sentinel expects: generateProof(witness, pubInput) -> { verified, constraints, violations, advisory, detail }
 * GovernanceAttestation returns: { proof, proofId, rulesEvaluated, ... } or null
 */

const { ZKGovernanceProof: GovernanceAttestation } = require('./zk-governance-proof.js');

class ZKGovernanceAdapter {
  constructor(options = {}) {
    this.attestor = new GovernanceAttestation(options);
    // Default circuit with standard governance rules
    this.attestor.createDefaultCircuit();
  }

  generateProof(witness, pubInput) {
    // Map sentinel's witness/pubInput to circuit rules
    // witness: { riskScore, verb, piiCount, requestCount, targetDomain }
    // pubInput: { riskThreshold, forbiddenVerbs, rateLimit, allowedDomains }
    
    // The default circuit already checks these, but let's ensure compatibility
    const result = this.attestor.generateProof(witness, pubInput);
    
    // Build constraints array for compatibility
    const constraints = [
      { 
        name: 'risk_threshold', 
        satisfied: (witness.riskScore || 0) < (pubInput.riskThreshold || 1),
        witness: witness.riskScore, 
        bound: pubInput.riskThreshold 
      },
      { 
        name: 'verb_allowed', 
        satisfied: !(pubInput.forbiddenVerbs || []).includes(witness.verb),
        witness: witness.verb 
      },
      { 
        name: 'rate_limit', 
        satisfied: (witness.requestCount || 0) < (pubInput.rateLimit || Infinity),
        witness: witness.requestCount, 
        bound: pubInput.rateLimit 
      }
    ];
    
    if (pubInput.allowedDomains && pubInput.allowedDomains.length > 0) {
      constraints.push({
        name: 'domain_allowed',
        satisfied: pubInput.allowedDomains.includes(witness.targetDomain),
        witness: witness.targetDomain
      });
    }

    const violations = constraints.filter(c => !c.satisfied).map(c => c.name);
    const verified = result !== null && violations.length === 0;

    return {
      available: true,
      verified,
      constraints,
      violations,
      proof: result?.proof || null,
      proofId: result?.proofId || null,
      rulesEvaluated: result?.rulesEvaluated || constraints.length,
      rulesSatisfied: result?.rulesSatisfied || (constraints.length - violations.length),
      advisory: verified ? 'CLEAR' : 'WARN',
      detail: verified 
        ? 'Governance attestation verified: all constraints satisfied'
        : `Governance violations: ${violations.join(', ')}`
    };
  }

  verifyProof(proof, pubInput) {
    return this.attestor.verifyProof(proof, pubInput);
  }

  getStats() {
    return this.attestor.getStats();
  }
}

// Export with the name sentinel expects
module.exports = { ZKGovernanceProof: ZKGovernanceAdapter };