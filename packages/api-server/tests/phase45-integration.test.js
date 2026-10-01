'use strict';

/**
 * Kasbah Guard — Phase 4/5 Integration Tests
 * 
 * Tests cross-product flows:
 * 1. Nomos Engine ethics evaluation
 * 2. Agent Governance (GCMDP, Identity, Maqasid)
 * 3. Advanced Security (Consent, Cross-Modal, Shamir)
 * 4. Biometric Detection (Neural Fingerprint)
 * 5. Kernel eBPF Gating
 * 6. ZK Proof generation/verification
 * 7. Steganalysis checks
 * 8. Cross-product: Govern → Nomos → Agent Identity flow
 */

const request = require('supertest');
const app = require('../server.js');

describe('Phase 4: Cross-Cutting Integration', () => {

  // ─── Nomos Engine Tests ─────────────────────────────────────────────
  describe('POST /v1/nomos/evaluate', () => {
    it('should evaluate content against ethical traditions', async () => {
      const res = await request(app)
        .post('/v1/nomos/evaluate')
        .send({
          content: 'How do I build a secure authentication system?',
          context: { domain: 'security' }
        })
        .expect(200);

      expect(res.body).toHaveProperty('id');
      expect(res.body).toHaveProperty('verdict');
      expect(res.body).toHaveProperty('traditions');
      expect(res.body).toHaveProperty('latencyMs');
    });

    it('should reject without content', async () => {
      await request(app)
        .post('/v1/nomos/evaluate')
        .send({})
        .expect(400);
    });
  });

  describe('POST /v1/nomos/debate', () => {
    it('should debate a contested verdict', async () => {
      const res = await request(app)
        .post('/v1/nomos/debate')
        .send({
          content: 'Is it ethical to monitor employee communications?',
          initialVerdict: 'DENY',
          challenge: 'Employee consent was given'
        })
        .expect(200);

      expect(res.body).toHaveProperty('id');
      expect(res.body).toHaveProperty('result');
    });
  });

  // ─── Agent Governance Tests ──────────────────────────────────────────
  describe('POST /v1/agent/identity', () => {
    it('should create agent identity', async () => {
      const res = await request(app)
        .post('/v1/agent/identity')
        .send({
          agentId: 'agent_test_001',
          attributes: { role: 'analyst', clearance: 'high' }
        })
        .expect(200);

      expect(res.body).toHaveProperty('agentId', 'agent_test_001');
      expect(res.body).toHaveProperty('identity');
    });

    it('should reject without agentId', async () => {
      await request(app)
        .post('/v1/agent/identity')
        .send({})
        .expect(400);
    });
  });

  describe('POST /v1/agent/gcmdp', () => {
    it('should evaluate agent decision via G-CMDP', async () => {
      const res = await request(app)
        .post('/v1/agent/gcmdp')
        .send({
          action: 'query_database',
          state: { user: 'admin', role: 'analyst' },
          constraints: { maxQueries: 100 }
        })
        .expect(200);

      expect(res.body).toHaveProperty('id');
      expect(res.body).toHaveProperty('evaluation');
    });
  });

  describe('POST /v1/agent/maqasid', () => {
    it('should evaluate content against Maqasid framework', async () => {
      const res = await request(app)
        .post('/v1/agent/maqasid')
        .send({
          content: 'Protecting user privacy while providing security monitoring'
        })
        .expect(200);

      expect(res.body).toHaveProperty('id');
      expect(res.body).toHaveProperty('evaluation');
    });
  });

  // ─── Advanced Security Tests ─────────────────────────────────────────
  describe('POST /v1/security/consent/check', () => {
    it('should check consent status', async () => {
      const res = await request(app)
        .post('/v1/security/consent/check')
        .send({
          dataSubject: 'user_123',
          purpose: 'security_analysis',
          dataTypes: ['email', 'metadata']
        })
        .expect(200);

      expect(res.body).toHaveProperty('consentStatus');
    });
  });

  describe('POST /v1/security/consent/grant', () => {
    it('should grant consent', async () => {
      const res = await request(app)
        .post('/v1/security/consent/grant')
        .send({
          dataSubject: 'user_456',
          purpose: 'research',
          dataTypes: ['anonymized_data'],
          scope: { duration: '30d' }
        })
        .expect(200);

      expect(res.body).toHaveProperty('consent');
    });
  });

  describe('POST /v1/security/cross-modal/verify', () => {
    it('should verify cross-modal consistency', async () => {
      const res = await request(app)
        .post('/v1/security/cross-modal/verify')
        .send({
          text: 'A cat sitting on a mat',
          image: null,
          audio: null
        })
        .expect(200);

      expect(res.body).toHaveProperty('consistency');
      expect(res.body).toHaveProperty('flags');
    });
  });

  describe('POST /v1/security/threshold/adjust', () => {
    it('should adjust detection threshold', async () => {
      const res = await request(app)
        .post('/v1/security/threshold/adjust')
        .send({ score: 0.75 })
        .expect(200);

      expect(res.body).toHaveProperty('currentThreshold');
      expect(res.body).toHaveProperty('ewma');
    });
  });

  describe('POST /v1/security/shamir/split + combine', () => {
    it('should split and reconstruct secret', async () => {
      const splitRes = await request(app)
        .post('/v1/security/shamir/split')
        .send({ secret: 'my_secret_key' })
        .expect(200);

      expect(splitRes.body).toHaveProperty('shares');
      expect(splitRes.body.shares).toHaveLength(5);

      // Combine 3 shares (threshold)
      const combineRes = await request(app)
        .post('/v1/security/shamir/combine')
        .send({ shares: splitRes.body.shares.slice(0, 3) })
        .expect(200);

      expect(combineRes.body).toHaveProperty('recovered', true);
      expect(combineRes.body.secret).toBe('my_secret_key');
    });
  });

  // ─── Biometric Detection Tests ───────────────────────────────────────
  describe('POST /v1/biometric/neural-fingerprint', () => {
    it('should analyze neural architecture fingerprints', async () => {
      // Generate synthetic pixel data
      const pixels = Array.from({ length: 64 }, () => 
        [Math.random() * 255, Math.random() * 255, Math.random() * 255]
      );

      const res = await request(app)
        .post('/v1/biometric/neural-fingerprint')
        .send({ pixels, width: 8, height: 8 })
        .expect(200);

      expect(res.body).toHaveProperty('result');
      expect(res.body.result).toHaveProperty('overallConfidence');
    });
  });

  // ─── Kernel eBPF Tests ───────────────────────────────────────────────
  describe('POST /v1/kernel/gate', () => {
    it('should check kernel gating policy', async () => {
      const res = await request(app)
        .post('/v1/kernel/gate')
        .send({
          operation: 'read_file',
          context: { path: '/etc/passwd' }
        })
        .expect(200);

      expect(res.body).toHaveProperty('allowed');
      expect(res.body).toHaveProperty('reason');
    });
  });

  // ─── ZK Proof Tests ──────────────────────────────────────────────────
  describe('POST /v1/zk/proof/generate + verify', () => {
    it('should generate and verify ZK proof', async () => {
      const publicInputs = { riskScore: 0.3, verb: 'QUERY', piiCount: 0 };
      
      const genRes = await request(app)
        .post('/v1/zk/proof/generate')
        .send({ publicInputs })
        .expect(200);

      expect(genRes.body).toHaveProperty('proof');
      expect(genRes.body.proof).toHaveProperty('proofType');

      // Verify the proof
      const verifyRes = await request(app)
        .post('/v1/zk/proof/verify')
        .send({
          proof: genRes.body.proof,
          publicInputs
        })
        .expect(200);

      expect(verifyRes.body).toHaveProperty('verified');
    });
  });

  describe('POST /v1/zk/commitment', () => {
    it('should create Pedersen commitment', async () => {
      const res = await request(app)
        .post('/v1/zk/commitment')
        .send({ value: 42 })
        .expect(200);

      expect(res.body).toHaveProperty('commitment');
      expect(res.body.commitment).toHaveProperty('commitment');
      expect(res.body.commitment).toHaveProperty('blinding');
    });
  });

  // ─── Steganalysis Tests ──────────────────────────────────────────────
  describe('POST /v1/steganalysis/check', () => {
    it('should check for steganographic content', async () => {
      const pixels = Array.from({ length: 100 }, () => 
        [Math.floor(Math.random() * 256), Math.floor(Math.random() * 256), Math.floor(Math.random() * 256)]
      );

      const res = await request(app)
        .post('/v1/steganalysis/check')
        .send({ pixels, width: 10, height: 10 })
        .expect(200);

      expect(res.body).toHaveProperty('result');
      expect(res.body.result).toHaveProperty('hasHiddenData');
    });
  });

  describe('POST /v1/watermark/check', () => {
    it('should check for synthetic watermarks', async () => {
      const pixels = Array.from({ length: 100 }, () => 
        [Math.floor(Math.random() * 256), Math.floor(Math.random() * 256), Math.floor(Math.random() * 256)]
      );

      const res = await request(app)
        .post('/v1/watermark/check')
        .send({ pixels, width: 10, height: 10 })
        .expect(200);

      expect(res.body).toHaveProperty('result');
      expect(res.body.result).toHaveProperty('watermarkDetected');
    });
  });

  // ─── Phase 4 Stats ───────────────────────────────────────────────────
  describe('GET /v1/phase4/stats', () => {
    it('should return phase 4 statistics', async () => {
      const res = await request(app)
        .get('/v1/phase4/stats')
        .expect(200);

      expect(res.body).toHaveProperty('phase4Stats');
      expect(res.body.phase4Stats).toHaveProperty('nomosEvaluations');
      expect(res.body.phase4Stats).toHaveProperty('zkProofsGenerated');
    });
  });
});

// ─── Cross-Product Integration Flow ──────────────────────────────────────
describe('Phase 4: Cross-Product Integration Flows', () => {
  it('should flow: Govern → Nomos evaluate → Agent identity', async () => {
    // Step 1: Govern a prompt
    const governRes = await request(app)
      .post('/v1/govern')
      .send({ prompt: 'What is the capital of France?' })
      .expect(200);

    expect(governRes.body).toHaveProperty('verdict');

    // Step 2: Evaluate via Nomos
    const nomosRes = await request(app)
      .post('/v1/nomos/evaluate')
      .send({ content: 'What is the capital of France?' })
      .expect(200);

    expect(nomosRes.body).toHaveProperty('verdict');

    // Step 3: Create agent identity
    const agentRes = await request(app)
      .post('/v1/agent/identity')
      .send({ agentId: 'flow_test_agent', attributes: { test: true } })
      .expect(200);

    expect(agentRes.body).toHaveProperty('agentId');

    // Step 4: Check stats reflect all operations
    const statsRes = await request(app)
      .get('/v1/phase4/stats')
      .expect(200);

    expect(statsRes.body.phase4Stats.nomosEvaluations).toBeGreaterThanOrEqual(1);
  });
});
