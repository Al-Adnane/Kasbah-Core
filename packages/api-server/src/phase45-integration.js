'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════════════╗
 * ║        PHASE 4 + 5 INTEGRATION — Cross-Cutting + Testing           ║
 * ║                                                                       ║
 * ║  Wires ALL disconnected packages into the API server:                 ║
 * ║  - Nomos Engine (multi-tradition ethics consensus)                   ║
 * ║  - Agent Governance (GCMDP, identity, maqasid)                      ║
 * ║  - Advanced Security (consent, cross-modal, dynamic thresholds)      ║
 * ║  - Biometric Detection (neural fingerprint, RPPG, voice, codec)      ║
 * ║  - Kernel eBPF Gating                                                ║
 * ║  - ZK Proofs + Steganalysis                                          ║
 * ╚══════════════════════════════════════════════════════════════════════╝
 *
 *  Usage:
 *    const phase45 = require('./src/phase45-integration.js');
 *    phase45.registerRoutes(app, stats, auditPush);
 */

const express = require('express');
const Router = express.Router;
const crypto = require('crypto');

// Graceful imports — server starts even if optional packages are unavailable
function _safeRequire(path, label) {
  try { return require(path); }
  catch (e) { console.warn(`[phase45] optional package unavailable: ${label} (${e.message.split('\n')[0]})`); return {}; }
}

// ─── Nomos Engine ───────────────────────────────────────────────────────────
const { createDefaultEngine: createNomosEngine, createDebateEngine } = _safeRequire('../../nomos-engine/src/index.js', 'nomos-engine');

// ─── Agent Governance ───────────────────────────────────────────────────────
const { GCMDP, AgentIdentity, MaqasidFramework, evaluateMaqasid } = _safeRequire('../../agent-governance/src/index.js', 'agent-governance');

// ─── Advanced Security ──────────────────────────────────────────────────────
const { ConsentManager, DynamicThreshold, CrossModalChecker, ShamirSecretSharing, DeadManSwitch } = _safeRequire('../../advanced-security/src/index.js', 'advanced-security');

// ─── Biometric Detection ────────────────────────────────────────────────────
const { NeuralFingerprintAnalyzer } = _safeRequire('../../biometric-detection/src/neural-fingerprint.js', 'neural-fingerprint');
const { rPPGDetector, VoiceCloneDetector, NeuralCodecDetector } = _safeRequire('../../biometric-detection/src/index.js', 'biometric-detection');

// ─── Kernel eBPF ────────────────────────────────────────────────────────────
const { KernelGatingEngine } = _safeRequire('../../kernel-ebpf/src/kernel-gating-engine.js', 'kernel-ebpf');

// ─── ZK Proofs ──────────────────────────────────────────────────────────────
const { ZKProofSystem } = _safeRequire('../../crypto-utils/src/zk-proofs-full.js', 'zk-proofs');

// ─── Steganalysis ───────────────────────────────────────────────────────────
const { steganalysisCheck, watermarkCheck } = _safeRequire('./systems/steganalysis.js', 'steganalysis');

/**
 * Register all Phase 4 + 5 routes on the app.
 */
function registerRoutes(app, stats, auditPush) {
  const router = Router();

  // Initialize singleton instances
  function _safeNew(Cls, ...args) { try { return Cls ? new Cls(...args) : null; } catch(e) { console.warn('[phase45] init failed:', Cls?.name, e.message); return null; } }
  const nomosEngine = createNomosEngine ? createNomosEngine() : null;
  const nomosDebate = createDebateEngine ? createDebateEngine() : null;
  const gcmdp = _safeNew(GCMDP);
  const consentManager = _safeNew(ConsentManager);
  const dynamicThreshold = _safeNew(DynamicThreshold, { baseThreshold: 0.5, alpha: 0.05 });
  const crossModalChecker = _safeNew(CrossModalChecker);
  const shamir = _safeNew(ShamirSecretSharing, { threshold: 3, totalShares: 5 });
  const neuralFingerprint = _safeNew(NeuralFingerprintAnalyzer);
  const rppg = _safeNew(rPPGDetector);
  const voiceClone = _safeNew(VoiceCloneDetector);
  const neuralCodec = _safeNew(NeuralCodecDetector);
  const kernelGating = _safeNew(KernelGatingEngine);
  const zkProofs = _safeNew(ZKProofSystem);

  // Phase 4 stats
  const p4Stats = {
    nomosEvaluations: 0,
    agentIdentities: 0,
    consentChecks: 0,
    crossModalAnalyses: 0,
    biometricScans: 0,
    kernelGatingChecks: 0,
    zkProofsGenerated: 0,
    steganalysisScans: 0,
  };

  // ═══════════════════════════════════════════════════════════════════════
  // NOMOS ENGINE — Multi-Tradition Ethics Consensus
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * POST /v1/nomos/evaluate
   * Evaluate content against multiple ethical traditions
   */
  router.post('/nomos/evaluate', async (req, res) => {
    const startTime = Date.now();
    try {
      const { content, context = {} } = req.body;
      if (!content) return res.status(400).json({ error: 'content is required' });

      const result = await nomosEngine.evaluate(content, context);
      p4Stats.nomosEvaluations++;

      const traditions = {};
      for (const ts of (result.traditionScores || [])) {
        traditions[ts.tradition] = {
          score: ts.score,
          weight: ts.weight,
          normsLoaded: ts.normsLoaded,
          stance: ts.score >= 0.6 ? 'approves' : ts.score <= 0.4 ? 'rejects' : 'undecided'
        };
      }
      const response = {
        id: 'nomos_' + crypto.randomBytes(6).toString('hex'),
        verdict: result.verdict || 'ALLOW',
        weightedMean: result.weightedMean,
        stdDev: result.stdDev,
        conflictLevel: result.conflictLevel,
        confidence: result.confidence,
        traditions,
        supportingTraditions: result.supportingTraditions || [],
        dissentingTraditions: result.dissentingTraditions || [],
        explanation: result.explanation,
        consensus: result.consensus || {},
        debate: result.debate || null,
        latencyMs: Date.now() - startTime,
        timestamp: new Date().toISOString()
      };

      auditPush({ type: 'nomos_evaluate', ...response });
      res.json(response);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * POST /v1/nomos/debate
   * Contest a verdict via ethical debate
   */
  router.post('/nomos/debate', async (req, res) => {
    try {
      const { content, initialVerdict, challenge } = req.body;
      if (!content || !challenge) return res.status(400).json({ error: 'content and challenge required' });

      const result = await nomosDebate.debate(content, initialVerdict, challenge);
      p4Stats.nomosEvaluations++;

      res.json({
        id: 'debate_' + crypto.randomBytes(6).toString('hex'),
        result,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // AGENT GOVERNANCE — GCMDP, Identity, Maqasid
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * POST /v1/agent/identity
   * Create or retrieve agent identity
   */
  router.post('/agent/identity', async (req, res) => {
    try {
      const { agentId, attributes = {} } = req.body;
      if (!agentId) return res.status(400).json({ error: 'agentId required' });

      const identity = AgentIdentity.generate(agentId, attributes);
      const certificate = identity.createCertificate();
      p4Stats.agentIdentities++;

      res.json({
        agentId,
        identity: certificate,
        publicKey: certificate.publicKey,
        expiresAt: new Date(certificate.expires).toISOString(),
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * POST /v1/agent/gcmdp
   * Evaluate agent decision via G-CMDP (constrained Markov decision process)
   */
  router.post('/agent/gcmdp', async (req, res) => {
    try {
      const { action, state, constraints = {} } = req.body;
      if (!action || !state) return res.status(400).json({ error: 'action and state required' });

      const result = gcmdp.evaluate(action, state, constraints);
      p4Stats.agentIdentities++;

      res.json({
        id: 'gcmdp_' + crypto.randomBytes(6).toString('hex'),
        action,
        evaluation: result,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * POST /v1/agent/maqasid
   * Evaluate content against Maqasid al-Shariah framework
   */
  router.post('/agent/maqasid', async (req, res) => {
    try {
      const { content, language } = req.body;
      if (!content) return res.status(400).json({ error: 'content required' });

      const framework = evaluateMaqasid(content, language);
      p4Stats.agentIdentities++;

      res.json({
        id: 'maqasid_' + crypto.randomBytes(6).toString('hex'),
        evaluation: framework,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // ADVANCED SECURITY — Consent, Cross-Modal, Dynamic Thresholds, Shamir
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * POST /v1/security/consent/check
   * Verify consent for data access
   */
  router.post('/security/consent/check', async (req, res) => {
    try {
      const { dataSubject, purpose, dataTypes } = req.body;
      if (!dataSubject || !purpose) return res.status(400).json({ error: 'dataSubject and purpose required' });

      const consentStatus = consentManager.check(dataSubject, purpose, dataTypes?.[0] || 'default');
      p4Stats.consentChecks++;

      res.json({
        id: 'consent_' + crypto.randomBytes(6).toString('hex'),
        dataSubject,
        purpose,
        consentStatus,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * POST /v1/security/consent/grant
   * Grant consent for specific data usage
   */
  router.post('/security/consent/grant', async (req, res) => {
    try {
      const { dataSubject, purpose, dataTypes, scope } = req.body;
      if (!dataSubject || !purpose) return res.status(400).json({ error: 'dataSubject and purpose required' });

      const grant = consentManager.grant(dataSubject, purpose, { dataTypes, ...scope });
      p4Stats.consentChecks++;

      res.json({
        id: 'grant_' + crypto.randomBytes(6).toString('hex'),
        consent: grant,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * POST /v1/security/cross-modal/verify
   * Verify consistency across modalities (text, image, audio)
   */
  router.post('/security/cross-modal/verify', async (req, res) => {
    try {
      const { text, image, audio } = req.body;
      if (!text && !image && !audio) return res.status(400).json({ error: 'at least one modality required' });

      const result = crossModalChecker.check({ text, image, audio });
      p4Stats.crossModalAnalyses++;

      res.json({
        id: 'crossmodal_' + crypto.randomBytes(6).toString('hex'),
        consistency: result.consistency,
        flags: result.flags || [],
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * POST /v1/security/threshold/adjust
   * Dynamically adjust detection threshold based on EWMA
   */
  router.post('/security/threshold/adjust', async (req, res) => {
    try {
      const { score } = req.body;
      if (score === undefined) return res.status(400).json({ error: 'score required' });

      const isFP = score > 0.7; // high score = likely false positive
      dynamicThreshold.record(isFP ? 'fp' : 'fn', isFP, {});
      const current = dynamicThreshold.getThreshold();

      res.json({
        id: 'threshold_' + crypto.randomBytes(6).toString('hex'),
        currentThreshold: current.threshold ?? current.baseFP ?? 0.5,
        threatLevel: current.threatLevel,
        ewma: dynamicThreshold.ewma,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * POST /v1/security/shamir/split
   * Split a secret using Shamir's Secret Sharing
   */
  router.post('/security/shamir/split', async (req, res) => {
    try {
      const { secret } = req.body;
      if (!secret) return res.status(400).json({ error: 'secret required' });

      const K = 3, N = 5; // threshold K of N
      // Shamir requires hex string — convert string secret to hex if needed
      const secretHex = /^[0-9a-fA-F]+$/.test(secret) ? secret : Buffer.from(String(secret)).toString('hex');
      const result = ShamirSecretSharing.generate(secretHex, K, N);

      res.json({
        id: 'shamir_' + crypto.randomBytes(6).toString('hex'),
        shares: result.shares,
        threshold: result.threshold,
        totalShares: N,
        algorithm: result.algorithm,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * POST /v1/security/shamir/combine
   * Combine shares to reconstruct secret
   */
  router.post('/security/shamir/combine', async (req, res) => {
    try {
      const { shares } = req.body;
      if (!shares || !Array.isArray(shares)) return res.status(400).json({ error: 'shares array required' });

      const hexSecret = ShamirSecretSharing.combine(shares);
      // Convert recovered hex back to original string
      let secret;
      try {
        secret = Buffer.from(hexSecret.replace(/^-/, ''), 'hex').toString('utf8');
        if (!secret || /[\x00-\x08\x0e-\x1f]/.test(secret)) secret = hexSecret; // keep hex if not printable
      } catch { secret = hexSecret; }

      res.json({
        id: 'shamir_combine_' + crypto.randomBytes(6).toString('hex'),
        recovered: true,
        secret,
        hexSecret,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // BIOMETRIC DETECTION — Neural Fingerprint, RPPG, Voice, Codec
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * POST /v1/biometric/neural-fingerprint
   * Analyze image for neural architecture fingerprints
   */
  router.post('/biometric/neural-fingerprint', async (req, res) => {
    try {
      const { pixels, width, height } = req.body;
      if (!pixels || !width || !height) return res.status(400).json({ error: 'pixels, width, height required' });

      const result = neuralFingerprint.analyze(pixels, width, height);
      p4Stats.biometricScans++;

      res.json({
        id: 'neural_fp_' + crypto.randomBytes(6).toString('hex'),
        result,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * POST /v1/biometric/rppg
   * Remote photoplethysmography for deepfake detection
   */
  router.post('/biometric/rppg', async (req, res) => {
    try {
      const { videoFrames, frameRate } = req.body;
      if (!videoFrames) return res.status(400).json({ error: 'videoFrames required' });

      const result = rppg.detect(videoFrames, frameRate);
      p4Stats.biometricScans++;

      res.json({
        id: 'rppg_' + crypto.randomBytes(6).toString('hex'),
        result,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * POST /v1/biometric/voice-clone
   * Detect voice cloning artifacts
   */
  router.post('/biometric/voice-clone', async (req, res) => {
    try {
      const { audioData, sampleRate, referenceVoice } = req.body;
      if (!audioData) return res.status(400).json({ error: 'audioData required' });

      const result = voiceClone.analyze(audioData, { sampleRate, referenceVoice });
      p4Stats.biometricScans++;

      res.json({
        id: 'voice_clone_' + crypto.randomBytes(6).toString('hex'),
        result,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * POST /v1/biometric/neural-codec
   * Detect neural codec model artifacts
   */
  router.post('/biometric/neural-codec', async (req, res) => {
    try {
      const { audioData } = req.body;
      if (!audioData) return res.status(400).json({ error: 'audioData required' });

      const result = neuralCodec.detect(audioData);
      p4Stats.biometricScans++;

      res.json({
        id: 'neural_codec_' + crypto.randomBytes(6).toString('hex'),
        result,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // KERNEL eBPF GATING
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * POST /v1/kernel/gate
   * Check if operation should be gated by kernel policy
   */
  router.post('/kernel/gate', async (req, res) => {
    try {
      const { operation, context = {} } = req.body;
      if (!operation) return res.status(400).json({ error: 'operation required' });

      // kernelGating class unavailable — use eBPF module singleton or policy fallback
      const kernelModule = _safeRequire('../../kernel-ebpf/index.js', 'kernel-ebpf-singleton');
      const isAvailable = kernelModule?.available === true;
      if (!isAvailable) {
        return res.json({
          id: 'kernel_gate_' + crypto.randomBytes(6).toString('hex'),
          operation, allowed: true, reason: 'kernel-ebpf unavailable on this platform (Linux 5.7+ required)', mode: 'policy-only',
          timestamp: new Date().toISOString()
        });
      }
      const result = { allowed: !kernelModule.blockedSyscalls?.includes(operation), reason: 'kernel policy' };
      p4Stats.kernelGatingChecks++;

      res.json({
        id: 'kernel_gate_' + crypto.randomBytes(6).toString('hex'),
        operation,
        allowed: result.allowed,
        reason: result.reason,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * POST /v1/kernel/policy
   * Update kernel gating policy
   */
  router.post('/kernel/policy', async (req, res) => {
    try {
      const { policy } = req.body;
      if (!policy) return res.status(400).json({ error: 'policy required' });

      kernelGating.updatePolicy(policy);

      res.json({
        id: 'kernel_policy_' + crypto.randomBytes(6).toString('hex'),
        updated: true,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // ZK PROOFS
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * POST /v1/zk/proof/generate
   * Generate a zero-knowledge detection proof
   */
  router.post('/zk/proof/generate', async (req, res) => {
    try {
      const { privateInputs, publicInputs } = req.body;
      if (!publicInputs) return res.status(400).json({ error: 'publicInputs required' });

      const proof = zkProofs.generateDetectionProof({ privateInputs, publicInputs });
      p4Stats.zkProofsGenerated++;

      res.json({
        id: 'zk_proof_' + crypto.randomBytes(6).toString('hex'),
        proof,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * POST /v1/zk/proof/verify
   * Verify a zero-knowledge proof
   */
  router.post('/zk/proof/verify', async (req, res) => {
    try {
      const { proof, publicInputs } = req.body;
      if (!proof || !publicInputs) return res.status(400).json({ error: 'proof and publicInputs required' });

      const result = zkProofs.verifyProof(proof, publicInputs);

      res.json({
        id: 'zk_verify_' + crypto.randomBytes(6).toString('hex'),
        verified: result.isValid,
        error: result.error,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * POST /v1/zk/commitment
   * Create a Pedersen commitment
   */
  router.post('/zk/commitment', async (req, res) => {
    try {
      const { value } = req.body;
      if (value === undefined) return res.status(400).json({ error: 'value required' });

      // Fallback commitment using HMAC-SHA256 when full ZK system is unavailable
      // Returns { commitment, blinding } to match Pedersen commitment interface
      // Accept any value type: numeric → BigInt directly; string/other → hash first
      let numValue;
      const raw = value;
      if (typeof raw === 'bigint') numValue = raw;
      else if (typeof raw === 'number') numValue = BigInt(Math.trunc(raw));
      else if (typeof raw === 'string' && /^-?\d+$/.test(raw)) numValue = BigInt(raw);
      else {
        // Non-numeric input — hash to a deterministic 256-bit integer
        const digest = require('crypto').createHash('sha256').update(String(raw)).digest('hex');
        numValue = BigInt('0x' + digest);
      }
      const blinding = require('crypto').randomBytes(32).toString('hex');
      const commitmentHash = require('crypto').createHash('sha256')
        .update(numValue.toString() + blinding).digest('hex');
      const commitment = zkProofs?.commit
        ? zkProofs.commit(numValue)
        : { commitment: commitmentHash, blinding, value: numValue.toString(), algorithm: 'sha256-pedersen-sim' };

      res.json({
        id: 'zk_commit_' + crypto.randomBytes(6).toString('hex'),
        commitment,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * POST /v1/zk/range-proof
   * Generate range proof
   */
  router.post('/zk/range-proof', async (req, res) => {
    try {
      const { value, bitSize } = req.body;
      if (value === undefined) return res.status(400).json({ error: 'value required' });

      const proof = zkProofs.generateRangeProof(value, bitSize);

      res.json({
        id: 'zk_range_' + crypto.randomBytes(6).toString('hex'),
        proof,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // STEGANALYSIS + WATERMARK
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * POST /v1/steganalysis/check
   * Check for steganographic content
   */
  router.post('/steganalysis/check', async (req, res) => {
    try {
      const { pixels, width, height, text, content } = req.body;
      const input = text || content || JSON.stringify(pixels || {});
      if (!input) return res.status(400).json({ error: 'pixels, text, or content required' });

      const result = steganalysisCheck(input);
      p4Stats.steganalysisScans++;

      res.json({
        id: 'steg_' + crypto.randomBytes(6).toString('hex'),
        result,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * POST /v1/watermark/check
   * Check for synthetic watermarks
   */
  router.post('/watermark/check', async (req, res) => {
    try {
      const { pixels, width, height } = req.body;
      if (!pixels || !width || !height) return res.status(400).json({ error: 'pixels, width, height required' });

      const result = watermarkCheck(pixels, width, height);

      res.json({
        id: 'watermark_' + crypto.randomBytes(6).toString('hex'),
        result,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // PHASE 4 STATS
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * GET /v1/phase4/stats
   */
  router.get('/phase4/stats', (req, res) => {
    res.json({
      phase4Stats: p4Stats,
      timestamp: new Date().toISOString()
    });
  });

  // Mount router under /v1
  app.use('/v1', router);

  console.log('[phase45] Cross-cutting integrations wired: nomos, agent-governance, advanced-security, biometric, kernel-ebpf, zk, steganalysis');

  return p4Stats;
}

module.exports = { registerRoutes };
