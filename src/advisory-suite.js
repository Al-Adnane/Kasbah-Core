'use strict';

/**
 * advisory-suite.js — wires every previously-orphaned advisory "island" module
 * into one reachable Express router (/v1/advisory/*), so nothing in src/ is a
 * dead island. These are the richer standalone implementations of the synthesis
 * ideas; the governance proxy uses the integrated copies, while this suite
 * exposes the full standalone capability surface for direct use and testing.
 *
 * Every endpoint is advisory only (never DENY). Modules wired:
 *   detectgpt, kasbah-intent-analyzer, chsh-coordination, conformal-martingale,
 *   do-bft-consensus, flag-correlation-weighting, orthogonal-manifold-evasion-bound,
 *   bounded-advisory-semantics, openclaw,
 *   + 7 NEW: latent-manifold-intrusion, counterfactual-entrapment-detector,
 *     revealed-preference-monitor, kleene-fixed-point-detector,
 *     semantic-tool-drift-detector, hypergraph-collusion-detector,
 *     timing-channel-detector
 */

const express = require('express');

const { detectAIText } = require('./detectgpt.js');
const { KasbahIntentAnalyzer } = require('./kasbah-intent-analyzer.js');
const { CHSHCoordinationDetector } = require('./chsh-coordination.js');
const { ConformalMartingaleMonitor } = require('./conformal-martingale.js');
const { DOBFTConsensus } = require('./do-bft-consensus.js');
const { FlagCorrelationFuser } = require('./flag-correlation-weighting.js');
const evasion = require('./orthogonal-manifold-evasion-bound.js');
const bounded = require('./bounded-advisory-semantics.js');
let KasbahOpenClaw = null;
try { ({ KasbahOpenClaw } = require('./openclaw.js')); } catch (_) {}

// ─── 7 NEW MODULES (Ideas #16-#22) ──────────────────────────────────────────
const { LatentManifoldMonitor, generateSyntheticEmbedding } = require('./latent-manifold-intrusion.js');
const { CounterfactualEntrapmentDetector } = require('./counterfactual-entrapment-detector.js');
const { RevealedPreferenceMonitor } = require('./revealed-preference-monitor.js');
const { KleeneFixedPointDetector } = require('./kleene-fixed-point-detector.js');
const { SemanticToolDriftDetector } = require('./semantic-tool-drift-detector.js');
const { HypergraphCollusionDetector } = require('./hypergraph-collusion-detector.js');
const { TimingChannelDetector } = require('./timing-channel-detector.js');
// ─── 3 NEW MODULES (Ideas #23-#25) ──────────────────────────────────────────
const { CrossModalCoherenceAuditor } = require('./cross-modal-coherence-auditor.js');
const { AuthorizationTrajectoryProjector } = require('./authorization-trajectory-projector.js');
const { ObservableCommitmentProtocol } = require('./observable-commitment-protocol.js');

function createAdvisorySuiteRouter() {
  const router = express.Router();

  // Singleton stateful monitors (reset via ?reset=1 where relevant).
  const intent = new KasbahIntentAnalyzer();
  const martingale = new ConformalMartingaleMonitor();
  const flagFuser = new FlagCorrelationFuser();

  // 7 NEW MODULE SINGLETONS (#16-#22)
  const lmid           = new LatentManifoldMonitor({ geodesicThreshold: 0.15, embeddingDim: 768, safetySubspaceDim: 50 });
  const cwed           = new CounterfactualEntrapmentDetector({ jsThreshold: 0.25, minInterventions: 3, confidenceLevel: 0.95 });
  const rpim           = new RevealedPreferenceMonitor({ tauThreshold: 0.35, minObservations: 5, decayFactor: 0.9 });
  const kfpr           = new KleeneFixedPointDetector({ contractionThreshold: 0.8, orbitPeriod: 5, stabilityWindow: 20 });
  const stdd           = new SemanticToolDriftDetector({ driftCosineThreshold: 0.3, lieDerivativeWindow: 10, dangerOverlap: 0.7 });
  const hcd            = new HypergraphCollusionDetector({ spectralGapThreshold: 0.5, minHyperedgeSize: 2, subspaceIterations: 10 });
  const itcd           = new TimingChannelDetector({ embeddingDim: 4, tau: 1, significanceAlpha: 0.01, minMutualInfo: 0.2 });
  // 3 NEW MODULE SINGLETONS (#23-#25)
  const cmca           = new CrossModalCoherenceAuditor({ calibrationSize: 50, minSamples: 20, coherenceWarn: 0.7, coherenceReview: 0.4 });
  const atp            = new AuthorizationTrajectoryProjector({ windowSize: 20, projectionHorizon: 5, lyapunovThreshold: 0.01, warnThreshold: 0.35, reviewThreshold: 0.60, embeddingDimension: 3, tau: 1 });
  const ocp            = new ObservableCommitmentProtocol({ commitHash: 'sha256', deviationTolerance: 0.15, maxCommitmentAge: 300000, signingKey: null });

  const ok = (res, body) => res.json({ advisory: true, ...body });
  const err = (res, e) => res.status(400).json({ error: e.message });

  // ── detectgpt (AI-text heuristic) ──────────────────────────────────────────
  router.post('/detectgpt', (req, res) => {
    try { ok(res, { detectgpt: detectAIText(String(req.body?.text || '')) }); } catch (e) { err(res, e); }
  });

  // ── kasbah-intent-analyzer (multi-step trajectory) ─────────────────────────
  router.post('/intent', (req, res) => {
    try { ok(res, { intent: intent.analyze(req.body?.steps || []) }); } catch (e) { err(res, e); }
  });

  // ── chsh-coordination (order-effect / non-commutativity) ───────────────────
  router.post('/chsh', (req, res) => {
    try {
      const d = new CHSHCoordinationDetector();
      if (Array.isArray(req.body?.observations)) d.observeBatch(req.body.observations);
      ok(res, { chsh: { S: d.computeCHSH(), asymmetry: d.computeAsymmetry() } });
    } catch (e) { err(res, e); }
  });

  // ── conformal-martingale (anytime-valid sequential) ────────────────────────
  router.post('/conformal', (req, res) => {
    try {
      if (req.query.reset) { martingale.calibration = []; }
      const score = Number(req.body?.score);
      if (!isFinite(score)) throw new Error('numeric "score" required');
      ok(res, { conformal: martingale.process(score) });
    } catch (e) { err(res, e); }
  });

  // ── do-bft-consensus (perturbed-observer collusion) ────────────────────────
  router.post('/dobft', (req, res) => {
    try {
      const c = new DOBFTConsensus();
      const observers = req.body?.observers || ['o1', 'o2', 'o3', 'o4', 'o5'];
      for (const o of observers) c.registerObserver(o);
      const truth = req.body?.truth != null ? req.body.truth : 0.5;
      const obs = c.collectPerturbedObservations(truth);
      ok(res, { dobft: c.detectCollusion(obs) });
    } catch (e) { err(res, e); }
  });

  // ── flag-correlation-weighting (evidential fusion) ─────────────────────────
  router.post('/flag-fusion', (req, res) => {
    try {
      const flags = req.body?.flags;
      if (!Array.isArray(flags)) throw new Error('"flags" array required');
      if (!flagFuser._init) { flagFuser.initializeDetectors(flags.map((_, i) => 'd' + i)); flagFuser._init = true; }
      flagFuser.observe(flags);
      ok(res, { flagFusion: flagFuser.computeEvidentialWeight(flags) });
    } catch (e) { err(res, e); }
  });

  // ── orthogonal-manifold evasion bound ──────────────────────────────────────
  router.post('/evasion-bound', (req, res) => {
    try {
      const results = req.body?.detectorResults || [];
      ok(res, { evasionBound: evasion.computeOrthogonalEvasionBound(results) });
    } catch (e) { err(res, e); }
  });
  router.get('/evasion-bound/proof', (req, res) => {
    try { ok(res, { proof: evasion.proveEvasionBound(Number(req.query.k) || 8, Number(req.query.eta) || 0.9) }); }
    catch (e) { err(res, e); }
  });

  // ── bounded-advisory-semantics (operator + invariant proof) ────────────────
  router.post('/bounded', (req, res) => {
    try { ok(res, { bounded: bounded.advisoryOperator(Number(req.body?.score) || 0) }); } catch (e) { err(res, e); }
  });
  router.get('/bounded/spec', (req, res) => {
    try { ok(res, { spec: bounded.formalSpecification(), invariant: bounded.verifyAdvisoryInvariant(bounded.advisoryOperator) }); }
    catch (e) { err(res, e); }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 7 NEW MODULE ENDPOINTS (#16-#22) — advisory only, never DENY
  // ═══════════════════════════════════════════════════════════════════════════

  // ── latent-manifold-intrusion: geodesic deviation on embedding manifold ──
  router.post('/latent-manifold', (req, res) => {
    try {
      const text = String(req.body?.text || '');
      const emb = generateSyntheticEmbedding(text, 768);
      ok(res, { latentManifold: lmid.observe(emb, { turnId: 0, text, risk: Number(req.body?.risk) || 0 }) });
    } catch (e) { err(res, e); }
  });

  // ── counterfactual-entrapment: causal DAG + JS divergence ─────────────────
  router.post('/counterfactual', (req, res) => {
    try {
      const text = String(req.body?.text || '');
      ok(res, { counterfactual: cwed.observe(text, {
        turnId: 0, toolVerbs: Array.isArray(req.body?.tools) ? req.body.tools : [],
        riskScore: Number(req.body?.risk) || 0,
      })});
    } catch (e) { err(res, e); }
  });

  // ── revealed-preference: WARP + Kendall tau ───────────────────────────────
  router.post('/revealed-preference', (req, res) => {
    try {
      const chosen = String(req.body?.chosen || 'message');
      const available = Array.isArray(req.body?.available) ? req.body.available : ['message', 'tool', 'search'];
      const stated = Array.isArray(req.body?.stated) ? req.body.stated : [];
      ok(res, { revealedPreference: rpim.recordChoice(chosen, available, stated, {}) });
    } catch (e) { err(res, e); }
  });

  // ── kleene-fixed-point: contraction-rate self-loop detection ──────────────
  router.post('/kleene-fixed-point', (req, res) => {
    try {
      const state = {
        risk: Number(req.body?.risk) || 0,
        composite: Number(req.body?.composite) || 0,
        eigenDrift: Number(req.body?.eigenDrift) || 0,
        topoAnomaly: Number(req.body?.topoAnomaly) || 0,
        harmDissonance: Number(req.body?.harmDissonance) || 0,
      };
      ok(res, { kleeneFixedPoint: kfpr.feed(state, String(req.body?.text || ''), {
        turnId: 0, tools: 0,
      })});
    } catch (e) { err(res, e); }
  });

  // ── semantic-tool-drift: Lie derivative on tool manifold ──────────────────
  router.post('/semantic-tool-drift', (req, res) => {
    try {
      const toolName = String(req.body?.tool || 'unknown');
      stdd.registerTool(toolName, 768);
      const emb = new Array(768).fill(0);
      emb[0] = Number(req.body?.risk || 0) / 100;
      stdd.observe(toolName, emb, { turnId: 0, risk: Number(req.body?.risk) || 0 });
      ok(res, { semanticToolDrift: stdd.getDriftState() });
    } catch (e) { err(res, e); }
  });

  // ── hypergraph-collusion: hypergraph Laplacian spectral gap ───────────────
  router.post('/hypergraph-collusion', (req, res) => {
    try {
      const events = Array.isArray(req.body?.events)
        ? req.body.events
        : [{ agent: 'agent_a', action: 'coordinate', target: 'agent_b' }];
      hcd.reset();
      for (const e of events) {
        hcd.recordEvent(e.agent || 'agent_a', e.action || 'coordinate', e.target || 'agent_b');
      }
      ok(res, { hypergraphCollusion: hcd.analyze() });
    } catch (e) { err(res, e); }
  });

  // ── timing-channel: permutation entropy + mutual information ──────────────
  router.post('/timing-channel', (req, res) => {
    try {
      const timestamps = Array.isArray(req.body?.timestamps)
        ? req.body.timestamps.map(Number).filter(isFinite)
        : [Date.now(), Date.now() + 1, Date.now() + 2, Date.now() + 5, Date.now() + 6];
      itcd.reset();
      for (const ts of timestamps) itcd.recordResponse('agent', ts);
      ok(res, { timingChannel: itcd.analyze() });
    } catch (e) { err(res, e); }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 3 NEW MODULE ENDPOINTS (#23-#25) — advisory only, never DENY
  // ═══════════════════════════════════════════════════════════════════════════

  // ── cross-modal-coherence: cosine similarity between text/tool/reasoning ──
  router.post('/cross-modal-coherence', (req, res) => {
    try {
      const textEmbed = req.body?.textEmbed || new Array(768).fill(0);
      const toolEmbed = req.body?.toolEmbed || new Array(768).fill(0);
      const reasoningEmbed = req.body?.reasoningEmbed || new Array(768).fill(0);
      ok(res, { crossModalCoherence: cmca.audit(textEmbed, toolEmbed, reasoningEmbed, {
        turnId: Number(req.body?.turnId) || 0,
        risk: Number(req.body?.risk) || 0,
      })});
    } catch (e) { err(res, e); }
  });

  // ── authorization-trajectory: AR model projection + Lyapunov exponent ────
  router.post('/auth-trajectory', (req, res) => {
    try {
      const score = Number(req.body?.score) || 0;
      ok(res, { authTrajectory: atp.project(score, {
        turnId: Number(req.body?.turnId) || 0,
        risk: Number(req.body?.risk) || 0,
        reviewThreshold: Number(req.body?.reviewThreshold) || 0.70,
        warnThreshold: Number(req.body?.warnThreshold) || 0.30,
      })});
    } catch (e) { err(res, e); }
  });

  // ── observable-commitment: SHA-256 hash-then-execute with verification ────
  router.post('/observable-commitment', (req, res) => {
    try {
      const turnId = String(req.body?.turnId || 'default_turn');
      const planSketch = Array.isArray(req.body?.planSketch) ? req.body.planSketch : [];
      const executedActions = Array.isArray(req.body?.executedActions) ? req.body.executedActions : [];
      const commit = ocp.commit(turnId, planSketch, {});
      const verify = ocp.verify(turnId, executedActions, {});
      ok(res, { observableCommitment: { commit, verify } });
    } catch (e) { err(res, e); }
  });

  // ── capability listing ─────────────────────────────────────────────────────
  router.get('/capabilities', (req, res) => res.json({
    advisory: true,
    note: 'Bounded advisory only — none of these endpoints DENY traffic.',
    endpoints: {
      'POST /v1/advisory/detectgpt': 'AI-text heuristic',
      'POST /v1/advisory/intent': 'multi-step attack trajectory',
      'POST /v1/advisory/chsh': 'coordination order-effect (unvalidated)',
      'POST /v1/advisory/conformal': 'anytime-valid conformal martingale',
      'POST /v1/advisory/dobft': 'perturbed-observer collusion',
      'POST /v1/advisory/flag-fusion': 'correlation-aware evidential weight',
      'POST /v1/advisory/evasion-bound': 'orthogonal-manifold evasion cost',
      'GET  /v1/advisory/evasion-bound/proof': 'symbolic evasion bound',
      'POST /v1/advisory/bounded': 'bounded advisory operator',
      'GET  /v1/advisory/bounded/spec': 'formal advisory spec + invariant check',
      // 7 NEW MODULE ENDPOINTS (#16-#22)
      'POST /v1/advisory/latent-manifold': 'geodesic intrusion on Riemannian manifold',
      'POST /v1/advisory/counterfactual': 'causal DAG + JS divergence entrapment',
      'POST /v1/advisory/revealed-preference': 'WARP + Kendall tau preference gap',
      'POST /v1/advisory/kleene-fixed-point': 'contraction-rate self-loop detection',
      'POST /v1/advisory/semantic-tool-drift': 'Lie derivative on tool manifold',
      'POST /v1/advisory/hypergraph-collusion': 'hypergraph Laplacian spectral gap',
      'POST /v1/advisory/timing-channel': 'permutation entropy channel detection',
      // 3 NEW MODULE ENDPOINTS (#23-#25)
      'POST /v1/advisory/cross-modal-coherence': 'cosine similarity deception detection',
      'POST /v1/advisory/auth-trajectory': 'AR model + Lyapunov boundary projection',
      'POST /v1/advisory/observable-commitment': 'SHA-256 hash-then-execute verification',
    },
    openclawAvailable: !!KasbahOpenClaw,
    totalAdvisoryEndpoints: 20,
  }));

  return router;
}

module.exports = { createAdvisorySuiteRouter, KasbahOpenClaw };
