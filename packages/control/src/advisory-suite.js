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
 *   bounded-advisory-semantics, openclaw.
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

function createAdvisorySuiteRouter() {
  const router = express.Router();

  // Singleton stateful monitors (reset via ?reset=1 where relevant).
  const intent = new KasbahIntentAnalyzer();
  const martingale = new ConformalMartingaleMonitor();
  const flagFuser = new FlagCorrelationFuser();

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
    },
    openclawAvailable: !!KasbahOpenClaw,
  }));

  return router;
}

module.exports = { createAdvisorySuiteRouter, KasbahOpenClaw };
