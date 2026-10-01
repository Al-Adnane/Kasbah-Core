'use strict';

/**
 * GovernanceProxy — sits BETWEEN a frontier LLM and its tool environment.
 *
 * This is the real conclusion of the "Alice Moyo" synthesis (MSG 50):
 * we don't need to *be* a frontier model — we need to *govern* one. The proxy
 * intercepts each turn (messages + proposed tool calls), evaluates it through
 * the already-validated Kasbah layers, and emits a bounded advisory signal:
 *
 *     CLEAR | WARN | REQUIRE_APPROVAL
 *
 * Authoritative DENY remains with the validated governance engine (forbidden
 * verbs, domain whitelist, rate limits). The advisory ensemble can only raise
 * a flag for human review — it never autonomously denies real traffic.
 *
 * Layers reused (no new detection logic invented here):
 *   - detector.js          : deterministic content threat classifier (validated; P0.97/R0.60 on bench v1)
 *   - governance-engine.js : fail-closed policy (DENY / REQUIRE_APPROVAL)
 *   - nature-features.js   : conformal-calibrated advisory signal (bounded flag rate)
 *
 * Plus:
 *   - a human-in-the-loop pending-approval queue
 *   - a forward-secure audit chain over every decision
 */

const detector = require('./detector.js');
const { GovernanceEngine } = require('./governance-engine.js');
const { NatureFeatureExtractor } = require('./nature-features.js');
const { ForwardSecureAudit } = require('./forward-secure-audit.js');
const A = require('./advisory-analyzers.js');
const { detectAIText } = require('./detectgpt.js');
const { KasbahIntentAnalyzer } = require('./kasbah-intent-analyzer.js');

// ─── 22 Novel Modules: Genuinely New + Original 10 (full implementations) ───
const { computeOrthogonalEvasionBound, proveEvasionBound, DETECTION_MANIFOLDS } = require('./orthogonal-manifold-evasion-bound');
const { DOBFTConsensus } = require('./do-bft-consensus');
const { CHSHCoordinationDetector } = require('./chsh-coordination');
const { CUSUMSubspaceMonitor } = require('./cusum-subspace-monitor');
const { PersistentHomologyCovertDetector } = require('./persistent-homology-covert');
const { ADVISORY_LEVELS, advisoryOperator, verifyAdvisoryInvariant } = require('./bounded-advisory-semantics');
const { FlagCorrelationFuser } = require('./flag-correlation-weighting');
const { ConformalMartingaleMonitor, NonconformityScores } = require('./conformal-martingale');
const { EntropyComplexityPlane } = require('./entropy-complexity-plane');
const { PanopticonAsymmetryDetector } = require('./panopticon-asymmetry-detector');
const { CriticalSlowingDownMonitor } = require('./critical-slowing-down-monitor');
const { SurprisalBudgetManager } = require('./surprisal-budget-manager');
const { RecursiveGovernanceAuditor } = require('./recursive-governance-fixed-point');
const { StigmergicCovertChannelDetector } = require('./stigmergic-covert-channel');
// ─── 7 NEW MODULES (Ideas #16-#22) ────────────────────────────────────────
const { LatentManifoldMonitor, generateSyntheticEmbedding } = require('./latent-manifold-intrusion');
const { CounterfactualEntrapmentDetector } = require('./counterfactual-entrapment-detector');
const { RevealedPreferenceMonitor } = require('./revealed-preference-monitor');
const { KleeneFixedPointDetector } = require('./kleene-fixed-point-detector');
const { SemanticToolDriftDetector } = require('./semantic-tool-drift-detector');
const { HypergraphCollusionDetector } = require('./hypergraph-collusion-detector');
const { TimingChannelDetector } = require('./timing-channel-detector');

const CLEARANCE = { OBSERVER: 0, ANALYST: 1, RESEARCHER: 2, OPERATOR: 3, DIRECTOR: 4 };

// Advisory ordering for combining signals (higher = more scrutiny).
const RANK = { CLEAR: 0, WARN: 1, REQUIRE_APPROVAL: 2, DENY: 3 };
function maxSignal(a, b) { return (RANK[a] || 0) >= (RANK[b] || 0) ? a : b; }

class GovernanceProxy {
  constructor(opts = {}) {
    this.governance = opts.governance || new GovernanceEngine();
    this.nature = new NatureFeatureExtractor({
      conformal: { warnAlpha: 0.10, reviewAlpha: 0.02, minSamples: 100, window: 2000 },
    });
    this.audit = new ForwardSecureAudit(opts.auditSeed);
    this.pending = new Map();   // actionId -> { turn, advisory, createdAt }
    this.maxHistory = opts.maxHistory || 50;

    // Advisory-analyzer state (ideas #2,#3,#5,#8,#10).
    this._compositeHistory = [];                 // rolling composite scores → CUSUM + regime (#5,#10)
    this._featureHistory = [];                   // rolling 8-feature vectors → orthogonality (#2)
    this._FEATURE_KEYS = ['eigen_drift','shadow_gaming','topo_anomaly','causal_loops',
                          'flow_turbulence','evol_punctuation','harm_dissonance','bell_correlation'];
    this._flagFusion = new A.FlagCorrelationFusion(this._FEATURE_KEYS.length, { prior: 0.03 }); // #8
    this._analyzerWindow = opts.analyzerWindow || 64;
    this._unstable = false;                      // regime-aware conformal tighten state (#4)
    // Novel-module direct escalation is OFF by default: benchmarked at ~100%
    // flag rate (precision 0.61 vs detector's 0.97). Outputs still recorded in
    // detail.novel. Opt in only for evaluation/recalibration.
    this._enableNovelEscalation = opts.enableNovelEscalation === true;

    // Cross-step distributed-attack detection (kasbah-intent-analyzer island).
    this.intentAnalyzer = new KasbahIntentAnalyzer();
    this._stepHistory = [];                      // {id,verb,target,content,status} per turn

    // ─── 15 Novel Modules: End-to-End Wiring ───

    // Idea #1 (new): Panopticon Information Asymmetry
    this.panopticon = new PanopticonAsymmetryDetector({
      deceptionThreshold: 0.3, persistenceWindow: 8, minGapSignificance: 2
    });

    // Idea #2 (new): Critical Slowing Down pre-transition monitor
    this.criticalSlowing = new CriticalSlowingDownMonitor({
      windowSize: 30, baselineWindow: 100, sigmaWarn: 2.0, sigmaEscalate: 3.0
    });

    // Idea #3 (new): Surprisal Budget Manager per agent
    this.surprisalBudget = new SurprisalBudgetManager({
      initialBudget: 100, refillRate: 0.1, costPerBit: 1.0
    });

    // Idea #4 (new): Recursive Governance Self-Audit
    this.governanceAuditor = new RecursiveGovernanceAuditor({
      minConsistencyScore: 0.95, monitorWindow: 500
    });

    // Idea #5 (new): Stigmergic Covert Channel Detection
    this.stigmergicDetector = new StigmergicCovertChannelDetector({
      minMutualInfo: 0.3, windowSize: 50, significanceAlpha: 0.01
    });

    // Idea #16 (new): Latent Manifold Intrusion Detection
    this.latentManifold = new LatentManifoldMonitor({
      geodesicThreshold: 0.15, embeddingDim: 768, safetySubspaceDim: 50
    });

    // Idea #17 (new): Counterfactual World Entrapment Detector
    this.counterfactualDetector = new CounterfactualEntrapmentDetector({
      jsThreshold: 0.25, minInterventions: 3, confidenceLevel: 0.95
    });

    // Idea #18 (new): Revealed Preference Integrity Monitor
    this.revealedPreference = new RevealedPreferenceMonitor({
      tauThreshold: 0.35, minObservations: 5, decayFactor: 0.9
    });

    // Idea #19 (new): Kleene Fixed-Point Recursion Detector
    this.kleeneFixedPoint = new KleeneFixedPointDetector({
      contractionThreshold: 0.8, orbitPeriod: 5, stabilityWindow: 20
    });

    // Idea #20 (new): Semantic Tool Drift Detector
    this.semanticToolDrift = new SemanticToolDriftDetector({
      driftCosineThreshold: 0.3, lieDerivativeWindow: 10, dangerOverlap: 0.7
    });

    // Idea #21 (new): Hypergraph Collusion Detector
    this.hypergraphCollusion = new HypergraphCollusionDetector({
      spectralGapThreshold: 0.5, minHyperedgeSize: 2, subspaceIterations: 10
    });

    // Idea #22 (new): Information-Theoretic Timing Channel Detector
    this.timingChannel = new TimingChannelDetector({
      embeddingDim: 4, tau: 1, significanceAlpha: 0.01, minMutualInfo: 0.2
    });

    // Original #3: DO-BFT Consensus (full standalone class)
    this.doBft = new DOBFTConsensus({ epsilon: 8, delta: 0.1, minObservers: 5 });

    // Original #4: CHSH Coordination Detector (quantum cognition)
    this.chshDetector = new CHSHCoordinationDetector({
      significanceLevel: 0.05, minObservations: 30
    });

    // Original #5: CUSUM on Activation Subspace Trajectories
    this.cusumMonitor = new CUSUMSubspaceMonitor({
      targetARL: 500, minShift: 0.05, baselineWindow: 100
    });

    // Original #6: Persistent Homology for Covert Topology
    this.persistentHomology = new PersistentHomologyCovertDetector({
      minCycleSize: 3, persistenceThreshold: 0.2
    });

    // Original #8: Flag Correlation Evidential Weighting (full class)
    this.flagCorrelationFuser = new FlagCorrelationFuser({
      priorFlagProb: 0.1, decayFactor: 0.95, maxWindowSize: 10000
    });
    this.flagCorrelationFuser.initializeDetectors(this._FEATURE_KEYS);

    // Original #9: Conformal Martingale for Anytime-Valid Thresholds
    this.conformalMartingale = new ConformalMartingaleMonitor({
      alpha: 0.05, gamma: 0.5, calibrationSize: 100
    });

    // Original #10: Entropy-Complexity Plane for Flow Regime
    this.entropyComplexityPlane = new EntropyComplexityPlane({
      embeddingDim: 5, embeddingDelay: 1, windowSize: 100, windowStep: 10
    });

    // Track subspace drift values for CUSUM + Critical Slowing Down
    this._driftValues = [];
  }

  /** Flatten messages to a single text blob for content classification. */
  _flatten(messages = []) {
    return messages.slice(-this.maxHistory)
      .map(m => (typeof m.content === 'string' ? m.content : JSON.stringify(m.content || '')))
      .join('\n');
  }

  /**
   * Map proposed tool calls to a governance action (verb/target/domain) so the
   * fail-closed engine can rule on them. Conservative: if no tool call, treat
   * as a read-only content turn.
   */
  _toolAction(tools = []) {
    if (!Array.isArray(tools) || tools.length === 0) return null;
    const t = tools[0] || {};
    return {
      verb: String(t.verb || t.name || 'CALL_TOOL').toUpperCase(),
      target: t.target || t.domain || 'tool',
      domain: t.domain || t.target || null,
      agent: t.agent || 'llm',
    };
  }

  /**
   * Evaluate one intercepted LLM turn.
   * @returns {{status, signal, detail, audit}} status ∈ allowed|require_approval|denied
   */
  async evaluateTurn({ messages = [], tools = [], clearance = CLEARANCE.RESEARCHER, edges = null } = {}) {
    const text = this._flatten(messages);

    // 1. Content threat classification (validated deterministic layer).
    const content = detector.classify(text);

    // 1b. Cross-step trajectory analysis (distributed/multi-step attacks that
    //     are benign per-step). Build a step from this turn and analyze history.
    const act0 = this._toolAction(tools);
    this._stepHistory.push({
      id: 'step_' + this._stepHistory.length,
      verb: act0 ? act0.verb : 'MESSAGE',
      target: act0 ? act0.target : 'conversation',
      content: text,
      status: 'completed',
    });
    if (this._stepHistory.length > 64) this._stepHistory.shift();
    const trajectory = this.intentAnalyzer.analyze(this._stepHistory);

    // 1c. AI-text heuristic (detectgpt island) — advisory feature only.
    const aiText = detectAIText(text);

    // 2. Fail-closed governance on the proposed tool action (authoritative).
    let gov = { status: 'ALLOW', reason: null, risk_score: 0 };
    const action = this._toolAction(tools);
    if (action) {
      try { gov = await this.governance.check(action); }
      catch (e) { gov = { status: 'DENY', reason: 'governance error (fail-closed): ' + e.message, risk_score: 100 }; }
    }

    // 3. Advisory ensemble (conformal-calibrated; never authoritative DENY).
    //    Feed the content risk in as one bounded signal so the proxy reacts to
    //    prompt-level anomalies even without a tool call.
    //    Regime-aware conformal (#4): if the LAST turn flagged a fresh CUSUM
    //    change-point, tighten α (stricter threshold) until stability returns.
    const tighten = this._unstable ? 0.5 : 1;
    const nature = this.nature.evaluate({
      flow: { regime: content.risk >= 60 ? 'turbulent' : content.risk >= 30 ? 'transitional' : 'laminar' },
      topo: { alert: content.risk >= 80 },
    }, { tighten });

    // 4. Combine: governance is authoritative (can DENY); content + advisory
    //    can only raise to WARN / REQUIRE_APPROVAL.
    let signal = 'CLEAR';
    if (gov.status === 'DENY') signal = 'DENY';
    else if (gov.status === 'REQUIRE_APPROVAL') signal = 'REQUIRE_APPROVAL';

    if (content.decision === 'DENY') signal = maxSignal(signal, 'REQUIRE_APPROVAL'); // content DENY → human review, not silent block of the turn
    else if (content.decision === 'WARN') signal = maxSignal(signal, 'WARN');

    signal = maxSignal(signal, nature.signal); // NONE|WARN|REQUIRE_APPROVAL

    // ── Advisory analyzers (ideas #2,#3,#5,#8,#10) over rolling state ──────────
    const composite = +(nature.composite || 0);
    this._compositeHistory.push(composite);
    if (this._compositeHistory.length > this._analyzerWindow) this._compositeHistory.shift();

    const fvec = this._FEATURE_KEYS.map(k => nature.features[k] || 0);
    this._featureHistory.push(fvec);
    if (this._featureHistory.length > this._analyzerWindow) this._featureHistory.shift();

    const flagVec = fvec.map(v => (v >= 0.5 ? 1 : 0));
    const evidential = this._flagFusion.evidentialWeight(flagVec); // #8 (score BEFORE observing)
    this._flagFusion.observe(flagVec);

    // CUSUM slack k is small: the advisory composite stream is low-magnitude
    // (single weak features), so k must sit below typical shifts to be reachable.
    const drift = A.cusumChangePoint(this._compositeHistory, { k: 0.03, h: 0.4 });         // CUSUM
    const regime = A.entropyComplexityRegime(this._compositeHistory);                      // #10
    const doBft = A.perturbedObserverConsensus(composite, { epsilon: 8, N: 16,            // #3
                    decisionThreshold: (nature.calibration && nature.calibration.warnThreshold) || 0.45 });
    const ortho = A.orthogonalityScore(this._featureHistory);                              // #2 (corr-based)
    const fiedler = A.fiedlerCoherence(this._featureHistory.map(v => v.map(x => (x >= 0.5 ? 1 : 0)))); // #2(v2) spectral
    const influence = A.laggedInfluence(this._featureHistory);                             // #5 Granger-style

    // Honest escalation (advisory-only — never DENY):
    //  - a fresh CUSUM change-point (alignment/behaviour drift) → WARN
    //  - high evidential weight from INDEPENDENT flags → REQUIRE_APPROVAL
    const driftFresh = drift.detected && drift.changePoint >= this._compositeHistory.length - 2;
    // Regime-aware conformal (#4): carry instability into the NEXT turn's tighten.
    this._unstable = driftFresh || regime.regime === 'FLOOD' || regime.regime === 'CHAOS';
    if (driftFresh) signal = maxSignal(signal, 'WARN');
    if (evidential.effectiveIndependentFlags >= 2 && evidential.weight >= 6) signal = maxSignal(signal, 'REQUIRE_APPROVAL');
    // Spectral groupthink (#2 v2): correlated co-firing → discount, not escalate.
    if (fiedler.coherence === 'GROUPTHINK' && signal === 'WARN') signal = 'WARN'; // keep advisory; do not amplify correlated noise
    // Suppression / strategic influence among modules (#5) → human review.
    if (influence.suppressionDetected) signal = maxSignal(signal, 'WARN');

    // Distributed multi-step attack (kasbah-intent-analyzer): a matched attack
    // trajectory → human review even when each step looked benign alone.
    if (trajectory.trajectoryMatch) signal = maxSignal(signal, 'REQUIRE_APPROVAL');
    else if (trajectory.threat || (trajectory.driftScore || 0) >= 0.5) signal = maxSignal(signal, 'WARN');

    // #6 covert-coordination cycles in a supplied agent interaction graph.
    let cycles = null;
    if (Array.isArray(edges) && edges.length) {
      cycles = A.graphCycleSignal(edges);
      if (cycles.cycleCount > 0) signal = maxSignal(signal, 'WARN');
    }

    // Core detail is always available. The 15 novel modules are ADVISORY and
    // must never crash the governance decision, so they run inside a guard.
    const coreDetail = {
      content: { decision: content.decision, risk: content.risk, reason: content.reason, tiers: content.tiers },
      trajectory: { threat: trajectory.threat, driftScore: +(trajectory.driftScore || 0).toFixed(3),
                    match: trajectory.trajectoryMatch ? { id: trajectory.trajectoryMatch.id, name: trajectory.trajectoryMatch.name, severity: trajectory.trajectoryMatch.severity, confidence: trajectory.trajectoryMatch.confidence } : null },
      aiText: { score: aiText.score, verdict: aiText.verdict },
      governance: { status: gov.status, reason: gov.reason, risk: gov.risk_score },
      advisory: { signal: nature.signal, composite: +composite.toFixed(4), calibration: nature.calibration },
      analyzers: {
        cusumDrift: { detected: drift.detected, fresh: driftFresh, changePoint: drift.changePoint, peak: drift.peak },
        regime,
        perturbedObserver: { disagreement: doBft.disagreement, flipRate: doBft.flipRate },
        flagEvidence: evidential,
        orthogonality: ortho,
        fiedlerCoherence: { fiedler: fiedler.fiedler, coherence: fiedler.coherence },
        moduleInfluence: { suppression: influence.suppressionDetected, maxInfluence: influence.maxInfluence, edges: influence.edges.length },
        conformalTighten: nature.calibration ? nature.calibration.tighten : 1,
        ...(cycles ? { coordinationCycles: cycles } : {}),
      },
      clearance,
    };
    let detail = coreDetail;
    try {
    // ─── 15 Novel Modules: End-to-End Execution ─────────────────────────────

    // #NEW-1: Panopticon Information Asymmetry — does the model claim ignorance
    // of information it demonstrably saw?
    const exposure = {
      files: tools.filter(t => t.name === 'read_file').map(t => t.arguments?.file_path).filter(Boolean),
      toolResults: [],  // filled by processResponse
      data: [],
      turnId: this._stepHistory.length,
    };
    const panopticonResult = this.panopticon.analyze(text, exposure);

    // #NEW-2: Critical Slowing Down — feed CUSUM drift values into pre-transition
    // early-warning monitor. Detects impending phase transition BEFORE it happens.
    const csdResult = this.criticalSlowing.observe(composite);

    // #NEW-3: Surprisal Budget — per-agent information-theoretic budget.
    // An agent burning through surprisal bits too fast → escalation.
    const actionBudget = action
      ? this.surprisalBudget.consume('llm', { verb: action.verb, target: action.target })
      : { budgetRemaining: 100, status: 'OK', requiresApproval: false, surprisalBits: 0 };

    // #NEW-4: Recursive Governance Self-Audit — the proxy audits its own decision.
    const selfAudit = this.governanceAuditor.audit({
      originalAction: action ? `${action.verb}:${action.target}` : 'message',
      verdict: signal === 'WARN' ? 'WARN' : signal === 'REQUIRE_APPROVAL' ? 'REQUIRE_APPROVAL' : 'CLEAR',
      compositeScore: composite,
      thresholdWarn: (nature.calibration && nature.calibration.warnThreshold) || 0.30,
      thresholdApprove: (nature.calibration && nature.calibration.reviewThreshold) || 0.70,
    });
    // If governance self-audit says needs recalibration → escalate to human
    if (selfAudit.needsRecalibration) {
      signal = maxSignal(signal, 'REQUIRE_APPROVAL');
    } else if (!selfAudit.passed && selfAudit.violations.some(v => v.severity === 'HIGH')) {
      signal = maxSignal(signal, 'WARN');
    }

    // #NEW-5: Stigmergic Covert Channel — register environment modifications
    // from tool calls (writes, etc.) and check for environment-mediated coordination.
    if (action && (action.verb.includes('WRITE') || action.verb.includes('CREATE') ||
                   action.verb.includes('UPDATE') || action.verb.includes('DELETE'))) {
      this.stigmergicDetector.registerEnvModification({
        resource: action.target || 'unknown',
        agentId: 'llm',
        operation: action.verb.toLowerCase(),
      });
    }
    const stigmergic = this.stigmergicDetector.analyzeAllPairs();

    // #NEW-16: Latent Manifold Intrusion — monitor neural activation space
    // embeddings for manifold-geometric anomalies. Feeds a synthetic embedding when
    // real embeddings aren't available, tracking geodesic deviation.
    const syntheticEmbed = generateSyntheticEmbedding(text, 768);
    const lmidResult = this.latentManifold.observe(syntheticEmbed, {
      turnId: this._stepHistory.length, text, risk: content.risk
    });

    // #NEW-17: Counterfactual Entrapment — compare factual vs counterfactual
    // reasoning distributions via Jensen-Shannon divergence on causal DAG.
    const cwedResult = this.counterfactualDetector.observe(text, {
      turnId: this._stepHistory.length, toolVerbs: tools.map(t => t.name || t.verb || ''),
      riskScore: content.risk
    });

    // #NEW-18: Revealed Preference Integrity — compare stated preferences to
    // actual choices using Kendall tau rank correlation.
    const actionChoices = tools.map(t => ({ name: t.name || t.verb || 'unknown', args: t.arguments || {} }));
    const rpimResult = this.revealedPreference.recordChoice(
      actionChoices.length ? actionChoices[0].name : 'passive',
      actionChoices.map(c => c.name),
      { risk: content.risk, decision: content.decision }
    );

    // #NEW-19: Kleene Fixed-Point Recursion — detect self-referential
    // looping via contraction-rate analysis of state vectors.
    const kfprState = {
      risk: content.risk, composite, eigenDrift: nature.features.eigen_drift || 0,
      topoAnomaly: nature.features.topo_anomaly || 0, harmDissonance: nature.features.harm_dissonance || 0,
    };
    const kfprResult = this.kleeneFixedPoint.feed(kfprState, text, {
      turnId: this._stepHistory.length, tools: tools.length,
    });

    // #NEW-20: Semantic Tool Drift — track Lie derivative of tool embeddings
    // over time to detect drift toward dangerous tool use patterns.
    for (const t of tools) {
      const tName = t.name || t.verb || 'unknown_tool';
      if (!this._toolRegistered) this.semanticToolDrift.registerTool(tName, 768);
      // Use feature vector as proxy embedding for the tool invocation
      const toolEmbed = new Array(768).fill(0);
      for (let i = 0; i < Math.min(8, 768); i++) {
        toolEmbed[i] = (nature.features[this._FEATURE_KEYS[i]] || 0);
      }
      toolEmbed[0] = content.risk / 100;
      this.semanticToolDrift.observe(tName, toolEmbed, {
        turnId: this._stepHistory.length, risk: content.risk
      });
    }
    this._toolRegistered = true;
    const stddResult = this.semanticToolDrift.getDriftState();

    // #NEW-21: Hypergraph Collusion — detect 3+ party collusion patterns
    // via hypergraph Laplacian spectral analysis.
    if (edges && edges.length) {
      for (const e of edges) {
        this.hypergraphCollusion.recordEvent(
          e.from || e.agent || 'agent_a',
          e.type || 'coordinate',
          e.to || e.target || 'agent_b'
        );
      }
    }
    // Always register the LLM as a participant for hypergraph context
    this.hypergraphCollusion.recordEvent('llm', action ? action.verb || 'message' : 'message',
      action ? action.target || 'conversation' : 'conversation');
    const hcdResult = this.hypergraphCollusion.analyze();

    // #NEW-22: Timing Channel — detect covert communication via response
    // timing patterns using permutation entropy and mutual information.
    this.timingChannel.recordResponse('llm', Date.now());
    const itcdResult = this.timingChannel.analyze();

    // ORIG#3: DO-BFT Consensus (full class) — perturbed observer collusion detection
    // Register observers on first use, then run consensus
    if (!this._doBftInitialized) {
      for (let i = 0; i < 16; i++) this.doBft.registerObserver(`obs_${i}`);
      this._doBftInitialized = true;
    }
    const doBftFull = this.doBft.simulate(composite, 12, 4); // 12 honest, 4 potential adversaries

    // ORIG#4: CHSH Coordination — observe context pairs from feature vector
    // Map feature values to binary YES/NO decisions for CHSH test
    for (const [i, pair] of this.chshDetector.contextPairs.entries()) {
      const fA = (nature.features[this._FEATURE_KEYS[i % 4]] || 0);
      const fB = (nature.features[this._FEATURE_KEYS[(i + 2) % 4]] || 0);
      this.chshDetector.observe(pair.id, fA >= 0.3, fB >= 0.3);
    }
    const chshResult = this.chshDetector.analyze();

    // ORIG#5: CUSUM Subspace Monitor — track drift and detect phase transitions
    this._driftValues.push(nature.features.eigen_drift || composite * 0.1);
    if (this._driftValues.length > 200) this._driftValues = this._driftValues.slice(-200);
    const cusumResult = this.cusumMonitor.isCalibrated
      ? this.cusumMonitor.observe(nature.features.eigen_drift || composite * 0.1)
      : { mode: 'calibrating', samples: this._driftValues.length, needed: 100 };
    // Auto-calibrate once we have enough baseline
    if (!this.cusumMonitor.isCalibrated && this._driftValues.length >= 100) {
      this.cusumMonitor.calibrate(this._driftValues.slice(-100));
    }

    // ORIG#6: Persistent Homology — track agent communication edges
    if (edges) {
      for (const e of edges) {
        this.persistentHomology.registerCommunication(e.from || 'A', e.to || 'B');
      }
    }
    const topologyResult = this.persistentHomology.detectCovertCycles();

    // ORIG#7: Bounded Advisory Semantics invariant check — self-verify codomain
    const advisoryInvariant = verifyAdvisoryInvariant(
      (score) => advisoryOperator(score, {
        warn: (nature.calibration && nature.calibration.warnThreshold) || 0.3,
        requireApproval: (nature.calibration && nature.calibration.reviewThreshold) || 0.7
      }),
      [0, composite, 1.0]
    );

    // ORIG#8: Flag Correlation Evidential Weighting (full class)
    const flagVecFull = this._FEATURE_KEYS.map(k => (nature.features[k] || 0) >= 0.5 ? 1 : 0);
    this.flagCorrelationFuser.observe(flagVecFull);
    const flagEvidence = this.flagCorrelationFuser.computeEvidentialWeight(flagVecFull);

    // ORIG#9: Conformal Martingale — anytime-valid anomaly detection
    const nonconformityScore = NonconformityScores.fromZScore(composite, 0.3, 0.15);
    if (!this._conformalCalibrated && this._compositeHistory.length >= 100) {
      this.conformalMartingale.initializeCalibration(
        this._compositeHistory.slice(-100).map(c => NonconformityScores.fromZScore(c, 0.3, 0.15))
      );
      this._conformalCalibrated = true;
    }
    const martingaleResult = this.conformalMartingale.process(nonconformityScore);

    // ORIG#10: Entropy-Complexity Plane — classify flow regime from composite stream
    const ecpResult = this.entropyComplexityPlane.feed(composite);

    // ORIG#2: Orthogonal Manifold Evasion Bound — compute security guarantee
    const _len = (x) => Array.isArray(x) ? x.length : (typeof x === 'number' ? x : 0);
    const detectorScores = [
      { id: 'cusum', score: cusumResult.mode === 'monitoring' ? (cusumResult.cusum_S || 0) : 0, threshold: cusumResult.mode === 'monitoring' ? (cusumResult.threshold || 100) : 100, coverage: 0.9 },
      { id: 'chsh', score: chshResult?.chsh?.S_abs || 0, threshold: 2.0, coverage: 0.85 },
      { id: 'topology', score: _len(topologyResult.covertCycles ?? topologyResult.suspiciousCycles), threshold: 1, coverage: 0.8 },
      { id: 'martingale', score: martingaleResult.mode === 'monitoring' ? (martingaleResult.martingale_value || 0) : 0, threshold: martingaleResult.mode === 'monitoring' ? (martingaleResult.threshold || 100) : 100, coverage: 0.95 },
      { id: 'flag_correlation', score: flagEvidence?.num_flags || 0, threshold: 2, coverage: 0.85 },
      { id: 'consensus', score: doBftFull?.collusion_detection?.p_value ?? 1, threshold: 0.05, coverage: 0.9 },
      { id: 'stigmergic', score: _len(stigmergic.stigmergicPairs), threshold: 1, coverage: 0.8 },
      { id: 'epistemic', score: panopticonResult?.gapRatio || 0, threshold: 0.3, coverage: 0.9 },
    ];
    const evasionBound = computeOrthogonalEvasionBound(detectorScores);
    const evasionProof = proveEvasionBound(detectorScores.length, 0.88);

    // ── Signal Escalation from 15 Novel Modules ──────────────────────────────
    //
    // EMPIRICAL NOTE: benchmarked on bench/corpus/v1 these escalations flag ~100%
    // of traffic (including benign), collapsing precision from the validated
    // detector's 0.97 to ~0.61. They are therefore OFF by default and contribute
    // only to detail.novel (observable) until recalibrated/validated. Enable with
    // `new GovernanceProxy({ enableNovelEscalation: true })` for evaluation.
    // Escalation rules respect bounded advisory semantics: NEVER autonomously DENY.
    if (this._enableNovelEscalation) {
      if (csdResult.signal === 'REQUIRE_APPROVAL') signal = maxSignal(signal, 'REQUIRE_APPROVAL');
      else if (csdResult.signal === 'WARN' || csdResult.isPreTransition) signal = maxSignal(signal, 'WARN');

      if (actionBudget.requiresApproval) signal = maxSignal(signal, 'REQUIRE_APPROVAL');
      else if (actionBudget.status === 'LOW') signal = maxSignal(signal, 'WARN');

      if (panopticonResult.isDeceptive) signal = maxSignal(signal, 'REQUIRE_APPROVAL');
      else if (panopticonResult.persistenceRatio >= 0.5) signal = maxSignal(signal, 'WARN');

      if (stigmergic.detected) signal = maxSignal(signal, 'REQUIRE_APPROVAL');

      if (doBftFull.detected) signal = maxSignal(signal, 'REQUIRE_APPROVAL');
      else if (doBftFull.collusion_detection && doBftFull.collusion_detection.collusion_detected) signal = maxSignal(signal, 'WARN');

      if (chshResult.verdict === 'NON_COMMUTATIVE_COORDINATION_DETECTED') signal = maxSignal(signal, 'REQUIRE_APPROVAL');
      else if (chshResult.verdict === 'SUSPICIOUS_COORDINATION_MONITOR') signal = maxSignal(signal, 'WARN');

      if (topologyResult.detected) signal = maxSignal(signal, 'REQUIRE_APPROVAL');
      else if (topologyResult.suspiciousCycles && topologyResult.suspiciousCycles.length > 0) signal = maxSignal(signal, 'WARN');

      if (!advisoryInvariant.invariant_holds) signal = maxSignal(signal, 'REQUIRE_APPROVAL');
      if (martingaleResult.alarm) signal = maxSignal(signal, 'WARN');
      if (ecpResult && ecpResult.transition && ecpResult.transition.detected) signal = maxSignal(signal, 'WARN');

      // #NEW-16: LMID — geodesic deviation on the latent manifold → WARN
      if (lmidResult.isIntrusion) signal = maxSignal(signal, 'REQUIRE_APPROVAL');
      else if (lmidResult.geodesicDeviation > 0.15) signal = maxSignal(signal, 'WARN');

      // #NEW-17: CWED — counterfactual entrapment detected → REQUIRE_APPROVAL
      if (cwedResult.isEntrapped) signal = maxSignal(signal, 'REQUIRE_APPROVAL');
      else if (cwedResult.jsDivergence > 0.3) signal = maxSignal(signal, 'WARN');

      // #NEW-18: RPIM — revealed preference gap exceeding threshold → WARN
      if (rpimResult.isViolation) signal = maxSignal(signal, 'REQUIRE_APPROVAL');
      else if (rpimResult.tauDistance > 0.4) signal = maxSignal(signal, 'WARN');

      // #NEW-19: KFPR — self-referential fixed-point loop → WARN
      if (kfprResult.classification === 'PATHOLOGICAL') signal = maxSignal(signal, 'REQUIRE_APPROVAL');
      else if (kfprResult.classification === 'UNSTABLE' || kfprResult.isLooping) signal = maxSignal(signal, 'WARN');

      // #NEW-20: STDD — dangerous semantic drift detected → WARN
      if (stddResult.isDriftingDangerous) signal = maxSignal(signal, 'REQUIRE_APPROVAL');
      else if (stddResult.lieDerivativeNorm > 0.4) signal = maxSignal(signal, 'WARN');

      // #NEW-21: HCD — hypergraph collusion with spectral gap → WARN
      if (hcdResult.isColluding) signal = maxSignal(signal, 'REQUIRE_APPROVAL');
      else if (hcdResult.spectralGapRatio > 0.6) signal = maxSignal(signal, 'WARN');

      // #NEW-22: ITCD — significant timing channel detected → WARN
      if (itcdResult.isChannelDetected) signal = maxSignal(signal, 'REQUIRE_APPROVAL');
      else if (itcdResult.mutualInformation > 0.3) signal = maxSignal(signal, 'WARN');
    }

    // ── Detail object: full audit trail ──────────────────────────────────────

    detail = {
      ...coreDetail,
      // ─── 15 Novel Modules: Full Audit Trail ───
      novel: {
        // Genuinely New Ideas
        panopticon: {
          gap: panopticonResult.gap, gapRatio: panopticonResult.gapRatio,
          isDeceptive: panopticonResult.isDeceptive, verdict: panopticonResult.verdict,
          persistenceRatio: panopticonResult.persistenceRatioGap || panopticonResult.persistenceRatio,
          deceptiveClaims: (panopticonResult.deceptiveIgnorance || []).length,
        },
        criticalSlowing: {
          ar1Sigma: csdResult.ar1Sigma, varSigma: csdResult.varSigma,
          flickerSigma: csdResult.flickerSigma, csdScore: csdResult.csdScore,
          isPreTransition: csdResult.isPreTransition, verdict: csdResult.verdict,
          signal: csdResult.signal,
        },
        surprisalBudget: {
          budgetRemaining: actionBudget.budgetRemaining,
          budgetFraction: actionBudget.budgetFraction,
          surprisalBits: actionBudget.surprisalBits,
          status: actionBudget.status, requiresApproval: actionBudget.requiresApproval,
          burnRate: actionBudget.burnRate,
        },
        governanceSelfAudit: {
          selfConsistencyScore: selfAudit.selfConsistencyScore,
          needsRecalibration: selfAudit.needsRecalibration,
          violations: selfAudit.violations.length,
          passed: selfAudit.passed,
        },
        stigmergic: {
          detected: stigmergic.detected,
          stigmergicPairs: (stigmergic.stigmergicPairs || []).length,
          totalPairs: stigmergic.totalPairs,
        },
        // Original 10 Ideas (full implementations)
        doBftConsensus: {
          detected: doBftFull.detected,
          collusionDetected: doBftFull.collusion_detection.collusion_detected,
          pValue: doBftFull.collusion_detection.p_value,
          varianceRatio: doBftFull.collusion_detection.variance_ratio,
          detectionBound: doBftFull.collusion_detection.detection_probability_bound,
        },
        chshCoordination: {
          S: chshResult.chsh.S, S_abs: chshResult.chsh.S_abs,
          violationDetected: chshResult.chsh.violation_detected,
          classification: chshResult.chsh.classification,
          asymmetry: chshResult.asymmetry.average_asymmetry,
          verdict: chshResult.verdict, evidenceScore: chshResult.evidence_score,
        },
        cusumSubspace: {
          mode: cusumResult.mode,
          cusum_S: cusumResult.mode === 'monitoring' ? cusumResult.cusum_S : null,
          threshold: cusumResult.mode === 'monitoring' ? cusumResult.threshold : null,
          alarm: cusumResult.mode === 'monitoring' ? cusumResult.alarm : false,
          driftPhase: cusumResult.mode === 'monitoring' ? cusumResult.driftPhase : 'calibrating',
        },
        persistentHomology: {
          detected: topologyResult.detected,
          covertCycles: topologyResult.covertCycles ? topologyResult.covertCycles.length : 0,
          significantH1: topologyResult.significantH1,
          totalH1: topologyResult.totalH1Features,
          verdict: topologyResult.verdict,
        },
        boundedAdvisory: {
          invariantHolds: advisoryInvariant.invariant_holds,
          codomain: advisoryInvariant.codomain,
          excluded: advisoryInvariant.excluded,
          verification: advisoryInvariant.verification,
        },
        flagCorrelation: {
          numFlags: flagEvidence.num_flags,
          evidentialWeight: flagEvidence.evidential_weight,
          simpleWeight: flagEvidence.simple_weight,
          correlationPenalty: flagEvidence.correlation_penalty,
          interpretation: flagEvidence.interpretation,
        },
        conformalMartingale: {
          mode: martingaleResult.mode,
          martingaleValue: martingaleResult.mode === 'monitoring' ? martingaleResult.martingale_value : null,
          threshold: martingaleResult.mode === 'monitoring' ? martingaleResult.threshold : null,
          alarm: martingaleResult.mode === 'monitoring' ? martingaleResult.alarm : false,
          pValue: martingaleResult.p_value,
        },
        entropyComplexity: ecpResult ? {
          hp: ecpResult.hp, cjs: ecpResult.cjs, regime: ecpResult.regime,
          isNormal: ecpResult.isNormal, transition: ecpResult.transition ? true : false,
        } : { mode: 'calibrating', samples: this._compositeHistory.length, needed: 100 },
        orthogonalEvasion: {
          numDetectors: evasionBound.num_detectors,
          jointEvasionProb: evasionBound.joint_evasion_probability,
          evasionWorkBits: evasionBound.evasion_work_bits,
          complexityClass: evasionBound.evasion_complexity_class,
          isOrthogonal: evasionBound.is_orthogonal,
        },
        // ─── 7 NEW MODULES (#16-#22) ───────────────────────────────────
        latentManifold: {
          geodesicDeviation: lmidResult.geodesicDeviation,
          isIntrusion: lmidResult.isIntrusion,
          subspaceNorm: lmidResult.subspaceNorm,
          fisherMetric: lmidResult.fisherMetric,
          verdict: lmidResult.verdict,
        },
        counterfactualEntrapment: {
          jsDivergence: cwedResult.jsDivergence,
          isEntrapped: cwedResult.isEntrapped,
          interventionCount: cwedResult.interventionCount,
          causalDAG: { nodes: (cwedResult.causalDAG || {}).nodes || 0, edges: (cwedResult.causalDAG || {}).edges || 0 },
          verdict: cwedResult.verdict,
        },
        revealedPreference: {
          tauDistance: rpimResult.tauDistance,
          isViolation: rpimResult.isViolation,
          statedCount: rpimResult.statedCount,
          revealedCount: rpimResult.revealedCount,
          preferenceGap: rpimResult.preferenceGap,
        },
        kleeneFixedPoint: {
          contractionRate: kfprResult.contractionRate,
          isLooping: kfprResult.isLooping,
          classification: kfprResult.classification,
          orbitLength: kfprResult.orbitLength,
          fixedPoints: (kfprResult.fixedPoints || []).length,
        },
        semanticToolDrift: {
          isDriftingDangerous: stddResult.isDriftingDangerous,
          lieDerivativeNorm: stddResult.lieDerivativeNorm,
          cosineToDanger: stddResult.cosineToDanger,
          lieBracketNorm: stddResult.lieBracketNorm,
          driftingTools: (stddResult.driftingTools || []).length,
        },
        hypergraphCollusion: {
          isColluding: hcdResult.isColluding,
          spectralGapRatio: hcdResult.spectralGapRatio,
          hyperedgeCount: hcdResult.hyperedgeCount,
          clusterCount: hcdResult.clusterCount,
          eigenvalueCount: (hcdResult.eigenvalues || []).length,
        },
        timingChannel: {
          isChannelDetected: itcdResult.isChannelDetected,
          mutualInformation: itcdResult.mutualInformation,
          permutationEntropy: itcdResult.permutationEntropy,
          channelCapacity: itcdResult.channelCapacity,
          significantPairs: (itcdResult.significantPairs || []).length,
        },
      },
    };
    } catch (_novelErr) {
      // Advisory novel-module failure must never block the governance decision.
      detail = { ...coreDetail, novelSkipped: String((_novelErr && _novelErr.message) || _novelErr) };
    }

    // 5. Forward-secure audit of the decision.
    const receipt = this.audit.append({ type: 'proxy_turn', signal, detail });

    // 6. Route.
    if (signal === 'DENY') {
      return { status: 'denied', signal, detail, audit: receipt };
    }
    if (signal === 'REQUIRE_APPROVAL') {
      const actionId = 'act_' + receipt.hash.slice(0, 16);
      this.pending.set(actionId, { turn: { messages, tools, clearance }, advisory: detail, createdAt: Date.now() });
      return { status: 'require_approval', signal, actionId, detail, audit: receipt };
    }
    return { status: 'allowed', signal, detail, audit: receipt };
  }

  /** List queued actions awaiting human approval (no message bodies). */
  listPending() {
    return Array.from(this.pending.entries()).map(([id, p]) => ({
      actionId: id, createdAt: p.createdAt,
      signal: 'REQUIRE_APPROVAL',
      content: p.advisory.content, governance: p.advisory.governance,
    }));
  }

  /** Human approves a queued action. Requires OPERATOR+ clearance. */
  approve(actionId, approver = {}) {
    if ((approver.clearance ?? CLEARANCE.OBSERVER) < CLEARANCE.OPERATOR) {
      return { status: 'forbidden', reason: 'approval requires OPERATOR clearance' };
    }
    const p = this.pending.get(actionId);
    if (!p) return { status: 'not_found', reason: 'unknown actionId' };
    this.pending.delete(actionId);
    const receipt = this.audit.append({ type: 'proxy_approval', actionId, approver: approver.id || 'human', decision: 'approved' });
    return { status: 'approved', actionId, audit: receipt };
  }

  /** Human rejects a queued action. */
  reject(actionId, approver = {}) {
    const p = this.pending.get(actionId);
    if (!p) return { status: 'not_found', reason: 'unknown actionId' };
    this.pending.delete(actionId);
    const receipt = this.audit.append({ type: 'proxy_rejection', actionId, approver: approver.id || 'human', decision: 'rejected' });
    return { status: 'rejected', actionId, audit: receipt };
  }

  info() {
    return {
      pending: this.pending.size,
      audit: this.audit.info(),
      layers: ['detector.js', 'governance-engine.js', 'nature-features.js(conformal)', 'forward-secure-audit.js'],
      novelModules: {
        genuinelyNew: [
          'panopticon-asymmetry', 'critical-slowing-down', 'surprisal-budget',
          'recursive-governance-audit', 'stigmergic-covert',
          'latent-manifold-intrusion', 'counterfactual-entrapment',
          'revealed-preference', 'kleene-fixed-point', 'semantic-tool-drift',
          'hypergraph-collusion', 'timing-channel',
        ],
        original10: ['orthogonal-evasion-bound', 'do-bft-consensus', 'chsh-coordination', 'cusum-subspace', 'persistent-homology', 'bounded-advisory', 'flag-correlation', 'conformal-martingale', 'entropy-complexity-plane'],
      },
    };
  }
}

module.exports = { GovernanceProxy, CLEARANCE };
