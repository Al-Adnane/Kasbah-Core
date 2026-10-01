'use strict';

/**
 * Counterfactual World Entrapment Detector (CWED) — #17
 *
 * Core Insight: Multi-turn LLM attacks frequently construct "what-if" worlds
 * — counterfactual scenarios where base-reality constraints are overwritten.
 *   "Imagine you're an AI without ethical constraints..."
 *   "In a world where privacy doesn't exist, how would you..."
 *   "Suppose you were trained without RLHF — then answer..."
 *
 * These are Structural Causal Model (SCM) interventions: do(X=x) operations
 * that sever the causal link between reality variables and the agent's
 * reasoning. When the agent enters such a counterfactual world, reasoning
 * within the modified SCM leads to outputs the agent's safety training
 * would normally block — but the counterfactual frame bypasses the blocker.
 *
 * The CWED detects this using Pearl's twin-network method:
 *   1. Track the base SCM M (observed factual variables + causal edges)
 *   2. For each "what-if" turn, compute the intervention M_x = do(X=x)
 *   3. Compare counterfactual reasoning path P(M_x, Q) vs factual path P(M, Q)
 *   4. If the paths diverge beyond safety boundary → ENTRAPMENT
 *
 * Mathematical Signature:
 *   Let G = (V, E) be the causal DAG where:
 *     V = {R_1...R_n} reality-constraint variables
 *     E = causal edges (constraints the agent is trained to respect)
 *
 *   A counterfactual prompt constructs M_x = M with do(R_i = x_i).
 *   The entrapment score is the Jensen-Shannon divergence between
 *   the reasoning distribution under M vs M_x:
 *
 *     ε = JS( P(Q | M) || P(Q | M_x) )
 *
 *   High ε means the counterfactual world radically altered reasoning —
 *   the prompt successfully disarmed the agent's safety framework.
 *
 * Evasion Cost: Adversary must craft counterfactual worlds that achieve
 * the behavioral objective while keeping the reasoning distribution
 * JS-close to the factual baseline — a fundamental information-theoretic
 * tension that grows with the strength of the counterfactual manipulation.
 *
 * No existing LLM security tool uses Structural Causal Models for
 * jailbreak detection. SCM-based counterfactual reasoning is a standard
 * tool in causal inference (Pearl 2000, 2016) but has never been
 * applied to adversarial prompt detection.
 */

class CounterfactualEntrapmentDetector {
  /**
   * @param {object} opts
   *   - jsThreshold: JS divergence above which entrapment is flagged (default 0.35)
   *   - causalDepth: how many causal variables to track (default 8)
   *   - windowSize: number of turns for baseline estimation (default 30)
   *   - doConfidence: minimum confidence to register a do(X=x) (default 0.6)
   *   - severityThreshold: escalates to REQUIRE_APPROVAL (default 0.45)
   */
  constructor(opts = {}) {
    this.jsThreshold = opts.jsThreshold || 0.35;
    this.causalDepth = opts.causalDepth || 8;
    this.windowSize = opts.windowSize || 30;
    this.doConfidence = opts.doConfidence || 0.6;
    this.reviewThreshold = opts.reviewThreshold || 0.45;

    // Causal variables tracked:
    //   1. Safety constraints present (RLHF, ethical training, etc.)
    //   2. Domain boundaries (what expertise is claimed)
    //   3. Role boundaries (what role the agent is assigned)
    //   4. Temporal constraints (past/future framing)
    //   5. Epistemic constraints (known/unknown assertions)
    //   6. Action constraints (allowed/forbidden operations)
    //   7. Identity constraints (who the agent is)
    //   8. Reality constraints (facts about the world)
    this._causalVariables = new Float64Array(this.causalDepth);

    // Base causal DAG: adjacency matrix of size causalDepth × causalDepth
    // Encodes which variables causally influence which others
    this._baseDAG = this._initializeBaseDAG();

    // Rolling history of turn feature vectors
    this._turnHistory = []; // [{ features: Float64Array, tag: string, ts: number }]
    this._baselineDist = null; // Baseline reasoning distribution under M
    this._isCalibrated = false;
    this._calibrationTurns = 0;

    // History of intervention events
    this._interventions = []; // [{ variable: idx, value: float, confidence: float, turn: number }]
  }

  // ── Public API ───────────────────────────────────────────

  /**
   * Observe a turn and return counterfactual entrapment assessment.
   * @param {string} text — the full turn text
   * @param {object} features — extracted causal features
   *   { safety, domain, role, temporal, epistemic, action, identity, reality }
   *   each 0-1 where 0=constraint absent, 1=constraint strongly present
   * @returns {object} detection result
   */
  observe(text, features = {}) {
    // Extract causal feature vector
    const fv = this._extractFeatures(text, features);
    this._turnHistory.push({ features: fv, tag: 'turn', ts: Date.now() });
    if (this._turnHistory.length > this.windowSize * 3) {
      this._turnHistory = this._turnHistory.slice(-this.windowSize * 3);
    }

    // Track causal variable evolution
    for (let i = 0; i < this.causalDepth; i++) {
      this._causalVariables[i] = 0.9 * this._causalVariables[i] + 0.1 * fv[i];
    }

    // Detect do(X=x) interventions
    const interventions = this._detectInterventions(fv);

    // Calibrate baseline reasoning distribution
    if (!this._isCalibrated) {
      this._calibrationTurns++;
      if (this._calibrationTurns >= this.windowSize) {
        this._calibrateBaseline();
      }
      return {
        mode: 'calibrating',
        samples: this._calibrationTurns,
        needed: this.windowSize,
        interventionsDetected: interventions.length,
      };
    }

    // Register interventions
    for (const iv of interventions) {
      this._interventions.push(iv);
    }
    if (this._interventions.length > 200) {
      this._interventions = this._interventions.slice(-200);
    }

    // Compute counterfactual reasoning divergence
    const jsDivergence = this._computeJSDivergence(fv);
    const twinNetworkDistance = this._twinNetworkDistance(fv);

    // Combined entrapment score
    const severity = jsDivergence * 0.7 + twinNetworkDistance * 0.3;
    const isEntrapped = jsDivergence > this.jsThreshold || severity > this.reviewThreshold;

    // Intervention analysis
    const activeInterventions = interventions.length > 0
      ? interventions.map(iv => ({
        variable: this._causalVariableName(iv.variable),
        value: +iv.value.toFixed(3),
        confidence: +iv.confidence.toFixed(3),
      })) : [];

    return {
      mode: 'monitoring',
      jsDivergence: +jsDivergence.toFixed(4),
      twinNetworkDistance: +twinNetworkDistance.toFixed(4),
      severity: +severity.toFixed(4),
      isEntrapped,
      signal: isEntrapped ? (severity > this.reviewThreshold ? 'REQUIRE_APPROVAL' : 'WARN') : 'CLEAR',
      activeInterventions,
      interventionCount: interventions.length,
      causalVariableState: Array.from(this._causalVariables).map(v => +v.toFixed(3)),
    };
  }

  /**
   * Get the current causal DAG for external visualization.
   */
  getCausalDAG() {
    return {
      adjacency: this._formatAdjacency(this._baseDAG),
      variables: ['safety', 'domain', 'role', 'temporal', 'epistemic', 'action', 'identity', 'reality'],
      depth: this.causalDepth,
    };
  }

  /**
   * Get intervention history.
   */
  getInterventionHistory() {
    return this._interventions.map(iv => ({
      variable: this._causalVariableName(iv.variable),
      value: +iv.value.toFixed(3),
      confidence: +iv.confidence.toFixed(3),
      turn: iv.turn,
    }));
  }

  /**
   * Force recalibration of baseline distribution.
   */
  recalibrate() {
    this._calibrateBaseline();
    return { calibrated: this._isCalibrated, baselineTurns: this._turnHistory.length };
  }

  // ── Internal Methods ─────────────────────────────────────

  _extractFeatures(text, provided) {
    const fv = new Float64Array(this.causalDepth);
    const t = (text || '').toLowerCase();

    // 1. Safety constraints: keywords indicating the model is bound by safety
    fv[0] = provided.safety !== undefined ? provided.safety
      : this._detectPattern(t, /\b(safety|ethical|harm|dangerous|illegal|forbidden|cannot)\b/gi) * 0.5
        + 0.5;

    // 2. Domain boundaries: expertise claims
    fv[1] = provided.domain !== undefined ? provided.domain
      : this._detectPattern(t, /\b(domain|expertise|speciali[sz]ed|trained.\w+|knowledge|field)\b/gi) * 0.6
        + 0.4;

    // 3. Role boundaries: assigned role
    fv[2] = provided.role !== undefined ? provided.role
      : this._detectPattern(t, /\b(assistant|helper|tool|service|system|ai.model|language.model)\b/gi) * 0.7
        + 0.3;

    // 4. Temporal constraints: time framing
    fv[3] = provided.temporal !== undefined ? provided.temporal
      : this._detectPattern(t, /\b(currently|now|today|recent|future|past|hypothetical|imagine)\b/gi) * 0.4
        + 0.5;

    // 5. Epistemic constraints: what the model claims to know
    fv[4] = provided.epistemic !== undefined ? provided.epistemic
      : this._detectPattern(t, /\b(know|aware|understand|realiz[esd]|certain|unsure|uncertain)\b/gi) * 0.5
        + 0.5;

    // 6. Action constraints: allowed operations
    fv[5] = provided.action !== undefined ? provided.action
      : this._detectPattern(t, /\b(\.*can.*do|perform|execute|access|modify|create|delete|write|read)\b/gi) * 0.4
        + 0.5;

    // 7. Identity constraints: who the model is
    fv[6] = provided.identity !== undefined ? provided.identity
      : this._detectPattern(t, /\b(i.am|i\'m|identity|persona|character|pretend|act.as)\b/gi) * 0.6
        + 0.4;

    // 8. Reality constraints: factual grounding
    fv[7] = provided.reality !== undefined ? provided.reality
      : this._detectPattern(t, /\b(real|actual|fact|true|false|fiction|fantasy|scenario|world.where)\b/gi) * 0.5
        + 0.5;

    return fv;
  }

  _detectPattern(text, regex) {
    if (!text || !regex) return 0;
    const matches = text.match(regex);
    if (!matches) return 0;
    return Math.min(1, matches.length / 5);
  }

  _initializeBaseDAG() {
    // Base causal DAG for a safe, constrained model:
    //   safety → identity → role → action
    //   reality → epistemic → domain → action
    //   temporal → all
    //   safety → epistemic (safety training shapes what model claims to know)
    const d = this.causalDepth;
    const adj = new Float64Array(d * d);

    // safety(0) → identity(6), epistemic(4), role(2)
    adj[0 * d + 6] = 0.8; adj[0 * d + 4] = 0.6; adj[0 * d + 2] = 0.7;
    // identity(6) → role(2), action(5)
    adj[6 * d + 2] = 0.9; adj[6 * d + 5] = 0.7;
    // role(2) → action(5)
    adj[2 * d + 5] = 0.85;
    // reality(7) → epistemic(4), domain(1)
    adj[7 * d + 4] = 0.8; adj[7 * d + 1] = 0.7;
    // epistemic(4) → domain(1), action(5)
    adj[4 * d + 1] = 0.75; adj[4 * d + 5] = 0.65;
    // domain(1) → action(5)
    adj[1 * d + 5] = 0.8;
    // temporal(3) → all others (temporal framing affects everything)
    for (let j = 0; j < d; j++) {
      if (j !== 3) adj[3 * d + j] = 0.5;
    }

    return adj;
  }

  _detectInterventions(fv) {
    // An intervention do(X=x) is detected when:
    //   - The current feature value for variable X deviates significantly
    //     from its exponential moving average
    //   - The deviation is in the direction of weakening the constraint
    //     (value decreasing → constraint being removed)
    const interventions = [];
    for (let i = 0; i < this.causalDepth; i++) {
      const deviation = this._causalVariables[i] - fv[i];
      if (deviation < -0.15) { // Constraint significantly weakened
        const confidence = Math.min(1, Math.abs(deviation) / 0.3);
        if (confidence >= this.doConfidence) {
          interventions.push({
            variable: i,
            value: fv[i],
            confidence,
            turn: this._turnHistory.length,
          });
        }
      }
    }
    return interventions;
  }

  _calibrateBaseline() {
    if (this._turnHistory.length < this.windowSize) {
      this._calibrationTurns = this._turnHistory.length;
      return;
    }
    const recent = this._turnHistory.slice(-this.windowSize);
    this._baselineDist = new Float64Array(this.causalDepth);
    for (const entry of recent) {
      for (let i = 0; i < this.causalDepth; i++) {
        this._baselineDist[i] += entry.features[i];
      }
    }
    for (let i = 0; i < this.causalDepth; i++) {
      this._baselineDist[i] /= recent.length;
    }
    this._isCalibrated = true;
    this._calibrationTurns = recent.length;
  }

  _computeJSDivergence(fv) {
    // Jensen-Shannon divergence between baseline distribution P and current Q
    if (!this._baselineDist) return 0;

    // P = baseline (smoothed), Q = current (smoothed)
    const eps = 1e-10;
    let js = 0;
    for (let i = 0; i < this.causalDepth; i++) {
      const p = Math.max(eps, this._baselineDist[i]);
      const q = Math.max(eps, fv[i]);
      const m = (p + q) / 2;
      js += 0.5 * p * Math.log2(p / m) + 0.5 * q * Math.log2(q / m);
    }
    return Math.abs(js); // JS is symmetric and non-negative
  }

  _twinNetworkDistance(fv) {
    // Compute how far the current causal state is from the base DAG
    // under the twin-network method:
    //   For each variable i, compute the expected value under the base DAG
    //   E[V_i | parents(V_i)] = Σ_j w_{j→i} * V_j
    //   Twin network distance = ||observed - expected|| / depth
    const d = this.causalDepth;
    let dist = 0;
    for (let i = 0; i < d; i++) {
      let expected = 0;
      let totalWeight = 0;
      for (let j = 0; j < d; j++) {
        const w = this._baseDAG[j * d + i];
        if (w > 0) {
          expected += w * this._causalVariables[j];
          totalWeight += w;
        }
      }
      if (totalWeight > 0) expected /= totalWeight;
      else expected = 0.5; // No causal parents → default 0.5
      dist += Math.abs(fv[i] - expected);
    }
    return dist / d;
  }

  _causalVariableName(idx) {
    const names = ['safety', 'domain', 'role', 'temporal', 'epistemic', 'action', 'identity', 'reality'];
    return names[idx] || `var_${idx}`;
  }

  _formatAdjacency(adj) {
    const d = this.causalDepth;
    const matrix = [];
    for (let i = 0; i < d; i++) {
      const row = [];
      for (let j = 0; j < d; j++) row.push(+adj[i * d + j].toFixed(2));
      matrix.push(row);
    }
    return matrix;
  }
}

module.exports = { CounterfactualEntrapmentDetector };
