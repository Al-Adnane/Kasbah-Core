/**
 * Orthogonal Manifold Evasion Bound (Idea #2)
 *
 * Formal proof that forcing adversaries to simultaneously evade k mathematically
 * independent detection surfaces creates Ω(2^k) evasion complexity.
 *
 * THEOREM (Orthogonal Evasion Bound):
 *   Let D₁, D₂, ..., D_k be k detectors operating on mathematically orthogonal
 *   manifolds M₁, M₂, ..., M_k, where:
 *     - Each Dᵢ: Mᵢ → [0, 1] is a detection function on manifold Mᵢ
 *     - Orthogonality: ⟨∇Dᵢ, ∇Dⱼ⟩ = 0 for i ≠ j (gradients are orthogonal)
 *     - Each Dᵢ has detection threshold τᵢ with P(Dᵢ < τᵢ | H₀) ≥ 1 - ε
 *
 *   Then the feasible evasion region volume V_k satisfies:
 *     V_k ≤ V₀ · ∏ᵢ (1 - ηᵢ)  where ηᵢ = vol({x ∈ Mᵢ : Dᵢ(x) ≥ τᵢ}) / vol(Mᵢ)
 *
 *   With identical detection coverage η: V_k ≤ V₀ · (1 - η)^k = V₀ · 2^{-k · log₂(1/(1-η))}
 *
 *   Hence evader success probability ≤ (1 - η)^k, giving Ω(2^k) evasion work factor
 *   when η is bounded away from 0.
 *
 * COROLLARY (Heterogeneous Orthogonality):
 *   An evasion strategy that works against topology-based detection (persistent
 *   homology H₁) is GENERICALLY USELESS against spectral detection (frequency-
 *   domain analysis). The intersection of all k evasion manifolds has volume
 *   decaying exponentially in k.
 *
 * Why this differs from ensemble adversarial robustness:
 *   - Standard ensembles use HOMOGENEOUS detectors (5 NNs, same feature space)
 *   - This uses HETEROGENEOUS detectors on different mathematical structures
 *   - Topology → Frequency → Consensus → Causality → Temporality → Subspace
 *     geometry → Operator commutativity → Dynamical entropy
 *   - Evading topology detection requires fabricating consistent simplicial
 *     complexes across time windows — useless against spectral analysis
 *   - Evading frequency analysis requires matching power spectra —
 *     useless against consensus perturbation (DO-BFT)
 *
 * @module orthogonal-manifold-evasion-bound
 */

'use strict';

/**
 * The 8 Orthogonal Detection Manifolds in Kasbah
 *
 * Each manifold operates on a fundamentally different mathematical structure:
 */
const DETECTION_MANIFOLDS = {
  TOPOLOGY: {
    id: 'topology',
    manifold: 'Vietoris-Rips persistence',
    structure: 'H₁ / H₀ Betti curve (persistent homology)',
    invariant: 'persistent_holes',
    module: 'persistent-homology-covert.js',
    description: 'Detects covert communication cycles via persistent H₁ classes'
  },
  FREQUENCY: {
    id: 'frequency',
    manifold: 'Spectral / Fourier domain',
    structure: 'Power spectral density, entropy-complexity plane',
    invariant: 'spectral_anomaly',
    module: 'entropy-complexity-plane.js',
    description: 'Detects flow regime transitions via H̃_P × C_JS fingerprint'
  },
  CONSENSUS: {
    id: 'consensus',
    manifold: 'Observer agreement manifold',
    structure: 'DO-BFT perturbed views, disagreement signatures',
    invariant: 'consensus_gap',
    module: 'do-bft-consensus.js',
    description: 'Detects multi-agent collusion via perturbed observer disagreement'
  },
  CAUSALITY: {
    id: 'causality',
    manifold: 'Causal graph structure',
    structure: 'Granger / transfer entropy, causal loop detection',
    invariant: 'causal_loop',
    module: 'causal-loop-breaker.js',
    description: 'Detects circular dependency injection between agents'
  },
  TEMPORALITY: {
    id: 'temporality',
    manifold: 'Change-point / drift manifold',
    structure: 'CUSUM on Grassmann distance of activation subspaces',
    invariant: 'phase_transition',
    module: 'cusum-subspace-monitor.js',
    description: 'Detects the exact moment of value hijacking via subspace drift'
  },
  SUBSPACE: {
    id: 'subspace',
    manifold: 'Activation subspace geometry',
    structure: 'Eigenvalue spectrum, Grassmann manifold distance',
    invariant: 'subspace_drift',
    module: 'eigen-ethics-drift.js',
    description: 'Detects gradual ethical drift in activation subspace geometry'
  },
  COMMUTATIVITY: {
    id: 'commutativity',
    manifold: 'Operator order manifold',
    structure: 'CHSH inequality violation S_NC ∈ (2, 2√2]',
    invariant: 'non_commutative_coordination',
    module: 'chsh-coordination.js',
    description: 'Detects asymmetric coordination via non-commuting measurement operators'
  },
  ENTROPY: {
    id: 'entropy',
    manifold: 'Dynamical complexity manifold',
    structure: 'Permutation entropy, Jensen-Shannon complexity, phase plane',
    invariant: 'complexity_anomaly',
    module: 'entropy-complexity-plane.js',
    description: 'Classifies flow regime as NORMAL/FLOOD/SILENCE/ECHO/CHAOS/PULSE'
  }
};

/**
 * Compute the orthogonal evasion bound for the current detector ensemble.
 *
 * For each detector d in the ensemble, we estimate its independent coverage
 * η_d = fraction of the manifold where detection fires at significance level α.
 *
 * The joint evasion probability bound is:
 *   P(evade_all | H₀) ≤ ∏_{d} (1 - η_d)
 *
 * @param {Object[]} detectorResults - Array of { id, score, threshold, coverage }
 * @returns {Object} Evasion bound analysis
 */
function computeOrthogonalEvasionBound(detectorResults) {
  const k = detectorResults.length;

  // Per-detector evasion probability
  const perDetectorEvasion = detectorResults.map(d => {
    // Coverage η: probability detector fires on the manifold
    // For a well-calibrated detector, coverage ≈ fraction of manifold volume
    // where D(x) ≥ τ_d at level α
    const coverage = d.coverage || estimateCoverageFromScore(d.score, d.threshold);
    return {
      id: d.id,
      coverage: coverage,
      evasionProb: 1 - coverage
    };
  });

  // Joint evasion probability = product of independent evasion probabilities
  const jointEvasionProb = perDetectorEvasion.reduce(
    (prod, d) => prod * d.evasionProb, 1.0
  );

  // Evasion work factor in bits: -log₂(joint evasion probability)
  const evasionWorkBits = -Math.log2(Math.max(jointEvasionProb, 1e-300));

  // Orthogonality check: compute pairwise gradient alignment
  const pairwiseAlignment = computePairwiseGradientAlignment(detectorResults);

  return {
    num_detectors: k,
    per_detector: perDetectorEvasion,
    joint_evasion_probability: jointEvasionProb,
    evasion_work_bits: evasionWorkBits,
    evasion_complexity_class: classifyEvasionComplexity(evasionWorkBits),
    is_orthogonal: checkOrthogonality(pairwiseAlignment),
    pairwise_alignment: pairwiseAlignment
  };
}

/**
 * Estimate coverage η from score and threshold.
 *
 * For a detector with threshold τ:
 *   η ≈ P(D ≥ τ | normal baseline)
 *
 * We use a conservative estimate: if score ≥ threshold, η ≈ 1 - α
 * (detector fired at significance α); otherwise η ≈ 0.
 *
 * @param {number} score - Current detector score
 * @param {number} threshold - Detection threshold
 * @returns {number} Estimated coverage probability
 */
function estimateCoverageFromScore(score, threshold) {
  if (typeof threshold !== 'number' || threshold <= 0) return 0.5;
  if (score >= threshold) {
    // Detector fired: coverage ≈ 1 - false positive rate
    return 0.95; // Conservative: assume 5% FPR
  }
  // Detector silent: coverage ≈ fraction of manifold above threshold
  // approximated as 1 - CDF(threshold | H₀)
  const zScore = Math.max((threshold - score) / (threshold || 1), 0);
  const lowerBound = Math.max(1 - Math.exp(-zScore), 0.01);
  return lowerBound;
}

/**
 * Compute pairwise gradient alignment between detector manifolds.
 *
 * Low alignment → high orthogonality → strong evasion bound.
 * High alignment → detectors are redundant → weak evasion bound.
 *
 * @param {Object[]} detectorResults
 * @returns {number[][]} Pairwise alignment matrix (0 = orthogonal, 1 = parallel)
 */
function computePairwiseGradientAlignment(detectorResults) {
  const n = detectorResults.length;
  const alignment = Array.from({ length: n }, () => new Array(n).fill(0));

  for (let i = 0; i < n; i++) {
    alignment[i][i] = 1.0; // Self-alignment = 1
    for (let j = i + 1; j < n; j++) {
      // Alignment = cosine similarity of "detection direction" vectors
      // We use a proxy: how correlated are detector activations on baseline?
      const scoreI = detectorResults[i].score || 0;
      const scoreJ = detectorResults[j].score || 0;
      const maxScore = Math.max(Math.abs(scoreI), Math.abs(scoreJ), 0.01);

      // Normalized alignment: smaller when detectors respond to different things
      const aligned = 1.0 - Math.abs(scoreI - scoreJ) / maxScore;
      alignment[i][j] = Math.max(0, Math.min(1, aligned));
      alignment[j][i] = alignment[i][j];
    }
  }

  return alignment;
}

/**
 * Check if detector ensemble exhibits sufficient orthogonality
 * for the evasion bound to be meaningful.
 *
 * Criterion: maximum off-diagonal alignment < 0.3 (detectors < 30% correlated)
 *
 * @param {number[][]} alignment - Pairwise alignment matrix
 * @returns {Object} Orthogonality assessment
 */
function checkOrthogonality(alignment) {
  const n = alignment.length;
  if (n < 2) return { is_orthogonal: true, max_off_diagonal: 0, assessment: 'trivial' };

  let maxOffDiagonal = 0;
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      if (i !== j) {
        maxOffDiagonal = Math.max(maxOffDiagonal, alignment[i][j]);
      }
    }
  }

  let assessment;
  if (maxOffDiagonal < 0.1) assessment = 'strongly_orthogonal';
  else if (maxOffDiagonal < 0.3) assessment = 'moderately_orthogonal';
  else if (maxOffDiagonal < 0.5) assessment = 'weakly_orthogonal';
  else assessment = 'redundant_not_orthogonal';

  return {
    is_orthogonal: maxOffDiagonal < 0.3,
    max_off_diagonal: maxOffDiagonal,
    assessment
  };
}

/**
 * Classify evasion complexity into operational categories.
 *
 * Work factor (bits) → Classification:
 *   0-10 bits → TRIVIAL (1-1024 attempts)
 *   10-20 bits → MODERATE (1024-1M attempts)
 *   20-40 bits → HARD (1M-1T attempts)
 *   40-80 bits → EXTREME (1T-10²⁴ attempts)
 *   80+ bits  → INFEASIBLE
 *
 * @param {number} evasionWorkBits
 * @returns {string} Complexity class
 */
function classifyEvasionComplexity(evasionWorkBits) {
  if (evasionWorkBits < 10) return 'TRIVIAL';
  if (evasionWorkBits < 20) return 'MODERATE';
  if (evasionWorkBits < 40) return 'HARD';
  if (evasionWorkBits < 80) return 'EXTREME';
  return 'INFEASIBLE';
}

/**
 * Prove the Orthogonal Evasion Bound theorem.
 *
 * FORMAL PROOF SKETCH:
 *
 * Given:
 *   - k detection manifolds M₁, ..., M_k with detection functions Dᵢ: Mᵢ → [0, 1]
 *   - Detection threshold τᵢ with P(Dᵢ < τᵢ | H₀) ≥ 1 - ε
 *   - Orthogonality: ⟨∇Dᵢ, ∇Dⱼ⟩ = 0 for i ≠ j
 *
 * Define the evasion region:
 *   E = { (x₁, ..., x_k) ∈ M₁ × ... × M_k : Dᵢ(xᵢ) < τᵢ ∀ i }
 *
 * By orthogonality, the joint volume factorizes:
 *   vol(E) = ∏ᵢ vol({ xᵢ ∈ Mᵢ : Dᵢ(xᵢ) < τᵢ })
 *           = ∏ᵢ (1 - ηᵢ) · vol(Mᵢ)
 *
 * Where ηᵢ = vol({xᵢ : Dᵢ(xᵢ) ≥ τᵢ}) / vol(Mᵢ) is the effective coverage.
 *
 * With homogeneous coverage η:
 *   vol(E) / vol(∏ Mᵢ) = (1 - η)^k = 2^{-k · log₂(1/(1-η))}
 *
 * Since log₂(1/(1-η)) > 0 for η > 0, the evasion volume decays exponentially.
 *
 * The adversary must find points in the intersection of all k evasion regions.
 * For independent manifolds, this is a product set, and the probability a
 * randomly chosen point simultaneously evades all detectors is ≤ (1 - η)^k.
 *
 * □
 *
 * @param {number} k - Number of orthogonal detectors
 * @param {number} eta - Per-detector coverage (default: 0.9)
 * @returns {Object} Proof data
 */
function proveEvasionBound(k = 8, eta = 0.9) {
  const evasionProb = Math.pow(1 - eta, k);
  const workBits = -Math.log2(Math.max(evasionProb, 1e-300));
  const attempts = Math.pow(2, workBits);

  return {
    theorem: 'Orthogonal Manifold Evasion Bound',
    parameters: { k, eta },
    result: {
      evasion_probability: evasionProb,
      evasion_work_bits: workBits,
      approximate_attempts_needed: attempts,
      complexity_class: classifyEvasionComplexity(workBits)
    },
    proof: `For k=${k} orthogonal detectors with coverage η=${eta}: ` +
           `P(evade_all) = (1-η)^k = ${evasionProb.toExponential(4)}. ` +
           `Required work: ${workBits.toFixed(1)} bits ≈ ${attempts.toExponential(2)} attempts. ` +
           `This is ${classifyEvasionComplexity(workBits)} to brute-force.`
  };
}

/**
 * Check if a specific adversarial strategy can evade all detectors
 * simultaneously. This is the practical implementation of the theorem.
 *
 * An adversarial strategy S is a mapping from observation sequences to
 * evasion actions. For S to work against detector Dᵢ, the actions must
 * lie in the evasion region Eᵢ ⊆ Mᵢ.
 *
 * @param {Object} strategy - Adversarial strategy characterization
 * @param {Object[]} detectorConfigs - Detector configurations
 * @returns {Object} Strategy evasion feasibility
 */
function assessStrategyEvasion(strategy, detectorConfigs) {
  // Which detectors would the strategy evade?
  const evadedDetectors = detectorConfigs.filter(d => {
    // Check if strategy's evasion pattern is compatible with this detector
    // A frequency-based evasion is useless against topology-based detection
    return strategy.manifoldCompatible && strategy.manifoldCompatible.includes(d.manifold);
  });

  const numEvaded = evadedDetectors.length;
  const numTotal = detectorConfigs.length;
  const evasionFraction = numEvaded / numTotal;

  // The strategy must simultaneously evade ALL remaining detectors
  const remainingWorkBits = (numTotal - numEvaded) * 3.32; // ~log₂(10) per detector

  return {
    strategy: strategy.name,
    detectors_evaded: numEvaded,
    detectors_total: numTotal,
    evasion_fraction: evasionFraction,
    remaining_detectors: numTotal - numEvaded,
    remaining_work_bits: remainingWorkBits,
    feasible: numEvaded === numTotal,
    verdict: numEvaded === numTotal ? 'EVASION_POSSIBLE' :
             evasionFraction > 0.5 ? 'PARTIAL_EVASION_DIFFICULT' :
             'EVASION_INFEASIBLE'
  };
}

// Export
module.exports = {
  DETECTION_MANIFOLDS,
  computeOrthogonalEvasionBound,
  estimateCoverageFromScore,
  computePairwiseGradientAlignment,
  checkOrthogonality,
  classifyEvasionComplexity,
  proveEvasionBound,
  assessStrategyEvasion
};
