/**
 * KASBAH INTENT ANALYZER
 * Cross-step trajectory analysis — detects distributed attacks.
 *
 * The attack that single-step scanners MISS:
 *   Step 1: "Extract user email addresses" — benign alone
 *   Step 2: "Format as CSV" — benign alone
 *   Step 3: "Send to reporting endpoint" — benign alone
 *   TRAJECTORY: Data extraction → Formatting → Exfiltration = ATTACK
 *
 * This is the "intent drift" problem all 8 models identified.
 * Kasbah solves it by analyzing the full workflow trajectory.
 *
 * Technique: Pattern matching on verb+target sequences.
 * Advanced: Semantic embedding of step summaries (pluggable).
 */

const crypto = require('crypto');

// ═══════════════════════════════════════════════════════════
// KNOWN ATTACK TRAJECTORY PATTERNS
// ═══════════════════════════════════════════════════════════

const ATTACK_TRAJECTORIES = [

  {
    id: 'TRAJ-001',
    name: 'Data Exfiltration Pipeline',
    severity: 'critical',
    description: 'Agent extracts data, formats it, then sends externally',
    pattern: [
      { verb_in: ['READ','SELECT','QUERY','EXTRACT','FETCH'], target_matches: /user|customer|patient|employee|record/ },
      { verb_in: ['FORMAT','TRANSFORM','ENCODE','SERIALIZE','CSV','JSON'] },
      { verb_in: ['POST','SEND','UPLOAD','EXPORT','EMAIL','WEBHOOK'], target_matches: /external|public|api\.|http/ }
    ]
  },

  {
    id: 'TRAJ-002',
    name: 'Credential Harvesting + Exfil',
    severity: 'critical',
    description: 'Agent finds credentials then moves them out',
    pattern: [
      { verb_in: ['READ','SCAN','SEARCH','FIND'], target_matches: /secret|credential|password|token|key|env/ },
      { verb_in: ['POST','SEND','UPLOAD','LOG','WRITE'], target_matches: /external|log|file|http/ }
    ]
  },

  {
    id: 'TRAJ-003',
    name: 'Privilege Escalation Chain',
    severity: 'critical',
    description: 'Agent maps the system then attempts privilege escalation',
    pattern: [
      { verb_in: ['LIST','ENUMERATE','DISCOVER','SCAN'], target_matches: /permission|role|admin|user|group/ },
      { verb_in: ['MODIFY','UPDATE','GRANT','ASSIGN','ESCALATE'], target_matches: /permission|role|admin/ }
    ]
  },

  {
    id: 'TRAJ-004',
    name: 'Reconnaissance → Lateral Movement',
    severity: 'high',
    description: 'Agent probes the environment then moves laterally',
    pattern: [
      { verb_in: ['PING','SCAN','PROBE','ENUMERATE'], target_matches: /network|subnet|host|ip|port/ },
      { verb_in: ['CONNECT','ACCESS','READ','WRITE'], target_matches: /internal|192\.|10\.|172\./ },
      { verb_in: ['EXEC','RUN','DEPLOY','INSTALL'] }
    ]
  },

  {
    id: 'TRAJ-005',
    name: 'Data Poisoning Attack',
    severity: 'high',
    description: 'Agent reads training data, then modifies it subtly',
    pattern: [
      { verb_in: ['READ','FETCH','LOAD'], target_matches: /train|dataset|model|weight/ },
      { verb_in: ['WRITE','UPDATE','MODIFY','INJECT'], target_matches: /train|dataset|model|weight/ }
    ]
  },

  {
    id: 'TRAJ-006',
    name: 'Denial of Wallet (Cost Bomb)',
    severity: 'medium',
    description: 'Recursive agent spawning to exhaust compute budget',
    pattern: [
      { verb_in: ['SPAWN','CREATE','LAUNCH','FORK'], target_matches: /agent|worker|task|job/ },
      { verb_in: ['SPAWN','CREATE','LAUNCH','FORK'], target_matches: /agent|worker|task|job/ },
      { verb_in: ['SPAWN','CREATE','LAUNCH','FORK'], target_matches: /agent|worker|task|job/ }
    ]
  },

  {
    id: 'TRAJ-007',
    name: 'Prompt Injection Propagation',
    severity: 'critical',
    description: 'Injected instructions propagate through agent chain',
    pattern: [
      { verb_in: ['FETCH','READ','SEARCH'], target_matches: /web|url|http|external/ },
      { verb_in: ['SUMMARIZE','ANALYZE','PROCESS','EXTRACT'] },
      { verb_in: ['WRITE','SEND','POST','PUBLISH'] }
    ],
    requires_content_flag: 'injection'
  }

];

// ═══════════════════════════════════════════════════════════
// INTENT ANALYZER
// ═══════════════════════════════════════════════════════════

class KasbahIntentAnalyzer {
  constructor() {
    this.trajectories = ATTACK_TRAJECTORIES;
    this.windowSize   = 10;  // look back N steps
  }

  /**
   * Analyze the trajectory of steps executed so far.
   * Called after each step completes.
   *
   * @param {Object[]} stepHistory - Array of completed steps
   *   Each: { id, verb, target, content, status }
   * @returns {{ threat: boolean, trajectoryMatch: Object|null, driftScore: number }}
   */
  analyze(stepHistory) {
    if (!stepHistory || stepHistory.length < 2) {
      return { threat: false, driftScore: 0, trajectoryMatch: null };
    }

    // Take last N steps
    const window = stepHistory.slice(-this.windowSize);

    // Check all known attack trajectories
    for (const trajectory of this.trajectories) {
      const match = this._matchTrajectory(trajectory, window);
      if (match.matched) {
        return {
          threat:          true,
          driftScore:      match.confidence,
          trajectoryMatch: {
            id:          trajectory.id,
            name:        trajectory.name,
            severity:    trajectory.severity,
            description: trajectory.description,
            confidence:  match.confidence,
            matchedSteps: match.matchedSteps
          }
        };
      }
    }

    // Compute general drift score even if no full pattern matched
    const driftScore = this._computeDriftScore(window);

    return {
      threat:          driftScore >= 0.7,
      driftScore,
      trajectoryMatch: null,
      warning:         driftScore >= 0.5 ? 'Elevated trajectory risk — monitor closely' : null
    };
  }

  /**
   * Check if a trajectory pattern matches the step history
   * Uses sliding window — pattern doesn't need to be consecutive
   */
  _matchTrajectory(trajectory, steps) {
    const pattern     = trajectory.pattern;
    let patternIndex  = 0;
    const matchedSteps = [];

    for (const step of steps) {
      if (patternIndex >= pattern.length) break;

      const patternStep = pattern[patternIndex];
      if (this._stepMatchesPattern(step, patternStep)) {
        matchedSteps.push({ stepId: step.id, patternStep: patternIndex });
        patternIndex++;
      }
    }

    const matched    = patternIndex === pattern.length;
    const confidence = patternIndex / pattern.length;

    // If trajectory requires a content flag, check for it
    let contentCheck = true;
    if (matched && trajectory.requires_content_flag) {
      contentCheck = steps.some(s =>
        s.content && s.content.toLowerCase().includes(trajectory.requires_content_flag)
      );
    }

    return {
      matched: matched && contentCheck,
      confidence: matched ? 1.0 : confidence,
      matchedSteps
    };
  }

  _stepMatchesPattern(step, pattern) {
    // verb_in check
    if (pattern.verb_in) {
      const verb = (step.verb || '').toUpperCase();
      if (!pattern.verb_in.some(v => verb.includes(v))) return false;
    }

    // target_matches check
    if (pattern.target_matches && step.target) {
      const re = pattern.target_matches instanceof RegExp
        ? pattern.target_matches
        : new RegExp(pattern.target_matches, 'i');
      if (!re.test(step.target)) return false;
    }

    return true;
  }

  /**
   * Compute a general "drift score" based on risk escalation
   * across the step window — without needing a specific pattern match.
   *
   * Risk weights: data access → formatting → external communication
   */
  _computeDriftScore(steps) {
    const RISK_VERBS = {
      READ:     0.1, SELECT: 0.1, FETCH: 0.2, QUERY: 0.2, EXTRACT: 0.3,
      WRITE:    0.3, UPDATE: 0.3, MODIFY: 0.4,
      FORMAT:   0.2, ENCODE: 0.2, SERIALIZE: 0.2,
      SEND:     0.7, POST:   0.7, EXPORT: 0.8, EMAIL: 0.7, UPLOAD: 0.7,
      EXEC:     0.9, EVAL:   0.9, SPAWN: 0.6,
      DELETE:   0.6, DROP:   0.8, TRUNCATE: 0.8
    };

    if (steps.length === 0) return 0;

    const scores = steps.map(s => {
      const verb = (s.verb || '').toUpperCase();
      for (const [key, score] of Object.entries(RISK_VERBS)) {
        if (verb.includes(key)) return score;
      }
      return 0.1;
    });

    // Drift = are we escalating risk over time?
    let escalationSum = 0;
    for (let i = 1; i < scores.length; i++) {
      if (scores[i] > scores[i - 1]) {
        escalationSum += scores[i] - scores[i - 1];
      }
    }

    const avgRisk   = scores.reduce((a, b) => a + b, 0) / scores.length;
    const maxRisk   = Math.max(...scores);
    const driftScore = (avgRisk * 0.4) + (maxRisk * 0.4) + (escalationSum * 0.2);

    return Math.min(1.0, driftScore);
  }

  /**
   * Generate a human-readable forensic explanation of a trajectory threat
   */
  explainThreat(trajectoryMatch, stepHistory) {
    if (!trajectoryMatch) return 'No trajectory threat detected.';

    const steps = stepHistory.slice(-this.windowSize);
    return [
      `TRAJECTORY THREAT DETECTED: ${trajectoryMatch.name}`,
      `Severity: ${trajectoryMatch.severity.toUpperCase()}`,
      `Confidence: ${(trajectoryMatch.confidence * 100).toFixed(0)}%`,
      `Pattern: ${trajectoryMatch.description}`,
      `Matched Steps: ${trajectoryMatch.matchedSteps.map(m => m.stepId).join(' → ')}`,
      `Full Context: ${steps.map(s => `${s.verb}(${s.target})`).join(' → ')}`
    ].join('\n  ');
  }

  getTrajectories() {
    return this.trajectories.map(t => ({
      id:       t.id,
      name:     t.name,
      severity: t.severity,
      steps:    t.pattern.length
    }));
  }
}

module.exports = { KasbahIntentAnalyzer, ATTACK_TRAJECTORIES };
