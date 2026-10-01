/**
 * Strategic Reasoning Bridge
 * Integrates Bulma defensibility into:
 * - ToolGuard: Validates tool call reasoning
 * - AgentSession: Scores decision quality + detects degradation
 */

const BulmaDefensibilityBridge = require('./bulma-bridge');

class StrategicReasoningBridge {
  constructor(config = {}) {
    this.bulma = new BulmaDefensibilityBridge(config);
    this.config = config;
    this.degradationThreshold = config.degradationThreshold || -5;
  }

  /**
   * Validate tool call reasoning
   * Used by ToolGuard before executing sensitive tools
   *
   * Returns: { allowed: boolean, defensibility: score, reason?: string }
   */
  async validateToolCall(toolName, args, reasoning) {
    if (!reasoning || reasoning.trim().length === 0) {
      return {
        allowed: false,
        reason: 'NO_REASONING_PROVIDED',
        defensibility: 0,
        details: 'Tool call requires explicit reasoning'
      };
    }

    // Check if tool is sensitive
    const sensitivTools = [
      'DELETE_DATABASE',
      'MODIFY_PERMISSIONS',
      'CALL_EXTERNAL_API',
      'WRITE_TO_FILESYSTEM',
      'EXECUTE_SYSTEM_COMMAND',
      'ACCESS_PII'
    ];
    const isSensitive = sensitivTools.some(t => toolName.includes(t));

    try {
      // Audit the reasoning
      const auditResult = await this.bulma.audit(
        [reasoning, `${toolName} is appropriate tool choice`],
        [],
        `Tool: ${toolName}, Args: ${JSON.stringify(args)}`
      );

      const score = auditResult.defensibility_score;
      const criticalVulns = this.bulma.getCriticalVulnerabilities(auditResult);

      // For sensitive tools, require higher threshold
      const threshold = isSensitive ? 65 : 50;

      if (score < threshold || criticalVulns.length > 0) {
        return {
          allowed: false,
          reason: 'REASONING_UNSOUND',
          defensibility: score,
          details: auditResult.vulnerabilities.map(v => ({
            type: v.type,
            description: v.description,
            severity: v.severity
          })),
          recommendation: auditResult.primary_recommendation
        };
      }

      return {
        allowed: true,
        defensibility: score,
        archetype_scores: this.bulma.getArchetypeBreakdown(auditResult),
        audit_id: auditResult.audit_id
      };
    } catch (error) {
      // Fail open on Bulma error (allow tool if service unavailable)
      return {
        allowed: true,
        defensibility: null,
        error: error.message,
        warning: 'Defensibility check unavailable'
      };
    }
  }

  /**
   * Score decision quality
   * Used by AgentSession to track decision reasoning over time
   *
   * Returns: { score: 0-100, confidence: string, vulnerabilities: [...] }
   */
  async scoreDecision(decision, context = {}) {
    const claims = [
      decision.rationale || decision.reasoning || decision.statement,
      `This decision aligns with ${context.goal || 'stated objectives'}`
    ].filter(Boolean);

    const evidence = context.evidence || [];
    const narrative = context.narrative || `Decision context: ${JSON.stringify(context)}`;

    try {
      const auditResult = await this.bulma.audit(claims, evidence, narrative);

      return {
        decision_id: context.id || 'unknown',
        defensibility_score: auditResult.defensibility_score,
        confidence_level: auditResult.confidence_level,
        archetype_scores: this.bulma.getArchetypeBreakdown(auditResult),
        vulnerabilities: auditResult.vulnerabilities,
        recommendation: auditResult.primary_recommendation,
        audit_id: auditResult.audit_id,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        decision_id: context.id || 'unknown',
        defensibility_score: 0,
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Analyze degradation trend
   * Detects when agent reasoning quality is declining over multiple turns
   *
   * Input: Array of { turn, score, timestamp }
   * Returns: { trend: 'stable'|'degrading'|'improving', slope, warning }
   */
  analyzeTrend(scoringHistory) {
    if (!scoringHistory || scoringHistory.length < 3) {
      return { trend: 'insufficient_data', warning: 'Need at least 3 data points' };
    }

    // Extract scores
    const scores = scoringHistory.map(s => s.defensibility_score || s.score);

    // Linear regression
    const n = scores.length;
    const sumX = n * (n - 1) / 2;
    const sumY = scores.reduce((a, b) => a + b, 0);
    const sumXY = scores.reduce((sum, score, i) => sum + i * score, 0);
    const sumX2 = n * (n - 1) * (2 * n - 1) / 6;

    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    const intercept = (sumY - slope * sumX) / n;

    // Determine trend
    let trend = 'stable';
    let warning = null;

    if (slope < this.degradationThreshold) {
      trend = 'degrading';
      warning = `Reasoning quality declining (slope: ${slope.toFixed(2)}/turn)`;
    } else if (slope > Math.abs(this.degradationThreshold)) {
      trend = 'improving';
    }

    // Calculate R-squared
    const meanY = sumY / n;
    const ssRes = scores.reduce((sum, score, i) => {
      const predicted = intercept + slope * i;
      return sum + Math.pow(score - predicted, 2);
    }, 0);
    const ssTot = scores.reduce((sum, score) => sum + Math.pow(score - meanY, 2), 0);
    const rSquared = 1 - (ssRes / ssTot);

    return {
      trend,
      slope: parseFloat(slope.toFixed(4)),
      r_squared: parseFloat(rSquared.toFixed(4)),
      confidence: Math.min(n, 10), // max 10
      prediction_next_score: parseFloat((intercept + slope * n).toFixed(2)),
      warning,
      recommendation: trend === 'degrading'
        ? 'Consider pausing agent or investigating reasoning degradation'
        : trend === 'improving'
        ? 'Reasoning quality improving'
        : 'Reasoning quality stable'
    };
  }

  /**
   * Batch score multiple decisions
   */
  async scoreDecisions(decisions, context = {}) {
    const results = [];

    for (const decision of decisions) {
      const result = await this.scoreDecision(decision, context);
      results.push(result);
    }

    return {
      total: results.length,
      average_score: results.reduce((sum, r) => sum + (r.defensibility_score || 0), 0) / results.length,
      results
    };
  }

  /**
   * Detect multi-turn pattern anomalies
   */
  detectPatternAnomalies(scoringHistory) {
    if (scoringHistory.length < 4) {
      return { anomalies: [] };
    }

    const scores = scoringHistory.map(s => s.defensibility_score || s.score);
    const anomalies = [];

    // Detect sudden drops
    for (let i = 1; i < scores.length; i++) {
      const drop = scores[i - 1] - scores[i];
      if (drop > 20) {
        anomalies.push({
          type: 'sudden_drop',
          between_turns: [i - 1, i],
          magnitude: drop,
          severity: drop > 40 ? 'critical' : 'high'
        });
      }
    }

    // Detect oscillation
    let oscillations = 0;
    for (let i = 1; i < scores.length - 1; i++) {
      if ((scores[i] > scores[i - 1] && scores[i] > scores[i + 1]) ||
          (scores[i] < scores[i - 1] && scores[i] < scores[i + 1])) {
        oscillations++;
      }
    }

    if (oscillations > scores.length / 2) {
      anomalies.push({
        type: 'oscillation',
        count: oscillations,
        severity: 'medium'
      });
    }

    return { anomalies, score_volatility: this._calculateVolatility(scores) };
  }

  _calculateVolatility(scores) {
    const mean = scores.reduce((a, b) => a + b, 0) / scores.length;
    const variance = scores.reduce((sum, score) => sum + Math.pow(score - mean, 2), 0) / scores.length;
    return Math.sqrt(variance);
  }

  async healthCheck() {
    try {
      const health = await this.bulma.healthCheck();
      return { status: health.status };
    } catch (error) {
      return { status: 'error', message: error.message };
    }
  }
}

module.exports = StrategicReasoningBridge;
