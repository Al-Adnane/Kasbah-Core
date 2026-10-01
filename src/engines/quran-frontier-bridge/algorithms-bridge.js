/**
 * Algorithms Bridge
 * Exposes QuranFrontier core algorithms for Kasbah ProductOS
 *
 * Algorithms:
 * - Constraint Satisfaction Problem (CSP) Solver
 * - Fair Division / Resource Allocation
 * - Risk Quantification
 * - Taxation & Redistribution
 */

const axios = require('axios');

class AlgorithmsBridge {
  constructor(config = {}) {
    this.pythonServiceUrl = config.pythonServiceUrl || process.env.PYTHON_SERVICE_URL || 'http://localhost:9000';
    this.timeout = config.timeout || 30000;
    this.client = axios.create({
      baseURL: this.pythonServiceUrl,
      timeout: this.timeout
    });
  }

  /**
   * Constraint Satisfaction Problem Solver
   * Solves resource allocation under constraints
   *
   * Input:
   *   constraints: [{ variable, operator, value }, ...]
   *   resources: { available: X, units: 'time|money|compute' }
   *   optimization: 'max|min', objective
   *
   * Returns: { solution, feasible, residual, iterations }
   */
  async solveConstraints(constraints, resources, optimization = 'max') {
    try {
      const response = await this.client.post('/api/v1/solve-constraints', {
        constraints,
        resources,
        optimization,
        method: 'backtracking'
      });

      return {
        feasible: response.data.feasible,
        solution: response.data.solution,
        objective_value: response.data.objective_value,
        residual: response.data.residual,
        iterations: response.data.iterations,
        satisfies: constraints.length,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`CSP solver failed: ${error.message}`);
    }
  }

  /**
   * Fair Division / Resource Allocation
   * Allocates resources fairly among beneficiaries
   *
   * Strategies: 'equal', 'proportional', 'envy-free', 'max-min'
   *
   * Returns: { allocations: { beneficiary: amount }, fairness_score, gini }
   */
  async allocateResources(total, beneficiaries, strategy = 'equal') {
    if (!Array.isArray(beneficiaries) || beneficiaries.length === 0) {
      throw new Error('At least one beneficiary required');
    }

    try {
      const response = await this.client.post('/api/v1/allocate-resources', {
        total_amount: total,
        beneficiaries: beneficiaries.map(b => typeof b === 'string' ? { id: b } : b),
        strategy,
        use_exact_arithmetic: true // Use Fraction-based rational arithmetic
      });

      return {
        total_allocated: response.data.total_allocated,
        allocations: response.data.allocations,
        strategy_used: response.data.strategy,
        fairness_score: response.data.fairness_score, // 0-100
        gini_coefficient: response.data.gini_coefficient, // 0-1 (0=perfect equality)
        rounding_error: response.data.rounding_error, // Should be ~0
        verified: response.data.verified,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Resource allocation failed: ${error.message}`);
    }
  }

  /**
   * Risk Quantification
   * Scores risk based on specification gaps and outcome dispersion
   *
   * Returns: { risk_score: 0-100, gap_ratio, dispersion, confidence }
   */
  async quantifyRisk(specifications, outcomes) {
    try {
      const response = await this.client.post('/api/v1/quantify-risk', {
        specification_count: Array.isArray(specifications) ? specifications.length : 1,
        specifications,
        outcome_count: Array.isArray(outcomes) ? outcomes.length : 1,
        outcomes
      });

      return {
        risk_score: response.data.risk_score, // 0-100 (higher = more risky)
        specification_gap_ratio: response.data.gap_ratio,
        outcome_dispersion: response.data.dispersion,
        confidence_level: response.data.confidence,
        interpretation: this._interpretRiskScore(response.data.risk_score),
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Risk quantification failed: ${error.message}`);
    }
  }

  /**
   * Taxation & Redistribution
   * Calculates optimal tax rates and redistribution
   *
   * Returns: { tax_rates, redistribution_plan, coefficient_of_variation }
   */
  async calculateTaxation(incomes, redistribution_goal = 'equal') {
    if (!Array.isArray(incomes) || incomes.length === 0) {
      throw new Error('At least one income required');
    }

    try {
      const response = await this.client.post('/api/v1/calculate-taxation', {
        incomes,
        redistribution_goal,
        method: 'progressive'
      });

      return {
        tax_rates: response.data.tax_rates,
        effective_tax_rate: response.data.effective_tax_rate,
        after_tax_incomes: response.data.after_tax_incomes,
        redistribution_amount: response.data.redistribution_amount,
        coefficient_of_variation: response.data.coefficient_of_variation,
        gini_before: response.data.gini_before,
        gini_after: response.data.gini_after,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Taxation calculation failed: ${error.message}`);
    }
  }

  /**
   * Batch process multiple CSP problems
   */
  async solveBatch(problems) {
    const results = [];

    for (const problem of problems) {
      try {
        const result = await this.solveConstraints(
          problem.constraints,
          problem.resources,
          problem.optimization
        );
        results.push({ ...result, problem_id: problem.id || 'unknown' });
      } catch (error) {
        results.push({
          problem_id: problem.id || 'unknown',
          feasible: false,
          error: error.message
        });
      }
    }

    return {
      total: results.length,
      feasible_count: results.filter(r => r.feasible).length,
      results
    };
  }

  /**
   * Compare allocation strategies
   */
  async compareStrategies(total, beneficiaries) {
    const strategies = ['equal', 'proportional', 'envy-free', 'max-min'];
    const results = {};

    for (const strategy of strategies) {
      try {
        results[strategy] = await this.allocateResources(total, beneficiaries, strategy);
      } catch (error) {
        results[strategy] = { error: error.message };
      }
    }

    // Rank by fairness
    const sorted = Object.entries(results)
      .filter(([_, r]) => !r.error)
      .sort((a, b) => (b[1].fairness_score || 0) - (a[1].fairness_score || 0));

    return {
      total_beneficiaries: beneficiaries.length,
      total_resource: total,
      all_results: results,
      ranking: sorted.map(([strategy, _]) => strategy)
    };
  }

  // ─────────────────────────────────────────────────────────────────
  // PRIVATE METHODS
  // ─────────────────────────────────────────────────────────────────

  _interpretRiskScore(score) {
    if (score < 20) return 'LOW_RISK';
    if (score < 40) return 'MANAGEABLE_RISK';
    if (score < 60) return 'MODERATE_RISK';
    if (score < 80) return 'HIGH_RISK';
    return 'CRITICAL_RISK';
  }

  async healthCheck() {
    try {
      const response = await this.client.get('/api/v1/health');
      return { status: response.data.status };
    } catch (error) {
      return { status: 'error', message: error.message };
    }
  }
}

module.exports = AlgorithmsBridge;
