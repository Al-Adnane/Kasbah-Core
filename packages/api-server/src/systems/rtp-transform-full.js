// Extracted from ARCHIVE — converted from TypeScript to JS
/**
 * Kasbah RTP Transform Engine
 *
 * Governance-Constrained Resource Allocation via 6-Stage Deterministic Pipeline
 *
 * Pipeline: f0 → f1 → f2 → f3 → f4 → f5
 * - f0: Normalize (text/code → standard form)
 * - f1: Frequency decompose (FFT → risk spectrum)
 * - f2: Readiness DAG (dependency graph)
 * - f3: Modulator I = L^n · P^(-m) · C^k
 * - f4: Brittleness reject (β > threshold → DENY)
 * - f5: Legal artifact (HMAC ticket + hash chain)
 *
 * @version 1.0.0
 * @patent Pending (AGENTUARD-PATENT-A-BRITTLENESS)
 */

'use strict';

const crypto = require('crypto');

// ═══════════════════════════════════════════════════════════════════════════
// RTP TRANSFORM ENGINE
// ═══════════════════════════════════════════════════════════════════════════

class RTPTransformEngine {
  constructor(config = {}) {
    this.config = {
      brittlenessThreshold: config.brittlenessThreshold !== undefined ? config.brittlenessThreshold : 50,
      latencyBudgetMs:      config.latencyBudgetMs      !== undefined ? config.latencyBudgetMs      : 100,
      enableHashChain:      config.enableHashChain      !== false,
      hmacSecret:           config.hmacSecret           || process.env.KASBAH_PROOF_KEY || (() => {
        if (process.env.NODE_ENV === 'production') throw new Error('RTP hmacSecret / KASBAH_PROOF_KEY must be set in production');
        return 'kasbah-rtp-dev-' + require('crypto').randomBytes(8).toString('hex');
      })(),
      n: config.n || 2,
      m: config.m || 1,
      k: config.k || 1
    };

    this.hashChain      = [];
    this.receiptCounter = 0;

    this._validateConfig();
  }

  _validateConfig() {
    if (process.env.NODE_ENV === 'production' && !process.env.KASBAH_PROOF_KEY) {
      throw new Error('KASBAH_PROOF_KEY must be set in production');
    }
    if (this.config.brittlenessThreshold < 0 || this.config.brittlenessThreshold > 100) {
      throw new Error('Brittleness threshold must be 0-100');
    }
    if (this.config.latencyBudgetMs < 10 || this.config.latencyBudgetMs > 1000) {
      throw new Error('Latency budget must be 10-1000ms');
    }
  }

  // ─── MAIN ENTRY POINT ────────────────────────────────────────────────────

  async transform(input) {
    const startTime = Date.now();

    try {
      const f0Result = await this._f0_normalize(input);
      const f1Result = await this._f1_frequencyDecompose(f0Result, input);
      const f2Result = await this._f2_readinessDAG(f1Result, input);
      const f3Result = await this._f3_modulator(f2Result, input);
      const f4Result = await this._f4_brittlenessReject(f3Result, input);
      const f5Result = await this._f5_legalArtifact(f4Result, input, startTime);

      const decision = f4Result.rejected ? 'DENY' : f3Result.output < 0.3 ? 'DEFER' : 'APPROVE';
      const ticket   = this._generateExecutionTicket(input, f5Result, decision);
      const receipt  = await this._generateAuditReceipt(input, f5Result, ticket);

      return {
        decision,
        brittlenessScore: f4Result.score,
        modulatorOutput:  f3Result.output,
        latencyMs: Date.now() - startTime,
        stages: { f0: f0Result, f1: f1Result, f2: f2Result, f3: f3Result, f4: f4Result, f5: f5Result },
        ticket,
        auditReceipt: receipt
      };
    } catch (error) {
      return this._createDenyResult(input, error, Date.now() - startTime);
    }
  }

  // ─── STAGE f0: NORMALIZE ─────────────────────────────────────────────────

  async _f0_normalize(input) {
    const keys        = Object.keys(input.payload || {}).sort();
    const standardForm = JSON.stringify(input.payload, keys);
    const hash        = crypto.createHash('sha256').update(standardForm).digest('hex');
    return { normalized: true, standardForm, hash };
  }

  // ─── STAGE f1: FREQUENCY DECOMPOSE ───────────────────────────────────────

  async _f1_frequencyDecompose(f0, input) {
    const sequence           = this._textToNumericSequence(f0.standardForm);
    const spectrum           = this._fftMagnitude(sequence);
    const dominantFrequencies = this._extractDominantFrequencies(spectrum);
    const riskIndicators     = this._identifyRiskIndicators(spectrum, input);
    return { spectrum, dominantFrequencies, riskIndicators };
  }

  _textToNumericSequence(text) {
    const sequence = new Array(256).fill(0);
    for (let i = 0; i < text.length; i++) {
      sequence[text.charCodeAt(i) % 256]++;
    }
    return sequence;
  }

  /**
   * Real-valued FFT magnitude via DFT (O(n²) — safe for fixed 256-element input).
   * Returns the magnitude spectrum (|X[k]|) for k=0..n-1.
   */
  _fftMagnitude(sequence) {
    const n   = sequence.length;
    const mag = new Array(n);
    const TWO_PI = 2 * Math.PI;

    for (let k = 0; k < n; k++) {
      let re = 0;
      let im = 0;
      for (let t = 0; t < n; t++) {
        const angle = (TWO_PI * k * t) / n;
        re += sequence[t] * Math.cos(angle);
        im -= sequence[t] * Math.sin(angle);
      }
      mag[k] = Math.sqrt(re * re + im * im);
    }
    return mag;
  }

  _extractDominantFrequencies(spectrum) {
    const maxMag    = Math.max(...spectrum);
    const threshold = maxMag * 0.5;
    return spectrum
      .map((magnitude, index) => ({ magnitude, index }))
      .filter(x => x.magnitude > threshold)
      .slice(0, 10)
      .map(x => x.index);
  }

  _identifyRiskIndicators(spectrum, input) {
    const indicators = [];
    const half       = Math.floor(spectrum.length / 2);
    const highFreqEnergy = spectrum.slice(half).reduce((a, b) => a + b, 0);
    const totalEnergy    = spectrum.reduce((a, b) => a + b, 0);

    if (totalEnergy > 0 && highFreqEnergy / totalEnergy > 0.3) {
      indicators.push('High-frequency content detected (possible obfuscation)');
    }
    if (input.context && input.context.environment === 'production') {
      indicators.push('Production environment (elevated scrutiny)');
    }
    if (input.context && input.context.priority === 'critical') {
      indicators.push('Critical priority action (expedited review)');
    }
    return indicators;
  }

  // ─── STAGE f2: READINESS DAG ─────────────────────────────────────────────

  async _f2_readinessDAG(f1, input) {
    const dag          = this._buildDependencyGraph(input);
    const criticalPath = this._findCriticalPath(dag);
    const readinessScore = this._calculateReadinessScore(dag, criticalPath);
    return { dag, criticalPath, readinessScore };
  }

  _buildDependencyGraph(input) {
    const nodes = [{
      id: 'validation',
      dependencies: [],
      estimatedLatencyMs: 5,
      resourceCost: 0.1,
      riskLevel: 'low'
    }];

    switch (input.action) {
      case 'DELETE':
      case 'DROP':
      case 'TRUNCATE':
        nodes.push({ id: 'destructive_action_check', dependencies: ['validation'], estimatedLatencyMs: 15, resourceCost: 0.3, riskLevel: 'high' });
        nodes.push({ id: 'backup_verification',       dependencies: ['destructive_action_check'], estimatedLatencyMs: 20, resourceCost: 0.5, riskLevel: 'medium' });
        break;
      case 'CREATE':
      case 'INSERT':
        nodes.push({ id: 'quota_check', dependencies: ['validation'], estimatedLatencyMs: 10, resourceCost: 0.2, riskLevel: 'low' });
        break;
      case 'EXECUTE':
        nodes.push({ id: 'permission_check',  dependencies: ['validation'],       estimatedLatencyMs: 10, resourceCost: 0.2, riskLevel: 'medium' });
        nodes.push({ id: 'sandbox_preparation', dependencies: ['permission_check'], estimatedLatencyMs: 15, resourceCost: 0.4, riskLevel: 'medium' });
        break;
      default:
        nodes.push({ id: 'standard_check', dependencies: ['validation'], estimatedLatencyMs: 8, resourceCost: 0.15, riskLevel: 'low' });
    }
    return nodes;
  }

  _findCriticalPath(dag) {
    const visited = new Set();
    const path    = [];

    const dfs = (nodeId) => {
      if (visited.has(nodeId)) return;
      visited.add(nodeId);
      const node = dag.find(n => n.id === nodeId);
      if (!node) return;
      for (const dep of node.dependencies) dfs(dep);
      path.push(nodeId);
    };

    for (const node of dag) dfs(node.id);
    return path;
  }

  _calculateReadinessScore(dag, criticalPath) {
    const totalLatency = criticalPath.reduce((sum, nodeId) => {
      const node = dag.find(n => n.id === nodeId);
      return sum + (node ? node.estimatedLatencyMs : 0);
    }, 0);

    const latencyScore = Math.max(0, 1 - totalLatency / this.config.latencyBudgetMs);

    const riskWeights = { low: 0.1, medium: 0.3, high: 0.6 };
    const totalRisk   = dag.reduce((sum, node) => sum + (riskWeights[node.riskLevel] || 0), 0);
    const riskScore   = Math.max(0, 1 - totalRisk / dag.length);

    return (latencyScore + riskScore) / 2;
  }

  // ─── STAGE f3: MODULATOR I = L^n · P^(-m) · C^k ─────────────────────────

  async _f3_modulator(f2, input) {
    const legitimacy = this._calculateLegitimacy(input);
    const penalty    = this._calculatePenalty(f2, input);
    const confidence = this._calculateConfidence(input);
    const output     = Math.pow(legitimacy, this.config.n) *
                       Math.pow(penalty,    -this.config.m) *
                       Math.pow(confidence,  this.config.k);
    return { legitimacy, penalty, confidence, output };
  }

  _calculateLegitimacy(input) {
    let L = 1.0;
    const idHash = crypto.createHash('sha256').update(input.agentId || '').digest('hex');
    if (idHash.startsWith('00') || idHash.startsWith('01')) L *= 0.9;

    const legitimateActions = ['READ', 'QUERY', 'SELECT', 'GET', 'LIST'];
    const suspiciousActions = ['DELETE', 'DROP', 'TRUNCATE', 'EXECUTE', 'GRANT'];
    if (suspiciousActions.includes(input.action)) L *= 0.7;
    else if (!legitimateActions.includes(input.action)) L *= 1.0;

    const envFactors = { development: 1.0, staging: 0.9, production: 0.8 };
    if (input.context && input.context.environment) {
      L *= (envFactors[input.context.environment] || 1.0);
    }
    return Math.max(0.1, Math.min(1.0, L));
  }

  _calculatePenalty(f2, input) {
    let P = 1.0;
    const highRiskNodes = f2.dag.filter(n => n.riskLevel === 'high').length;
    P *= (1 + highRiskNodes * 0.2);

    const resources = (input.context && input.context.resourceRequirements) || {};
    if (resources.cpu     && resources.cpu     > 80) P *= 1.3;
    if (resources.memory  && resources.memory  > 80) P *= 1.3;
    if (resources.network && resources.network > 80) P *= 1.2;

    const priorityFactors = { low: 1.2, medium: 1.0, high: 0.9, critical: 0.8 };
    if (input.context && input.context.priority) {
      P *= (priorityFactors[input.context.priority] || 1.0);
    }
    return Math.max(1.0, P);
  }

  _calculateConfidence(input) {
    let C = 1.0;
    const payloadKeys = Object.keys(input.payload || {});
    if (payloadKeys.length === 0) C *= 0.5;
    if (payloadKeys.length > 20)  C *= 0.9;

    const resources = (input.context && input.context.resourceRequirements) || {};
    if (!resources.cpu)    C *= 0.95;
    if (!resources.memory) C *= 0.95;

    const age = Date.now() - (input.timestamp || Date.now());
    if (age > 300000) C *= 0.5;
    else if (age > 60000) C *= 0.8;

    return Math.max(0.1, Math.min(1.0, C));
  }

  // ─── STAGE f4: BRITTLENESS REJECT ────────────────────────────────────────

  async _f4_brittlenessReject(f3, input) {
    const factors = [];

    factors.push({
      id: 'modulator_output',
      weight: 0.3,
      score: f3.output < 0.3 ? 80 : f3.output < 0.5 ? 50 : 20,
      description: `Modulator output: ${f3.output.toFixed(3)}`
    });

    const divergence = Math.abs(f3.legitimacy - (1 / f3.penalty));
    factors.push({
      id: 'legitimacy_penalty_divergence',
      weight: 0.25,
      score: Math.min(100, divergence * 100),
      description: `L-P divergence: ${divergence.toFixed(3)}`
    });

    factors.push({
      id: 'confidence_uncertainty',
      weight: 0.25,
      score: (1 - f3.confidence) * 100,
      description: `Confidence uncertainty: ${((1 - f3.confidence) * 100).toFixed(1)}%`
    });

    const envRiskScores = { development: 20, staging: 40, production: 60 };
    const env = (input.context && input.context.environment) || 'development';
    factors.push({
      id: 'environment_risk',
      weight: 0.2,
      score: envRiskScores[env] || 40,
      description: `Environment: ${env}`
    });

    // Production safety bonus: destructive actions in production get mandatory elevation.
    // DELETE/DROP/TRUNCATE/EXEC in production are high-stakes — brittleness must reflect this.
    const destructiveActions = ['DELETE', 'DROP', 'TRUNCATE', 'EXEC', 'PURGE', 'WIPE'];
    if (env === 'production' && destructiveActions.includes((input.action || '').toUpperCase())) {
      factors.push({
        id: 'production_destructive_action',
        weight: 0.15,
        score: 100,  // maximum — this combination is always high brittleness
        description: `Destructive action (${input.action}) in production environment`
      });
    }

    const score    = factors.reduce((sum, f) => sum + f.weight * f.score, 0);
    const rejected = score >= this.config.brittlenessThreshold;
    return { score, factors, rejected };
  }

  // ─── STAGE f5: LEGAL ARTIFACT ─────────────────────────────────────────────

  async _f5_legalArtifact(f4, input, startTime) {
    const latencyMs = Date.now() - startTime;
    const ticketContent = {
      agentId: input.agentId,
      action: input.action,
      timestamp: input.timestamp,
      brittlenessScore: f4.score,
      latencyMs
    };

    const hmacSignature = crypto
      .createHmac('sha256', this.config.hmacSecret)
      .update(JSON.stringify(ticketContent))
      .digest('hex');

    const ticketHash = crypto
      .createHash('sha256')
      .update(hmacSignature)
      .digest('hex');

    const previousReceiptHash = this.hashChain.length > 0
      ? this.hashChain[this.hashChain.length - 1]
      : '0x0';

    const expiresAt = (input.timestamp || Date.now()) + 3_600_000; // 1 hour TTL

    return { ticketHash, hmacSignature, chainPointer: previousReceiptHash, expiresAt };
  }

  // ─── SUPPORTING FUNCTIONS ─────────────────────────────────────────────────

  _generateExecutionTicket(input, f5, decision) {
    const ttl = decision === 'APPROVE' ? 100 : 0;
    return {
      ticketId:  f5.ticketHash,
      agentId:   input.agentId,
      action:    input.action,
      ttl,
      expiresAt: f5.expiresAt,
      scope:     [input.action],
      hmac:      f5.hmacSignature
    };
  }

  async _generateAuditReceipt(input, f5, ticket) {
    const receiptId  = crypto.randomUUID();
    const timestamp  = new Date().toISOString();
    const actionHash = crypto.createHash('sha256').update(JSON.stringify(input)).digest('hex');
    const previousReceiptHash = this.hashChain.length > 0
      ? this.hashChain[this.hashChain.length - 1]
      : '0x0';

    const merklePath = [previousReceiptHash, actionHash];

    const signature = crypto
      .createHmac('sha256', this.config.hmacSecret)
      .update(receiptId + timestamp + actionHash)
      .digest('hex');

    if (this.config.enableHashChain) {
      const receiptHash = crypto
        .createHash('sha256')
        .update(receiptId + timestamp + actionHash + signature)
        .digest('hex');
      this.hashChain.push(receiptHash);
      if (this.hashChain.length > 10000) {
        this.hashChain = this.hashChain.slice(-5000);
      }
    }

    this.receiptCounter++;
    return { receiptId, timestamp, actionHash, previousReceiptHash, merklePath, signature };
  }

  _createDenyResult(input, error, latencyMs) {
    return {
      decision: 'DENY',
      brittlenessScore: 100,
      modulatorOutput: 0,
      latencyMs,
      stages: {
        f0: { normalized: false, standardForm: '', hash: '' },
        f1: { spectrum: [], dominantFrequencies: [], riskIndicators: [] },
        f2: { dag: [], criticalPath: [], readinessScore: 0 },
        f3: { legitimacy: 0, penalty: 1, confidence: 0, output: 0 },
        f4: { score: 100, factors: [], rejected: true },
        f5: { ticketHash: '', hmacSignature: '', chainPointer: '', expiresAt: 0 }
      },
      ticket: {
        ticketId: '', agentId: input.agentId, action: input.action,
        ttl: 0, expiresAt: 0, scope: [], hmac: ''
      },
      auditReceipt: {
        receiptId: '', timestamp: '', actionHash: '',
        previousReceiptHash: '', merklePath: [], signature: ''
      }
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONVENIENCE FUNCTION
// ═══════════════════════════════════════════════════════════════════════════

async function analyzeWithRTP(input, config = {}) {
  const engine = new RTPTransformEngine(config);
  return engine.transform(input);
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

module.exports = { RTPTransformEngine, analyzeWithRTP };
