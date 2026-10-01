/**
 * Bulma Defensibility Bridge
 * Connects Kasbah to Bulma Auditor Python API
 * Handles: Cache, retry logic, error handling
 */

const axios = require('axios');

class BulmaDefensibilityBridge {
  constructor(config = {}) {
    this.apiUrl = config.bulmaApiUrl || 'http://localhost:8000';
    this.timeout = config.timeout || 5000;
    this.cache = new Map();
    this.cacheSize = config.cacheSize || 10000;
    this.cacheTTL = config.cacheTTL || 300000; // 5 minutes
    this.client = axios.create({
      baseURL: this.apiUrl,
      timeout: this.timeout
    });
  }

  /**
   * Core audit endpoint - validates claims with defensibility analysis
   */
  async audit(claims, evidence = [], narrative = '') {
    // Try cache first
    const cacheKey = this._getCacheKey(claims, evidence, narrative);
    if (this.cache.has(cacheKey)) {
      const cached = this.cache.get(cacheKey);
      if (Date.now() - cached.timestamp < this.cacheTTL) {
        return cached.result;
      } else {
        this.cache.delete(cacheKey);
      }
    }

    try {
      const response = await this.client.post('/api/v1/audit', {
        claims: Array.isArray(claims) ? claims : [claims],
        evidence_sources: evidence,
        narrative_context: narrative,
        include_trace: true
      });

      const result = response.data;

      // Cache result
      this._setCache(cacheKey, result);

      return result;
    } catch (error) {
      throw new Error(`Bulma audit failed: ${error.message}`);
    }
  }

  /**
   * Get previous audit by ID
   */
  async getAudit(auditId) {
    try {
      const response = await this.client.get(`/api/v1/audit/${auditId}`);
      return response.data;
    } catch (error) {
      throw new Error(`Failed to retrieve audit ${auditId}: ${error.message}`);
    }
  }

  /**
   * List recent audits
   */
  async listAudits(limit = 50) {
    try {
      const response = await this.client.get('/api/v1/audits', { params: { limit } });
      return response.data.audits;
    } catch (error) {
      throw new Error(`Failed to list audits: ${error.message}`);
    }
  }

  /**
   * Health check
   */
  async healthCheck() {
    try {
      const response = await this.client.get('/api/v1/health');
      return response.data;
    } catch (error) {
      return { status: 'error', message: error.message };
    }
  }

  /**
   * Extract defensibility score (0-100)
   */
  getDefensibilityScore(auditResult) {
    return auditResult.defensibility_score || 0;
  }

  /**
   * Get archetype breakdown (6 strategies)
   */
  getArchetypeBreakdown(auditResult) {
    const breakdown = {};
    for (const archetype of auditResult.archetype_scores || []) {
      breakdown[archetype.archetype] = {
        score: archetype.score,
        weight: archetype.weight,
        contribution: archetype.weighted_contribution
      };
    }
    return breakdown;
  }

  /**
   * Check if audit passed (defensibility >= threshold)
   */
  isPassed(auditResult, threshold = 70) {
    return auditResult.defensibility_score >= threshold;
  }

  /**
   * Get vulnerabilities
   */
  getVulnerabilities(auditResult, severity = null) {
    let vulns = auditResult.vulnerabilities || [];
    if (severity) {
      vulns = vulns.filter(v => v.severity === severity);
    }
    return vulns;
  }

  /**
   * Get critical vulnerabilities only
   */
  getCriticalVulnerabilities(auditResult) {
    return this.getVulnerabilities(auditResult, 'critical');
  }

  // ─────────────────────────────────────────────────────────────────
  // PRIVATE METHODS
  // ─────────────────────────────────────────────────────────────────

  _getCacheKey(claims, evidence, narrative) {
    const combined = [
      Array.isArray(claims) ? claims.join('|') : claims,
      Array.isArray(evidence) ? evidence.join('|') : evidence,
      narrative || ''
    ].join('::');

    return Buffer.from(combined).toString('base64');
  }

  _setCache(key, result) {
    if (this.cache.size >= this.cacheSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }

    this.cache.set(key, {
      result,
      timestamp: Date.now()
    });
  }

  clearCache() {
    this.cache.clear();
  }

  getCacheStats() {
    return {
      size: this.cache.size,
      maxSize: this.cacheSize,
      ttl: this.cacheTTL
    };
  }
}

module.exports = BulmaDefensibilityBridge;
