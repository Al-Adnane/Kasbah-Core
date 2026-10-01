/**
 * Verification Bridge
 * Byzantine Fault Tolerant (BFT) chain verification
 * Integrates Bulma's ChainBFT algorithm
 */

const axios = require('axios');

class VerificationBridge {
  constructor(config = {}) {
    this.pythonServiceUrl = config.pythonServiceUrl || process.env.PYTHON_SERVICE_URL || 'http://localhost:9000';
    this.timeout = config.timeout || 30000;
    this.client = axios.create({
      baseURL: this.pythonServiceUrl,
      timeout: this.timeout
    });
  }

  /**
   * Byzantine Chain Verification (BFT)
   * Verifies chain integrity when up to f nodes can be faulty
   *
   * Input:
   *   chain: [{ hash, data, timestamp, signer }, ...]
   *   trustedCount: Number of nodes we trust (n >= 3f + 1)
   *
   * Returns: { valid: boolean, faulty_blocks: [...], consensus: boolean }
   */
  async verifyChainBFT(chain, trustedCount) {
    if (!Array.isArray(chain) || chain.length === 0) {
      throw new Error('Chain must be non-empty array');
    }

    // BFT requires n >= 3f + 1, so max faults f = (n-1)/3
    const maxFaults = Math.floor((trustedCount - 1) / 3);
    if (maxFaults < 1) {
      throw new Error(`Insufficient trusted nodes for BFT. Need at least 4, have ${trustedCount}`);
    }

    try {
      const response = await this.client.post('/api/v1/verify-chain-bft', {
        chain: chain.map(block => ({
          hash: block.hash,
          data: block.data,
          timestamp: block.timestamp,
          signer: block.signer,
          index: block.index || chain.indexOf(block)
        })),
        trusted_count: trustedCount,
        max_faults: maxFaults
      });

      return {
        chain_length: chain.length,
        is_valid: response.data.valid,
        consensus_reached: response.data.consensus,
        faulty_blocks: response.data.faulty_blocks || [],
        faulty_count: (response.data.faulty_blocks || []).length,
        max_tolerable_faults: maxFaults,
        verification_time_ms: response.data.verification_time_ms,
        confidence: this._calculateConfidence(maxFaults, response.data.faulty_blocks || []),
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`BFT verification failed: ${error.message}`);
    }
  }

  /**
   * Variant Graph Analysis
   * Analyzes variations in data structure (like Quranic variants)
   * Returns: similarity matrix, consensus sequence
   */
  async analyzeVariants(sequences) {
    if (!Array.isArray(sequences) || sequences.length < 2) {
      throw new Error('At least 2 sequences required');
    }

    try {
      const response = await this.client.post('/api/v1/analyze-variants', {
        sequences: sequences.map((seq, idx) => ({
          id: seq.id || `seq_${idx}`,
          data: seq.data || seq,
          metadata: seq.metadata || {}
        }))
      });

      return {
        total_sequences: sequences.length,
        consensus_sequence: response.data.consensus,
        similarity_matrix: response.data.similarity_matrix,
        variant_positions: response.data.variant_positions,
        confidence_scores: response.data.confidence_scores,
        clustering: response.data.clustering,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Variant analysis failed: ${error.message}`);
    }
  }

  /**
   * Multi-witness attestation
   * Verifies data against multiple independent witnesses
   */
  async verifyWithWitnesses(data, witnesses) {
    if (!Array.isArray(witnesses) || witnesses.length < 1) {
      throw new Error('At least one witness required');
    }

    try {
      const response = await this.client.post('/api/v1/verify-witnesses', {
        data,
        witnesses: witnesses.map((w, idx) => ({
          id: w.id || `witness_${idx}`,
          attestation: w.attestation,
          confidence: w.confidence || 0.9,
          source: w.source
        })),
        consensus_threshold: 0.66 // 2/3 majority
      });

      return {
        is_verified: response.data.verified,
        consensus_reached: response.data.consensus,
        agreement_rate: response.data.agreement_rate,
        dissenting_witnesses: response.data.dissenting || [],
        confidence_level: response.data.confidence,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Witness verification failed: ${error.message}`);
    }
  }

  /**
   * Detect tampering
   * Identifies potentially modified data in a chain
   */
  async detectTampering(chain, baseline = null) {
    try {
      const response = await this.client.post('/api/v1/detect-tampering', {
        chain: chain.map((block, idx) => ({
          hash: block.hash,
          data: block.data,
          timestamp: block.timestamp,
          index: block.index || idx
        })),
        baseline: baseline,
        sensitivity: 'high' // Can be 'low', 'medium', 'high'
      });

      return {
        tampered: response.data.tampered,
        tampered_blocks: response.data.tampered_blocks || [],
        anomaly_score: response.data.anomaly_score,
        confidence: response.data.confidence,
        recommendations: response.data.recommendations || [],
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Tampering detection failed: ${error.message}`);
    }
  }

  /**
   * Batch verify multiple chains
   */
  async verifyBatch(chains, trustedCount) {
    const results = [];

    for (const chain of chains) {
      try {
        const result = await this.verifyChainBFT(chain.data || chain, trustedCount);
        results.push({ ...result, chain_id: chain.id || 'unknown' });
      } catch (error) {
        results.push({
          chain_id: chain.id || 'unknown',
          is_valid: false,
          error: error.message
        });
      }
    }

    return {
      total: results.length,
      valid_count: results.filter(r => r.is_valid).length,
      results
    };
  }

  /**
   * Calculate confidence level
   */
  _calculateConfidence(maxFaults, faultyBlocks) {
    const faultyCount = faultyBlocks.length;

    if (faultyCount > maxFaults) {
      return 'CRITICAL'; // More faults than tolerable
    } else if (faultyCount === maxFaults) {
      return 'LOW';
    } else if (faultyCount > maxFaults / 2) {
      return 'MEDIUM';
    }

    return 'HIGH';
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

module.exports = VerificationBridge;
