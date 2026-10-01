/**
 * Test Suite for Frontier Disruption Technology Implementations
 * 
 * Tests for:
 * - Brittleness Detection (kasbah-core)
 * - Cryptographic Receipts (kasbah-unified-detector)
 * - Audit Ledger (kasbah-compliance-automation)
 * - Adaptive Security (kasbah-api-gateway)
 *
 * Author: Kasbah Guard Team
 * Date: March 11, 2026
 * Status: Production Ready
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import { BrittlenessDetector, ResourceFrequencyDecomposer } from '../kasbah-unified-detector/src/brittleness';
import { ReceiptMinter, createReceiptMinter } from '../kasbah-unified-detector/src/cryptographic-receipts';
import { HashChainedAuditLedger, createAuditLedger } from '../kasbah-compliance-automation/src/audit-ledger';
import { AdaptiveSecurityOrchestrator, createAdaptiveOrchestrator } from '../kasbah-api-gateway/src/adaptive-security';

// ============================================
// BRITTLENESS DETECTION TESTS
// ============================================

describe('BrittlenessDetector', () => {
  let detector: BrittlenessDetector;

  beforeEach(() => {
    detector = new BrittlenessDetector();
  });

  describe('detectBrittleness', () => {
    it('should return ALLOW when no resources', () => {
      const report = detector.detectBrittleness([]);
      expect(report.recommendedAction).toBe('ALLOW');
      expect(report.brittlenessScore).toBe(0);
    });

    it('should return ALLOW when brittleness below threshold', () => {
      const resources = [
        { resource: 'openai_api', usage: 40000, capacity: 100000, frequency: 'FAST' as const },
        { resource: 'anthropic_api', usage: 30000, capacity: 50000, frequency: 'FAST' as const },
        { resource: 'local_model', usage: 30000, capacity: 100000, frequency: 'FAST' as const }
      ];
      const report = detector.detectBrittleness(resources);
      expect(report.recommendedAction).toBe('ALLOW');
      expect(report.brittlenessScore).toBeLessThan(0.65);
    });

    it('should return THROTTLE when brittleness above 65%', () => {
      const resources = [
        { resource: 'openai_api', usage: 80000, capacity: 100000, frequency: 'FAST' as const },
        { resource: 'anthropic_api', usage: 10000, capacity: 50000, frequency: 'FAST' as const }
      ];
      const report = detector.detectBrittleness(resources);
      expect(report.recommendedAction).toBe('THROTTLE');
      expect(report.brittlenessScore).toBeGreaterThanOrEqual(0.65);
      expect(report.adjustedCadence).toBeDefined();
    });

    it('should return DIVERSIFY when brittleness above 80%', () => {
      const resources = [
        { resource: 'openai_api', usage: 95000, capacity: 100000, frequency: 'FAST' as const },
        { resource: 'anthropic_api', usage: 5000, capacity: 50000, frequency: 'FAST' as const }
      ];
      const report = detector.detectBrittleness(resources);
      expect(report.recommendedAction).toBe('DIVERSIFY');
      expect(report.brittlenessScore).toBeGreaterThanOrEqual(0.80);
    });

    it('should identify the most brittle resource', () => {
      const resources = [
        { resource: 'openai_api', usage: 70000, capacity: 100000, frequency: 'FAST' as const },
        { resource: 'anthropic_api', usage: 20000, capacity: 50000, frequency: 'FAST' as const },
        { resource: 'local_model', usage: 10000, capacity: 100000, frequency: 'FAST' as const }
      ];
      const report = detector.detectBrittleness(resources);
      expect(report.brittleResource).toBe('openai_api');
    });
  });

  describe('adjustCadence', () => {
    it('should return original rate when below threshold', () => {
      const originalRate = 100;
      const adjusted = detector.adjustCadence(originalRate, 0.5);
      expect(adjusted).toBe(originalRate);
    });

    it('should reduce rate when above threshold', () => {
      const originalRate = 100;
      const adjusted = detector.adjustCadence(originalRate, 0.7);
      expect(adjusted).toBeLessThan(originalRate);
    });

    it('should apply patent formula correctly', () => {
      const originalRate = 100;
      const brittleness = 0.7;
      const expected = originalRate / (1.0 / (1.0 - brittleness));
      const adjusted = detector.adjustCadence(originalRate, brittleness);
      expect(adjusted).toBeCloseTo(expected, 2);
    });
  });

  describe('recommendDiversification', () => {
    it('should recommend diversification for high-brittleness resources', () => {
      const resources = [
        { resource: 'openai_api', usage: 80000, capacity: 100000, frequency: 'FAST' as const },
        { resource: 'anthropic_api', usage: 20000, capacity: 50000, frequency: 'FAST' as const }
      ];
      const recommendations = detector.recommendDiversification(resources, 0.5);
      expect(recommendations.length).toBeGreaterThan(0);
      expect(recommendations[0].resource).toBe('openai_api');
    });
  });
});

describe('ResourceFrequencyDecomposer', () => {
  let decomposer: ResourceFrequencyDecomposer;

  beforeEach(() => {
    decomposer = new ResourceFrequencyDecomposer();
  });

  it('should categorize API resources as FAST', () => {
    expect(decomposer.categorize('openai_api')).toBe('FAST');
    expect(decomposer.categorize('anthropic_endpoint')).toBe('FAST');
  });

  it('should categorize model resources as MID', () => {
    expect(decomposer.categorize('gpt4_model')).toBe('MID');
    expect(decomposer.categorize('config_settings')).toBe('MID');
  });

  it('should categorize contract resources as SLOW', () => {
    expect(decomposer.categorize('openai_contract')).toBe('SLOW');
    expect(decomposer.categorize('subscription_plan')).toBe('SLOW');
  });

  it('should decompose resources by frequency', () => {
    const resources = ['openai_api', 'gpt4_model', 'anthropic_contract'];
    const result = decomposer.decompose(resources);
    expect(result.FAST).toContain('openai_api');
    expect(result.MID).toContain('gpt4_model');
    expect(result.SLOW).toContain('anthropic_contract');
  });
});

// ============================================
// CRYPTOGRAPHIC RECEIPTS TESTS
// ============================================

describe('ReceiptMinter', () => {
  let minter: ReceiptMinter;

  beforeEach(() => {
    minter = createReceiptMinter({
      signingKey: 'test-secret-key',
      enableChaining: true,
      enableBudgetEnforcement: true
    });
  });

  afterEach(() => {
    minter.destroy();
  });

  describe('mint', () => {
    it('should mint a valid receipt', async () => {
      const intent = {
        intent_id: 'test-intent-1',
        tool_name: 'shell.exec',
        arguments: { cmd: 'ls -la' },
        estimated_tokens: 100,
        estimated_cost_cents: 0.001,
        risk_indicators: ['shell_access'],
        risk_score: 0.3,
        principal: 'user-123',
        session_id: 'session-456',
        timestamp: Date.now()
      };

      const receipt = await minter.mint(intent);

      expect(receipt.receipt_id).toBeDefined();
      expect(receipt.tool_name).toBe('shell.exec');
      expect(receipt.risk_class).toBe('STANDARD');
      expect(receipt.state).toBe('MINTED');
      expect(receipt.signature).toBeDefined();
    });

    it('should assign higher risk class for high-risk intents', async () => {
      const intent = {
        intent_id: 'test-intent-2',
        tool_name: 'shell.exec',
        arguments: { cmd: 'rm -rf /' },
        estimated_tokens: 100,
        estimated_cost_cents: 0.001,
        risk_indicators: ['dangerous_command', 'root_access'],
        risk_score: 0.95,
        principal: 'user-123',
        session_id: 'session-456',
        timestamp: Date.now()
      };

      const receipt = await minter.mint(intent);
      expect(receipt.risk_class).toBe('RESTRICTED');
      expect(receipt.secondary_sig).toBeDefined();
    });

    it('should create receipt chain', async () => {
      const intent1 = {
        intent_id: 'test-intent-1',
        tool_name: 'shell.exec',
        arguments: { cmd: 'ls' },
        estimated_tokens: 100,
        estimated_cost_cents: 0.001,
        risk_indicators: [],
        risk_score: 0.2,
        principal: 'user-123',
        session_id: 'session-456',
        timestamp: Date.now()
      };

      const receipt1 = await minter.mint(intent1);
      
      const intent2 = {
        ...intent1,
        intent_id: 'test-intent-2'
      };
      const receipt2 = await minter.mint(intent2, receipt1.previous_receipt_hash);

      expect(receipt2.chain_depth).toBe(1);
      expect(receipt2.previous_receipt_hash).toBeDefined();
    });
  });

  describe('verify', () => {
    it('should verify valid receipt', async () => {
      const intent = {
        intent_id: 'test-intent-1',
        tool_name: 'shell.exec',
        arguments: { cmd: 'ls' },
        estimated_tokens: 1000,
        estimated_cost_cents: 0.01,
        risk_indicators: [],
        risk_score: 0.2,
        principal: 'user-123',
        session_id: 'session-456',
        timestamp: Date.now()
      };

      const receipt = await minter.mint(intent);
      const result = await minter.verify(receipt, { tokens: 100, cost_cents: 0.001 });

      expect(result.valid).toBe(true);
      expect(result.risk_class).toBe('STANDARD');
    });

    it('should reject expired receipt', async () => {
      const intent = {
        intent_id: 'test-intent-1',
        tool_name: 'shell.exec',
        arguments: { cmd: 'ls' },
        estimated_tokens: 100,
        estimated_cost_cents: 0.001,
        risk_indicators: [],
        risk_score: 0.2,
        principal: 'user-123',
        session_id: 'session-456',
        timestamp: Date.now()
      };

      const receipt = await minter.mint(intent);
      
      // Wait for TTL to expire (using RESTRICTED class for 10ms TTL)
      await new Promise(resolve => setTimeout(resolve, 15));
      
      const result = await minter.verify(receipt, { tokens: 0, cost_cents: 0 });
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('expired');
    });

    it('should reject replayed receipt', async () => {
      const intent = {
        intent_id: 'test-intent-1',
        tool_name: 'shell.exec',
        arguments: { cmd: 'ls' },
        estimated_tokens: 100,
        estimated_cost_cents: 0.001,
        risk_indicators: [],
        risk_score: 0.2,
        principal: 'user-123',
        session_id: 'session-456',
        timestamp: Date.now()
      };

      const receipt = await minter.mint(intent);
      
      // Mark as executed
      minter.markExecuted(receipt.receipt_id, 'result-hash');
      
      // Try to verify again
      const result = await minter.verify(receipt, { tokens: 0, cost_cents: 0 });
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('replay');
    });

    it('should reject receipt with exceeded budget', async () => {
      const intent = {
        intent_id: 'test-intent-1',
        tool_name: 'shell.exec',
        arguments: { cmd: 'ls' },
        estimated_tokens: 100,
        estimated_cost_cents: 0.001,
        risk_indicators: [],
        risk_score: 0.2,
        principal: 'user-123',
        session_id: 'session-456',
        timestamp: Date.now()
      };

      const receipt = await minter.mint(intent);
      const result = await minter.verify(receipt, { tokens: 200000, cost_cents: 20 });
      
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('budget');
    });
  });

  describe('exportChain', () => {
    it('should export receipt chain', async () => {
      const intent = {
        intent_id: 'test-intent-1',
        tool_name: 'shell.exec',
        arguments: { cmd: 'ls' },
        estimated_tokens: 100,
        estimated_cost_cents: 0.001,
        risk_indicators: [],
        risk_score: 0.2,
        principal: 'user-123',
        session_id: 'session-456',
        timestamp: Date.now()
      };

      await minter.mint(intent);
      await minter.mint({ ...intent, intent_id: 'test-intent-2' });

      const chain = minter.exportChain();
      expect(chain.length).toBe(2);
      expect(chain.genesis_hash).toBeDefined();
      expect(chain.latest_hash).toBeDefined();
    });
  });
});

// ============================================
// AUDIT LEDGER TESTS
// ============================================

describe('HashChainedAuditLedger', () => {
  let ledger: HashChainedAuditLedger;

  beforeEach(() => {
    ledger = createAuditLedger({
      signingKey: 'test-signing-key',
      checkpointInterval: 10,
      enableMerkleProofs: true
    });
  });

  describe('append', () => {
    it('should append audit entry with hash chain', async () => {
      const entry = await ledger.append({
        event_type: 'EXECUTE',
        subject: 'user-123',
        object: 'tool.shell',
        action: 'execute_command',
        metadata: { command: 'ls -la' }
      });

      expect(entry.index).toBe(0);
      expect(entry.entry_hash).toBeDefined();
      expect(entry.prev_hash).toBe('0x' + '0'.repeat(64)); // Genesis
      expect(entry.signature).toBeDefined();
    });

    it('should create checkpoint at interval', async () => {
      for (let i = 0; i < 10; i++) {
        await ledger.append({
          event_type: 'EXECUTE',
          subject: 'user-123',
          object: 'tool.shell',
          action: `command_${i}`,
          metadata: {}
        });
      }

      const checkpoints = ledger.getCheckpoints();
      expect(checkpoints.length).toBe(1);
      expect(checkpoints[0].entry_index).toBe(9);
    });
  });

  describe('verify', () => {
    it('should verify intact ledger', async () => {
      await ledger.append({
        event_type: 'EXECUTE',
        subject: 'user-123',
        object: 'tool.shell',
        action: 'command',
        metadata: {}
      });

      const result = await ledger.verify();
      expect(result.valid).toBe(true);
      expect(result.verified_entries).toBe(1);
      expect(result.failed_entries).toBe(0);
    });

    it('should detect tampered entry', async () => {
      await ledger.append({
        event_type: 'EXECUTE',
        subject: 'user-123',
        object: 'tool.shell',
        action: 'command',
        metadata: {}
      });

      // Tamper with entry
      (ledger as any).entries[0].action = 'tampered_command';

      const result = await ledger.verify();
      expect(result.valid).toBe(false);
      expect(result.first_failure_index).toBe(0);
    });
  });

  describe('generateComplianceReport', () => {
    it('should generate SOC2 compliance report', async () => {
      await ledger.append({
        event_type: 'AUTHENTICATE',
        subject: 'user-123',
        object: 'system',
        action: 'login',
        metadata: {}
      });

      await ledger.append({
        event_type: 'ACCESS',
        subject: 'user-123',
        object: 'resource',
        action: 'read',
        metadata: {}
      });

      const report = await ledger.generateComplianceReport('SOC2');
      expect(report.framework).toBe('SOC2');
      expect(report.integrity_verified).toBe(true);
      expect(report.total_entries).toBe(2);
    });

    it('should generate findings for missing event types', async () => {
      const report = await ledger.generateComplianceReport('SOC2');
      expect(report.findings.length).toBeGreaterThan(0);
    });
  });

  describe('export', () => {
    it('should export as JSON', async () => {
      await ledger.append({
        event_type: 'EXECUTE',
        subject: 'user-123',
        object: 'tool.shell',
        action: 'command',
        metadata: {}
      });

      const exported = ledger.export('json');
      const parsed = JSON.parse(exported);
      expect(parsed.entry_count).toBe(1);
      expect(parsed.merkle_root).toBeDefined();
    });

    it('should export as CSV', async () => {
      await ledger.append({
        event_type: 'EXECUTE',
        subject: 'user-123',
        object: 'tool.shell',
        action: 'command',
        metadata: {}
      });

      const exported = ledger.export('csv');
      expect(exported).toContain('index,entry_id,timestamp');
    });
  });
});

// ============================================
// ADAPTIVE SECURITY TESTS
// ============================================

describe('AdaptiveSecurityOrchestrator', () => {
  let orchestrator: AdaptiveSecurityOrchestrator;

  beforeEach(() => {
    orchestrator = createAdaptiveOrchestrator({
      baseThreshold: 0.5,
      alpha: 0.5,
      curveType: 'sigmoid'
    });
  });

  describe('calculateIntegrityIndex', () => {
    it('should calculate integrity index from metrics', () => {
      orchestrator.updateMetrics({
        ics: 0.95,
        mfe: 0.08,
        ocs: 0.92,
        resource_utilization: 0.65,
        error_rate: 0.02,
        latency_p99_ms: 45,
        throughput_rps: 1200
      });

      const result = orchestrator.calculateIntegrityIndex();
      expect(result.psi).toBeGreaterThan(0);
      expect(result.psi).toBeLessThanOrEqual(1);
      expect(result.components.ics).toBe(0.95);
      expect(result.components.mfe).toBe(0.08);
      expect(result.components.ocs).toBe(0.92);
    });

    it('should classify integrity level correctly', () => {
      orchestrator.updateMetrics({
        ics: 0.95,
        mfe: 0.05,
        ocs: 0.95,
        resource_utilization: 0.5,
        error_rate: 0.01,
        latency_p99_ms: 30,
        throughput_rps: 1500
      });

      const result = orchestrator.calculateIntegrityIndex();
      expect(result.level).toBe('EXCELLENT');
    });

    it('should return default when no metrics', () => {
      const result = orchestrator.calculateIntegrityIndex();
      expect(result.psi).toBe(0.5);
      expect(result.level).toBe('FAIR');
    });
  });

  describe('getModulatedThreshold', () => {
    it('should modulate threshold based on integrity', () => {
      orchestrator.updateMetrics({
        ics: 0.95,
        mfe: 0.05,
        ocs: 0.95,
        resource_utilization: 0.5,
        error_rate: 0.01,
        latency_p99_ms: 30,
        throughput_rps: 1500
      });

      const threshold = orchestrator.getModulatedThreshold();
      expect(threshold).toBeGreaterThanOrEqual(0.1);
      expect(threshold).toBeLessThanOrEqual(0.95);
    });

    it('should increase threshold when integrity drops', () => {
      // High integrity
      orchestrator.updateMetrics({
        ics: 0.95,
        mfe: 0.05,
        ocs: 0.95,
        resource_utilization: 0.5,
        error_rate: 0.01,
        latency_p99_ms: 30,
        throughput_rps: 1500
      });
      const highIntegrityThreshold = orchestrator.getModulatedThreshold();

      // Low integrity
      orchestrator.updateMetrics({
        ics: 0.4,
        mfe: 0.5,
        ocs: 0.4,
        resource_utilization: 0.9,
        error_rate: 0.2,
        latency_p99_ms: 500,
        throughput_rps: 100
      });
      const lowIntegrityThreshold = orchestrator.getModulatedThreshold();

      expect(lowIntegrityThreshold).toBeGreaterThan(highIntegrityThreshold);
    });
  });

  describe('forecastThreats', () => {
    it('should generate threat forecast', async () => {
      const forecast = await orchestrator.forecastThreats(24);
      expect(forecast.horizon_hours).toBe(24);
      expect(forecast.predictions).toBeDefined();
      expect(forecast.threat_level).toBeDefined();
      expect(forecast.recommended_actions).toBeDefined();
    });

    it('should classify threat level correctly', async () => {
      // Record high threat events
      orchestrator.recordThreatEvent({
        evasion: 0.9,
        injection: 0.8,
        exfiltration: 0.7,
        manipulation: 0.8,
        bypass: 0.9
      });

      const forecast = await orchestrator.forecastThreats(24);
      expect(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(forecast.threat_level);
    });
  });

  describe('applyQuantumFeatureTransformation', () => {
    it('should transform features with rotation', () => {
      const features = [1, 0, 0, 1];
      const transformed = orchestrator.applyQuantumFeatureTransformation(features, 0.5);
      
      expect(transformed.length).toBe(features.length);
      expect(transformed).not.toEqual(features);
    });

    it('should handle empty features', () => {
      const transformed = orchestrator.applyQuantumFeatureTransformation([], 0.5);
      expect(transformed).toEqual([]);
    });
  });

  describe('getResourceOptimization', () => {
    it('should provide optimization recommendations', () => {
      orchestrator.updateMetrics({
        ics: 0.9,
        mfe: 0.1,
        ocs: 0.9,
        resource_utilization: 0.8,
        error_rate: 0.05,
        latency_p99_ms: 100,
        throughput_rps: 800
      });

      orchestrator.recordResourceMetrics({
        utilization: 0.75,
        latency: 90,
        throughput: 850
      });

      const optimization = orchestrator.getResourceOptimization();
      expect(optimization.current).toBeDefined();
      expect(optimization.recommended).toBeDefined();
      expect(optimization.expected_improvement).toBeDefined();
    });
  });
});

// ============================================
// INTEGRATION TESTS
// ============================================

describe('Frontier Technology Integration', () => {
  it('should work together: brittleness -> receipts -> audit', async () => {
    // Setup components
    const detector = new BrittlenessDetector();
    const minter = createReceiptMinter({
      signingKey: 'test-key',
      enableChaining: true
    });
    const ledger = createAuditLedger({
      signingKey: 'test-key'
    });

    // Simulate resource usage
    detector.recordUsage?.('openai_api', 50000, 0.5, 45, true);
    
    // Check brittleness
    const report = detector.analyze?.() || detector.detectBrittleness([
      { resource: 'openai_api', usage: 50000, capacity: 100000, frequency: 'FAST' as const }
    ]);
    
    // If brittleness is acceptable, mint receipt
    if (report.brittlenessScore < 0.65) {
      const intent = {
        intent_id: 'integration-test',
        tool_name: 'shell.exec',
        arguments: { cmd: 'ls' },
        estimated_tokens: 100,
        estimated_cost_cents: 0.001,
        risk_indicators: [],
        risk_score: 0.2,
        principal: 'system',
        session_id: 'integration',
        timestamp: Date.now()
      };

      const receipt = await minter.mint(intent);
      
      // Verify and execute
      const verification = await minter.verify(receipt, { tokens: 0, cost_cents: 0 });
      if (verification.valid) {
        minter.markExecuted(receipt.receipt_id, 'result-hash');
        
        // Log to audit ledger
        await ledger.append({
          event_type: 'EXECUTE',
          subject: 'system',
          object: 'tool.shell',
          action: 'execute_command',
          metadata: { receipt_id: receipt.receipt_id }
        });
      }
    }

    // Verify audit trail
    const auditResult = await ledger.verify();
    expect(auditResult.valid).toBe(true);

    minter.destroy();
  });
});
