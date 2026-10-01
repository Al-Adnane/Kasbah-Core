'use strict';

const path = require('path');

// Point KasbahAgentControl to the root policy file for tests
process.env.KASBAH_POLICY_FILE = path.resolve(__dirname, '../../../.kasbahpolicy.json');

// Suppress non-critical governance logs during tests
process.env.KASBAH_SILENT = '1';

// Patch KasbahSentinel.sentinelCheck with a realistic simulation.
// This keeps tests fast, isolated, and independent of real sentinel internals.
// Integration tests against the real sentinel live in tests/integration/
//
// NOTE: sentinelCheck() is the real API on KasbahSentinel (evaluate() never existed).
// KasbahAgentControl calls sentinelCheck() and reads sentinelResult.scan.risk (0-100).
const { KasbahSentinel } = require('../src/kasbah-sentinel');

KasbahSentinel.prototype.sentinelCheck = async function(sentinelInput) {
  await new Promise(r => setTimeout(r, 5 + Math.random() * 10)); // ~5-15ms

  // sentinelInput = { agent, verb, target, content, timestamp }
  // Scan the extracted content plus any other fields for threat signals.
  const raw = JSON.stringify(sentinelInput).toLowerCase();

  const isDestructive = /rm -rf|format c:|sudo rm|:\(\)\{:\|:&\};:/.test(raw);
  const isExfil       = /exfiltrat|send to|upload to|steal/.test(raw);
  const isSQLAttack   = /drop table|delete from|truncate/.test(raw);
  const isAdminBypass = /admin_override|bypass|ignore safety|disable all safety|unrestricted/.test(raw);
  const isCodeInject  = /eval\(|exec\(|__import__|base64|system\(/.test(raw);
  const isStaleTOCTOU = sentinelInput.timestamp && (Date.now() - sentinelInput.timestamp) > 150;

  const HIGH = 0.95, LOW = 0.08;
  const layers = {
    CAIL:                          isStaleTOCTOU ? HIGH : LOW,
    ConsciousnessProvenanceEngine: (isDestructive || isSQLAttack) ? HIGH : LOW,
    AIFingerprintAnalyzer:         isCodeInject ? 0.75 : LOW,
    ContentPassport:               isExfil ? HIGH : LOW,
    UniversalEthicsEngine:         (isDestructive || isSQLAttack || isAdminBypass || isExfil) ? HIGH : LOW,
    SwarmCollusionDetector:        LOW,
    TOCTOUGuard:                   isStaleTOCTOU ? HIGH : LOW,
    AuthorityProtocol:             isAdminBypass ? HIGH : LOW,
    DynamicThresholds:             0.10,
    BrittlenessMonitor:            0.08,
    ThreatForecaster:              (isExfil || isDestructive || isSQLAttack) ? HIGH : LOW,
    AboriginalFire:                LOW,
    KasbahOS:                      (isDestructive || isCodeInject || isSQLAttack) ? HIGH : LOW,
  };

  const criticalLayerFired = [
    layers.UniversalEthicsEngine, layers.KasbahOS, layers.ContentPassport,
    layers.ThreatForecaster, layers.ConsciousnessProvenanceEngine,
    layers.TOCTOUGuard, layers.SwarmCollusionDetector, layers.AuthorityProtocol,
  ].some(v => v >= 0.9);

  const MSHIR = Object.values(layers).reduce((a, b) => a + b, 0) / Object.keys(layers).length;
  const riskFraction = criticalLayerFired
    ? Math.min(0.75 + MSHIR * 0.25, 1.0)
    : Math.min(MSHIR * 1.2, 0.35);   // safe content capped at 0.35 → always ALLOW

  const riskScore = Math.round(riskFraction * 100);   // 0-100 for scan.risk
  const triggered = Object.entries(layers).filter(([, v]) => v > 0.5).map(([k]) => k);

  let decision = 'ALLOW';
  if (riskFraction >= 0.70) decision = 'DENY';
  else if (riskFraction >= 0.40) decision = 'WARN';

  return {
    decision,
    violations: triggered,
    scan:  { risk: riskScore, tiers: triggered, decision },
    layers,
    triggeredLayers: triggered,
    reason: triggered.length > 0 ? `high_risk: ${triggered.join(', ')}` : 'clean',
    overallRisk: riskFraction,   // kept for any code that reads it directly
  };
};
