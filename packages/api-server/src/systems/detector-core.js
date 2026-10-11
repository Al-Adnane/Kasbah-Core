'use strict';
/**
 * Detector Core — thin wrapper re-exporting Kasbah Detection Engine v3.5
 * with a normalized interface for frontier.js consumption.
 *
 * Source: /detector.js
 * Exports:
 *   classify     — primary entry point: classify(text) → { decision, risk, ... }
 *   getRisk      — getRisk(text) → number
 *   getDecision  — getDecision(text) → string
 *   detectCore   — normalized alias: detectCore(text) → { decision, risk, ... }
 *   detectFull   — full engine object (all exports) for advanced use
 */
const engine = require('../../../../src/detector.js');

module.exports = {
  // Normalized single-function interface for frontier.js
  detectCore: (text) =>
    engine.classify   ? engine.classify(text)  :
    engine.detect     ? engine.detect(text)     :
    engine.analyze    ? engine.analyze(text)    :
    engine.scan       ? engine.scan(text)       : null,

  // Full engine passthrough
  detectFull: engine,

  // Convenience re-exports from the engine
  classify:                engine.classify,
  getRisk:                 engine.getRisk,
  getDecision:             engine.getDecision,
  hashContent:             engine.hashContent,
  hybridHash:              engine.hybridHash,
  djb2Hash:                engine.djb2Hash,
  fnv1aHash:               engine.fnv1aHash,
  generateDetectionProof:  engine.generateDetectionProof,
  constantTimeEqual:       engine.constantTimeEqual,
  detectPlatform:          engine.detectPlatform,
  getPatternStats:         engine.getPatternStats,
  patternConfidenceBoost:  engine.patternConfidenceBoost,
  computePatternHash:      engine.computePatternHash,
  verifyPatternIntegrity:  engine.verifyPatternIntegrity,
  selfTest:                engine.selfTest,
  luhnCheck:               engine.luhnCheck,
  normalizeHomoglyphs:     engine.normalizeHomoglyphs,
  checkBehavioral:         engine.checkBehavioral,
  detectStringConcatBypass: engine.detectStringConcatBypass,
  resetBehavioral:         engine.resetBehavioral,
  lanzatechTransform:      engine.lanzatechTransform,
  beeodiversityBoost:      engine.beeodiversityBoost,
  soilSecurityAggregate:   engine.soilSecurityAggregate,
  fungiCorrelation:        engine.fungiCorrelation,
  breatheEasyFilter:       engine.breatheEasyFilter,
  PATTERN_VERSION:         engine.PATTERN_VERSION,
  DECISION_MODE:           engine.DECISION_MODE,
  FEATURES:                engine.FEATURES,
};
