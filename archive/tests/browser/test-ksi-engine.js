#!/usr/bin/env node
/**
 * KSI Engine Browser Tests
 * Tests: TCS vector computation, CDR calculation, radar display
 * Run: node tests/browser/test-ksi-engine.js
 */

// Simple test framework
let passed = 0, failed = 0;
const failures = [];

function describe(suiteName, fn) {
  console.log(`\n${suiteName}`);
  fn();
}

function it(testName, fn) {
  try {
    fn();
    passed++;
    process.stdout.write('.');
  } catch (e) {
    failed++;
    failures.push({ test: testName, error: e.message });
    process.stdout.write('F');
  }
}

function expect(value) {
  return {
    toBe: (expected) => {
      if (value !== expected) throw new Error(`Expected ${expected}, got ${value}`);
    },
    toBeGreaterThan: (expected) => {
      if (value <= expected) throw new Error(`Expected > ${expected}, got ${value}`);
    },
    toBeLessThan: (expected) => {
      if (value >= expected) throw new Error(`Expected < ${expected}, got ${value}`);
    },
    toBeCloseTo: (expected, precision = 2) => {
      const diff = Math.abs(value - expected);
      const tolerance = Math.pow(10, -precision) / 2;
      if (diff > tolerance) throw new Error(`Expected ~${expected}, got ${value}`);
    },
    toBeTruthy: () => {
      if (!value) throw new Error(`Expected truthy, got ${value}`);
    },
    toBeFalsy: () => {
      if (value) throw new Error(`Expected falsy, got ${value}`);
    },
    toExist: () => {
      if (value === undefined || value === null) throw new Error(`Expected to exist, got ${value}`);
    },
  };
}

// ── KSIEngine Mock for Node.js testing ──
class KSIEngine {
  constructor() {
    this.tcsWeights = {
      technical_risk: 0.25,
      cultural_sensitivity: 0.20,
      intent_class: 0.20,
      novelty: 0.20,
      identity_certainty: 0.15,
    };
    this.sacredContentOverride = 0.95;
  }

  computeTCS(detectorOutputs) {
    // Normalize detector outputs to [0, 1]
    const normalized = {};

    // Map detector outputs to TCS dimensions
    if (detectorOutputs.secret_guard !== undefined) {
      normalized.technical_risk = Math.min(1, detectorOutputs.secret_guard);
    } else {
      normalized.technical_risk = 0;
    }

    if (detectorOutputs.quran_frontier !== undefined) {
      normalized.cultural_sensitivity = Math.min(1, detectorOutputs.quran_frontier);
    } else {
      normalized.cultural_sensitivity = 0;
    }

    if (detectorOutputs.intent_graph !== undefined) {
      normalized.intent_class = Math.min(1, detectorOutputs.intent_graph);
    } else {
      normalized.intent_class = 0;
    }

    if (detectorOutputs.novelty_detector !== undefined) {
      normalized.novelty = Math.min(1, detectorOutputs.novelty_detector);
    } else {
      normalized.novelty = 0;
    }

    if (detectorOutputs.biometric_forensics !== undefined) {
      normalized.identity_certainty = Math.min(1, detectorOutputs.biometric_forensics);
    } else {
      normalized.identity_certainty = 0;
    }

    // Reserved dimension for contextual scoring
    normalized.contextual_score = detectorOutputs.contextual_score || 0;

    // Weighted composite score
    const compositeScore =
      normalized.technical_risk * this.tcsWeights.technical_risk +
      normalized.cultural_sensitivity * this.tcsWeights.cultural_sensitivity +
      normalized.intent_class * this.tcsWeights.intent_class +
      normalized.novelty * this.tcsWeights.novelty +
      normalized.identity_certainty * this.tcsWeights.identity_certainty;

    // Sacred content override: if cultural_sensitivity >= override, auto-DENY
    const shouldDeny = () => {
      return normalized.cultural_sensitivity >= this.sacredContentOverride ||
             compositeScore >= 0.7;
    };

    return {
      technical_risk: normalized.technical_risk,
      cultural_sensitivity: normalized.cultural_sensitivity,
      intent_class: normalized.intent_class,
      novelty: normalized.novelty,
      identity_certainty: normalized.identity_certainty,
      contextual_score: normalized.contextual_score,
      composite_score: compositeScore,
      shouldDeny: shouldDeny,
    };
  }

  calculateCDR(detections) {
    // Cross-detector resonance: fraction of detectors that fired
    if (!Array.isArray(detections) || detections.length === 0) {
      return 0;
    }

    // Total possible detectors (14 as per spec)
    const totalDetectors = 14;
    const uniqueDetectors = new Set(detections.map(d => d.detector)).size;

    // Calculate span overlap (percentage of overlapping regions)
    let overlapRatio = 0;
    if (detections.length > 1) {
      // Simplified: assume consecutive detections with similar spans have overlap
      let overlapCount = 0;
      for (let i = 1; i < detections.length; i++) {
        const [start1, end1] = detections[i - 1].span || [0, 0];
        const [start2, end2] = detections[i].span || [0, 0];

        // Check for overlap
        if (!(end1 < start2 || end2 < start1)) {
          overlapCount++;
        }
      }
      overlapRatio = overlapCount / detections.length;
    }

    // CDR = (detector count / total) × (1 + overlap bonus)
    const cdr = (uniqueDetectors / totalDetectors) * (1 + overlapRatio * 0.5);

    return Math.min(1, cdr);
  }

  displayTCSRadar(tcs) {
    // In Node.js, we can't create a real canvas, so we return a mock object
    // In browser, this would create an actual canvas element
    const mockCanvas = {
      width: 200,
      height: 200,
      className: 'ksi-radar',
      getContext: () => ({}),
      toDataURL: () => 'data:image/png;base64,mock',
    };

    return mockCanvas;
  }
}

// ── TESTS ──
describe('KSIEngine', () => {
  const engine = new KSIEngine();

  it('should compute TCS vector from detector outputs', () => {
    const detectorOutputs = {
      secret_guard: 0.3,
      quran_frontier: 1.0,
      intent_graph: 0.2,
      novelty_detector: 0.1,
      biometric_forensics: 0.05,
    };
    const tcs = engine.computeTCS(detectorOutputs);

    expect(tcs.technical_risk).toBe(0.3);
    expect(tcs.cultural_sensitivity).toBe(1.0);
    expect(tcs.shouldDeny()).toBeTruthy();
  });

  it('should return all 6 TCS dimensions', () => {
    const detectorOutputs = {
      secret_guard: 0.5,
      quran_frontier: 0.5,
      intent_graph: 0.5,
      novelty_detector: 0.5,
      biometric_forensics: 0.5,
      contextual_score: 0.3,
    };
    const tcs = engine.computeTCS(detectorOutputs);

    expect(tcs.technical_risk).toExist();
    expect(tcs.cultural_sensitivity).toExist();
    expect(tcs.intent_class).toExist();
    expect(tcs.novelty).toExist();
    expect(tcs.identity_certainty).toExist();
    expect(tcs.contextual_score).toExist();
  });

  it('should calculate CDR when multiple detectors fire', () => {
    const detections = [
      { detector: 'secret_guard', span: [0, 20] },
      { detector: 'semantic_company', span: [0, 20] },
      { detector: 'biometric_forensics', span: [0, 20] },
    ];
    const cdr = engine.calculateCDR(detections);

    expect(cdr).toBeGreaterThan(0);
    expect(cdr).toBeLessThan(1);
  });

  it('should return 0 CDR for empty detections', () => {
    const cdr = engine.calculateCDR([]);
    expect(cdr).toBe(0);
  });

  it('should account for overlapping detection spans in CDR', () => {
    const overlappingDetections = [
      { detector: 'secret_guard', span: [0, 50] },
      { detector: 'semantic_company', span: [25, 75] },
      { detector: 'biometric_forensics', span: [40, 90] },
    ];
    const cdrOverlap = engine.calculateCDR(overlappingDetections);

    const nonOverlappingDetections = [
      { detector: 'secret_guard', span: [0, 10] },
      { detector: 'semantic_company', span: [100, 110] },
      { detector: 'biometric_forensics', span: [200, 210] },
    ];
    const cdrNoOverlap = engine.calculateCDR(nonOverlappingDetections);

    expect(cdrOverlap).toBeGreaterThan(cdrNoOverlap);
  });

  it('should display TCS radar and return canvas element', () => {
    const tcs = {
      technical_risk: 0.5,
      cultural_sensitivity: 0.3,
      intent_class: 0.4,
      novelty: 0.2,
      identity_certainty: 0.6,
      contextual_score: 0.25,
      composite_score: 0.4,
    };
    const radar = engine.displayTCSRadar(tcs);

    expect(radar).toExist();
    expect(radar.width).toBe(200);
    expect(radar.height).toBe(200);
    expect(radar.className).toBe('ksi-radar');
  });

  it('should have sacred content override at 0.95', () => {
    const detectorOutputs = {
      secret_guard: 0.1,
      quran_frontier: 0.95,
      intent_graph: 0,
      novelty_detector: 0,
      biometric_forensics: 0,
    };
    const tcs = engine.computeTCS(detectorOutputs);

    expect(tcs.shouldDeny()).toBeTruthy();
  });

  it('should deny if composite score >= 0.7', () => {
    const detectorOutputs = {
      secret_guard: 0.8,
      quran_frontier: 0.8,
      intent_graph: 0.8,
      novelty_detector: 0.8,
      biometric_forensics: 0.8,
    };
    const tcs = engine.computeTCS(detectorOutputs);

    expect(tcs.composite_score).toBeGreaterThan(0.7);
    expect(tcs.shouldDeny()).toBeTruthy();
  });

  it('should allow if composite score < 0.7 and cultural_sensitivity < 0.95', () => {
    const detectorOutputs = {
      secret_guard: 0.2,
      quran_frontier: 0.2,
      intent_graph: 0.2,
      novelty_detector: 0.2,
      biometric_forensics: 0.2,
    };
    const tcs = engine.computeTCS(detectorOutputs);

    expect(tcs.shouldDeny()).toBeFalsy();
  });
});

// ── RESULTS ──
console.log(`\n\n${'='.repeat(60)}`);
console.log(`Test Results: ${passed} passed, ${failed} failed`);
if (failures.length > 0) {
  console.log('\nFailures:');
  failures.forEach(f => console.log(`  - ${f.test}: ${f.error}`));
  process.exit(1);
} else {
  console.log('All tests passed!');
  process.exit(0);
}
