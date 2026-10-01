/**
 * Kasbah Benchmark Suite v1.0
 * Performance and accuracy benchmarking for all detectors
 * 
 * Usage:
 *   node benchmark.js
 *   node benchmark.js --detector=ai-text --samples=1000
 */

var AITextDetector = require('./kasbah-ai-text-detector/src/aitext-detector');
var VoiceCloningDetector = require('./kasbah-voice-detector/src/voice-detector');
var DeepfakeDetector = require('./kasbah-deepfake-detector/src/deepfake-detector-v2');
var CodeStyleAnalyzer = require('./kasbah-code-style-analyzer/src/code-style-analyzer-v2');
var KasbahDetector = require('./Kasbah-site/kasbah-guard-dist/extensions/chrome/src/detector-v5');

// Benchmark configuration
var CONFIG = {
  warmup: 10,
  samples: 1000,
  detectors: ['ai-text', 'voice', 'deepfake', 'code', 'secrets', 'all']
};

// Test datasets
var TEST_DATA = {
  aiText: [
    "Furthermore, it is important to note that the aforementioned considerations are particularly significant in this context. Moreover, it is worth noting that these points are particularly important to consider.",
    "In conclusion, the aforementioned points demonstrate the significance of these considerations. Additionally, it is important to note that further research is needed.",
    "I went to the store yesterday and bought some milk. The weather was nice, sunny with a few clouds. My neighbor waved at me while I was walking."
  ],
  code: [
    "function hello() { console.log('world'); }",
    "const x = 10; let y = 20; var z = 30;",
    "class MyClass { constructor() { this.value = 0; } getValue() { return this.value; } }"
  ]
};

// Benchmark results
var results = {
  latency: {},
  accuracy: {},
  memory: {}
};

/**
 * Run latency benchmark
 */
function benchmarkLatency(detectorName, fn, samples) {
  console.log('\n📊 Latency Benchmark: ' + detectorName);
  console.log('Samples: ' + samples);
  
  // Warmup
  for (var i = 0; i < CONFIG.warmup; i++) {
    fn();
  }
  
  // Benchmark
  var latencies = [];
  var startTime = Date.now();
  
  for (var i = 0; i < samples; i++) {
    var iterStart = Date.now();
    fn();
    latencies.push(Date.now() - iterStart);
  }
  
  var totalTime = Date.now() - startTime;
  
  // Sort for percentiles
  latencies.sort(function(a, b) { return a - b; });
  
  var p50 = latencies[Math.floor(samples * 0.50)];
  var p95 = latencies[Math.floor(samples * 0.95)];
  var p99 = latencies[Math.floor(samples * 0.99)];
  var mean = latencies.reduce(function(a, b) { return a + b; }, 0) / samples;
  var max = latencies[samples - 1];
  
  results.latency[detectorName] = {
    p50: p50,
    p95: p95,
    p99: p99,
    mean: mean,
    max: max,
    totalMs: totalTime,
    samplesPerSecond: samples / (totalTime / 1000)
  };
  
  console.log('p50: ' + p50.toFixed(2) + 'ms');
  console.log('p95: ' + p95.toFixed(2) + 'ms');
  console.log('p99: ' + p99.toFixed(2) + 'ms');
  console.log('mean: ' + mean.toFixed(2) + 'ms');
  console.log('max: ' + max.toFixed(2) + 'ms');
  console.log('Throughput: ' + (samples / (totalTime / 1000)).toFixed(0) + ' samples/sec');
  
  return results.latency[detectorName];
}

/**
 * Run accuracy benchmark
 */
function benchmarkAccuracy(detectorName, testCases) {
  console.log('\n🎯 Accuracy Benchmark: ' + detectorName);
  console.log('Test cases: ' + testCases.length);
  
  var correct = 0;
  var falsePositives = 0;
  var falseNegatives = 0;
  var truePositives = 0;
  var trueNegatives = 0;
  
  for (var i = 0; i < testCases.length; i++) {
    var testCase = testCases[i];
    var result = testCase.fn(testCase.input);
    var predicted = result.isAI || result.isFake || result.isSynthetic || (result.riskScore > 50);
    var actual = testCase.expected;
    
    if (predicted === actual) {
      correct++;
      if (predicted) truePositives++;
      else trueNegatives++;
    } else {
      if (predicted) falsePositives++;
      else falseNegatives++;
    }
  }
  
  var accuracy = correct / testCases.length;
  var precision = truePositives / Math.max(1, truePositives + falsePositives);
  var recall = truePositives / Math.max(1, truePositives + falseNegatives);
  var f1 = 2 * (precision * recall) / Math.max(0.001, precision + recall);
  
  results.accuracy[detectorName] = {
    accuracy: accuracy,
    precision: precision,
    recall: recall,
    f1: f1,
    correct: correct,
    total: testCases.length,
    falsePositives: falsePositives,
    falseNegatives: falseNegatives
  };
  
  console.log('Accuracy: ' + (accuracy * 100).toFixed(1) + '%');
  console.log('Precision: ' + (precision * 100).toFixed(1));
  console.log('Recall: ' + (recall * 100).toFixed(1));
  console.log('F1 Score: ' + (f1 * 100).toFixed(1));
  
  return results.accuracy[detectorName];
}

/**
 * Run memory benchmark
 */
function benchmarkMemory(detectorName, fn) {
  console.log('\n💾 Memory Benchmark: ' + detectorName);
  
  if (typeof process !== 'undefined' && process.memoryUsage) {
    var initialMemory = process.memoryUsage();
    
    // Run detection
    fn();
    
    var finalMemory = process.memoryUsage();
    
    var heapUsed = finalMemory.heapUsed - initialMemory.heapUsed;
    var rss = finalMemory.rss - initialMemory.rss;
    
    results.memory[detectorName] = {
      heapUsed: heapUsed,
      heapUsedMB: (heapUsed / 1024 / 1024).toFixed(2),
      rss: rss,
      rssMB: (rss / 1024 / 1024).toFixed(2)
    };
    
    console.log('Heap Used: ' + results.memory[detectorName].heapUsedMB + ' MB');
    console.log('RSS: ' + results.memory[detectorName].rssMB + ' MB');
  } else {
    console.log('Memory benchmarking not available in this environment');
    results.memory[detectorName] = { available: false };
  }
}

/**
 * Run all benchmarks
 */
function runAllBenchmarks() {
  console.log('🚀 Kasbah Benchmark Suite v1.0');
  console.log('================================');
  console.log('Warmup: ' + CONFIG.warmup + ' iterations');
  console.log('Samples: ' + CONFIG.samples + ' iterations');
  console.log('');
  
  // AI Text Detector benchmarks
  benchmarkLatency('ai-text', function() {
    var detector = new AITextDetector();
    detector.detect(TEST_DATA.aiText[0]);
  }, CONFIG.samples);
  
  // Code Style Analyzer benchmarks
  benchmarkLatency('code-style', function() {
    var analyzer = new CodeStyleAnalyzer();
    analyzer.analyze(TEST_DATA.code[0]);
  }, CONFIG.samples);
  
  // Secret Detection benchmarks
  benchmarkLatency('secrets', function() {
    KasbahDetector.detect({
      text: 'My AWS key is AKIAIOSFODNN7EXAMPLE'
    });
  }, CONFIG.samples);
  
  // Full detector benchmarks
  benchmarkLatency('full-detector', function() {
    KasbahDetector.detect({
      text: TEST_DATA.aiText[0],
      code: TEST_DATA.code[0]
    }, { detectAI: true });
  }, CONFIG.samples / 10); // Fewer samples for full detector
  
  // Accuracy benchmarks (with mock test cases)
  var mockTestCases = [
    { input: TEST_DATA.aiText[0], expected: true, fn: function(input) { return new AITextDetector().detect(input); } },
    { input: TEST_DATA.aiText[1], expected: true, fn: function(input) { return new AITextDetector().detect(input); } },
    { input: TEST_DATA.aiText[2], expected: false, fn: function(input) { return new AITextDetector().detect(input); } }
  ];
  
  benchmarkAccuracy('ai-text', mockTestCases);
  
  // Print summary
  printSummary();
}

/**
 * Print benchmark summary
 */
function printSummary() {
  console.log('\n================================');
  console.log('📊 BENCHMARK SUMMARY');
  console.log('================================\n');
  
  console.log('LATENCY (p50/p95/p99):');
  for (var detector in results.latency) {
    var r = results.latency[detector];
    console.log(detector + ': ' + r.p50.toFixed(2) + 'ms / ' + r.p95.toFixed(2) + 'ms / ' + r.p99.toFixed(2) + 'ms');
  }
  
  console.log('\nACCURACY:');
  for (var detector in results.accuracy) {
    var r = results.accuracy[detector];
    console.log(detector + ': ' + (r.accuracy * 100).toFixed(1) + '% (F1: ' + (r.f1 * 100).toFixed(1) + ')');
  }
  
  console.log('\nMEMORY:');
  for (var detector in results.memory) {
    var r = results.memory[detector];
    if (r.available !== false) {
      console.log(detector + ': ' + r.heapUsedMB + ' MB heap, ' + r.rssMB + ' MB RSS');
    }
  }
  
  // Save results to file
  if (typeof require !== 'undefined') {
    var fs = require('fs');
    var filename = 'benchmark-results-' + Date.now() + '.json';
    fs.writeFileSync(filename, JSON.stringify(results, null, 2));
    console.log('\n💾 Results saved to: ' + filename);
  }
}

// Run benchmarks
runAllBenchmarks();

// Export for programmatic use
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    benchmarkLatency: benchmarkLatency,
    benchmarkAccuracy: benchmarkAccuracy,
    benchmarkMemory: benchmarkMemory,
    runAllBenchmarks: runAllBenchmarks,
    results: results
  };
}
