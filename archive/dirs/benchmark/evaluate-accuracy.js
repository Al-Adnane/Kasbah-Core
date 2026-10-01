#!/usr/bin/env node
/**
 * Kasbah Accuracy Evaluation Suite
 * 
 * Tests all AI detectors against labeled datasets
 * Generates accuracy, precision, recall, F1 scores
 * 
 * Usage:
 *   node evaluate-accuracy.js
 *   node evaluate-accuracy.js --detector=ai-text
 */

var fs = require('fs');
var path = require('path');

// Import detectors
var AITextDetector = require('../kasbah-ai-text-detector/src/aitext-detector');
var VoiceCloningDetector = require('../kasbah-voice-detector/src/voice-detector');
var DeepfakeDetector = require('../kasbah-deepfake-detector/src/deepfake-detector-v2');
var CodeStyleAnalyzer = require('../kasbah-code-style-analyzer/src/code-style-analyzer-v2');
var KasbahDetector = require('../Kasbah-site/kasbah-guard-dist/extensions/chrome/src/detector-v5').KasbahDetector || require('../Kasbah-site/kasbah-guard-dist/extensions/chrome/src/detector-v5');

// Test configuration
var CONFIG = {
  verbose: true,
  outputDir: './benchmark/results',
  datasets: {
    aiText: './benchmark/test-datasets/ai-text-complete.json',
    voice: './benchmark/test-datasets/voice.json',
    deepfake: './benchmark/test-datasets/deepfake.json',
    code: './benchmark/test-datasets/code-authorship.json'
  }
};

// Results storage
var evaluationResults = {
  timestamp: new Date().toISOString(),
  detectors: {}
};

/**
 * Load test dataset
 */
function loadDataset(datasetPath) {
  try {
    var data = fs.readFileSync(datasetPath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error loading dataset:', datasetPath);
    console.error(error.message);
    return [];
  }
}

/**
 * Calculate evaluation metrics
 */
function calculateMetrics(results) {
  var truePositives = results.filter(function(r) { return r.predicted && r.actual; }).length;
  var trueNegatives = results.filter(function(r) { return !r.predicted && !r.actual; }).length;
  var falsePositives = results.filter(function(r) { return r.predicted && !r.actual; }).length;
  var falseNegatives = results.filter(function(r) { return !r.predicted && r.actual; }).length;
  
  var total = results.length;
  var accuracy = (truePositives + trueNegatives) / Math.max(1, total);
  var precision = truePositives / Math.max(1, truePositives + falsePositives);
  var recall = truePositives / Math.max(1, truePositives + falseNegatives);
  var f1 = 2 * (precision * recall) / Math.max(0.001, precision + recall);
  
  return {
    accuracy: accuracy,
    precision: precision,
    recall: recall,
    f1: f1,
    truePositives: truePositives,
    trueNegatives: trueNegatives,
    falsePositives: falsePositives,
    falseNegatives: falseNegatives,
    total: total,
    correct: truePositives + trueNegatives,
    incorrect: falsePositives + falseNegatives
  };
}

/**
 * Evaluate AI Text Detector
 */
function evaluateAIText() {
  console.log('\n📊 Evaluating AI Text Detector...\n');
  
  var dataset = loadDataset(CONFIG.datasets.aiText);
  if (dataset.length === 0) {
    console.error('No AI text dataset found');
    return null;
  }
  
  var detector = new AITextDetector();
  var results = [];
  
  for (var i = 0; i < dataset.length; i++) {
    var testCase = dataset[i];
    var detection = detector.detect(testCase.text);
    
    results.push({
      id: testCase.id,
      source: testCase.source,
      predicted: detection.isAI,
      actual: testCase.isAI,
      confidence: detection.confidence,
      expectedConfidence: testCase.confidence
    });
  }
  
  var metrics = calculateMetrics(results);
  metrics.bySource = {};
  
  // Group by source
  var sources = {};
  results.forEach(function(r) {
    if (!sources[r.source]) sources[r.source] = [];
    sources[r.source].push(r);
  });
  
  for (var source in sources) {
    metrics.bySource[source] = calculateMetrics(sources[source]);
  }
  
  evaluationResults.detectors['ai-text'] = {
    name: 'AI Text Detection',
    version: '1.0.0',
    dataset: CONFIG.datasets.aiText,
    samples: dataset.length,
    metrics: metrics,
    results: results
  };
  
  if (CONFIG.verbose) {
    printMetrics('AI Text Detection', metrics);
  }
  
  return metrics;
}

/**
 * Evaluate Code Style Analyzer
 */
function evaluateCodeStyle() {
  console.log('\n📊 Evaluating Code Style Analyzer...\n');
  
  // Mock test cases for code authorship
  var testCases = [
    {
      id: 'code-001',
      code1: 'function hello() { console.log("world"); }',
      code2: 'function greet() { console.log("hello"); }',
      sameAuthor: true
    },
    {
      id: 'code-002',
      code1: 'const x = 10; let y = 20;',
      code2: 'var x = 10; var y = 20;',
      sameAuthor: false
    },
    {
      id: 'code-003',
      code1: 'class A { constructor() { this.x = 0; } }',
      code2: 'class B { constructor() { this.y = 0; } }',
      sameAuthor: true
    }
  ];
  
  var analyzer = new CodeStyleAnalyzer();
  var results = [];
  
  for (var i = 0; i < testCases.length; i++) {
    var testCase = testCases[i];
    var fp1 = analyzer.analyze(testCase.code1);
    var fp2 = analyzer.analyze(testCase.code2);
    var similarity = analyzer.compareFingerprints(fp1.fingerprint, fp2.fingerprint);
    
    var predictedSame = similarity.overall > 0.75;
    
    results.push({
      id: testCase.id,
      predicted: predictedSame,
      actual: testCase.sameAuthor,
      similarity: similarity.overall
    });
  }
  
  var metrics = calculateMetrics(results);
  
  evaluationResults.detectors['code-style'] = {
    name: 'Code Style Analysis',
    version: '2.0.0',
    samples: testCases.length,
    metrics: metrics,
    results: results
  };
  
  if (CONFIG.verbose) {
    printMetrics('Code Style Analysis', metrics);
  }
  
  return metrics;
}

/**
 * Evaluate Secret Detection
 */
function evaluateSecretDetection() {
  console.log('\n📊 Evaluating Secret Detection...\n');
  
  var testCases = [
    { id: 'secret-001', text: 'AKIAIOSFODNN7EXAMPLE', hasSecret: true, secretType: 'AWS' },
    { id: 'secret-002', text: 'ghp_abc123def456ghi789jkl012mno345pqr678', hasSecret: true, secretType: 'GitHub' },
    { id: 'secret-003', text: 'sk_live_abc123def456ghi789', hasSecret: true, secretType: 'Stripe' },
    { id: 'secret-004', text: '123-45-6789', hasSecret: true, secretType: 'SSN' },
    { id: 'secret-005', text: '4532015112830366', hasSecret: true, secretType: 'Credit Card' },
    { id: 'secret-006', text: 'Hello world, this is normal text', hasSecret: false },
    { id: 'secret-007', text: 'Just a regular sentence with no secrets', hasSecret: false },
    { id: 'secret-008', text: 'Contact me at john@example.com', hasSecret: false }
  ];
  
  var results = [];
  
  for (var i = 0; i < testCases.length; i++) {
    var testCase = testCases[i];
    var detector = new KasbahDetector();
    var detection = detector.detect({ text: testCase.text });
    
    var hasDetectedSecret = detection.secrets && detection.secrets.length > 0;
    
    results.push({
      id: testCase.id,
      predicted: hasDetectedSecret,
      actual: testCase.hasSecret,
      riskScore: detection.riskScore,
      secretsDetected: detection.secrets ? detection.secrets.length : 0
    });
  }
  
  var metrics = calculateMetrics(results);
  
  evaluationResults.detectors['secret-detection'] = {
    name: 'Secret Detection',
    version: '5.0.0',
    samples: testCases.length,
    metrics: metrics,
    results: results
  };
  
  if (CONFIG.verbose) {
    printMetrics('Secret Detection', metrics);
  }
  
  return metrics;
}

/**
 * Print metrics to console
 */
function printMetrics(detectorName, metrics) {
  console.log('================================');
  console.log(detectorName + ' Results');
  console.log('================================');
  console.log('Samples: ' + metrics.total);
  console.log('Correct: ' + metrics.correct + ' (' + (metrics.accuracy * 100).toFixed(1) + '%)');
  console.log('Incorrect: ' + metrics.incorrect + ' (' + ((1 - metrics.accuracy) * 100).toFixed(1) + '%)');
  console.log('');
  console.log('True Positives: ' + metrics.truePositives);
  console.log('True Negatives: ' + metrics.trueNegatives);
  console.log('False Positives: ' + metrics.falsePositives);
  console.log('False Negatives: ' + metrics.falseNegatives);
  console.log('');
  console.log('Precision: ' + (metrics.precision * 100).toFixed(1) + '%');
  console.log('Recall: ' + (metrics.recall * 100).toFixed(1) + '%');
  console.log('F1 Score: ' + (metrics.f1 * 100).toFixed(1));
  console.log('================================\n');
}

/**
 * Save results to file
 */
function saveResults() {
  var outputDir = CONFIG.outputDir;
  
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  
  var timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  var filename = path.join(outputDir, 'accuracy-results-' + timestamp + '.json');
  
  // Remove detailed results for summary file
  var summaryResults = JSON.parse(JSON.stringify(evaluationResults));
  for (var detector in summaryResults.detectors) {
    summaryResults.detectors[detector].results = undefined;
  }
  
  fs.writeFileSync(filename, JSON.stringify(summaryResults, null, 2));
  console.log('💾 Results saved to: ' + filename);
  
  // Also save detailed results
  var detailedFilename = path.join(outputDir, 'accuracy-results-detailed-' + timestamp + '.json');
  fs.writeFileSync(detailedFilename, JSON.stringify(evaluationResults, null, 2));
  console.log('📋 Detailed results saved to: ' + detailedFilename);
}

/**
 * Print summary
 */
function printSummary() {
  console.log('\n================================');
  console.log('📊 ACCURACY EVALUATION SUMMARY');
  console.log('================================\n');
  
  var totalSamples = 0;
  var totalCorrect = 0;
  
  for (var detector in evaluationResults.detectors) {
    var data = evaluationResults.detectors[detector];
    totalSamples += data.metrics.total;
    totalCorrect += data.metrics.correct;
    
    console.log(data.name + ':');
    console.log('  Accuracy: ' + (data.metrics.accuracy * 100).toFixed(1) + '%');
    console.log('  Precision: ' + (data.metrics.precision * 100).toFixed(1));
    console.log('  Recall: ' + (data.metrics.recall * 100).toFixed(1));
    console.log('  F1 Score: ' + (data.metrics.f1 * 100).toFixed(1));
    console.log('  Samples: ' + data.metrics.total);
    console.log('');
  }
  
  var overallAccuracy = totalCorrect / Math.max(1, totalSamples);
  console.log('================================');
  console.log('OVERALL:');
  console.log('  Total Samples: ' + totalSamples);
  console.log('  Total Correct: ' + totalCorrect);
  console.log('  Overall Accuracy: ' + (overallAccuracy * 100).toFixed(1) + '%');
  console.log('================================\n');
}

/**
 * Main evaluation function
 */
function runEvaluation() {
  console.log('🚀 Kasbah Accuracy Evaluation Suite');
  console.log('====================================');
  console.log('Timestamp: ' + new Date().toISOString());
  console.log('');
  
  // Run evaluations
  evaluateAIText();
  evaluateCodeStyle();
  evaluateSecretDetection();
  
  // Print summary
  printSummary();
  
  // Save results
  saveResults();
  
  console.log('✅ Evaluation complete!');
  
  return evaluationResults;
}

// Run if called directly
if (require.main === module) {
  runEvaluation();
}

// Export for programmatic use
module.exports = {
  runEvaluation: runEvaluation,
  evaluateAIText: evaluateAIText,
  evaluateCodeStyle: evaluateCodeStyle,
  evaluateSecretDetection: evaluateSecretDetection,
  calculateMetrics: calculateMetrics
};
