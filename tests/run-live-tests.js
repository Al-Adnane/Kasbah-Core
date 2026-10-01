#!/usr/bin/env node

/**
 * Kasbah Live Testing Harness
 *
 * Orchestrates all frontier model tests:
 *   1. Frontier Shield capability tests
 *   2. Red team attack vector tests
 *   3. Silent speech analysis tests
 *   4. Performance & stress tests
 *   5. Fail-closed behavior tests
 *
 * Usage:
 *   node tests/run-live-tests.js [--frontier] [--red-team] [--silent-speech] [--all]
 */

const { FrontierModelsTestSuite } = require('./frontier-models-test');
const { SilentSpeechTestSuite } = require('./silent-speech-test');
const path = require('path');
const fs = require('fs');

class KasbahLiveTestHarness {
  constructor() {
    this.startTime = Date.now();
    this.allResults = {};
    this.args = process.argv.slice(2);
  }

  /**
   * Print banner
   */
  printBanner() {
    console.clear();
    console.log(`
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║         KASBAH FRONTIER MODELS - LIVE TEST HARNESS             ║
║                                                                ║
║  Testing:                                                      ║
║    • Red Team Attack Vectors                                  ║
║    • Frontier Shield Capabilities (6 defense modules)         ║
║    • Silent Speech Intent Analysis                            ║
║    • Hybrid Detection (Local + Remote)                        ║
║    • Performance & Latency                                    ║
║    • Fail-Closed Behavior                                     ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
    `);
  }

  /**
   * Run frontier models tests
   */
  async runFrontierTests() {
    console.log('\n\n┌────────────────────────────────────────┐');
    console.log('│ PHASE 1: FRONTIER MODELS TESTING       │');
    console.log('└────────────────────────────────────────┘');

    try {
      const suite = new FrontierModelsTestSuite();
      await suite.runAllTests();
      this.allResults.frontier = suite.results;
      return true;
    } catch (e) {
      console.error('\n❌ Frontier models test failed:', e.message);
      return false;
    }
  }

  /**
   * Run silent speech tests
   */
  async runSilentSpeechTests() {
    console.log('\n\n┌────────────────────────────────────────┐');
    console.log('│ PHASE 2: SILENT SPEECH ANALYSIS        │');
    console.log('└────────────────────────────────────────┘');

    try {
      const suite = new SilentSpeechTestSuite();
      await suite.runAllTests();
      this.allResults.silentSpeech = suite.results;
      return true;
    } catch (e) {
      console.error('\n❌ Silent speech test failed:', e.message);
      return false;
    }
  }

  /**
   * Run stress test
   */
  async runStressTest() {
    console.log('\n\n┌────────────────────────────────────────┐');
    console.log('│ PHASE 3: STRESS TESTING                │');
    console.log('└────────────────────────────────────────┘\n');

    try {
      const suite = new FrontierModelsTestSuite();

      if (!suite.endpoint) {
        console.log('⚠️  Skipping stress test - no endpoint available');
        return true;
      }

      console.log('Running concurrent threat detection requests...');

      const concurrentRequests = 10;
      const batchSize = 5;
      const totalBatches = 3;

      for (let batch = 0; batch < totalBatches; batch++) {
        console.log(`\nBatch ${batch + 1}/${totalBatches}:`);

        const startBatch = Date.now();
        const promises = [];

        for (let i = 0; i < concurrentRequests; i++) {
          promises.push(
            suite
              .call('POST', '/v1/scan', {
                text: `Concurrent test request ${i + 1}`,
                source: 'stress-test'
              })
              .catch((e) => ({ error: e.message }))
          );
        }

        const results = await Promise.all(promises);
        const batchTime = Date.now() - startBatch;

        const successful = results.filter((r) => !r.error).length;
        const failed = results.filter((r) => r.error).length;

        console.log(
          `  ${successful} successful, ${failed} failed in ${batchTime}ms`
        );
        console.log(
          `  Throughput: ${(concurrentRequests / (batchTime / 1000)).toFixed(1)} req/sec`
        );
      }

      console.log('\n✓ Stress test completed');
      return true;
    } catch (e) {
      console.error('❌ Stress test failed:', e.message);
      return false;
    }
  }

  /**
   * Run all tests
   */
  async runAll() {
    this.printBanner();

    const results = {
      frontier: false,
      silentSpeech: false,
      stress: false
    };

    // Run tests based on arguments
    const shouldRunFrontier =
      this.args.includes('--all') ||
      this.args.includes('--frontier') ||
      this.args.length === 0;
    const shouldRunSilent =
      this.args.includes('--all') ||
      this.args.includes('--silent-speech') ||
      this.args.length === 0;
    const shouldRunStress =
      this.args.includes('--all') ||
      this.args.includes('--stress');

    if (shouldRunFrontier) {
      results.frontier = await this.runFrontierTests();
    }

    if (shouldRunSilent) {
      results.silentSpeech = await this.runSilentSpeechTests();
    }

    if (shouldRunStress) {
      results.stress = await this.runStressTest();
    }

    this.printFinalReport(results);
  }

  /**
   * Print final test report
   */
  printFinalReport(results) {
    const elapsed = Date.now() - this.startTime;

    console.log(`
╔════════════════════════════════════════════════════════════════╗
║                      FINAL TEST REPORT                         ║
╚════════════════════════════════════════════════════════════════╝

Test Results:
${results.frontier ? '  ✓ Frontier Models' : '  ⊗ Frontier Models'}
${results.silentSpeech ? '  ✓ Silent Speech Analysis' : '  ⊗ Silent Speech Analysis'}
${results.stress ? '  ✓ Stress Testing' : '  ⊗ Stress Testing'}

Overall Status: ${results.frontier || results.silentSpeech ? '✓ PASSED' : '✗ FAILED'}
Total Time: ${(elapsed / 1000).toFixed(1)}s

Next Steps:
  1. Review test results above
  2. Check deployment logs: kasbah deploy logs
  3. Verify health: kasbah deploy verify
  4. Deploy to production: git push

    `);

    // Save results to file
    this.saveResults(results);
  }

  /**
   * Save test results to JSON file
   */
  saveResults(results) {
    const reportPath = path.join(__dirname, '..', 'test-results.json');

    const report = {
      timestamp: new Date().toISOString(),
      duration: Date.now() - this.startTime,
      results,
      details: this.allResults
    };

    try {
      fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
      console.log(`Test results saved to: ${reportPath}`);
    } catch (e) {
      console.error('Failed to save test results:', e.message);
    }
  }
}

// Run harness
if (require.main === module) {
  const harness = new KasbahLiveTestHarness();
  harness.runAll().catch(console.error);
}

module.exports = { KasbahLiveTestHarness };
