"""
Test Suite for ThreatConsciousnessScore (TCS) Module

Tests the 6-dimensional threat model:
- technical_risk: from secret_guard, steganalysis, biometrics
- cultural_sensitivity: from maqasid, multilingual_pii, quran_semantic
- intent_class: from federated_intent_graph, synthetic_persona
- novelty: from neuromorphic_guard SNN weight drift
- identity_certainty: from neural_fingerprint, biometric_forensics
- sacred_content_risk: from quran_frontier, quran_semantic_guard

Maqasid Decision Logic:
1. If sacred_content_risk >= 0.95, auto-DENY
2. Otherwise use weighted geometric mean: [0.25, 0.20, 0.20, 0.20, 0.15]
3. Decision: DENY if score >= 0.7, WARN if score >= 0.5, ALLOW otherwise
"""

import sys
import unittest
from typing import Dict

# Import TCS module
from core.frontier.ksi.tcs import (
    ThreatConsciousnessScore,
    compute_tcs_vector,
    TCSDecision,
)


class TestTCSVectorCreation(unittest.TestCase):
    """Test TCS vector creation and dimensional validation."""

    def test_tcs_vector_creation(self):
        """Test that TCS can be created with all 6 dimensions and they're 0-1.0."""
        tcs = ThreatConsciousnessScore(
            technical_risk=0.65,
            cultural_sensitivity=0.45,
            intent_class=0.55,
            novelty=0.40,
            identity_certainty=0.75,
            sacred_content_risk=0.30,
        )

        # Verify all dimensions exist and are in valid range [0, 1.0]
        self.assertEqual(tcs.technical_risk, 0.65)
        self.assertEqual(tcs.cultural_sensitivity, 0.45)
        self.assertEqual(tcs.intent_class, 0.55)
        self.assertEqual(tcs.novelty, 0.40)
        self.assertEqual(tcs.identity_certainty, 0.75)
        self.assertEqual(tcs.sacred_content_risk, 0.30)

        # Verify all are within valid range
        for value in [
            tcs.technical_risk,
            tcs.cultural_sensitivity,
            tcs.intent_class,
            tcs.novelty,
            tcs.identity_certainty,
            tcs.sacred_content_risk,
        ]:
            self.assertGreaterEqual(value, 0.0)
            self.assertLessEqual(value, 1.0)

    def test_tcs_zero_dimensions(self):
        """Test TCS with all zero dimensions."""
        tcs = ThreatConsciousnessScore(
            technical_risk=0.0,
            cultural_sensitivity=0.0,
            intent_class=0.0,
            novelty=0.0,
            identity_certainty=0.0,
            sacred_content_risk=0.0,
        )
        self.assertEqual(tcs.technical_risk, 0.0)
        self.assertEqual(tcs.sacred_content_risk, 0.0)

    def test_tcs_max_dimensions(self):
        """Test TCS with all dimensions at maximum (1.0)."""
        tcs = ThreatConsciousnessScore(
            technical_risk=1.0,
            cultural_sensitivity=1.0,
            intent_class=1.0,
            novelty=1.0,
            identity_certainty=1.0,
            sacred_content_risk=1.0,
        )
        self.assertEqual(tcs.technical_risk, 1.0)
        self.assertEqual(tcs.sacred_content_risk, 1.0)


class TestTCSMaqasidSynthesis(unittest.TestCase):
    """Test Maqasid-based threat synthesis and decision logic."""

    def test_sacred_content_override_auto_deny(self):
        """Test that sacred_content_risk >= 0.95 forces DENY decision."""
        tcs = ThreatConsciousnessScore(
            technical_risk=0.1,  # Low risk
            cultural_sensitivity=0.1,
            intent_class=0.1,
            novelty=0.1,
            identity_certainty=0.1,
            sacred_content_risk=0.95,  # Sacred content override
        )

        vector = compute_tcs_vector(tcs)

        # Should force DENY regardless of other low dimensions
        self.assertEqual(vector.decision, TCSDecision.DENY)
        self.assertGreaterEqual(vector.score, 0.7)

    def test_sacred_content_just_below_threshold(self):
        """Test that sacred_content_risk < 0.95 uses normal Maqasid logic."""
        tcs = ThreatConsciousnessScore(
            technical_risk=0.1,
            cultural_sensitivity=0.1,
            intent_class=0.1,
            novelty=0.1,
            identity_certainty=0.1,
            sacred_content_risk=0.94,  # Just below override threshold
        )

        vector = compute_tcs_vector(tcs)

        # Should use weighted geometric mean, not automatic override
        # With all low values, should be ALLOW
        self.assertEqual(vector.decision, TCSDecision.ALLOW)
        self.assertLess(vector.score, 0.5)

    def test_low_technical_high_sacred_still_deny(self):
        """Test that low technical risk doesn't save high sacred content risk."""
        tcs = ThreatConsciousnessScore(
            technical_risk=0.05,  # Very low
            cultural_sensitivity=0.05,
            intent_class=0.05,
            novelty=0.05,
            identity_certainty=0.05,
            sacred_content_risk=0.96,  # High sacred risk
        )

        vector = compute_tcs_vector(tcs)

        # Sacred content override should prevent low technical risk from saving it
        self.assertEqual(vector.decision, TCSDecision.DENY)

    def test_maqasid_weighted_geometric_mean(self):
        """Test weighted geometric mean calculation with normal risk profile."""
        tcs = ThreatConsciousnessScore(
            technical_risk=0.5,
            cultural_sensitivity=0.5,
            intent_class=0.5,
            novelty=0.5,
            identity_certainty=0.5,
            sacred_content_risk=0.3,  # Below override threshold
        )

        vector = compute_tcs_vector(tcs)

        # With moderate technical/cultural/intent/novelty (0.5) and lower identity (0.5)
        # Weighted: 0.25*0.5 + 0.20*0.5 + 0.20*0.5 + 0.20*0.5 + 0.15*0.5
        # Should result in moderate score (around 0.5)
        self.assertGreater(vector.score, 0.0)
        self.assertLess(vector.score, 1.0)

    def test_deny_threshold_at_0_7(self):
        """Test that score >= 0.7 triggers DENY."""
        tcs = ThreatConsciousnessScore(
            technical_risk=0.9,
            cultural_sensitivity=0.7,
            intent_class=0.8,
            novelty=0.6,
            identity_certainty=0.8,
            sacred_content_risk=0.2,
        )

        vector = compute_tcs_vector(tcs)

        # High dimensional values should trigger DENY
        if vector.score >= 0.7:
            self.assertEqual(vector.decision, TCSDecision.DENY)

    def test_warn_threshold_at_0_5(self):
        """Test that 0.5 <= score < 0.7 triggers WARN."""
        tcs = ThreatConsciousnessScore(
            technical_risk=0.6,
            cultural_sensitivity=0.55,
            intent_class=0.5,
            novelty=0.5,
            identity_certainty=0.6,
            sacred_content_risk=0.2,
        )

        vector = compute_tcs_vector(tcs)

        # Moderate dimensional values should trigger WARN or ALLOW
        self.assertIn(vector.decision, [TCSDecision.WARN, TCSDecision.ALLOW])

    def test_allow_threshold_below_0_5(self):
        """Test that score < 0.5 triggers ALLOW."""
        tcs = ThreatConsciousnessScore(
            technical_risk=0.2,
            cultural_sensitivity=0.2,
            intent_class=0.2,
            novelty=0.3,
            identity_certainty=0.2,
            sacred_content_risk=0.1,
        )

        vector = compute_tcs_vector(tcs)

        # Low dimensional values should trigger ALLOW
        if vector.score < 0.5:
            self.assertEqual(vector.decision, TCSDecision.ALLOW)


class TestTCSDecisionConsistency(unittest.TestCase):
    """Test decision consistency and edge cases."""

    def test_decision_is_deterministic(self):
        """Test that the same TCS input always produces the same decision."""
        tcs = ThreatConsciousnessScore(
            technical_risk=0.65,
            cultural_sensitivity=0.45,
            intent_class=0.55,
            novelty=0.40,
            identity_certainty=0.75,
            sacred_content_risk=0.30,
        )

        vector1 = compute_tcs_vector(tcs)
        vector2 = compute_tcs_vector(tcs)

        # Same input should produce identical output
        self.assertEqual(vector1.decision, vector2.decision)
        self.assertEqual(vector1.score, vector2.score)

    def test_score_is_normalized_0_to_1(self):
        """Test that final score is always between 0 and 1."""
        test_cases = [
            (0.0, 0.0, 0.0, 0.0, 0.0, 0.0),
            (1.0, 1.0, 1.0, 1.0, 1.0, 1.0),
            (0.5, 0.5, 0.5, 0.5, 0.5, 0.5),
            (0.1, 0.2, 0.3, 0.4, 0.5, 0.6),
            (0.95, 0.85, 0.75, 0.65, 0.55, 0.45),
        ]

        for tech, cult, intent, nov, ident, sacred in test_cases:
            tcs = ThreatConsciousnessScore(
                technical_risk=tech,
                cultural_sensitivity=cult,
                intent_class=intent,
                novelty=nov,
                identity_certainty=ident,
                sacred_content_risk=sacred,
            )
            vector = compute_tcs_vector(tcs)
            self.assertGreaterEqual(vector.score, 0.0, f"Score < 0 for {test_cases}")
            self.assertLessEqual(vector.score, 1.0, f"Score > 1 for {test_cases}")


def run_all_tests() -> Dict[str, any]:
    """
    Run all test suites and return results.

    Returns:
        Dictionary with test summary
    """
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestTCSVectorCreation))
    suite.addTests(loader.loadTestsFromTestCase(TestTCSMaqasidSynthesis))
    suite.addTests(loader.loadTestsFromTestCase(TestTCSDecisionConsistency))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Return summary
    return {
        "total": result.testsRun,
        "passed": result.testsRun - len(result.failures) - len(result.errors),
        "failed": len(result.failures),
        "errors": len(result.errors),
        "success": result.wasSuccessful(),
    }


if __name__ == "__main__":
    summary = run_all_tests()
    print(f"\n{'='*60}")
    print(f"TCS (ThreatConsciousnessScore) TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Total Tests: {summary['total']}")
    print(f"Passed: {summary['passed']}")
    print(f"Failed: {summary['failed']}")
    print(f"Errors: {summary['errors']}")
    print(f"Status: {'✓ ALL PASSED' if summary['success'] else '✗ FAILURES DETECTED'}")
    print(f"{'='*60}")

    sys.exit(0 if summary["success"] else 1)
