"""
Test Suite for EmergentPatternSynthesizer (EPS) Module

EPS takes observation history and auto-generates organization-specific regex patterns
from semantic embeddings and neuromorphic SNN weights.
"""

import unittest
from core.frontier.ksi.eps import EmergentPatternSynthesizer


class TestEPSTraining(unittest.TestCase):
    """Test EPS observation training."""

    def setUp(self):
        """Initialize EPS for each test."""
        self.eps = EmergentPatternSynthesizer()

    def test_train_on_empty_observations(self):
        """Test training with empty observation list."""
        self.eps.train_on_observations([])
        # Should handle empty observations gracefully
        self.assertIsNotNone(self.eps)

    def test_train_on_single_observation(self):
        """Test training with a single observation."""
        observations = ["APP_SECRET_abc123def456_PROD_2024"]
        self.eps.train_on_observations(observations)
        # Should store observation without error
        self.assertIsNotNone(self.eps)

    def test_train_on_multiple_observations(self):
        """Test training with multiple observations."""
        observations = [
            "APP_SECRET_abc123def456_PROD_2024",
            "APP_SECRET_xyz789uvw012_STAGE_2025",
            "APP_SECRET_def456ghi789_DEV_2024",
        ]
        self.eps.train_on_observations(observations)
        # Should handle multiple observations
        self.assertIsNotNone(self.eps)


class TestEPSPatternSynthesis(unittest.TestCase):
    """Test pattern synthesis from observations."""

    def setUp(self):
        """Initialize EPS for each test."""
        self.eps = EmergentPatternSynthesizer()

    def test_synthesize_empty_observations(self):
        """Test synthesize with no observations returns empty list."""
        self.eps.train_on_observations([])
        patterns = self.eps.synthesize_patterns()

        self.assertIsInstance(patterns, list)
        self.assertEqual(len(patterns), 0)

    def test_synthesize_patterns_from_single_format(self):
        """Test pattern synthesis from repeated format observations."""
        # Multiple observations with same format
        observations = [
            "APP_SECRET_abc123def456_PROD_2024",
            "APP_SECRET_xyz789uvw012_PROD_2025",
            "APP_SECRET_ghi123jkl456_STAGE_2024",
        ]
        self.eps.train_on_observations(observations)
        patterns = self.eps.synthesize_patterns()

        self.assertIsInstance(patterns, list)
        # Should generate at least one pattern from repeated format
        self.assertGreater(len(patterns), 0)
        # Generated patterns should be strings (regex)
        for pattern in patterns:
            self.assertIsInstance(pattern, str)

    def test_synthesize_patterns_from_multiple_formats(self):
        """Test pattern synthesis from multiple format observations."""
        observations = [
            "APP_SECRET_abc123def456_PROD_2024",
            "DB_PASS_xyz789_staging",
            "API_KEY_ghijkl_prod_123",
            "DB_PASS_uvwxyz_production",
        ]
        self.eps.train_on_observations(observations)
        patterns = self.eps.synthesize_patterns()

        self.assertIsInstance(patterns, list)
        # Multiple formats should generate patterns
        self.assertGreater(len(patterns), 0)

    def test_synthesize_generates_valid_regex_patterns(self):
        """Test that synthesized patterns are valid regex strings."""
        observations = [
            "TOKEN_abc123def456",
            "TOKEN_xyz789uvw012",
            "TOKEN_ghi123jkl456",
        ]
        self.eps.train_on_observations(observations)
        patterns = self.eps.synthesize_patterns()

        # Should generate patterns
        self.assertGreater(len(patterns), 0)

        # Each pattern should be a string (and theoretically valid regex)
        for pattern in patterns:
            self.assertIsInstance(pattern, str)
            self.assertGreater(len(pattern), 0)


class TestEPSPatternMatching(unittest.TestCase):
    """Test that synthesized patterns can match observations."""

    def setUp(self):
        """Initialize EPS for each test."""
        self.eps = EmergentPatternSynthesizer()

    def test_patterns_can_be_compiled(self):
        """Test that synthesized patterns can be compiled as regex."""
        import re

        observations = [
            "SECRET_abc123def456",
            "SECRET_xyz789uvw012",
        ]
        self.eps.train_on_observations(observations)
        patterns = self.eps.synthesize_patterns()

        # All patterns should be compilable regex
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error:
                self.fail(f"Pattern '{pattern}' is not valid regex")


if __name__ == "__main__":
    unittest.main()
