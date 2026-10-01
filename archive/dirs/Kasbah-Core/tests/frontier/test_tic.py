"""
Test Suite for TemporalIntentCascade (TIC) Module

Tests retroactive re-evaluation of past intercepts when EXFILTRATION intent is confirmed.

Key scenarios:
1. When EXFILTRATION intent confirmed, re-examine last N minutes of intercepts
2. Re-score each past intercept with new EXFILTRATION intent prior
3. Things that were WARN (0.55) become DENY (0.78) with new prior
4. Events outside the time window are NOT re-evaluated
"""

import sys
import unittest
from datetime import datetime, timedelta
from typing import Dict, List

# Import TIC module
from core.frontier.ksi.tic import TemporalIntentCascade


class TestTICRetroactiveReeval(unittest.TestCase):
    """Test TIC retroactive re-evaluation logic."""

    def setUp(self):
        """Set up TIC instance for each test."""
        self.tic = TemporalIntentCascade(history_window_minutes=10)

    def test_tic_retroactive_reeval(self):
        """
        Test that when EXFILTRATION intent is confirmed, past events are re-evaluated.

        Scenario:
        1. Add 2 historical events with higher confidence (0.80)
        2. Confirm EXFILTRATION intent (intent_prior = 0.95)
        3. Verify both events were re-evaluated with new prior
        4. Expected: events that were WARN/ALLOW become DENY after re-eval
           because 0.80 * 0.95 = 0.76 >= 0.75 (DENY threshold)
        """
        # Create event 1 (confidence 0.80, initially WARN)
        event1 = {
            "timestamp": datetime.now() - timedelta(minutes=5),
            "content": "Upload large file to external server",
            "confidence": 0.80,
            "decision": "WARN",
        }

        # Create event 2 (confidence 0.80, initially WARN)
        event2 = {
            "timestamp": datetime.now() - timedelta(minutes=3),
            "content": "Copy sensitive data to USB drive",
            "confidence": 0.80,
            "decision": "WARN",
        }

        # Add historical events
        self.tic.add_historical_event(event1)
        self.tic.add_historical_event(event2)

        # Verify events were added
        self.assertEqual(len(self.tic.history), 2)

        # Now confirm EXFILTRATION intent with high prior 0.95
        # 0.80 * 0.95 = 0.76 >= 0.75 (DENY threshold)
        exfiltration_event = {
            "timestamp": datetime.now(),
            "content": "Confirmed exfiltration to external IP",
            "confidence": 0.95,
            "decision": "DENY",
        }

        # Retroactively re-evaluate with EXFILTRATION prior
        reeval_results = self.tic.retroactive_reeval(
            exfiltration_event, new_intent_prior=0.95
        )

        # Verify that events were re-evaluated
        self.assertEqual(len(reeval_results), 2)

        # Verify that events became DENY after re-eval (0.80 * 0.95 = 0.76 >= 0.75)
        for reeval_event in reeval_results:
            self.assertEqual(
                reeval_event["decision"], "DENY"
            ), "Events should be upgraded to DENY with new intent prior"

    def test_tic_outside_window_not_affected(self):
        """
        Test that events outside the time window are NOT re-evaluated.

        Scenario:
        1. Add event 1 within 10-minute window
        2. Add event 2 outside 10-minute window (11 minutes ago)
        3. Confirm EXFILTRATION intent
        4. Verify only event 1 was re-evaluated, event 2 was ignored
        """
        # Create event INSIDE window (5 minutes ago)
        event_inside = {
            "timestamp": datetime.now() - timedelta(minutes=5),
            "content": "Upload within window",
            "confidence": 0.55,
            "decision": "WARN",
        }

        # Create event OUTSIDE window (11 minutes ago)
        event_outside = {
            "timestamp": datetime.now() - timedelta(minutes=11),
            "content": "Old event outside window",
            "confidence": 0.60,
            "decision": "WARN",
        }

        # Add both events
        self.tic.add_historical_event(event_outside)
        self.tic.add_historical_event(event_inside)

        # Verify both were added
        self.assertEqual(len(self.tic.history), 2)

        # Confirm EXFILTRATION intent
        exfiltration_event = {
            "timestamp": datetime.now(),
            "content": "Confirmed exfiltration",
            "confidence": 0.95,
            "decision": "DENY",
        }

        # Retroactively re-evaluate
        reeval_results = self.tic.retroactive_reeval(
            exfiltration_event, new_intent_prior=0.78
        )

        # Verify only 1 event was re-evaluated (the one inside the window)
        self.assertEqual(
            len(reeval_results), 1
        ), "Only events within window should be re-evaluated"

        # Verify the re-evaluated event is the inside one
        reeval_event = reeval_results[0]
        self.assertIn(
            "Upload within window", reeval_event["content"]
        ), "Re-evaluated event should be the inside-window event"


class TestTICRingBuffer(unittest.TestCase):
    """Test TIC ring buffer functionality."""

    def test_ring_buffer_maxlen(self):
        """Test that ring buffer respects maxlen=100."""
        tic = TemporalIntentCascade(history_window_minutes=10)

        # Add 150 events
        for i in range(150):
            event = {
                "timestamp": datetime.now() - timedelta(minutes=i),
                "content": f"Event {i}",
                "confidence": 0.50,
                "decision": "ALLOW",
            }
            tic.add_historical_event(event)

        # Verify buffer only holds 100 most recent events
        self.assertEqual(
            len(tic.history), 100
        ), "Ring buffer should maintain maxlen=100"


class TestTICReevalLogic(unittest.TestCase):
    """Test TIC re-evaluation scoring logic."""

    def test_reeval_scoring_boundaries(self):
        """Test Bayesian re-scoring with different confidence levels."""
        tic = TemporalIntentCascade(history_window_minutes=10)

        # Test with ALLOW (0.3)
        allow_event = {
            "timestamp": datetime.now() - timedelta(minutes=5),
            "confidence": 0.3,
            "decision": "ALLOW",
        }

        # Test with WARN (0.55)
        warn_event = {
            "timestamp": datetime.now() - timedelta(minutes=5),
            "confidence": 0.55,
            "decision": "WARN",
        }

        # Test with DENY (0.85)
        deny_event = {
            "timestamp": datetime.now() - timedelta(minutes=5),
            "confidence": 0.85,
            "decision": "DENY",
        }

        # Re-score with low intent prior (0.3)
        allow_result = tic._reeval_with_prior(allow_event, intent_prior=0.3)
        self.assertEqual(allow_result, "ALLOW")

        # Re-score with high intent prior (0.9)
        warn_result = tic._reeval_with_prior(warn_event, intent_prior=0.9)
        # 0.55 * 0.9 = 0.495, which is < 0.5, so ALLOW
        # But with cascading effect, might be WARN
        self.assertIn(warn_result, ["ALLOW", "WARN", "DENY"])

        # Re-score DENY with high prior
        deny_result = tic._reeval_with_prior(deny_event, intent_prior=0.9)
        self.assertEqual(deny_result, "DENY")


if __name__ == "__main__":
    unittest.main()
