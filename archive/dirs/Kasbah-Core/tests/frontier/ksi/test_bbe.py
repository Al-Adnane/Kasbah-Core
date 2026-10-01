"""
Test Suite for BiosignatureBehavioralEngine (BBE) Module

BBE implements behavioral baseline detection - learns user's typing/paste patterns,
detects account takeovers.
"""

import unittest
from datetime import datetime
from core.frontier.ksi.bbe import (
    BiosignatureBehavioralEngine,
    BehavioralBaseline,
    TakeoverAlert,
)


class TestBehavioralBaselineCreation(unittest.TestCase):
    """Test BehavioralBaseline dataclass creation."""

    def test_baseline_creation(self):
        """Test creating a BehavioralBaseline instance."""
        baseline = BehavioralBaseline(
            user_id="user-001",
            typing_speed=72.5,
            paste_frequency=2.3,
            click_velocity=45.8,
            keyboard_vs_mouse=0.65,
        )
        self.assertEqual(baseline.user_id, "user-001")
        self.assertEqual(baseline.typing_speed, 72.5)
        self.assertEqual(baseline.paste_frequency, 2.3)
        self.assertEqual(baseline.sample_count, 0)

    def test_baseline_with_sample_count(self):
        """Test BehavioralBaseline with sample count."""
        baseline = BehavioralBaseline(
            user_id="user-002",
            typing_speed=65.0,
            paste_frequency=1.5,
            click_velocity=40.0,
            keyboard_vs_mouse=0.75,
            sample_count=50,
        )
        self.assertEqual(baseline.sample_count, 50)


class TestBBEBuildBaseline(unittest.TestCase):
    """Test BBE baseline building from events."""

    def setUp(self):
        """Initialize BBE for each test."""
        self.bbe = BiosignatureBehavioralEngine()

    def test_build_baseline_from_single_event(self):
        """Test building baseline from a single event."""
        events = [
            {
                "user_id": "user-001",
                "timestamp": datetime.now(),
                "typing_speed": 70,
                "paste_count": 2,
                "click_count": 45,
                "keyboard_inputs": 100,
                "mouse_inputs": 50,
            }
        ]

        baseline = self.bbe.build_baseline(events)

        self.assertIsNotNone(baseline)
        self.assertEqual(baseline.user_id, "user-001")
        self.assertGreater(baseline.typing_speed, 0)

    def test_build_baseline_from_multiple_events(self):
        """Test building baseline from multiple events (5 events)."""
        events = [
            {
                "user_id": "user-001",
                "timestamp": datetime.now(),
                "typing_speed": 70,
                "paste_count": 2,
                "click_count": 45,
                "keyboard_inputs": 100,
                "mouse_inputs": 50,
            },
            {
                "user_id": "user-001",
                "timestamp": datetime.now(),
                "typing_speed": 75,
                "paste_count": 3,
                "click_count": 48,
                "keyboard_inputs": 110,
                "mouse_inputs": 45,
            },
            {
                "user_id": "user-001",
                "timestamp": datetime.now(),
                "typing_speed": 72,
                "paste_count": 2,
                "click_count": 46,
                "keyboard_inputs": 105,
                "mouse_inputs": 52,
            },
            {
                "user_id": "user-001",
                "timestamp": datetime.now(),
                "typing_speed": 68,
                "paste_count": 1,
                "click_count": 44,
                "keyboard_inputs": 98,
                "mouse_inputs": 48,
            },
            {
                "user_id": "user-001",
                "timestamp": datetime.now(),
                "typing_speed": 73,
                "paste_count": 2,
                "click_count": 47,
                "keyboard_inputs": 108,
                "mouse_inputs": 51,
            },
        ]

        baseline = self.bbe.build_baseline(events)

        self.assertIsNotNone(baseline)
        self.assertEqual(baseline.user_id, "user-001")
        self.assertGreater(baseline.typing_speed, 0)
        self.assertGreater(baseline.paste_frequency, 0)
        self.assertGreater(baseline.click_velocity, 0)
        self.assertGreater(baseline.keyboard_vs_mouse, 0)
        self.assertEqual(baseline.sample_count, 5)

    def test_build_baseline_returns_stats(self):
        """Test that baseline contains proper statistics."""
        events = [
            {
                "user_id": "user-001",
                "typing_speed": 70,
                "paste_count": 2,
                "click_count": 45,
                "keyboard_inputs": 100,
                "mouse_inputs": 50,
            },
            {
                "user_id": "user-001",
                "typing_speed": 80,
                "paste_count": 3,
                "click_count": 50,
                "keyboard_inputs": 120,
                "mouse_inputs": 40,
            },
        ]

        baseline = self.bbe.build_baseline(events)

        # Verify typing speed is within range of inputs
        self.assertGreaterEqual(baseline.typing_speed, 70)
        self.assertLessEqual(baseline.typing_speed, 80)


class TestBBEDetectAccountTakeover(unittest.TestCase):
    """Test BBE account takeover detection."""

    def setUp(self):
        """Initialize BBE for each test."""
        self.bbe = BiosignatureBehavioralEngine()

    def test_no_takeover_same_behavior(self):
        """Test no alert when behavior matches baseline."""
        # Build baseline
        baseline_events = [
            {
                "user_id": "user-001",
                "typing_speed": 70,
                "paste_count": 2,
                "click_count": 45,
                "keyboard_inputs": 100,
                "mouse_inputs": 50,
            },
            {
                "user_id": "user-001",
                "typing_speed": 72,
                "paste_count": 2,
                "click_count": 46,
                "keyboard_inputs": 102,
                "mouse_inputs": 48,
            },
            {
                "user_id": "user-001",
                "typing_speed": 68,
                "paste_count": 2,
                "click_count": 44,
                "keyboard_inputs": 98,
                "mouse_inputs": 52,
            },
        ]

        baseline = self.bbe.build_baseline(baseline_events)

        # Current event within normal range
        current_event = {
            "user_id": "user-001",
            "typing_speed": 71,
            "paste_count": 2,
            "click_count": 45,
            "keyboard_inputs": 100,
            "mouse_inputs": 50,
        }

        alert = self.bbe.detect_account_takeover(current_event, baseline)

        self.assertIsNone(alert)

    def test_detect_takeover_drastically_different_behavior(self):
        """Test takeover detection with drastically different behavior."""
        # Build baseline with normal user behavior
        baseline_events = [
            {
                "user_id": "user-001",
                "typing_speed": 70,
                "paste_count": 2,
                "click_count": 45,
                "keyboard_inputs": 100,
                "mouse_inputs": 50,
            },
            {
                "user_id": "user-001",
                "typing_speed": 72,
                "paste_count": 2,
                "click_count": 46,
                "keyboard_inputs": 102,
                "mouse_inputs": 48,
            },
            {
                "user_id": "user-001",
                "typing_speed": 68,
                "paste_count": 2,
                "click_count": 44,
                "keyboard_inputs": 98,
                "mouse_inputs": 52,
            },
        ]

        baseline = self.bbe.build_baseline(baseline_events)

        # Drastically different behavior (3x typing speed, no mouse)
        attacker_event = {
            "user_id": "user-001",
            "typing_speed": 210,  # 3x normal
            "paste_count": 15,
            "click_count": 200,
            "keyboard_inputs": 300,
            "mouse_inputs": 0,
        }

        alert = self.bbe.detect_account_takeover(attacker_event, baseline)

        self.assertIsNotNone(alert)
        self.assertIsInstance(alert, TakeoverAlert)
        self.assertEqual(alert.user_id, "user-001")
        self.assertGreater(alert.deviation_score, 0.7)

    def test_takeover_alert_has_required_fields(self):
        """Test that TakeoverAlert contains required fields."""
        baseline = BehavioralBaseline(
            user_id="user-001",
            typing_speed=70,
            paste_frequency=2,
            click_velocity=45,
            keyboard_vs_mouse=0.66,
        )

        attacker_event = {
            "user_id": "user-001",
            "typing_speed": 150,
            "paste_count": 20,
            "click_count": 100,
            "keyboard_inputs": 200,
            "mouse_inputs": 10,
        }

        alert = self.bbe.detect_account_takeover(attacker_event, baseline)

        self.assertIsNotNone(alert)
        self.assertTrue(hasattr(alert, "user_id"))
        self.assertTrue(hasattr(alert, "deviation_score"))
        self.assertTrue(hasattr(alert, "reason"))


if __name__ == "__main__":
    unittest.main()
