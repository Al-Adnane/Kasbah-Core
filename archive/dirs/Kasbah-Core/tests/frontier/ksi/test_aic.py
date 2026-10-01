"""
Test Suite for AdversarialIdentityChronicle (AIC) Module

AIC implements cross-session threat actor tracking using neural fingerprint
and behavioral patterns, persisting threat actor graphs.
"""

import unittest
from datetime import datetime
from core.frontier.ksi.aic import (
    AdversarialIdentityChronicle,
    ThreatActor,
)


class TestThreatActorCreation(unittest.TestCase):
    """Test ThreatActor dataclass creation."""

    def test_threat_actor_creation(self):
        """Test creating a ThreatActor instance."""
        actor = ThreatActor(
            actor_id="actor-2026-001",
            fingerprint={"entropy": 0.85, "timing_variance": 0.42},
            first_seen=datetime.now(),
        )
        self.assertEqual(actor.actor_id, "actor-2026-001")
        self.assertEqual(actor.fingerprint["entropy"], 0.85)
        self.assertEqual(len(actor.events), 0)

    def test_threat_actor_with_events(self):
        """Test ThreatActor with events added."""
        actor = ThreatActor(
            actor_id="actor-2026-002",
            fingerprint={"entropy": 0.82},
            first_seen=datetime.now(),
            events=[
                {"timestamp": datetime.now(), "type": "login", "ip": "192.168.1.1"}
            ],
        )
        self.assertEqual(len(actor.events), 1)
        self.assertEqual(actor.events[0]["type"], "login")


class TestAICIdentifyNewThreatActor(unittest.TestCase):
    """Test AIC threat actor identification - new actors."""

    def setUp(self):
        """Initialize AIC for each test."""
        self.aic = AdversarialIdentityChronicle()

    def test_identify_new_threat_actor(self):
        """Test that a new event creates a new threat actor with unique ID."""
        event = {
            "timestamp": datetime.now(),
            "ip": "203.0.113.45",
            "user_agent": "Mozilla/5.0...",
            "behavioral_features": {"typing_speed": 65, "paste_count": 3},
        }

        actor = self.aic.identify_threat_actor(event)

        self.assertIsNotNone(actor)
        self.assertIsNotNone(actor.actor_id)
        self.assertTrue(actor.actor_id.startswith("actor-"))
        self.assertEqual(len(actor.events), 1)
        self.assertEqual(actor.events[0], event)


class TestAICIdentifyReturningThreatActor(unittest.TestCase):
    """Test AIC threat actor identification - returning actors."""

    def setUp(self):
        """Initialize AIC for each test."""
        self.aic = AdversarialIdentityChronicle()

    def test_recognize_returning_attacker_same_fingerprint(self):
        """Test that returning attacker with same fingerprint is recognized."""
        # First event
        event1 = {
            "timestamp": datetime.now(),
            "ip": "203.0.113.45",
            "user_agent": "Mozilla/5.0 Windows NT 10.0",
            "behavioral_features": {"typing_speed": 65, "paste_count": 3},
        }

        actor1 = self.aic.identify_threat_actor(event1)
        actor_id_1 = actor1.actor_id

        # Second event with same/similar fingerprint
        event2 = {
            "timestamp": datetime.now(),
            "ip": "203.0.113.45",
            "user_agent": "Mozilla/5.0 Windows NT 10.0",
            "behavioral_features": {"typing_speed": 67, "paste_count": 2},
        }

        actor2 = self.aic.identify_threat_actor(event2)
        actor_id_2 = actor2.actor_id

        # Should be the same actor
        self.assertEqual(actor_id_1, actor_id_2)
        # Should have both events
        self.assertEqual(len(actor2.events), 2)

    def test_distinguish_different_threat_actors(self):
        """Test that different fingerprints create different actors."""
        event1 = {
            "timestamp": datetime.now(),
            "ip": "203.0.113.45",
            "user_agent": "Mozilla/5.0 Windows NT 10.0",
            "behavioral_features": {"typing_speed": 65, "paste_count": 3},
        }

        event2 = {
            "timestamp": datetime.now(),
            "ip": "198.51.100.89",
            "user_agent": "Safari MacOS",
            "behavioral_features": {"typing_speed": 120, "paste_count": 15},
        }

        actor1 = self.aic.identify_threat_actor(event1)
        actor2 = self.aic.identify_threat_actor(event2)

        # Different fingerprints should create different actors
        self.assertNotEqual(actor1.actor_id, actor2.actor_id)


class TestAICActorTimeline(unittest.TestCase):
    """Test AIC actor event timeline retrieval."""

    def setUp(self):
        """Initialize AIC for each test."""
        self.aic = AdversarialIdentityChronicle()

    def test_get_actor_timeline_single_event(self):
        """Test timeline retrieval for actor with single event."""
        event = {
            "timestamp": datetime.now(),
            "ip": "203.0.113.45",
            "event_type": "login_attempt",
        }

        actor = self.aic.identify_threat_actor(event)
        timeline = self.aic.get_actor_timeline(actor.actor_id)

        self.assertEqual(len(timeline), 1)
        self.assertEqual(timeline[0]["event_type"], "login_attempt")

    def test_get_actor_timeline_multiple_events_in_order(self):
        """Test that timeline returns events in chronological order."""
        import time

        event1 = {
            "timestamp": datetime(2026, 3, 10, 10, 0, 0),
            "ip": "203.0.113.45",
            "sequence": 1,
        }

        actor = self.aic.identify_threat_actor(event1)
        actor_id = actor.actor_id

        # Add second event (simulate returning attacker)
        event2 = {
            "timestamp": datetime(2026, 3, 10, 10, 5, 0),
            "ip": "203.0.113.45",
            "sequence": 2,
        }

        self.aic.identify_threat_actor(event2)

        timeline = self.aic.get_actor_timeline(actor_id)

        self.assertEqual(len(timeline), 2)
        # Verify chronological order
        self.assertLessEqual(timeline[0]["timestamp"], timeline[1]["timestamp"])
        self.assertEqual(timeline[0]["sequence"], 1)
        self.assertEqual(timeline[1]["sequence"], 2)

    def test_get_actor_timeline_nonexistent_actor(self):
        """Test timeline retrieval for nonexistent actor returns empty list."""
        timeline = self.aic.get_actor_timeline("actor-nonexistent")
        self.assertEqual(timeline, [])


if __name__ == "__main__":
    unittest.main()
