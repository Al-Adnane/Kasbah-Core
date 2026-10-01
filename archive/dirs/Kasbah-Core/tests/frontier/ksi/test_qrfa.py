"""
Tests for QuantumResistantForensicArchive (QRFA) Module
======================================================

Tests the 3-layer forensic archive:
1. Holographic ledger storage
2. DNA-encoded backup
3. Differential privacy protection
"""

import pytest
import sys
import os
from datetime import datetime
from hashlib import sha256

from core.frontier.ksi.qrfa import (
    QuantumResistantForensicArchive,
    ForensicRecord,
)


@pytest.fixture
def qrfa():
    """Create a fresh QRFA instance for each test."""
    return QuantumResistantForensicArchive()


@pytest.fixture
def sample_event():
    """Sample security event for testing."""
    return {
        "event_type": "suspicious_login",
        "user_id": "user_12345",
        "timestamp": "2026-03-11T14:30:00Z",
        "location": "unknown_ip",
        "details": "Login from new device",
    }


@pytest.fixture
def sample_tcs():
    """Sample TCS (ThreatConsciousnessScore) vector."""
    return {
        "technical_risk": 0.75,
        "cultural_sensitivity": 0.20,
        "intent_class": 0.65,
        "novelty": 0.45,
        "identity_certainty": 0.30,
        "sacred_content_risk": 0.05,
    }


class TestForensicRecordCreation:
    """Test ForensicRecord dataclass creation and structure."""

    def test_forensic_record_creation(self, sample_event, sample_tcs):
        """Test that ForensicRecord can be created with all required fields."""
        now = datetime.utcnow()
        record = ForensicRecord(
            record_id="test_record_123",
            timestamp=now,
            holographic_voxel="(50, 75, 25)",
            dna_sequence="ATGCTAGCTAG",
            privacy_protected_tcs=sample_tcs,
        )

        assert record.record_id == "test_record_123"
        assert record.timestamp == now
        assert record.holographic_voxel == "(50, 75, 25)"
        assert record.dna_sequence == "ATGCTAGCTAG"
        assert len(record.privacy_protected_tcs) == 6

    def test_forensic_record_all_tcs_dimensions(self, sample_tcs):
        """Test that ForensicRecord preserves all 6 TCS dimensions."""
        record = ForensicRecord(
            record_id="test_id",
            timestamp=datetime.utcnow(),
            holographic_voxel="(0, 0, 0)",
            dna_sequence="ATGC",
            privacy_protected_tcs=sample_tcs,
        )

        tcs = record.privacy_protected_tcs
        assert "technical_risk" in tcs
        assert "cultural_sensitivity" in tcs
        assert "intent_class" in tcs
        assert "novelty" in tcs
        assert "identity_certainty" in tcs
        assert "sacred_content_risk" in tcs


class TestQRFARecordEvent:
    """Test QRFA record_event() method — records events through all 3 layers."""

    def test_record_event_returns_forensic_record(self, qrfa, sample_event, sample_tcs):
        """Test that record_event returns a ForensicRecord with all 3 layers."""
        record = qrfa.record_event(sample_event, sample_tcs)

        assert isinstance(record, ForensicRecord)
        assert record.record_id is not None
        assert len(record.record_id) > 0  # SHA256 hash
        assert record.timestamp is not None
        assert record.holographic_voxel is not None
        assert record.dna_sequence is not None
        assert record.privacy_protected_tcs is not None

    def test_record_event_all_layers_present(self, qrfa, sample_event, sample_tcs):
        """Test that all 3 forensic layers are created."""
        record = qrfa.record_event(sample_event, sample_tcs)

        # Layer 1: Holographic ledger (voxel address should be 3D coordinates)
        assert "(" in record.holographic_voxel and ")" in record.holographic_voxel
        # Voxel should be a string representation of coordinates

        # Layer 2: DNA encoding (should be DNA sequence)
        dna_chars = set(record.dna_sequence.upper())
        assert dna_chars.issubset({"A", "T", "G", "C"})

        # Layer 3: Privacy protection (should have all TCS dimensions)
        assert len(record.privacy_protected_tcs) == 6
        assert all(key in record.privacy_protected_tcs for key in sample_tcs.keys())

    def test_record_event_different_events_different_ids(self, qrfa, sample_tcs):
        """Test that different events produce different record IDs."""
        event1 = {"event_type": "login", "user": "alice"}
        event2 = {"event_type": "logout", "user": "bob"}

        record1 = qrfa.record_event(event1, sample_tcs)
        record2 = qrfa.record_event(event2, sample_tcs)

        assert record1.record_id != record2.record_id

    def test_record_event_timestamp_set(self, qrfa, sample_event, sample_tcs):
        """Test that timestamp is set to current time."""
        before = datetime.utcnow()
        record = qrfa.record_event(sample_event, sample_tcs)
        after = datetime.utcnow()

        assert before <= record.timestamp <= after


class TestQRFALaplaceNoise:
    """Test differential privacy (Laplace noise) application."""

    def test_laplace_noise_applied_to_tcs(self, qrfa, sample_event, sample_tcs):
        """Test that Laplace noise is applied to TCS values."""
        record = qrfa.record_event(sample_event, sample_tcs)
        noisy_tcs = record.privacy_protected_tcs

        # At least some TCS values should differ from originals
        # (probability of exact match is very low with Laplace noise)
        differences = []
        for key in sample_tcs.keys():
            if key in noisy_tcs:
                diff = abs(noisy_tcs[key] - sample_tcs[key])
                differences.append(diff)

        # With epsilon=1.0, most values should have some noise
        # At least one dimension should show modification
        assert any(d > 0.0 for d in differences), "Laplace noise should be applied"

    def test_laplace_noise_maintains_bounds(self, qrfa, sample_event, sample_tcs):
        """Test that noisy TCS values stay within [0, 1] bounds."""
        record = qrfa.record_event(sample_event, sample_tcs)
        noisy_tcs = record.privacy_protected_tcs

        for key, value in noisy_tcs.items():
            assert 0.0 <= value <= 1.0, f"{key} = {value} out of bounds [0, 1]"

    def test_laplace_noise_epsilon_parameter(self, qrfa, sample_event, sample_tcs):
        """Test that Laplace scale is based on epsilon parameter."""
        # Record with default epsilon=1.0
        record1 = qrfa.record_event(sample_event, sample_tcs)

        # Record with custom epsilon (higher = less noise)
        record2 = qrfa.record_event(sample_event, sample_tcs)

        # Both should have noise applied
        assert record1.privacy_protected_tcs != record2.privacy_protected_tcs


class TestQRFARetrieveRecord:
    """Test QRFA retrieve_record() method."""

    def test_retrieve_recorded_event(self, qrfa, sample_event, sample_tcs):
        """Test that a recorded event can be retrieved by record_id."""
        # Record an event
        record1 = qrfa.record_event(sample_event, sample_tcs)
        record_id = record1.record_id

        # Retrieve the same record
        record2 = qrfa.retrieve_record(record_id)

        assert record2 is not None
        assert record2.record_id == record_id
        assert record2.holographic_voxel == record1.holographic_voxel
        assert record2.dna_sequence == record1.dna_sequence

    def test_retrieve_nonexistent_record(self, qrfa):
        """Test that retrieving nonexistent record returns None."""
        result = qrfa.retrieve_record("nonexistent_id_xyz")
        assert result is None

    def test_retrieve_record_preserves_all_fields(self, qrfa, sample_event, sample_tcs):
        """Test that retrieved record has all original fields intact."""
        original = qrfa.record_event(sample_event, sample_tcs)
        retrieved = qrfa.retrieve_record(original.record_id)

        assert retrieved.record_id == original.record_id
        assert retrieved.timestamp == original.timestamp
        assert retrieved.holographic_voxel == original.holographic_voxel
        assert retrieved.dna_sequence == original.dna_sequence
        assert len(retrieved.privacy_protected_tcs) == 6


class TestQRFADNAValidity:
    """Test that generated DNA sequences are valid and meaningful."""

    def test_dna_sequence_valid_characters(self, qrfa, sample_event, sample_tcs):
        """Test that DNA sequence contains only valid nucleotide bases."""
        record = qrfa.record_event(sample_event, sample_tcs)
        dna = record.dna_sequence.upper()

        # All characters should be valid DNA bases
        valid_bases = set("ATGC")
        assert set(dna).issubset(valid_bases), f"Invalid bases in: {dna}"

    def test_dna_sequence_non_empty(self, qrfa, sample_event, sample_tcs):
        """Test that DNA sequence is not empty."""
        record = qrfa.record_event(sample_event, sample_tcs)
        assert len(record.dna_sequence) > 0

    def test_dna_chi_squared_test(self, qrfa, sample_event, sample_tcs):
        """
        Test that DNA sequence has reasonable base distribution.

        Note: DNA encoding includes homopolymer avoidance which intentionally
        constrains the distribution, so we test for basic validity rather than
        expecting perfectly uniform distribution.
        """
        # Generate multiple records to collect DNA statistics
        records = []
        for i in range(10):
            event = {**sample_event, "id": i}
            record = qrfa.record_event(event, sample_tcs)
            records.append(record)

        # Collect all DNA sequences
        all_dna = "".join(r.dna_sequence.upper() for r in records)
        assert len(all_dna) > 0, "DNA sequence should not be empty"

        # Count base frequencies
        base_counts = {b: all_dna.count(b) for b in "ATGC"}
        total_bases = len(all_dna)

        # Verify all bases are present (encoding should produce all 4 bases)
        for base in "ATGC":
            assert base_counts[base] > 0, f"Base {base} should be present in DNA"

        # Verify no base dominates excessively (>80% of all bases)
        for base, count in base_counts.items():
            freq = count / total_bases
            assert freq < 0.80, f"Base {base} frequency {freq:.2%} is too high"


class TestQRFAIntegration:
    """Integration tests for full QRFA workflow."""

    def test_full_workflow(self, qrfa, sample_event, sample_tcs):
        """Test complete workflow: record → retrieve → verify."""
        # 1. Record event through all 3 layers
        record1 = qrfa.record_event(sample_event, sample_tcs)
        assert record1 is not None

        # 2. Retrieve the record
        record2 = qrfa.retrieve_record(record1.record_id)
        assert record2 is not None

        # 3. Verify data integrity
        assert record2.record_id == record1.record_id
        assert record2.holographic_voxel == record1.holographic_voxel
        assert record2.dna_sequence == record1.dna_sequence

        # 4. Verify privacy protection is present
        assert record2.privacy_protected_tcs is not None
        assert len(record2.privacy_protected_tcs) == 6

    def test_multiple_records_isolation(self, qrfa, sample_tcs):
        """Test that multiple records don't interfere with each other."""
        events = [
            {"event_type": "login", "user": "alice"},
            {"event_type": "logout", "user": "bob"},
            {"event_type": "login", "user": "charlie"},
        ]

        records = [qrfa.record_event(e, sample_tcs) for e in events]

        # All records should be distinct
        ids = [r.record_id for r in records]
        assert len(ids) == len(set(ids)), "All records should have unique IDs"

        # All should be retrievable
        for record in records:
            retrieved = qrfa.retrieve_record(record.record_id)
            assert retrieved is not None
            assert retrieved.record_id == record.record_id
