"""
Tests for Phase 8 Orchestrator Integration
===========================================

Tests the KSI Phase 8 detector registration and adapter functionality.
"""

import pytest
from core.frontier.orchestrator import (
    _KSISynthesisAdapter,
    DetectionType,
)
from core.frontier.ksi import (
    ThreatConsciousnessScore, CrossDetectorResonance,
    TemporalIntentCascade, CulturalTriageEngine,
    EmergentPatternSynthesizer, SacredContentSanctuaryManager,
    AdversarialIdentityChronicle, BiosignatureBehavioralEngine,
    UniversalSecurityCertificateManager, QuantumResistantForensicArchive,
)


@pytest.fixture
def ksi_adapter():
    """Create a KSISynthesisAdapter instance."""
    return _KSISynthesisAdapter(
        tcs=ThreatConsciousnessScore(
            technical_risk=0.0,
            cultural_sensitivity=0.0,
            intent_class=0.0,
            novelty=0.0,
            identity_certainty=0.0,
            sacred_content_risk=0.0,
        ),
        cdr=CrossDetectorResonance(),
        tic=TemporalIntentCascade(),
        cte=CulturalTriageEngine(),
        eps=EmergentPatternSynthesizer(),
        scs=SacredContentSanctuaryManager(),
        aic=AdversarialIdentityChronicle(),
        bbe=BiosignatureBehavioralEngine(),
        usc=UniversalSecurityCertificateManager(),
        qrfa=QuantumResistantForensicArchive(),
    )


class TestDetectionTypeEnum:
    """Test DetectionType enum includes KSI_SYNTHESIS."""

    def test_ksi_synthesis_in_enum(self):
        """Test that KSI_SYNTHESIS is defined in DetectionType enum."""
        assert hasattr(DetectionType, 'KSI_SYNTHESIS')
        assert DetectionType.KSI_SYNTHESIS.value == "ksi_synthesis"

    def test_all_detection_types(self):
        """Test that all expected detection types are present."""
        expected_types = [
            "biometric",
            "neural_fingerprint",
            "prompt",
            "secret",
            "steganalysis",
            "synthetic_persona",
            "rag_security",
            "stream",
            "multilingual",
            "maqasid",
            "multilingual_pii",
            "quran_semantic",
            "federated_intent",
            "semantic_company",
            "ksi_synthesis",  # Phase 8
        ]
        actual_types = [dt.value for dt in DetectionType]
        for dtype in expected_types:
            assert dtype in actual_types, f"Missing detection type: {dtype}"


class TestKSISynthesisAdapter:
    """Test KSISynthesisAdapter initialization and detection."""

    def test_adapter_creation(self, ksi_adapter):
        """Test that KSISynthesisAdapter can be instantiated."""
        assert ksi_adapter is not None
        assert len(ksi_adapter.modules) == 10  # All 10 KSI modules

    def test_adapter_has_all_modules(self, ksi_adapter):
        """Test that all 10 KSI modules are initialized."""
        expected_modules = [
            'tcs', 'cdr', 'tic', 'cte', 'eps',
            'scs', 'aic', 'bbe', 'usc', 'qrfa'
        ]
        for module_name in expected_modules:
            assert module_name in ksi_adapter.modules, f"Missing module: {module_name}"
            assert ksi_adapter.modules[module_name] is not None

    def test_adapter_detect_returns_dict(self, ksi_adapter):
        """Test that detect() returns a dictionary with required keys."""
        payload = {"text": "test"}
        options = {}

        result = ksi_adapter.detect(payload, options)

        assert isinstance(result, dict)
        assert "detected" in result
        assert "confidence" in result
        assert "details" in result

    def test_adapter_detect_with_event(self, ksi_adapter):
        """Test detect() with event and TCS data."""
        payload = {"text": "test event"}
        options = {
            "event": {
                "event_type": "login",
                "user": "alice",
                "timestamp": "2026-03-11T12:00:00Z",
            },
            "tcs": {
                "technical_risk": 0.5,
                "cultural_sensitivity": 0.2,
                "intent_class": 0.3,
                "novelty": 0.4,
                "identity_certainty": 0.6,
                "sacred_content_risk": 0.1,
            },
        }

        result = ksi_adapter.detect(payload, options)

        assert result["detected"] is True  # QRFA should detect the event
        assert result["confidence"] > 0.0
        assert "qrfa" in result["details"]["module_results"]

    def test_adapter_detect_qrfa_creates_record(self, ksi_adapter):
        """Test that QRFA module creates forensic records during detection."""
        payload = {"text": "security event"}
        options = {
            "event": {"event_type": "anomaly", "severity": "high"},
            "tcs": {
                "technical_risk": 0.8,
                "cultural_sensitivity": 0.1,
                "intent_class": 0.7,
                "novelty": 0.5,
                "identity_certainty": 0.4,
                "sacred_content_risk": 0.0,
            },
        }

        result = ksi_adapter.detect(payload, options)

        # Check QRFA result
        qrfa_result = result["details"]["module_results"].get("qrfa")
        assert qrfa_result is not None
        assert "record_id" in qrfa_result
        assert "voxel" in qrfa_result
        assert "dna_length" in qrfa_result

    def test_adapter_detect_tcs_validation(self, ksi_adapter):
        """Test that adapter validates TCS data."""
        payload = {"text": "test"}
        options = {
            "tcs": {
                "technical_risk": 0.5,
                "cultural_sensitivity": 0.2,
                "intent_class": 0.3,
                "novelty": 0.4,
                "identity_certainty": 0.6,
                "sacred_content_risk": 0.1,
            }
        }

        result = ksi_adapter.detect(payload, options)

        # TCS should be validated and present in results
        tcs_result = result["details"]["module_results"].get("tcs")
        assert tcs_result is not None
        assert tcs_result.get("present") is True
        assert tcs_result.get("dimensions") == 6

    def test_adapter_confidence_bounds(self, ksi_adapter):
        """Test that confidence is always in [0, 1]."""
        payload = {"text": "test"}

        # Test multiple times to account for randomness
        for _ in range(5):
            options = {
                "event": {"type": "test"},
                "tcs": {
                    "technical_risk": 0.5,
                    "cultural_sensitivity": 0.5,
                    "intent_class": 0.5,
                    "novelty": 0.5,
                    "identity_certainty": 0.5,
                    "sacred_content_risk": 0.5,
                },
            }
            result = ksi_adapter.detect(payload, options)
            assert 0.0 <= result["confidence"] <= 1.0

    def test_adapter_synthesis_notes(self, ksi_adapter):
        """Test that synthesis notes are provided."""
        payload = {"text": "test"}
        options = {
            "event": {"type": "security"},
            "tcs": {
                "technical_risk": 0.5,
                "cultural_sensitivity": 0.2,
                "intent_class": 0.3,
                "novelty": 0.4,
                "identity_certainty": 0.6,
                "sacred_content_risk": 0.1,
            },
        }

        result = ksi_adapter.detect(payload, options)

        notes = result["details"].get("synthesis_notes")
        assert notes is not None
        assert "KSI Phase 8" in notes


class TestPhase8Integration:
    """Integration tests for Phase 8 with full KSI stack."""

    def test_qrfa_records_multiple_events(self, ksi_adapter):
        """Test that QRFA can record multiple events with different payloads."""
        events = [
            {"type": "login", "user": "alice"},
            {"type": "logout", "user": "bob"},
            {"type": "access", "resource": "file1"},
        ]

        tcs = {
            "technical_risk": 0.5,
            "cultural_sensitivity": 0.2,
            "intent_class": 0.3,
            "novelty": 0.4,
            "identity_certainty": 0.6,
            "sacred_content_risk": 0.1,
        }

        results = []
        for event in events:
            result = ksi_adapter.detect(
                {"text": str(event)},
                {"event": event, "tcs": tcs}
            )
            results.append(result)

        # All should have detected=True (QRFA recorded events)
        assert all(r["detected"] for r in results)
        # All should have unique record IDs
        record_ids = [
            r["details"]["module_results"]["qrfa"]["record_id"]
            for r in results
        ]
        assert len(set(record_ids)) == len(record_ids), "Record IDs should be unique"

    def test_phase8_full_synthesis(self, ksi_adapter):
        """Test full Phase 8 synthesis with all KSI data."""
        payload = {"text": "comprehensive security analysis"}
        options = {
            "event": {
                "event_type": "threat_detected",
                "severity": "critical",
                "timestamp": "2026-03-11T14:30:00Z",
                "indicators": ["malware", "exfiltration"],
            },
            "tcs": {
                "technical_risk": 0.9,
                "cultural_sensitivity": 0.3,
                "intent_class": 0.85,
                "novelty": 0.7,
                "identity_certainty": 0.4,
                "sacred_content_risk": 0.05,
            },
        }

        result = ksi_adapter.detect(payload, options)

        # Verify complete synthesis
        assert result["detected"] is True
        assert result["confidence"] > 0.0
        assert len(result["details"]["module_results"]) >= 2  # TCS and QRFA
        assert result["details"]["modules_active"] == 10
