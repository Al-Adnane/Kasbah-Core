"""
Test Suite for UniversalSecurityCertificate (USC) Module

USC implements per-transfer Ed25519-signed cryptographic compliance certificates.
"""

import unittest
from datetime import datetime
from core.frontier.ksi.usc import (
    UniversalSecurityCertificate,
    UniversalSecurityCertificateManager,
)


class TestUniversalSecurityCertificateCreation(unittest.TestCase):
    """Test UniversalSecurityCertificate dataclass creation."""

    def test_certificate_creation(self):
        """Test creating a USC instance."""
        cert = UniversalSecurityCertificate(
            cert_id="ksc-2026-03-11-a3f9abc123",
            tcs_vector={
                "technical_risk": 0.45,
                "cultural_sensitivity": 0.30,
                "intent_class": "BENIGN",
                "novelty": 0.15,
                "identity_certainty": 0.85,
                "sacred_content_risk": 0.05,
            },
            cultural_framework="GDPR_EU",
            intent_class="BENIGN",
            cdr_coefficient=0.62,
            decision="ALLOW",
            signature="sig_abc123def456...",
            ledger_voxel="voxel-2026-03-11-xyz789",
            issued_at=datetime.now(),
        )

        self.assertEqual(cert.cert_id, "ksc-2026-03-11-a3f9abc123")
        self.assertEqual(cert.cultural_framework, "GDPR_EU")
        self.assertEqual(cert.decision, "ALLOW")
        self.assertIsNotNone(cert.signature)


class TestUSCGenerateCertificate(unittest.TestCase):
    """Test USC manager certificate generation."""

    def setUp(self):
        """Initialize USC manager for each test."""
        self.manager = UniversalSecurityCertificateManager()

    def test_generate_certificate(self):
        """Test generating a basic certificate."""
        event = {
            "type": "data_transfer",
            "user_id": "user-001",
            "timestamp": datetime.now(),
            "size_bytes": 1024,
        }

        tcs = {
            "technical_risk": 0.45,
            "cultural_sensitivity": 0.30,
            "intent_class": "BENIGN",
            "novelty": 0.15,
            "identity_certainty": 0.85,
            "sacred_content_risk": 0.05,
        }

        cert = self.manager.generate_certificate(event, tcs, "ALLOW")

        self.assertIsNotNone(cert)
        self.assertIsNotNone(cert.cert_id)
        self.assertTrue(cert.cert_id.startswith("ksc-"))
        self.assertEqual(cert.decision, "ALLOW")

    def test_certificate_has_all_tcs_dimensions(self):
        """Test that certificate includes all 6 TCS dimensions."""
        event = {
            "type": "data_transfer",
            "user_id": "user-001",
        }

        tcs = {
            "technical_risk": 0.45,
            "cultural_sensitivity": 0.30,
            "intent_class": "BENIGN",
            "novelty": 0.15,
            "identity_certainty": 0.85,
            "sacred_content_risk": 0.05,
        }

        cert = self.manager.generate_certificate(event, tcs, "ALLOW")

        # Verify all 6 dimensions are in the certificate
        self.assertEqual(len(cert.tcs_vector), 6)
        self.assertIn("technical_risk", cert.tcs_vector)
        self.assertIn("cultural_sensitivity", cert.tcs_vector)
        self.assertIn("intent_class", cert.tcs_vector)
        self.assertIn("novelty", cert.tcs_vector)
        self.assertIn("identity_certainty", cert.tcs_vector)
        self.assertIn("sacred_content_risk", cert.tcs_vector)

    def test_certificate_has_signature(self):
        """Test that generated certificate has a signature."""
        event = {"type": "data_transfer"}
        tcs = {
            "technical_risk": 0.50,
            "cultural_sensitivity": 0.35,
            "intent_class": "SUSPICIOUS",
            "novelty": 0.20,
            "identity_certainty": 0.75,
            "sacred_content_risk": 0.10,
        }

        cert = self.manager.generate_certificate(event, tcs, "WARN")

        self.assertIsNotNone(cert.signature)
        self.assertGreater(len(cert.signature), 0)

    def test_certificate_has_ledger_voxel(self):
        """Test that certificate has a ledger voxel address."""
        event = {"type": "data_transfer"}
        tcs = {
            "technical_risk": 0.65,
            "cultural_sensitivity": 0.40,
            "intent_class": "SUSPICIOUS",
            "novelty": 0.25,
            "identity_certainty": 0.70,
            "sacred_content_risk": 0.15,
        }

        cert = self.manager.generate_certificate(event, tcs, "WARN")

        self.assertIsNotNone(cert.ledger_voxel)
        self.assertGreater(len(cert.ledger_voxel), 0)

    def test_generate_different_decision_types(self):
        """Test generating certificates with different decisions."""
        event = {"type": "data_transfer"}
        base_tcs = {
            "technical_risk": 0.50,
            "cultural_sensitivity": 0.35,
            "intent_class": "BENIGN",
            "novelty": 0.20,
            "identity_certainty": 0.75,
            "sacred_content_risk": 0.10,
        }

        for decision in ["ALLOW", "WARN", "DENY"]:
            cert = self.manager.generate_certificate(event, base_tcs, decision)
            self.assertEqual(cert.decision, decision)


class TestUSCVerifyCertificate(unittest.TestCase):
    """Test USC certificate verification."""

    def setUp(self):
        """Initialize USC manager for each test."""
        self.manager = UniversalSecurityCertificateManager()

    def test_verify_valid_certificate(self):
        """Test verifying a valid certificate."""
        event = {"type": "data_transfer"}
        tcs = {
            "technical_risk": 0.45,
            "cultural_sensitivity": 0.30,
            "intent_class": "BENIGN",
            "novelty": 0.15,
            "identity_certainty": 0.85,
            "sacred_content_risk": 0.05,
        }

        cert = self.manager.generate_certificate(event, tcs, "ALLOW")
        public_key = self.manager.get_public_key()

        is_valid = self.manager.verify_certificate(cert, public_key)

        self.assertTrue(is_valid)

    def test_verify_certificate_with_correct_public_key(self):
        """Test that certificate verification works with matching key."""
        event = {"type": "data_transfer", "user_id": "user-001"}
        tcs = {
            "technical_risk": 0.50,
            "cultural_sensitivity": 0.35,
            "intent_class": "SUSPICIOUS",
            "novelty": 0.20,
            "identity_certainty": 0.75,
            "sacred_content_risk": 0.10,
        }

        cert = self.manager.generate_certificate(event, tcs, "WARN")
        public_key = self.manager.get_public_key()

        is_valid = self.manager.verify_certificate(cert, public_key)
        self.assertTrue(is_valid)

    def test_certificate_verification_fails_with_wrong_key(self):
        """Test that verification fails with incorrect public key."""
        event = {"type": "data_transfer"}
        tcs = {
            "technical_risk": 0.55,
            "cultural_sensitivity": 0.40,
            "intent_class": "SUSPICIOUS",
            "novelty": 0.25,
            "identity_certainty": 0.70,
            "sacred_content_risk": 0.15,
        }

        cert = self.manager.generate_certificate(event, tcs, "DENY")

        # Use a different (wrong) public key
        wrong_key = "invalid_public_key_data"

        is_valid = self.manager.verify_certificate(cert, wrong_key)
        self.assertFalse(is_valid)

    def test_certificate_verification_fails_when_tampered(self):
        """Test that verification fails when certificate data is tampered."""
        event = {"type": "data_transfer"}
        tcs = {
            "technical_risk": 0.45,
            "cultural_sensitivity": 0.30,
            "intent_class": "BENIGN",
            "novelty": 0.15,
            "identity_certainty": 0.85,
            "sacred_content_risk": 0.05,
        }

        cert = self.manager.generate_certificate(event, tcs, "ALLOW")
        public_key = self.manager.get_public_key()

        # Tamper with the certificate decision
        cert.decision = "DENY"

        is_valid = self.manager.verify_certificate(cert, public_key)
        self.assertFalse(is_valid)


if __name__ == "__main__":
    unittest.main()
