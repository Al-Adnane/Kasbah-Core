"""Tests for Kasbah Python SDK models"""

import unittest
from kasbah.models import (
    Decision,
    ScanResult,
    GeneratorInfo,
    CalibrationStats,
    MaqasidScores,
    EthicsEvaluation,
    DetectionResult,
    ExecutionProof
)


class TestDecision(unittest.TestCase):
    """Test Decision enum"""

    def test_decision_values(self):
        """Test decision enum values"""
        self.assertEqual(Decision.ALLOW.value, "ALLOW")
        self.assertEqual(Decision.REVIEW.value, "REVIEW")
        self.assertEqual(Decision.DENY.value, "DENY")


class TestScanResult(unittest.TestCase):
    """Test ScanResult dataclass"""

    def test_scan_result_creation(self):
        """Test ScanResult creation"""
        result = ScanResult(
            risk=0.8,
            decision=Decision.DENY,
            reason="High risk secret detected",
            violations=["AWS_KEY"]
        )
        self.assertEqual(result.risk, 0.8)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(len(result.violations), 1)


class TestGeneratorInfo(unittest.TestCase):
    """Test GeneratorInfo class"""

    def test_generator_info_creation(self):
        """Test GeneratorInfo creation"""
        info = GeneratorInfo(
            name="GPT-4",
            version="2024.01",
            media_type="text",
            confidence_threshold=0.5
        )
        self.assertEqual(info.name, "GPT-4")
        self.assertEqual(info.media_type, "text")
        self.assertEqual(info.confidence_threshold, 0.5)

    def test_generator_info_to_dict(self):
        """Test GeneratorInfo to_dict method"""
        info = GeneratorInfo(name="Test", version="1.0", media_type="text")
        data = info.to_dict()
        self.assertEqual(data["name"], "Test")
        self.assertEqual(data["version"], "1.0")

    def test_generator_info_from_dict(self):
        """Test GeneratorInfo from_dict method"""
        data = {"name": "Test", "version": "2.0", "media_type": "image"}
        info = GeneratorInfo.from_dict(data)
        self.assertEqual(info.name, "Test")
        self.assertEqual(info.version, "2.0")


class TestCalibrationStats(unittest.TestCase):
    """Test CalibrationStats class"""

    def test_calibration_stats_creation(self):
        """Test CalibrationStats creation"""
        stats = CalibrationStats(
            domain="image",
            true_positive_rate=0.95,
            false_positive_rate=0.05,
            threshold=0.5,
            sample_count=1000
        )
        self.assertEqual(stats.domain, "image")
        self.assertEqual(stats.true_positive_rate, 0.95)
        self.assertEqual(stats.sample_count, 1000)

    def test_calibration_stats_to_dict(self):
        """Test CalibrationStats to_dict method"""
        stats = CalibrationStats(
            domain="text",
            true_positive_rate=0.9,
            false_positive_rate=0.1,
            threshold=0.45
        )
        data = stats.to_dict()
        self.assertEqual(data["domain"], "text")
        self.assertEqual(data["true_positive_rate"], 0.9)


class TestMaqasidScores(unittest.TestCase):
    """Test MaqasidScores class"""

    def test_maqasid_scores_creation(self):
        """Test MaqasidScores creation"""
        scores = MaqasidScores(
            faith=0.9,
            life=0.8,
            intellect=0.85,
            lineage=0.75,
            wealth=0.7
        )
        self.assertEqual(scores.faith, 0.9)
        self.assertEqual(scores.life, 0.8)

    def test_maqasid_scores_overall(self):
        """Test overall score calculation"""
        scores = MaqasidScores(
            faith=1.0,
            life=1.0,
            intellect=1.0,
            lineage=1.0,
            wealth=1.0
        )
        self.assertEqual(scores.overall, 1.0)

    def test_maqasid_scores_clamping(self):
        """Test score clamping to 0-1 range"""
        scores = MaqasidScores(faith=1.5, life=-0.5, intellect=0.5, lineage=0.5, wealth=0.5)
        self.assertEqual(scores.faith, 1.0)
        self.assertEqual(scores.life, 0.0)

    def test_maqasid_scores_to_dict(self):
        """Test MaqasidScores to_dict method"""
        scores = MaqasidScores(faith=0.9, life=0.8, intellect=0.85, lineage=0.75, wealth=0.7)
        data = scores.to_dict()
        self.assertIn("overall", data)
        self.assertAlmostEqual(data["overall"], 0.8, places=2)


class TestEthicsEvaluation(unittest.TestCase):
    """Test EthicsEvaluation class"""

    def test_ethics_evaluation_creation(self):
        """Test EthicsEvaluation creation"""
        evaluation = EthicsEvaluation(
            permissible=True,
            score=0.85,
            violations=[],
            recommendation="Content is permissible"
        )
        self.assertTrue(evaluation.permissible)
        self.assertEqual(evaluation.score, 0.85)
        self.assertEqual(len(evaluation.violations), 0)

    def test_ethics_evaluation_with_violations(self):
        """Test EthicsEvaluation with violations"""
        evaluation = EthicsEvaluation(
            permissible=False,
            score=0.3,
            violations=["Harmful content", "Misinformation"],
            recommendation="Content should be blocked"
        )
        self.assertFalse(evaluation.permissible)
        self.assertEqual(len(evaluation.violations), 2)

    def test_ethics_evaluation_with_maqasid(self):
        """Test EthicsEvaluation with MaqasidScores"""
        maqasid = MaqasidScores(faith=0.9, life=0.8, intellect=0.85, lineage=0.75, wealth=0.7)
        evaluation = EthicsEvaluation(
            permissible=True,
            score=0.85,
            maqasid_scores=maqasid
        )
        self.assertIsNotNone(evaluation.maqasid_scores)
        self.assertEqual(evaluation.maqasid_scores.faith, 0.9)

    def test_ethics_evaluation_to_dict(self):
        """Test EthicsEvaluation to_dict method"""
        evaluation = EthicsEvaluation(
            permissible=True,
            score=0.85,
            recommendation="Approved"
        )
        data = evaluation.to_dict()
        self.assertEqual(data["permissible"], True)
        self.assertEqual(data["recommendation"], "Approved")


class TestDetectionResult(unittest.TestCase):
    """Test DetectionResult dataclass"""

    def test_detection_result_creation(self):
        """Test DetectionResult creation"""
        result = DetectionResult(
            verdict="deepfake",
            confidence=0.95,
            confidence_level="very_high",
            processing_time_ms=45.2
        )
        self.assertEqual(result.verdict, "deepfake")
        self.assertEqual(result.confidence, 0.95)

    def test_detection_result_to_dict(self):
        """Test DetectionResult to_dict method"""
        result = DetectionResult(
            verdict="authentic",
            confidence=0.1,
            confidence_level="very_low",
            processing_time_ms=12.5,
            indicators=["test"]
        )
        data = result.to_dict()
        self.assertEqual(data["verdict"], "authentic")
        self.assertEqual(len(data["indicators"]), 1)


class TestExecutionProof(unittest.TestCase):
    """Test ExecutionProof dataclass"""

    def test_execution_proof_creation(self):
        """Test ExecutionProof creation"""
        import time
        proof = ExecutionProof(
            proof_hash="abc123",
            ticket_id="ticket-456",
            generated_at=int(time.time() * 1000),
            nonce="xyz789"
        )
        self.assertEqual(proof.proof_hash, "abc123")
        self.assertEqual(proof.ticket_id, "ticket-456")

    def test_execution_proof_to_dict(self):
        """Test ExecutionProof to_dict method"""
        proof = ExecutionProof(
            proof_hash="hash",
            ticket_id="ticket",
            generated_at=1234567890,
            nonce="nonce"
        )
        data = proof.to_dict()
        self.assertEqual(data["proof_hash"], "hash")
        self.assertEqual(data["ticket_id"], "ticket")


if __name__ == "__main__":
    unittest.main()
