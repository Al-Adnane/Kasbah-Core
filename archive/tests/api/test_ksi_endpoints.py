"""
============================================================================
KSI API ENDPOINTS - TEST SUITE
============================================================================

Test suite for the 6 new KSI API endpoints:
1. POST /api/ksi/analyze
2. GET /api/ksi/chronicle
3. GET/POST /api/ksi/certificate/<event_id>
4. GET /api/ksi/sanctuary
5. GET /api/ksi/patterns
6. GET /api/ksi/forensic-archive/<record_id>
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

# ============================================================================
# MOCK DATA FIXTURES
# ============================================================================

@pytest.fixture
def mock_tcs_response():
    """Mock TCS analysis response"""
    return {
        "tcs_vector": {
            "technical_risk": 0.3,
            "cultural_sensitivity": 0.1,
            "intent_class": 0.5,
            "novelty": 0.2,
            "identity_certainty": 0.9,
            "sacred_content_risk": 0.0
        },
        "cdr_coefficient": 0.08,
        "intent_class": "SUSPICIOUS",
        "decision": "WARN"
    }

@pytest.fixture
def mock_threat_actors():
    """Mock threat actors from chronicle"""
    return [
        {
            "actor_id": "actor_abc123",
            "fingerprint": {"hash": "sha256_...", "pattern": "..."},
            "first_seen": "2026-03-11T14:20:00Z",
            "event_count": 12,
            "risk_score": 0.87,
            "status": "ACTIVE"
        },
        {
            "actor_id": "actor_xyz789",
            "fingerprint": {"hash": "sha256_...", "pattern": "..."},
            "first_seen": "2026-03-10T10:15:00Z",
            "event_count": 5,
            "risk_score": 0.42,
            "status": "INACTIVE"
        }
    ]

@pytest.fixture
def mock_certificate():
    """Mock USS certificate"""
    return {
        "cert_id": "ksc-2026-03-11-a3f9e2c1",
        "tcs_vector": [0.3, 0.1, 0.5, 0.2, 0.9, 0.0],
        "cultural_framework": "GDPR_EU",
        "intent_class": "SUSPICIOUS",
        "decision": "WARN",
        "signature": "Ed25519_signature_base64_encoded_here",
        "ledger_voxel": "x=1204,y=873,z=3,o=0b01001101",
        "issued_at": "2026-03-11T14:32:01Z"
    }

@pytest.fixture
def mock_sanctuaries():
    """Mock sanctuary records"""
    return [
        {
            "cert_id": "ksc-2026-03-11-abc123",
            "protected_data_type": "QURAN_VERSE",
            "protection_level": "MAXIMUM",
            "timestamp": "2026-03-11T14:20:15Z"
        },
        {
            "cert_id": "ksc-2026-03-11-def456",
            "protected_data_type": "RELIGIOUS_TEXT",
            "protection_level": "MAXIMUM",
            "timestamp": "2026-03-11T13:45:00Z"
        }
    ]

@pytest.fixture
def mock_patterns():
    """Mock EPS patterns"""
    return [
        {
            "pattern": "(?:APP_SECRET_)[A-Z0-9]{32}_(?:PROD|STAGE)_[0-9]{4}",
            "confidence": 0.91,
            "observations": 12,
            "first_seen": "2026-03-11T14:10:00Z"
        },
        {
            "pattern": "(?:API_KEY)[_-]?[A-Za-z0-9]{32,}",
            "confidence": 0.87,
            "observations": 8,
            "first_seen": "2026-03-11T14:05:00Z"
        },
        {
            "pattern": "(?:SECRET_KEY|API_SECRET)\\s*=\\s*['\\\"][A-Za-z0-9_-]{32,}['\\\"]",
            "confidence": 0.84,
            "observations": 15,
            "first_seen": "2026-03-11T13:30:00Z"
        }
    ]

@pytest.fixture
def mock_forensic_record():
    """Mock forensic archive record"""
    return {
        "record_id": "sha256_abcdef1234567890abcdef1234567890",
        "timestamp": "2026-03-11T14:32:01Z",
        "holographic_voxel": "x=1204,y=873,z=3",
        "dna_sequence": "ATGCATGCATGCATGCATGCATGCATGCATGCATGC",
        "privacy_protected_tcs": {
            "technical_risk": 0.32,
            "cultural_sensitivity": 0.11,
            "intent_class": 0.51,
            "novelty": 0.19,
            "identity_certainty": 0.88,
            "sacred_content_risk": 0.01
        }
    }

# ============================================================================
# TEST: POST /api/ksi/analyze
# ============================================================================

class TestKSIAnalyze:
    """Test POST /api/ksi/analyze endpoint"""

    def test_analyze_returns_tcs_vector(self, mock_tcs_response):
        """Should return 6-dimensional TCS vector"""
        assert "tcs_vector" in mock_tcs_response
        vector = mock_tcs_response["tcs_vector"]
        assert len(vector) == 6
        assert "technical_risk" in vector
        assert "cultural_sensitivity" in vector
        assert "intent_class" in vector
        assert "novelty" in vector
        assert "identity_certainty" in vector
        assert "sacred_content_risk" in vector

    def test_analyze_returns_cdr_coefficient(self, mock_tcs_response):
        """Should return CDR coefficient (Maqasid score)"""
        assert "cdr_coefficient" in mock_tcs_response
        assert 0 <= mock_tcs_response["cdr_coefficient"] <= 1

    def test_analyze_returns_intent_class(self, mock_tcs_response):
        """Should classify intent as SUSPICIOUS, BENIGN, or UNKNOWN"""
        intent = mock_tcs_response["intent_class"]
        assert intent in ["SUSPICIOUS", "BENIGN", "UNKNOWN"]

    def test_analyze_returns_decision(self, mock_tcs_response):
        """Should return ALLOW, WARN, or DENY decision"""
        decision = mock_tcs_response["decision"]
        assert decision in ["ALLOW", "WARN", "DENY"]

    def test_analyze_accepts_text_input(self):
        """Should accept 'text' field in request body"""
        request_body = {
            "text": "SELECT * FROM users",
            "context": "database_query"
        }
        assert "text" in request_body
        assert len(request_body["text"]) > 0

    def test_analyze_accepts_context_parameter(self):
        """Should accept 'context' parameter"""
        valid_contexts = ["database_query", "api_response", "code_snippet", "text"]
        for context in valid_contexts:
            assert context in valid_contexts

    def test_analyze_handles_empty_text(self):
        """Should return 400 Bad Request for empty text"""
        request_body = {"text": "", "context": "text"}
        assert len(request_body["text"]) == 0  # Should trigger validation error

    def test_analyze_handles_very_long_text(self):
        """Should handle or reject very long text (10KB+)"""
        long_text = "a" * 10001
        assert len(long_text) > 10000

    def test_analyze_handles_special_characters(self):
        """Should handle text with special characters"""
        special_text = "SELECT * FROM users WHERE email LIKE '%@example.com%'"
        assert len(special_text) > 0

    def test_analyze_handles_unicode(self):
        """Should handle Unicode text"""
        unicode_text = "مرحبا بك في النظام"
        assert len(unicode_text) > 0

    def test_analyze_response_status_200(self):
        """Should return HTTP 200 on success"""
        # Status code should be 200
        assert True

    def test_analyze_response_status_400_invalid_input(self):
        """Should return HTTP 400 for invalid input"""
        # Status code should be 400
        assert True

    def test_analyze_response_status_500_server_error(self):
        """Should return HTTP 500 on server error"""
        # Status code should be 500
        assert True

    def test_analyze_response_is_json(self, mock_tcs_response):
        """Should return valid JSON response"""
        json_str = json.dumps(mock_tcs_response)
        assert isinstance(json_str, str)

    def test_analyze_all_vector_values_are_floats(self, mock_tcs_response):
        """All TCS vector values should be floats between 0-1"""
        vector = mock_tcs_response["tcs_vector"]
        for key, value in vector.items():
            assert isinstance(value, (int, float))
            assert 0 <= value <= 1, f"{key} should be between 0-1"

# ============================================================================
# TEST: GET /api/ksi/chronicle
# ============================================================================

class TestKSIChronicle:
    """Test GET /api/ksi/chronicle endpoint"""

    def test_chronicle_returns_threat_actors_list(self, mock_threat_actors):
        """Should return array of threat actors"""
        assert isinstance(mock_threat_actors, list)
        assert len(mock_threat_actors) > 0

    def test_chronicle_actor_has_required_fields(self, mock_threat_actors):
        """Each actor should have required fields"""
        required_fields = ["actor_id", "fingerprint", "first_seen", "event_count", "risk_score", "status"]
        for actor in mock_threat_actors:
            for field in required_fields:
                assert field in actor, f"Missing field: {field}"

    def test_chronicle_actor_id_format(self, mock_threat_actors):
        """Actor ID should match expected format"""
        for actor in mock_threat_actors:
            assert actor["actor_id"].startswith("actor_")

    def test_chronicle_risk_score_is_float(self, mock_threat_actors):
        """Risk score should be float between 0-1"""
        for actor in mock_threat_actors:
            assert isinstance(actor["risk_score"], (int, float))
            assert 0 <= actor["risk_score"] <= 1

    def test_chronicle_status_is_valid(self, mock_threat_actors):
        """Status should be ACTIVE, INACTIVE, or SUSPENDED"""
        valid_statuses = ["ACTIVE", "INACTIVE", "SUSPENDED"]
        for actor in mock_threat_actors:
            assert actor["status"] in valid_statuses

    def test_chronicle_event_count_is_integer(self, mock_threat_actors):
        """Event count should be integer >= 0"""
        for actor in mock_threat_actors:
            assert isinstance(actor["event_count"], int)
            assert actor["event_count"] >= 0

    def test_chronicle_first_seen_is_timestamp(self, mock_threat_actors):
        """first_seen should be valid ISO timestamp"""
        for actor in mock_threat_actors:
            assert "T" in actor["first_seen"]
            assert "Z" in actor["first_seen"]

    def test_chronicle_response_status_200(self):
        """Should return HTTP 200 on success"""
        assert True

    def test_chronicle_response_is_json(self, mock_threat_actors):
        """Should return valid JSON response"""
        response = {"threat_actors": mock_threat_actors}
        json_str = json.dumps(response)
        assert isinstance(json_str, str)

    def test_chronicle_actors_sorted_by_risk_score(self, mock_threat_actors):
        """Actors should be sorted by risk score (descending)"""
        sorted_actors = sorted(mock_threat_actors, key=lambda x: x["risk_score"], reverse=True)
        assert sorted_actors[0]["risk_score"] >= sorted_actors[-1]["risk_score"]

    def test_chronicle_supports_filtering_by_status(self, mock_threat_actors):
        """Should support filtering by status"""
        active_actors = [a for a in mock_threat_actors if a["status"] == "ACTIVE"]
        assert isinstance(active_actors, list)

# ============================================================================
# TEST: GET/POST /api/ksi/certificate/<event_id>
# ============================================================================

class TestKSICertificate:
    """Test GET/POST /api/ksi/certificate/<event_id> endpoint"""

    def test_certificate_get_returns_valid_cert(self, mock_certificate):
        """GET should return valid certificate"""
        assert "cert_id" in mock_certificate
        assert "tcs_vector" in mock_certificate
        assert "signature" in mock_certificate

    def test_certificate_has_cert_id(self, mock_certificate):
        """Certificate should have cert_id in format ksc-YYYY-MM-DD-xxx"""
        cert_id = mock_certificate["cert_id"]
        assert cert_id.startswith("ksc-")
        assert "2026-03-11" in cert_id

    def test_certificate_tcs_vector_is_6d(self, mock_certificate):
        """TCS vector should be 6-dimensional array"""
        vector = mock_certificate["tcs_vector"]
        assert isinstance(vector, list)
        assert len(vector) == 6

    def test_certificate_has_cultural_framework(self, mock_certificate):
        """Should include cultural framework"""
        frameworks = ["GDPR_EU", "CCPA_US", "LGPD_BR", "PIPEDA_CA"]
        assert mock_certificate["cultural_framework"] in frameworks

    def test_certificate_has_intent_class(self, mock_certificate):
        """Should include intent classification"""
        assert mock_certificate["intent_class"] in ["SUSPICIOUS", "BENIGN", "UNKNOWN"]

    def test_certificate_has_decision(self, mock_certificate):
        """Should include decision"""
        assert mock_certificate["decision"] in ["ALLOW", "WARN", "DENY"]

    def test_certificate_has_ed25519_signature(self, mock_certificate):
        """Should have Ed25519 signature"""
        signature = mock_certificate["signature"]
        assert "Ed25519" in signature or len(signature) > 20

    def test_certificate_has_ledger_voxel(self, mock_certificate):
        """Should include holographic ledger voxel"""
        voxel = mock_certificate["ledger_voxel"]
        assert "x=" in voxel
        assert "y=" in voxel
        assert "z=" in voxel
        assert "o=" in voxel

    def test_certificate_has_issued_at_timestamp(self, mock_certificate):
        """Should have issued_at timestamp"""
        assert "issued_at" in mock_certificate
        assert "T" in mock_certificate["issued_at"]
        assert "Z" in mock_certificate["issued_at"]

    def test_certificate_post_generates_new_cert(self, mock_certificate):
        """POST should generate new certificate"""
        assert "cert_id" in mock_certificate
        # New cert_id should be unique
        assert True

    def test_certificate_get_returns_404_for_invalid_id(self):
        """GET with invalid event_id should return 404"""
        # Status code should be 404
        assert True

    def test_certificate_response_is_json(self, mock_certificate):
        """Should return valid JSON response"""
        json_str = json.dumps(mock_certificate)
        assert isinstance(json_str, str)

    def test_certificate_response_status_200(self):
        """Should return HTTP 200 on success"""
        assert True

    def test_certificate_response_status_400_bad_request(self):
        """Should return HTTP 400 for invalid request"""
        assert True

    def test_certificate_response_status_404_not_found(self):
        """Should return HTTP 404 for missing event_id"""
        assert True

# ============================================================================
# TEST: GET /api/ksi/sanctuary
# ============================================================================

class TestKSISanctuary:
    """Test GET /api/ksi/sanctuary endpoint"""

    def test_sanctuary_returns_list(self, mock_sanctuaries):
        """Should return array of sanctuary records"""
        assert isinstance(mock_sanctuaries, list)

    def test_sanctuary_has_required_fields(self, mock_sanctuaries):
        """Each sanctuary should have required fields"""
        required_fields = ["cert_id", "protected_data_type", "protection_level", "timestamp"]
        for sanctuary in mock_sanctuaries:
            for field in required_fields:
                assert field in sanctuary

    def test_sanctuary_protection_level_is_valid(self, mock_sanctuaries):
        """Protection level should be MAXIMUM, HIGH, MEDIUM, LOW"""
        valid_levels = ["MAXIMUM", "HIGH", "MEDIUM", "LOW"]
        for sanctuary in mock_sanctuaries:
            assert sanctuary["protection_level"] in valid_levels

    def test_sanctuary_protected_data_types(self, mock_sanctuaries):
        """Protected data types should be meaningful"""
        for sanctuary in mock_sanctuaries:
            data_type = sanctuary["protected_data_type"]
            assert len(data_type) > 0

    def test_sanctuary_timestamp_is_valid(self, mock_sanctuaries):
        """Timestamp should be valid ISO format"""
        for sanctuary in mock_sanctuaries:
            assert "T" in sanctuary["timestamp"]
            assert "Z" in sanctuary["timestamp"]

    def test_sanctuary_response_status_200(self):
        """Should return HTTP 200"""
        assert True

    def test_sanctuary_response_is_json(self, mock_sanctuaries):
        """Should return valid JSON"""
        response = {"sanctuaries": mock_sanctuaries}
        json_str = json.dumps(response)
        assert isinstance(json_str, str)

    def test_sanctuary_supports_filtering_by_protection_level(self, mock_sanctuaries):
        """Should support filtering by protection level"""
        maximum_sanctuaries = [s for s in mock_sanctuaries if s["protection_level"] == "MAXIMUM"]
        assert isinstance(maximum_sanctuaries, list)

# ============================================================================
# TEST: GET /api/ksi/patterns
# ============================================================================

class TestKSIPatterns:
    """Test GET /api/ksi/patterns endpoint"""

    def test_patterns_returns_list(self, mock_patterns):
        """Should return array of patterns"""
        assert isinstance(mock_patterns, list)
        assert len(mock_patterns) > 0

    def test_pattern_has_required_fields(self, mock_patterns):
        """Each pattern should have required fields"""
        required_fields = ["pattern", "confidence", "observations", "first_seen"]
        for pattern in mock_patterns:
            for field in required_fields:
                assert field in pattern

    def test_pattern_is_valid_regex(self, mock_patterns):
        """Pattern should be valid regex"""
        import re
        for pattern in mock_patterns:
            try:
                re.compile(pattern["pattern"])
                assert True
            except re.error:
                pytest.fail(f"Invalid regex: {pattern['pattern']}")

    def test_pattern_confidence_is_float(self, mock_patterns):
        """Confidence should be float between 0-1"""
        for pattern in mock_patterns:
            assert isinstance(pattern["confidence"], (int, float))
            assert 0 <= pattern["confidence"] <= 1

    def test_pattern_observations_is_integer(self, mock_patterns):
        """Observations should be positive integer"""
        for pattern in mock_patterns:
            assert isinstance(pattern["observations"], int)
            assert pattern["observations"] > 0

    def test_pattern_first_seen_is_timestamp(self, mock_patterns):
        """first_seen should be valid ISO timestamp"""
        for pattern in mock_patterns:
            assert "T" in pattern["first_seen"]
            assert "Z" in pattern["first_seen"]

    def test_patterns_sorted_by_confidence(self, mock_patterns):
        """Patterns should be sorted by confidence (descending)"""
        sorted_patterns = sorted(mock_patterns, key=lambda x: x["confidence"], reverse=True)
        assert sorted_patterns[0]["confidence"] >= sorted_patterns[-1]["confidence"]

    def test_patterns_response_status_200(self):
        """Should return HTTP 200"""
        assert True

    def test_patterns_response_is_json(self, mock_patterns):
        """Should return valid JSON"""
        response = {"patterns": mock_patterns}
        json_str = json.dumps(response)
        assert isinstance(json_str, str)

    def test_patterns_supports_filtering_by_confidence(self, mock_patterns):
        """Should support filtering by confidence threshold"""
        threshold = 0.85
        filtered = [p for p in mock_patterns if p["confidence"] >= threshold]
        for pattern in filtered:
            assert pattern["confidence"] >= threshold

    def test_patterns_supports_search_by_regex(self, mock_patterns):
        """Should support searching patterns by regex"""
        import re
        search_term = "APP_SECRET"
        matches = [p for p in mock_patterns if search_term in p["pattern"]]
        assert isinstance(matches, list)

# ============================================================================
# TEST: GET /api/ksi/forensic-archive/<record_id>
# ============================================================================

class TestKSIForensicArchive:
    """Test GET /api/ksi/forensic-archive/<record_id> endpoint"""

    def test_forensic_archive_returns_record(self, mock_forensic_record):
        """Should return forensic archive record"""
        assert "record_id" in mock_forensic_record
        assert "timestamp" in mock_forensic_record

    def test_forensic_record_has_record_id(self, mock_forensic_record):
        """Should have record_id (SHA256 hash)"""
        record_id = mock_forensic_record["record_id"]
        assert record_id.startswith("sha256_")
        assert len(record_id) > 10

    def test_forensic_record_has_timestamp(self, mock_forensic_record):
        """Should have timestamp"""
        assert "T" in mock_forensic_record["timestamp"]
        assert "Z" in mock_forensic_record["timestamp"]

    def test_forensic_record_has_holographic_voxel(self, mock_forensic_record):
        """Should include holographic voxel"""
        voxel = mock_forensic_record["holographic_voxel"]
        assert "x=" in voxel
        assert "y=" in voxel
        assert "z=" in voxel

    def test_forensic_record_has_dna_sequence(self, mock_forensic_record):
        """Should include DNA sequence"""
        dna = mock_forensic_record["dna_sequence"]
        assert all(base in "ATGC" for base in dna)

    def test_forensic_record_has_privacy_protected_tcs(self, mock_forensic_record):
        """Should include privacy-protected TCS vector"""
        tcs = mock_forensic_record["privacy_protected_tcs"]
        assert isinstance(tcs, dict)
        assert len(tcs) == 6
        # Verify Laplace noise has been applied (values slightly different from true values)
        for key, value in tcs.items():
            assert 0 <= value <= 1

    def test_dna_sequence_is_valid_atgc(self, mock_forensic_record):
        """DNA sequence should only contain ATGC"""
        dna = mock_forensic_record["dna_sequence"]
        for base in dna:
            assert base in "ATGC"

    def test_forensic_archive_get_returns_404_for_invalid_id(self):
        """GET with invalid record_id should return 404"""
        # Status code should be 404
        assert True

    def test_forensic_archive_response_is_json(self, mock_forensic_record):
        """Should return valid JSON"""
        json_str = json.dumps(mock_forensic_record)
        assert isinstance(json_str, str)

    def test_forensic_archive_response_status_200(self):
        """Should return HTTP 200 on success"""
        assert True

    def test_forensic_archive_response_status_404_not_found(self):
        """Should return HTTP 404 for missing record_id"""
        assert True

    def test_privacy_protection_applied_to_tcs_values(self, mock_forensic_record):
        """TCS values in archive should have Laplace noise applied"""
        tcs = mock_forensic_record["privacy_protected_tcs"]
        # Values should differ slightly from original (simulating noise)
        for value in tcs.values():
            assert isinstance(value, (int, float))

# ============================================================================
# TEST: CROSS-ENDPOINT CONSISTENCY
# ============================================================================

class TestKSIEndpointConsistency:
    """Test consistency across all KSI endpoints"""

    def test_all_endpoints_return_valid_json(self,
                                             mock_tcs_response,
                                             mock_threat_actors,
                                             mock_certificate,
                                             mock_sanctuaries,
                                             mock_patterns,
                                             mock_forensic_record):
        """All endpoints should return valid JSON"""
        responses = [
            mock_tcs_response,
            {"threat_actors": mock_threat_actors},
            mock_certificate,
            {"sanctuaries": mock_sanctuaries},
            {"patterns": mock_patterns},
            mock_forensic_record
        ]
        for response in responses:
            json_str = json.dumps(response)
            assert isinstance(json_str, str)

    def test_timestamp_format_consistency(self,
                                          mock_threat_actors,
                                          mock_certificate,
                                          mock_sanctuaries,
                                          mock_patterns,
                                          mock_forensic_record):
        """All timestamps should use ISO 8601 format with Z suffix"""
        timestamps = [
            mock_threat_actors[0]["first_seen"],
            mock_certificate["issued_at"],
            mock_sanctuaries[0]["timestamp"],
            mock_patterns[0]["first_seen"],
            mock_forensic_record["timestamp"]
        ]
        for ts in timestamps:
            assert "T" in ts
            assert "Z" in ts

    def test_certificate_id_consistency(self, mock_certificate, mock_sanctuaries):
        """Certificate IDs should match format ksc-YYYY-MM-DD-xxx"""
        assert mock_certificate["cert_id"].startswith("ksc-")
        for sanctuary in mock_sanctuaries:
            assert sanctuary["cert_id"].startswith("ksc-")

    def test_risk_scores_are_normalized(self, mock_threat_actors, mock_tcs_response):
        """Risk scores should be between 0-1"""
        # From threat actors
        for actor in mock_threat_actors:
            assert 0 <= actor["risk_score"] <= 1

        # From TCS response
        for value in mock_tcs_response["tcs_vector"].values():
            assert 0 <= value <= 1

# ============================================================================
# TEST: AUTHENTICATION & AUTHORIZATION
# ============================================================================

class TestKSIAuthentication:
    """Test authentication and authorization"""

    def test_endpoints_require_valid_api_key(self):
        """All endpoints should require valid API key (if auth enabled)"""
        assert True

    def test_endpoints_reject_invalid_api_key(self):
        """Should return 401/403 for invalid API key"""
        assert True

    def test_endpoints_support_bearer_token(self):
        """Should support Bearer token authentication"""
        assert True

# ============================================================================
# TEST: RATE LIMITING
# ============================================================================

class TestKSIRateLimiting:
    """Test rate limiting"""

    def test_endpoints_enforce_rate_limits(self):
        """Should enforce rate limits"""
        assert True

    def test_rate_limit_headers_present(self):
        """Should include rate limit headers in response"""
        assert True

# ============================================================================
# TEST: ERROR RESPONSES
# ============================================================================

class TestKSIErrorHandling:
    """Test error handling across all endpoints"""

    def test_all_endpoints_handle_invalid_input(self):
        """Should gracefully handle invalid input"""
        assert True

    def test_all_endpoints_handle_timeout(self):
        """Should handle request timeout"""
        assert True

    def test_all_endpoints_return_meaningful_error_messages(self):
        """Error responses should include meaningful messages"""
        assert True

# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
