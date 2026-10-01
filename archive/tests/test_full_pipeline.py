"""
============================================================================
KASBAH INTEGRATION TEST SUITE
============================================================================

Comprehensive integration tests for the entire Kasbah detection pipeline.

Tests:
- Full pipeline detection
- Secret detection end-to-end
- AI text detection end-to-end
- Moats integration
- Audit ledger integrity
- Performance benchmarks

Usage:
    pytest tests/integration/ -v
"""

import pytest
import time
import sys
import os

# Add kasbah-core to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'kasbah-core'))

from kasbah_core import KasbahPipeline


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def pipeline():
    """Create and initialize Kasbah pipeline."""
    p = KasbahPipeline()
    p.initialize()
    yield p
    p.shutdown()


@pytest.fixture
def sample_secrets():
    """Sample secrets for testing."""
    return {
        'aws_key': 'AKIAIOSFODNN7EXAMPLE',
        'github_pat': 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'stripe_key': 'sk_live_xxxxxxxxxxxxxxxxxxxxxxxx',
        'ssn': '123-45-6789',
        'credit_card': '4532015112830366'
    }


@pytest.fixture
def sample_ai_text():
    """Sample AI-generated text for testing."""
    return [
        'Furthermore, it is important to note that artificial intelligence has become increasingly prevalent.',
        'I hope this helps! Let me know if you have any other questions.',
        'As an AI language model, I cannot provide personal opinions.',
        'In conclusion, the aforementioned points demonstrate the significance of this topic.'
    ]


@pytest.fixture
def sample_human_text():
    """Sample human-written text for testing."""
    return [
        'I think this is gonna work, but idk for sure lol',
        'OMG did u see that?? crazy!!',
        'my code doesnt work pls help',
        'tbh i dont understand this at all'
    ]


# ============================================================================
# DETECTION TESTS
# ============================================================================

class TestSecretDetection:
    """Test secret detection end-to-end."""
    
    def test_aws_key_detection(self, pipeline, sample_secrets):
        """Test AWS key detection."""
        result = pipeline.detect({
            'text': f'My AWS key is {sample_secrets["aws_key"]}'
        })
        
        assert result['detected'] == True
        assert result['overall_risk'] > 50
        assert 'secret_detected' in result['indicators']
    
    def test_github_pat_detection(self, pipeline, sample_secrets):
        """Test GitHub PAT detection."""
        result = pipeline.detect({
            'text': f'GitHub token: {sample_secrets["github_pat"]}'
        })
        
        assert result['detected'] == True
        assert result['overall_risk'] > 50
    
    def test_stripe_key_detection(self, pipeline, sample_secrets):
        """Test Stripe key detection."""
        result = pipeline.detect({
            'text': f'Stripe key: {sample_secrets["stripe_key"]}'
        })
        
        assert result['detected'] == True
        assert result['overall_risk'] > 50
    
    def test_ssn_detection(self, pipeline, sample_secrets):
        """Test SSN detection."""
        result = pipeline.detect({
            'text': f'SSN: {sample_secrets["ssn"]}'
        })
        
        assert result['detected'] == True
        assert 'pii_detected' in result['indicators']
    
    def test_credit_card_detection(self, pipeline, sample_secrets):
        """Test credit card detection with Luhn validation."""
        result = pipeline.detect({
            'text': f'Card: {sample_secrets["credit_card"]}'
        })
        
        assert result['detected'] == True
        assert 'credit_card_detected' in result['indicators']


class TestAITextDetection:
    """Test AI text detection end-to-end."""
    
    def test_ai_text_detection(self, pipeline, sample_ai_text):
        """Test AI text detection."""
        for text in sample_ai_text:
            result = pipeline.detect({'text': text})
            
            assert result['ai_text']['is_ai'] == True
            assert result['ai_text']['confidence'] > 0.5
    
    def test_human_text_detection(self, pipeline, sample_human_text):
        """Test human text detection."""
        for text in sample_human_text:
            result = pipeline.detect({'text': text})
            
            # Humans should have lower AI scores
            assert result['ai_text']['confidence'] < 0.5
    
    def test_ai_typical_words(self, pipeline):
        """Test detection of AI-typical words."""
        ai_words = ['furthermore', 'moreover', 'additionally', 'consequently']
        
        for word in ai_words:
            result = pipeline.detect({
                'text': f'{word.capitalize()}, this is important.'
            })
            
            assert result['ai_text']['word_score'] > 0.3


class TestMoatsIntegration:
    """Test 13 moats integration."""
    
    def test_all_moats_active(self, pipeline):
        """Test all 13 moats are active."""
        status = pipeline.get_moats_status()
        
        assert len(status['active']) >= 10
        assert status['overall_integrity'] > 0.8
    
    def test_audit_ledger_moat(self, pipeline):
        """Test audit ledger moat."""
        # Run detection
        pipeline.detect({'text': 'test content'})
        
        # Export audit
        audit = pipeline.export_audit_ledger()
        
        assert 'entries' in audit
        assert len(audit['entries']) > 0
        assert audit['chain_integrity'] == True
    
    def test_dynamic_thresholds_moat(self, pipeline):
        """Test dynamic thresholds moat."""
        integrity = pipeline.get_integrity_index()
        
        assert 'dynamic_thresholds' in integrity['components']
        assert integrity['components']['dynamic_thresholds'] > 0.8
    
    def test_brittleness_moat(self, pipeline):
        """Test brittleness monitor moat."""
        integrity = pipeline.get_integrity_index()
        
        assert 'brittleness' in integrity['components']


class TestPerformance:
    """Test performance benchmarks."""
    
    def test_detection_latency(self, pipeline):
        """Test detection latency meets SLA."""
        latencies = []
        
        for _ in range(100):
            start = time.time()
            pipeline.detect({'text': 'test content'})
            end = time.time()
            latencies.append((end - start) * 1000)  # ms
        
        p50 = sorted(latencies)[len(latencies) // 2]
        p95 = sorted(latencies)[int(len(latencies) * 0.95)]
        p99 = sorted(latencies)[int(len(latencies) * 0.99)]
        
        assert p50 < 10, f'P50 latency {p50}ms exceeds 10ms SLA'
        assert p95 < 50, f'P95 latency {p95}ms exceeds 50ms SLA'
        assert p99 < 100, f'P99 latency {p99}ms exceeds 100ms SLA'
    
    def test_detection_throughput(self, pipeline):
        """Test detection throughput."""
        start = time.time()
        
        for _ in range(1000):
            pipeline.detect({'text': 'test content'})
        
        elapsed = time.time() - start
        throughput = 1000 / elapsed
        
        assert throughput > 50, f'Throughput {throughput} req/s below 50 req/s target'
    
    def test_memory_usage(self, pipeline):
        """Test memory usage."""
        import tracemalloc
        tracemalloc.start()
        
        for _ in range(1000):
            pipeline.detect({'text': 'test content'})
        
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        # Peak memory should be under 500MB
        assert peak < 500 * 1024 * 1024, f'Peak memory {peak / 1024 / 1024:.2f}MB exceeds 500MB limit'


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_empty_content(self, pipeline):
        """Test empty content handling."""
        result = pipeline.detect({'text': ''})
        
        assert result['detected'] == False
        assert result['overall_risk'] == 0
    
    def test_very_long_content(self, pipeline):
        """Test very long content handling."""
        long_text = 'test ' * 10000  # 50,000 characters
        
        result = pipeline.detect({'text': long_text})
        
        assert 'detected' in result
        assert 'overall_risk' in result
    
    def test_unicode_content(self, pipeline):
        """Test unicode content handling."""
        unicode_text = '你好世界 🌍 مرحبا بالعالم'
        
        result = pipeline.detect({'text': unicode_text})
        
        assert 'detected' in result
    
    def test_mixed_content(self, pipeline):
        """Test mixed content handling."""
        mixed_text = '''
        Here's my code:
        def hello():
            print("Hello, world!")
        
        And my API key: AKIAIOSFODNN7EXAMPLE
        '''
        
        result = pipeline.detect({'text': mixed_text})
        
        assert result['detected'] == True
        assert 'secret_detected' in result['indicators']


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
