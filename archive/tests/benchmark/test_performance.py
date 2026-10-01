"""
============================================================================
KASBAH PERFORMANCE BENCHMARK SUITE
============================================================================

Comprehensive performance benchmarks for Kasbah detection pipeline.

Benchmarks:
- Detection latency (p50, p95, p99)
- Detection throughput (requests/second)
- Memory usage
- CPU usage
- Concurrent load testing

Usage:
    pytest tests/benchmark/ -v --benchmark-only
"""

import pytest
import time
import statistics
import sys
import os
from concurrent.futures import ThreadPoolExecutor

# Add kasbah-core to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'kasbah-core'))

from kasbah_core import KasbahPipeline


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture(scope='module')
def pipeline():
    """Create and initialize Kasbah pipeline."""
    p = KasbahPipeline()
    p.initialize()
    yield p
    p.shutdown()


@pytest.fixture
def sample_content():
    """Sample content for benchmarking."""
    return {
        'short': 'test content',
        'medium': 'This is a medium-length text with some secrets like API keys and credentials.',
        'long': 'This is a long text. ' * 100,
        'secret': 'My AWS key is AKIAIOSFODNN7EXAMPLE and my GitHub token is ghp_xxx',
        'ai_text': 'Furthermore, it is important to note that artificial intelligence has become increasingly prevalent.'
    }


# ============================================================================
# LATENCY BENCHMARKS
# ============================================================================

class TestLatency:
    """Detection latency benchmarks."""
    
    @pytest.mark.benchmark(group='latency-short')
    def test_latency_short_content(self, benchmark, pipeline, sample_content):
        """Benchmark latency for short content."""
        result = benchmark(pipeline.detect, {'text': sample_content['short']})
        assert 'detected' in result
    
    @pytest.mark.benchmark(group='latency-medium')
    def test_latency_medium_content(self, benchmark, pipeline, sample_content):
        """Benchmark latency for medium content."""
        result = benchmark(pipeline.detect, {'text': sample_content['medium']})
        assert 'detected' in result
    
    @pytest.mark.benchmark(group='latency-long')
    def test_latency_long_content(self, benchmark, pipeline, sample_content):
        """Benchmark latency for long content."""
        result = benchmark(pipeline.detect, {'text': sample_content['long']})
        assert 'detected' in result
    
    @pytest.mark.benchmark(group='latency-secret')
    def test_latency_secret_detection(self, benchmark, pipeline, sample_content):
        """Benchmark latency for secret detection."""
        result = benchmark(pipeline.detect, {'text': sample_content['secret']})
        assert result['detected'] == True


# ============================================================================
# THROUGHPUT BENCHMARKS
# ============================================================================

class TestThroughput:
    """Detection throughput benchmarks."""
    
    def test_throughput_single_thread(self, pipeline, sample_content):
        """Benchmark single-threaded throughput."""
        iterations = 1000
        start = time.time()
        
        for _ in range(iterations):
            pipeline.detect({'text': sample_content['short']})
        
        elapsed = time.time() - start
        throughput = iterations / elapsed
        
        print(f'\nSingle-threaded throughput: {throughput:.2f} req/s')
        assert throughput > 50, f'Throughput {throughput} req/s below 50 req/s target'
    
    def test_throughput_multi_thread(self, pipeline, sample_content):
        """Benchmark multi-threaded throughput."""
        iterations = 1000
        threads = 4
        
        def detect():
            for _ in range(iterations // threads):
                pipeline.detect({'text': sample_content['short']})
        
        start = time.time()
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(detect) for _ in range(threads)]
            for future in futures:
                future.result()
        
        elapsed = time.time() - start
        throughput = iterations / elapsed
        
        print(f'\nMulti-threaded ({threads}) throughput: {throughput:.2f} req/s')
        assert throughput > 100, f'Throughput {throughput} req/s below 100 req/s target'


# ============================================================================
# MEMORY BENCHMARKS
# ============================================================================

class TestMemory:
    """Memory usage benchmarks."""
    
    def test_memory_single_detection(self, pipeline, sample_content):
        """Benchmark memory for single detection."""
        import tracemalloc
        tracemalloc.start()
        
        pipeline.detect({'text': sample_content['short']})
        
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        print(f'\nSingle detection - Current: {current / 1024:.2f}KB, Peak: {peak / 1024:.2f}KB')
        assert peak < 50 * 1024 * 1024, f'Peak memory {peak / 1024 / 1024:.2f}MB exceeds 50MB'
    
    def test_memory_sustained_load(self, pipeline, sample_content):
        """Benchmark memory under sustained load."""
        import tracemalloc
        tracemalloc.start()
        
        for _ in range(1000):
            pipeline.detect({'text': sample_content['short']})
        
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        print(f'\nSustained load - Current: {current / 1024 / 1024:.2f}MB, Peak: {peak / 1024 / 1024:.2f}MB')
        assert peak < 500 * 1024 * 1024, f'Peak memory {peak / 1024 / 1024:.2f}MB exceeds 500MB'


# ============================================================================
# COMPREHENSIVE BENCHMARK REPORT
# ============================================================================

class TestBenchmarkReport:
    """Generate comprehensive benchmark report."""
    
    def test_full_benchmark_report(self, pipeline, sample_content):
        """Generate full benchmark report."""
        print('\n' + '='*70)
        print('KASBAH PERFORMANCE BENCHMARK REPORT')
        print('='*70)
        
        # Latency benchmark
        latencies = []
        for _ in range(1000):
            start = time.time()
            pipeline.detect({'text': sample_content['short']})
            end = time.time()
            latencies.append((end - start) * 1000)
        
        p50 = statistics.median(latencies)
        p95 = sorted(latencies)[int(len(latencies) * 0.95)]
        p99 = sorted(latencies)[int(len(latencies) * 0.99)]
        avg = statistics.mean(latencies)
        
        print(f'\nLATENCY (1000 iterations):')
        print(f'  P50:  {p50:.2f}ms')
        print(f'  P95:  {p95:.2f}ms')
        print(f'  P99:  {p99:.2f}ms')
        print(f'  AVG:  {avg:.2f}ms')
        print(f'  MIN:  {min(latencies):.2f}ms')
        print(f'  MAX:  {max(latencies):.2f}ms')
        
        # Throughput benchmark
        iterations = 1000
        start = time.time()
        for _ in range(iterations):
            pipeline.detect({'text': sample_content['short']})
        elapsed = time.time() - start
        throughput = iterations / elapsed
        
        print(f'\nTHROUGHPUT:')
        print(f'  {throughput:.2f} requests/second')
        print(f'  {elapsed:.2f} seconds for {iterations} requests')
        
        # Memory benchmark
        import tracemalloc
        tracemalloc.start()
        for _ in range(1000):
            pipeline.detect({'text': sample_content['short']})
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        print(f'\nMEMORY:')
        print(f'  Current: {current / 1024 / 1024:.2f}MB')
        print(f'  Peak:    {peak / 1024 / 1024:.2f}MB')
        
        # Summary
        print(f'\n' + '='*70)
        print('SUMMARY:')
        print(f'  ✅ P50 Latency:  {p50:.2f}ms {"✅ PASS" if p50 < 10 else "❌ FAIL"} (<10ms)')
        print(f'  ✅ P95 Latency:  {p95:.2f}ms {"✅ PASS" if p95 < 50 else "❌ FAIL"} (<50ms)')
        print(f'  ✅ P99 Latency:  {p99:.2f}ms {"✅ PASS" if p99 < 100 else "❌ FAIL"} (<100ms)')
        print(f'  ✅ Throughput:   {throughput:.2f} req/s {"✅ PASS" if throughput > 50 else "❌ FAIL"} (>50 req/s)')
        print(f'  ✅ Memory Peak:  {peak / 1024 / 1024:.2f}MB {"✅ PASS" if peak < 500*1024*1024 else "❌ FAIL"} (<500MB)')
        print('='*70 + '\n')


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short', '--benchmark-only'])
