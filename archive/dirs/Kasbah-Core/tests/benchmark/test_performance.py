#!/usr/bin/env python3
"""
Kasbah Core Performance Benchmark Suite

Comprehensive performance testing for all moats and detection modules.

Author: Kasbah Guard Team
Date: March 11, 2026
License: MIT
"""

import sys
import os
import time
import statistics
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Import moats modules
from core.moats import (
    record_threat_event,
    get_current_threat_level,
    get_adaptive_thresholds,
    record_indicator_usage,
    calculate_system_brittleness,
    generate_ticket,
    verify_ticket,
    consume_ticket,
    initialize_ledger,
    add_audit_entry,
    verify_ledger_integrity,
    detect_adversarial_patterns,
    sha256,
    hmac_sha256,
)
from core.moats.brittleness_governor import BrittlenessGovernor


@dataclass
class BenchmarkResult:
    """Results from a single benchmark test"""
    name: str
    iterations: int
    total_time_ms: float
    avg_time_ms: float
    p50_time_ms: float
    p95_time_ms: float
    p99_time_ms: float
    min_time_ms: float
    max_time_ms: float
    ops_per_second: float


def run_benchmark(name: str, func, iterations: int = 1000, *args, **kwargs) -> BenchmarkResult:
    """
    Run a benchmark test and collect statistics
    
    Args:
        name: Name of the benchmark
        func: Function to benchmark
        iterations: Number of iterations
        *args, **kwargs: Arguments to pass to func
    
    Returns:
        BenchmarkResult with statistics
    """
    times: List[float] = []
    
    for _ in range(iterations):
        start = time.perf_counter()
        func(*args, **kwargs)
        end = time.perf_counter()
        times.append((end - start) * 1000)  # Convert to ms
    
    times.sort()
    total_time = sum(times)
    avg_time = total_time / iterations
    
    p50_idx = int(len(times) * 0.50)
    p95_idx = int(len(times) * 0.95)
    p99_idx = int(len(times) * 0.99)
    
    return BenchmarkResult(
        name=name,
        iterations=iterations,
        total_time_ms=total_time,
        avg_time_ms=avg_time,
        p50_time_ms=times[p50_idx],
        p95_time_ms=times[p95_idx],
        p99_time_ms=times[p99_idx],
        min_time_ms=times[0],
        max_time_ms=times[-1],
        ops_per_second=iterations / (total_time / 1000)
    )


def benchmark_threat_recording() -> BenchmarkResult:
    """Benchmark threat event recording"""
    def record():
        record_threat_event(
            vector='evasion_attempt',
            details={'test': True}
        )
    
    return run_benchmark("Threat Event Recording", record, iterations=1000)


def benchmark_threshold_lookup() -> BenchmarkResult:
    """Benchmark adaptive threshold lookup"""
    def lookup():
        get_adaptive_thresholds()
    
    return run_benchmark("Threshold Lookup", lookup, iterations=1000)


def benchmark_brittleness_calculation() -> BenchmarkResult:
    """Benchmark system brittleness calculation"""
    # Setup: record some indicator usage
    for i in range(10):
        record_indicator_usage(f"indicator_{i}")
    
    def calculate():
        calculate_system_brittleness()
    
    return run_benchmark("Brittleness Calculation", calculate, iterations=100)


def benchmark_ticket_generation() -> BenchmarkResult:
    """Benchmark execution ticket generation"""
    def generate():
        generate_ticket("test_resource", "test_action", "SUCCESS", 0.95, "low")
    
    return run_benchmark("Ticket Generation", generate, iterations=500)


def benchmark_ticket_verification() -> BenchmarkResult:
    """Benchmark execution ticket verification"""
    # Generate a ticket first
    ticket = generate_ticket("ALLOW", "test_resource", "AUTHENTIC", 0.95, "low")
    
    def verify():
        # verify_ticket takes the ticket object directly
        verify_ticket(ticket)
    
    return run_benchmark("Ticket Verification", verify, iterations=500)


def benchmark_audit_logging() -> BenchmarkResult:
    """Benchmark audit ledger logging"""
    initialize_ledger()
    
    def log():
        add_audit_entry(
            action='DETECT',
            resource='test_resource',
            result='SUCCESS',
            metadata={'test': True}
        )
    
    return run_benchmark("Audit Logging", log, iterations=500)


def benchmark_ledger_verification() -> BenchmarkResult:
    """Benchmark ledger integrity verification"""
    initialize_ledger()
    for i in range(10):
        add_audit_entry(
            action='DETECT',
            resource=f'resource_{i}',
            result='SUCCESS',
            metadata={'index': i}
        )
    
    def verify():
        verify_ledger_integrity()
    
    return run_benchmark("Ledger Verification", verify, iterations=100)


def benchmark_adversarial_detection() -> BenchmarkResult:
    """Benchmark adversarial pattern detection"""
    test_text = "This is a normal text without any adversarial patterns"
    
    def detect():
        detect_adversarial_patterns("test_file.txt", test_text)
    
    return run_benchmark("Adversarial Detection", detect, iterations=200)


def benchmark_crypto_hash() -> BenchmarkResult:
    """Benchmark SHA-256 hashing"""
    test_data = "test_data_for_hashing" * 100
    
    def hash_data():
        sha256(test_data)
    
    return run_benchmark("SHA-256 Hashing", hash_data, iterations=1000)


def benchmark_crypto_hmac() -> BenchmarkResult:
    """Benchmark HMAC-SHA256"""
    test_data = "test_data_for_hmac" * 100
    secret = "test_secret_key"
    
    def hmac():
        hmac_sha256(test_data, secret)
    
    return run_benchmark("HMAC-SHA256", hmac, iterations=1000)


def benchmark_brittleness_governor() -> BenchmarkResult:
    """Benchmark brittleness governor analysis"""
    governor = BrittlenessGovernor(
        resource_affinity_groups={
            "llm": ["openai", "anthropic", "local"]
        }
    )
    
    # Record some usage
    for i in range(20):
        governor.record_usage(
            resource_id=["openai", "anthropic", "local"][i % 3],
            tokens=1000,
            cost_cents=0.01,
            latency_ms=50,
            success=True
        )
    
    def analyze():
        governor.analyze()
    
    return run_benchmark("Brittleness Governor Analysis", analyze, iterations=100)


def run_all_benchmarks() -> List[BenchmarkResult]:
    """Run all benchmarks and return results"""
    print("=" * 70)
    print("KASBAH CORE PERFORMANCE BENCHMARK SUITE")
    print(f"Timestamp: {datetime.utcnow().isoformat()}")
    print("=" * 70)
    print()
    
    benchmarks = [
        benchmark_threat_recording,
        benchmark_threshold_lookup,
        benchmark_brittleness_calculation,
        benchmark_ticket_generation,
        benchmark_ticket_verification,
        benchmark_audit_logging,
        benchmark_ledger_verification,
        benchmark_adversarial_detection,
        benchmark_crypto_hash,
        benchmark_crypto_hmac,
        benchmark_brittleness_governor,
    ]
    
    results: List[BenchmarkResult] = []
    
    for benchmark_func in benchmarks:
        print(f"Running {benchmark_func.__name__}...", end=" ", flush=True)
        try:
            result = benchmark_func()
            results.append(result)
            print(f"✓ {result.avg_time_ms:.3f}ms avg, {result.ops_per_second:.0f} ops/sec")
        except Exception as e:
            print(f"✗ FAILED: {e}")
    
    return results


def print_summary(results: List[BenchmarkResult]):
    """Print benchmark summary"""
    print()
    print("=" * 70)
    print("BENCHMARK SUMMARY")
    print("=" * 70)
    print()
    print(f"{'Benchmark':<35} {'Avg (ms)':<12} {'P50 (ms)':<12} {'P95 (ms)':<12} {'P99 (ms)':<12} {'Ops/sec':<12}")
    print("-" * 95)
    
    for r in results:
        print(f"{r.name:<35} {r.avg_time_ms:<12.3f} {r.p50_time_ms:<12.3f} {r.p95_time_ms:<12.3f} {r.p99_time_ms:<12.3f} {r.ops_per_second:<12.0f}")
    
    print()
    print("=" * 70)
    
    # Calculate overall statistics
    if results:
        avg_ops = statistics.mean([r.ops_per_second for r in results])
        fastest = max(results, key=lambda r: r.ops_per_second)
        slowest = min(results, key=lambda r: r.ops_per_second)
        
        print(f"Overall Average: {avg_ops:.0f} ops/sec")
        print(f"Fastest: {fastest.name} ({fastest.ops_per_second:.0f} ops/sec)")
        print(f"Slowest: {slowest.name} ({slowest.ops_per_second:.0f} ops/sec)")
    
    print("=" * 70)


def main():
    """Main entry point"""
    results = run_all_benchmarks()
    print_summary(results)
    
    # Save results to file
    output_file = os.path.join(os.path.dirname(__file__), "benchmark_results.json")
    import json
    
    with open(output_file, 'w') as f:
        json.dump([asdict(r) for r in results], f, indent=2)
    
    print(f"\nResults saved to: {output_file}")
    
    return 0 if all(r.avg_time_ms < 100 for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
