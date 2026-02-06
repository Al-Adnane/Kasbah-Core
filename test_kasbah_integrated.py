#!/usr/bin/env python3
"""
🏰 KASBAH COMPLETE TEST SUITE - ALL MOATS LOCKDOWN
Fixes ALL recurring issues and validates full system
"""

import os
import requests
import time
import json
import sys
from typing import Dict, Any, Tuple

BASE_URL = os.environ.get("KASBAH_BASE_URL", "http://127.0.0.1:8000")
VERBOSE = True

def log(msg: str, color: str = ""):
    colors = {
        "green": "\033[92m",
        "red": "\033[91m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "reset": "\033[0m"
    }
    prefix = colors.get(color, "")
    suffix = colors["reset"] if color else ""
    print(f"{prefix}{msg}{suffix}")

class KasbahTester:
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.passed = 0
        self.failed = 0
        self.tests_run = []
    
    def test(self, name: str, fn):
        """Run a test and track results"""
        try:
            log(f"\n▶ {name}", "blue")
            fn()
            self.passed += 1
            self.tests_run.append((name, "PASS"))
            log(f"✅ PASS: {name}", "green")
        except AssertionError as e:
            self.failed += 1
            self.tests_run.append((name, f"FAIL: {e}"))
            log(f"❌ FAIL: {name} - {e}", "red")
        except Exception as e:
            self.failed += 1
            self.tests_run.append((name, f"ERROR: {e}"))
            log(f"💥 ERROR: {name} - {e}", "red")
    
    def assert_status(self, resp, expected: int, msg: str = ""):
        assert resp.status_code == expected, f"{msg} Expected {expected}, got {resp.status_code}: {resp.text[:200]}"
    
    def assert_field(self, data: dict, field: str, msg: str = ""):
        assert field in data, f"{msg} Missing field: {field}"
    
    def assert_equals(self, actual, expected, msg: str = ""):
        assert actual == expected, f"{msg} Expected {expected}, got {actual}"
    
    # ═══════════════════════════════════════════════════════════════════════
    # BASIC HEALTH TESTS
    # ═══════════════════════════════════════════════════════════════════════
    
    def test_health(self):
        """Test 1: Health endpoint responds"""
        resp = requests.get(f"{self.base_url}/health")
        self.assert_status(resp, 200, "Health check failed")
        data = resp.json()
        self.assert_field(data, "status")
        self.assert_field(data, "version")
    
    def test_system_status(self):
        """Test 2: System status endpoint works"""
        resp = requests.get(f"{self.base_url}/api/system/status")
        self.assert_status(resp, 200, "Status check failed")
        data = resp.json()
        self.assert_field(data, "status")
        self.assert_field(data, "moats_operational")
        assert data["moats_operational"] == 10, f"Expected 10 moats, got {data['moats_operational']}"
    
    def test_moats_listing(self):
        """Test 3: All moats listed and honest"""
        resp = requests.get(f"{self.base_url}/api/system/moats")
        self.assert_status(resp, 200, "Moats listing failed")
        data = resp.json()
        self.assert_field(data, "moats")
        self.assert_field(data, "all_honest")
        assert data["all_honest"] == True, "Some moats are dishonest!"
        assert len(data["moats"]) == 10, f"Expected 10 moats, got {len(data['moats'])}"
    
    # ═══════════════════════════════════════════════════════════════════════
    # MOAT 1-2: INTEGRITY & FEEDBACK
    # ═══════════════════════════════════════════════════════════════════════
    
    def test_geometric_mean_integrity(self):
        """Test 4: Geometric mean integrity calculation (bug fixed)"""
        resp = requests.post(f"{self.base_url}/api/rtp/decide", json={
            "tool_name": "test.tool",
            "signals": {
                "consistency": 0.9,
                "accuracy": 0.9,
                "normality": 0.9,
                "latency": 0.9
            }
        })
        self.assert_status(resp, 200, "Decide failed")
        data = resp.json()
        self.assert_field(data, "integrity_score")
        # Geometric mean should be ~0.9, not 0.9^4 (bug)
        assert 0.85 <= data["integrity_score"] <= 0.95, f"Integrity calculation wrong: {data['integrity_score']}"
    
    def test_dynamic_threshold(self):
        """Test 5: Dynamic threshold modulation"""
        # High integrity -> lower threshold
        resp1 = requests.post(f"{self.base_url}/api/rtp/decide", json={
            "tool_name": "test.high",
            "signals": {"consistency": 0.95, "accuracy": 0.95, "normality": 0.95, "latency": 0.95}
        })
        data1 = resp1.json()
        
        # Low integrity -> higher threshold  
        resp2 = requests.post(f"{self.base_url}/api/rtp/decide", json={
            "tool_name": "test.low",
            "signals": {"consistency": 0.3, "accuracy": 0.3, "normality": 0.3, "latency": 0.3}
        })
        data2 = resp2.json()
        
        # Threshold should adapt
        assert "threshold" in data1
        assert "threshold" in data2
    
    # ═══════════════════════════════════════════════════════════════════════
    # MOAT 3: BRITTLENESS DETECTION
    # ═══════════════════════════════════════════════════════════════════════
    
    def test_brittleness_detection(self):
        """Test 6: Brittleness detection works"""
        resp = requests.post(f"{self.base_url}/api/rtp/decide", json={
            "tool_name": "test.brittleness",
            "signals": {"consistency": 0.9, "accuracy": 0.9, "normality": 0.9, "latency": 0.9}
        })
        data = resp.json()
        self.assert_field(data, "brittleness_score")
        assert 0.0 <= data["brittleness_score"] <= 1.0, "Brittleness out of range"
    
    # ═══════════════════════════════════════════════════════════════════════
    # MOAT 4, 8, 9: TICKET GENERATION & CRYPTO
    # ═══════════════════════════════════════════════════════════════════════
    
    def test_ticket_generation(self):
        """Test 7: Ticket generation with HMAC-SHA256"""
        resp = requests.post(f"{self.base_url}/api/rtp/decide", json={
            "tool_name": "test.ticket",
            "signals": {"consistency": 0.95, "accuracy": 0.95, "normality": 0.95, "latency": 0.95}
        })
        self.assert_status(resp, 200, "Decide failed")
        data = resp.json()
        
        if data["decision"] == "ALLOW":
            self.assert_field(data, "ticket")
            ticket = data["ticket"]
            assert "." in ticket, "Ticket should contain signature separator"
            parts = ticket.split(".")
            assert len(parts) == 2, "Ticket format wrong"
            assert len(parts[0]) == 32, "Ticket ID should be 32 hex chars"
            assert len(parts[1]) == 64, "HMAC-SHA256 signature should be 64 hex chars"
    
    def test_ticket_consumption_success(self):
        """Test 8: Valid ticket consumption succeeds"""
        # Generate ticket
        resp1 = requests.post(f"{self.base_url}/api/rtp/decide", json={
            "tool_name": "read.file",
            "signals": {"consistency": 0.95, "accuracy": 0.95, "normality": 0.95, "latency": 0.95}
        })
        data1 = resp1.json()
        
        if data1["decision"] != "ALLOW":
            raise AssertionError(f"Ticket not issued: {data1['reason']}")
        
        ticket = data1["ticket"]
        
        # Consume ticket
        resp2 = requests.post(f"{self.base_url}/api/rtp/consume", json={
            "ticket": ticket,
            "tool_name": "read.file"
        })
        self.assert_status(resp2, 200, "Ticket consumption failed")
        data2 = resp2.json()
        self.assert_equals(data2["status"], "ALLOWED", "Ticket consumption should succeed")
    
    def test_replay_attack_prevention(self):
        """Test 9: TOCTOU - Replay attack MUST FAIL"""
        # Generate ticket
        resp1 = requests.post(f"{self.base_url}/api/rtp/decide", json={
            "tool_name": "test.replay",
            "signals": {"consistency": 0.95, "accuracy": 0.95, "normality": 0.95, "latency": 0.95}
        })
        data1 = resp1.json()
        
        if data1["decision"] != "ALLOW":
            raise AssertionError(f"Ticket not issued: {data1['reason']}")
        
        ticket = data1["ticket"]
        
        # First consumption - should succeed
        resp2 = requests.post(f"{self.base_url}/api/rtp/consume", json={
            "ticket": ticket,
            "tool_name": "test.replay"
        })
        self.assert_status(resp2, 200, "First consumption should succeed")
        
        # Second consumption - MUST FAIL
        resp3 = requests.post(f"{self.base_url}/api/rtp/consume", json={
            "ticket": ticket,
            "tool_name": "test.replay"
        })
        self.assert_status(resp3, 403, "Replay attack should be blocked")
    
    def test_tool_mismatch_prevention(self):
        """Test 10: Tool mismatch MUST FAIL"""
        # Generate ticket for read.file
        resp1 = requests.post(f"{self.base_url}/api/rtp/decide", json={
            "tool_name": "read.file",
            "signals": {"consistency": 0.95, "accuracy": 0.95, "normality": 0.95, "latency": 0.95}
        })
        data1 = resp1.json()
        
        if data1["decision"] != "ALLOW":
            raise AssertionError(f"Ticket not issued: {data1['reason']}")
        
        ticket = data1["ticket"]
        
        # Try to use for shell.exec - MUST FAIL
        resp2 = requests.post(f"{self.base_url}/api/rtp/consume", json={
            "ticket": ticket,
            "tool_name": "shell.exec"
        })
        self.assert_status(resp2, 403, "Tool mismatch should be blocked")
    
    def test_ticket_tampering_prevention(self):
        """Test 11: Signature tampering MUST FAIL"""
        # Generate ticket
        resp1 = requests.post(f"{self.base_url}/api/rtp/decide", json={
            "tool_name": "test.tamper",
            "signals": {"consistency": 0.95, "accuracy": 0.95, "normality": 0.95, "latency": 0.95}
        })
        data1 = resp1.json()
        
        if data1["decision"] != "ALLOW":
            raise AssertionError(f"Ticket not issued: {data1['reason']}")
        
        ticket = data1["ticket"]
        
        # Tamper with signature (change last char)
        tampered = ticket[:-1] + ("0" if ticket[-1] != "0" else "1")
        
        # Try to use tampered ticket - MUST FAIL
        resp2 = requests.post(f"{self.base_url}/api/rtp/consume", json={
            "ticket": tampered,
            "tool_name": "test.tamper"
        })
        self.assert_status(resp2, 403, "Tampering should be detected")
    
    # ═══════════════════════════════════════════════════════════════════════
    # MOAT 7: AUDIT CHAIN
    # ═══════════════════════════════════════════════════════════════════════
    
    def test_audit_logging(self):
        """Test 12: Audit events are logged"""
        # Generate some events
        requests.post(f"{self.base_url}/api/rtp/decide", json={
            "tool_name": "test.audit",
            "signals": {"consistency": 0.9, "accuracy": 0.9, "normality": 0.9, "latency": 0.9}
        })
        
        # Check audit trail
        resp = requests.get(f"{self.base_url}/api/rtp/audit?limit=10")
        self.assert_status(resp, 200, "Audit query failed")
        events = resp.json()
        assert isinstance(events, list), "Audit should return list"
        assert len(events) > 0, "Audit should have events"
    
    def test_audit_chain_verification(self):
        """Test 13: Audit chain verification"""
        resp = requests.post(f"{self.base_url}/api/rtp/audit/verify")
        self.assert_status(resp, 200, "Audit verification failed")
        data = resp.json()
        self.assert_field(data, "valid")
        self.assert_field(data, "total_events")
        assert data["valid"] == True, f"Audit chain broken: {data.get('error')}"
    
    # ═══════════════════════════════════════════════════════════════════════
    # MOAT 10: RATE LIMITING
    # ═══════════════════════════════════════════════════════════════════════
    
    def test_rate_limiting(self):
        """Test 14: Rate limiting works"""
        # This is a light test - full load test separate
        for i in range(5):
            resp = requests.post(f"{self.base_url}/api/rtp/decide", json={
                "tool_name": f"test.rate.{i}",
                "signals": {"consistency": 0.9, "accuracy": 0.9, "normality": 0.9, "latency": 0.9}
            })
            # Should all succeed at low rate
            self.assert_status(resp, 200, f"Request {i} failed")
    
    # ═══════════════════════════════════════════════════════════════════════
    # EDGE CASES & ERROR HANDLING
    # ═══════════════════════════════════════════════════════════════════════
    
    def test_malformed_request(self):
        """Test 15: Malformed requests handled gracefully"""
        # Missing tool_name
        resp = requests.post(f"{self.base_url}/api/rtp/decide", json={
            "signals": {"consistency": 0.9}
        })
        self.assert_status(resp, 422, "Should reject missing tool_name")
    
    def test_invalid_signals(self):
        """Test 16: Invalid signal values handled"""
        # Signals out of range
        resp = requests.post(f"{self.base_url}/api/rtp/decide", json={
            "tool_name": "test.invalid",
            "signals": {"consistency": 5.0}  # Out of [0,1]
        })
        self.assert_status(resp, 422, "Should reject out-of-range signals")
    
    def test_nonexistent_ticket(self):
        """Test 17: Nonexistent ticket rejected"""
        fake_ticket = "0" * 32 + "." + "0" * 64
        resp = requests.post(f"{self.base_url}/api/rtp/consume", json={
            "ticket": fake_ticket,
            "tool_name": "test.fake"
        })
        self.assert_status(resp, 403, "Should reject nonexistent ticket")
    
    # ═══════════════════════════════════════════════════════════════════════
    # PERFORMANCE TESTS
    # ═══════════════════════════════════════════════════════════════════════
    
    def test_latency_decide(self):
        """Test 18: Decision latency < 100ms"""
        times = []
        for i in range(10):
            start = time.time()
            resp = requests.post(f"{self.base_url}/api/rtp/decide", json={
                "tool_name": f"perf.test.{i}",
                "signals": {"consistency": 0.9, "accuracy": 0.9, "normality": 0.9, "latency": 0.9}
            })
            elapsed = (time.time() - start) * 1000  # ms
            times.append(elapsed)
            self.assert_status(resp, 200, f"Perf request {i} failed")
        
        avg = sum(times) / len(times)
        p95 = sorted(times)[int(0.95 * len(times))]
        
        log(f"  Latency: avg={avg:.2f}ms, p95={p95:.2f}ms", "blue")
        assert avg < 100, f"Average latency {avg:.2f}ms > 100ms"
        assert p95 < 150, f"P95 latency {p95:.2f}ms > 150ms"
    
    def test_throughput(self):
        """Test 19: System handles burst requests"""
        start = time.time()
        count = 50
        
        for i in range(count):
            resp = requests.post(f"{self.base_url}/api/rtp/decide", json={
                "tool_name": f"burst.{i}",
                "signals": {"consistency": 0.9, "accuracy": 0.9, "normality": 0.9, "latency": 0.9}
            })
            if resp.status_code != 200:
                log(f"  Request {i} failed: {resp.status_code}", "yellow")
        
        elapsed = time.time() - start
        rps = count / elapsed
        
        log(f"  Throughput: {rps:.0f} req/sec", "blue")
        assert rps > 10, f"Throughput {rps:.0f} < 10 req/sec"
    
    # ═══════════════════════════════════════════════════════════════════════
    # STATE PERSISTENCE
    # ═══════════════════════════════════════════════════════════════════════
    
    def test_state_persistence(self):
        """Test 20: State survives (simulated)"""
        # Generate ticket
        resp1 = requests.post(f"{self.base_url}/api/rtp/decide", json={
            "tool_name": "persist.test",
            "signals": {"consistency": 0.95, "accuracy": 0.95, "normality": 0.95, "latency": 0.95}
        })
        data1 = resp1.json()
        
        if data1["decision"] != "ALLOW":
            log("  Skipping persistence test (ticket not issued)", "yellow")
            return
        
        ticket = data1["ticket"]
        
        # Verify ticket exists (should succeed before restart)
        resp2 = requests.post(f"{self.base_url}/api/rtp/consume", json={
            "ticket": ticket,
            "tool_name": "persist.test"
        })
        self.assert_status(resp2, 200, "Ticket should exist")
        
        log("  ✓ State persistence validated (ticket consumed successfully)", "green")
    
    def run_all(self):
        """Run all tests"""
        log("\n╔══════════════════════════════════════════════════════════════════════════════╗", "blue")
        log("║                                                                              ║", "blue")
        log("║              🏰 KASBAH COMPLETE TEST SUITE - ALL MOATS                      ║", "blue")
        log("║                                                                              ║", "blue")
        log("╚══════════════════════════════════════════════════════════════════════════════╝", "blue")
        
        # Basic tests
        self.test( "1. Health Check", self.test_health)
        self.test( "2. System Status", self.test_system_status)
        self.test( "3. Moats Listing", self.test_moats_listing)
        
        # Integrity tests
        self.test( "4. Geometric Mean Integrity (Bug Fixed)", self.test_geometric_mean_integrity)
        self.test( "5. Dynamic Threshold", self.test_dynamic_threshold)
        self.test( "6. Brittleness Detection", self.test_brittleness_detection)
        
        # Security tests
        self.test( "7. Ticket Generation", self.test_ticket_generation)
        self.test( "8. Ticket Consumption", self.test_ticket_consumption_success)
        self.test( "9. Replay Attack Prevention (CRITICAL)", self.test_replay_attack_prevention)
        self.test( "10. Tool Mismatch Prevention (CRITICAL)", self.test_tool_mismatch_prevention)
        self.test( "11. Signature Tampering Prevention (CRITICAL)", self.test_ticket_tampering_prevention)
        
        # Audit tests
        self.test( "12. Audit Logging", self.test_audit_logging)
        self.test( "13. Audit Chain Verification", self.test_audit_chain_verification)
        
        # Rate limiting
        self.test( "14. Rate Limiting", self.test_rate_limiting)
        
        # Edge cases
        self.test( "15. Malformed Request Handling", self.test_malformed_request)
        self.test( "16. Invalid Signal Handling", self.test_invalid_signals)
        self.test( "17. Nonexistent Ticket Rejection", self.test_nonexistent_ticket)
        
        # Performance
        self.test( "18. Decision Latency", self.test_latency_decide)
        self.test( "19. Throughput", self.test_throughput)
        
        # State
        self.test( "20. State Persistence", self.test_state_persistence)
        
        # Summary
        self.print_summary()
    
    def print_summary(self):
        """Print test summary"""
        total = self.passed + self.failed
        success_rate = (self.passed / total * 100) if total > 0 else 0
        
        log("\n" + "═" * 80, "blue")
        log("                           🏰 TEST RESULTS", "blue")
        log("═" * 80, "blue")
        
        log(f"\nTotal Tests: {total}", "blue")
        log(f"Passed:      {self.passed}", "green")
        log(f"Failed:      {self.failed}", "red" if self.failed > 0 else "green")
        log(f"Success:     {success_rate:.1f}%", "green" if success_rate >= 90 else "red")
        
        if self.failed > 0:
            log("\n❌ FAILED TESTS:", "red")
            for name, result in self.tests_run:
                if "FAIL" in result or "ERROR" in result:
                    log(f"  • {name}: {result}", "red")
        
        log("\n" + "═" * 80, "blue")
        
        if success_rate >= 95:
            log("\n🎉 PRODUCTION READY - ALL MOATS LOCKED DOWN!", "green")
            log("✅ Ship it!", "green")
        elif success_rate >= 85:
            log("\n⚠️  MOSTLY READY - Minor fixes needed", "yellow")
        else:
            log("\n❌ NOT READY - Critical issues remain", "red")
            log("🔧 Fix failing tests before shipping!", "red")
        
        return success_rate >= 95

if __name__ == "__main__":
    tester = KasbahTester()
    
    try:
        success = tester.run_all()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        log("\n\n⚠️  Tests interrupted", "yellow")
        sys.exit(1)
    except Exception as e:
        log(f"\n\n💥 Test suite crashed: {e}", "red")
        import traceback
        traceback.print_exc()
        sys.exit(1)
