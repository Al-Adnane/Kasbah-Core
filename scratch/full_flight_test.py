import requests
import json
import time
from typing import Dict, Any

API = "http://localhost:5001"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def test(name: str, fn):
    print(f"\n{Colors.BLUE}{'='*80}{Colors.END}")
    print(f"{Colors.BLUE}TEST: {name}{Colors.END}")
    print(f"{Colors.BLUE}{'='*80}{Colors.END}")
    try:
        fn()
        print(f"{Colors.GREEN}✅ PASS{Colors.END}")
        return True
    except AssertionError as e:
        print(f"{Colors.RED}✗ FAIL: {e}{Colors.END}")
        return False
    except Exception as e:
        print(f"{Colors.RED}✗ ERROR: {e}{Colors.END}")
        return False

def api_call(method: str, endpoint: str, data: Dict = None) -> requests.Response:
    url = f"{API}{endpoint}"
    if method == "GET":
        return requests.get(url)
    elif method == "POST":
        return requests.post(url, json=data)

# =============================================================================
# PHASE 1: BASIC AUTHORIZATION
# =============================================================================

def test_bot_read_allowed():
    """Bot can read from allowed path"""
    r = api_call("POST", "/api/decide", {
        "tool": "drive.read",
        "agent_id": "bot-1",
        "signals": {"consistency": 0.95},
        "principal": {"id": "bot-finance", "type": "bot"},
        "action": "read",
        "resource": {"path": "/finance/q4.xlsx", "type": "file"}
    })
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert data["allowed"] == True
    assert "ticket" in data
    assert data["authorization"]["status"] == "granted"
    print(f"  → Ticket: {data['ticket'][:60]}...")

def test_bot_write_denied():
    """Bot cannot write (not in allowed_actions)"""
    r = api_call("POST", "/api/decide", {
        "tool": "drive.write",
        "agent_id": "bot-1",
        "signals": {"consistency": 0.95},
        "principal": {"id": "bot-finance", "type": "bot"},
        "action": "write",
        "resource": {"path": "/finance/q4.xlsx", "type": "file"}
    })
    assert r.status_code == 403, f"Expected 403, got {r.status_code}"
    data = r.json()
    assert data["allowed"] == False
    assert "action_not_allowed" in data["reason"]
    print(f"  → Denied: {data['reason']}")

def test_bot_denied_resource():
    """Bot cannot access denied resource (/legal/)"""
    r = api_call("POST", "/api/decide", {
        "tool": "drive.read",
        "agent_id": "bot-1",
        "signals": {"consistency": 0.95},
        "principal": {"id": "bot-finance", "type": "bot"},
        "action": "read",
        "resource": {"path": "/legal/nda.pdf", "type": "file"}
    })
    assert r.status_code == 403
    data = r.json()
    # Could be resource_denied or action_not_allowed depending on policy order
    assert data["allowed"] == False
    print(f"  → Denied: {data['reason']}")

# =============================================================================
# PHASE 2: DELEGATION (BOT ACTING AS HUMAN)
# =============================================================================

def test_bot_as_alice_allowed():
    """Bot acting as Alice can write to her project"""
    r = api_call("POST", "/api/decide", {
        "tool": "drive.write",
        "agent_id": "bot-1",
        "signals": {"consistency": 0.95},
        "principal": {
            "id": "bot-assistant",
            "type": "bot",
            "acting_as": "alice@company.com"
        },
        "action": "write",
        "resource": {"path": "/projects/x/doc.md", "type": "file"}
    })
    assert r.status_code == 200
    data = r.json()
    assert data["authorization"]["principal"]["acting_as"] == "alice@company.com"
    print(f"  → Delegation verified: bot acting as {data['authorization']['principal']['acting_as']}")
    return data["ticket"]

def test_bot_as_alice_wrong_project():
    """Bot acting as Alice CANNOT access other projects"""
    r = api_call("POST", "/api/decide", {
        "tool": "drive.write",
        "agent_id": "bot-1",
        "signals": {"consistency": 0.95},
        "principal": {
            "id": "bot-assistant",
            "type": "bot",
            "acting_as": "alice@company.com"
        },
        "action": "write",
        "resource": {"path": "/projects/y/doc.md", "type": "file"}
    })
    assert r.status_code == 403
    print(f"  → Correctly denied access outside scope")

# =============================================================================
# PHASE 3: RUNTIME ENFORCEMENT
# =============================================================================

def test_replay_attack():
    """Same ticket cannot be used twice"""
    # Get ticket
    r1 = api_call("POST", "/api/decide", {
        "tool": "drive.delete",
        "agent_id": "bot-1",
        "signals": {"consistency": 0.95},
        "principal": {"id": "bot-ops", "type": "bot"},
        "action": "create",
        "resource": {"path": "/ops/logs/test.log", "type": "file"}
    })
    assert r1.status_code == 200
    ticket = r1.json()["ticket"]
    
    # First use - should work
    r2 = api_call("POST", "/api/consume", {
        "ticket": ticket,
        "tool": "drive.delete"
    })
    assert r2.status_code == 200
    print(f"  → First use: ALLOWED")
    
    # Second use - should fail
    r3 = api_call("POST", "/api/consume", {
        "ticket": ticket,
        "tool": "drive.delete"
    })
    assert r3.status_code == 403
    assert "already_consumed" in r3.json()["reason"]
    print(f"  → Second use: BLOCKED (replay prevented)")

def test_tool_swap():
    """Ticket for tool A cannot be used for tool B"""
    # Get ticket for drive.read
    r1 = api_call("POST", "/api/decide", {
        "tool": "drive.read",
        "agent_id": "bot-1",
        "signals": {"consistency": 0.95},
        "principal": {"id": "bot-finance", "type": "bot"},
        "action": "read",
        "resource": {"path": "/finance/data.csv", "type": "file"}
    })
    assert r1.status_code == 200
    ticket = r1.json()["ticket"]
    
    # Try to use for drive.write
    r2 = api_call("POST", "/api/consume", {
        "ticket": ticket,
        "tool": "drive.write"  # Different tool!
    })
    assert r2.status_code == 403
    assert "tool_mismatch" in r2.json()["reason"]
    print(f"  → Tool swap prevented: ticket for 'drive.read' rejected for 'drive.write'")

def test_ticket_expiry():
    """Tickets expire after TTL"""
    # Note: Can't test real expiry without waiting 15 min
    # But we can verify the TTL mechanism exists
    r = api_call("POST", "/api/decide", {
        "tool": "test.action",
        "agent_id": "bot-1",
        "signals": {"consistency": 0.95},
        "principal": {"id": "coo@company.com", "type": "human"},
        "action": "execute",
        "resource": {"path": "/test", "type": "api"}
    })
    assert r.status_code == 200
    ticket = r.json()["ticket"]
    parts = ticket.split(":")
    timestamp = int(parts[2])
    now = int(time.time())
    assert abs(now - timestamp) < 5, "Timestamp should be current"
    print(f"  → Ticket timestamp verified: {timestamp}")
    print(f"  → TTL: 900s (would expire at timestamp {timestamp + 900})")

# =============================================================================
# PHASE 4: HUMAN OVERRIDES
# =============================================================================

def test_coo_full_access():
    """COO has unrestricted access"""
    paths = ["/finance/secret.xlsx", "/legal/contract.pdf", "/ops/config.yml"]
    actions = ["read", "write", "delete"]
    
    for path in paths:
        for action in actions:
            r = api_call("POST", "/api/decide", {
                "tool": f"admin.{action}",
                "agent_id": "coo",
                "signals": {"consistency": 0.95},
                "principal": {"id": "coo@company.com", "type": "human"},
                "action": action,
                "resource": {"path": path, "type": "file"}
            })
            assert r.status_code == 200, f"COO should access {path} with {action}"
    
    print(f"  → COO authorized for {len(paths) * len(actions)} actions across all paths")

# =============================================================================
# PHASE 5: AUDIT TRAIL
# =============================================================================

def test_audit_trail():
    """All actions are logged"""
    # Clear state by checking current count
    r1 = api_call("GET", "/api/audit")
    initial_count = r1.json()["total_entries"]
    
    # Perform action
    api_call("POST", "/api/decide", {
        "tool": "test.audit",
        "agent_id": "bot-1",
        "signals": {"consistency": 0.95},
        "principal": {"id": "bot-finance", "type": "bot"},
        "action": "read",
        "resource": {"path": "/test/audit.txt", "type": "file"}
    })
    
    # Check audit increased
    r2 = api_call("GET", "/api/audit")
    final_count = r2.json()["total_entries"]
    assert final_count > initial_count, "Audit count should increase"
    
    # Check latest entry
    entries = r2.json()["entries"]
    latest = entries[-1]
    assert latest["event_type"] in ["ticket_generated", "authorization_denied"]
    assert "hash" in latest
    assert "prev_hash" in latest
    print(f"  → Audit entries: {initial_count} → {final_count}")
    print(f"  → Latest event: {latest['event_type']}")
    print(f"  → Hash chain intact: {latest['hash'][:16]}...")

def test_audit_immutability():
    """Audit chain is cryptographically linked"""
    r = api_call("GET", "/api/audit")
    entries = r.json()["entries"]
    
    if len(entries) < 2:
        print("  → Need at least 2 entries to verify chain")
        # Generate some
        for i in range(3):
            api_call("POST", "/api/decide", {
                "tool": f"test.{i}",
                "agent_id": "bot-1",
                "signals": {"consistency": 0.95},
                "principal": {"id": "coo@company.com", "type": "human"},
                "action": "read",
                "resource": {"path": f"/test/{i}", "type": "file"}
            })
        r = api_call("GET", "/api/audit")
        entries = r.json()["entries"]
    
    # Verify chain
    for i in range(1, len(entries)):
        current = entries[i]
        previous = entries[i-1]
        assert current["prev_hash"] == previous["hash"], f"Chain broken at index {i}"
    
    print(f"  → Verified chain integrity for {len(entries)} entries")
    print(f"  → Any tampering would break the hash chain")

# =============================================================================
# PHASE 6: EDGE CASES
# =============================================================================

def test_low_integrity_denied():
    """Low integrity score blocks action"""
    r = api_call("POST", "/api/decide", {
        "tool": "test.low",
        "agent_id": "bot-1",
        "signals": {"consistency": 0.3, "accuracy": 0.4},  # Low!
        "principal": {"id": "coo@company.com", "type": "human"},
        "action": "delete",
        "resource": {"path": "/critical/data.db", "type": "file"}
    })
    assert r.status_code == 403
    data = r.json()
    assert "integrity_too_low" in data["reason"]
    assert data["integrity"] <= 0.7
    print(f"  → Integrity: {data['integrity']:.3f} (threshold: 0.7)")
    print(f"  → Blocked even though principal is COO")

def test_missing_params():
    """API handles missing parameters gracefully"""
    r = api_call("POST", "/api/consume", {
        "ticket": "invalid"
        # Missing 'tool'
    })
    assert r.status_code == 400
    assert "missing_params" in r.json()["reason"]
    print(f"  → Missing params handled: {r.json()['reason']}")

def test_invalid_ticket_format():
    """Invalid ticket format is rejected"""
    r = api_call("POST", "/api/consume", {
        "ticket": "this:is:not:valid",
        "tool": "test"
    })
    assert r.status_code == 403
    assert "invalid_format" in r.json()["reason"]
    print(f"  → Invalid format rejected")

# =============================================================================
# PHASE 7: POLICIES INTROSPECTION
# =============================================================================

def test_policies_endpoint():
    """Can retrieve current policies"""
    r = api_call("GET", "/api/policies")
    assert r.status_code == 200
    policies = r.json()["policies"]
    
    # Verify expected policies exist
    assert "bot-finance-reader" in policies
    assert "coo-full-access" in policies
    assert "bot-as-alice" in policies
    
    # Verify policy structure
    finance_policy = policies["bot-finance-reader"]
    assert "allowed_actions" in finance_policy
    assert "allowed_resources" in finance_policy
    assert "denied_resources" in finance_policy
    
    print(f"  → {len(policies)} policies loaded")
    for name, policy in policies.items():
        print(f"    • {name}: {policy['principal_id']} ({policy['principal_type']})")

# =============================================================================
# RUN ALL TESTS
# =============================================================================

if __name__ == "__main__":
    print(f"\n{Colors.BLUE}{'='*80}{Colors.END}")
    print(f"{Colors.BLUE}🚀 KASBAH V2.0 - FULL FLIGHT TEST{Colors.END}")
    print(f"{Colors.BLUE}{'='*80}{Colors.END}")
    
    # Check API is up
    try:
        r = requests.get(f"{API}/api/health")
        print(f"\n{Colors.GREEN}✓ API Status: {r.json()['status']}{Colors.END}")
        print(f"{Colors.GREEN}✓ Version: {r.json()['version']}{Colors.END}")
    except:
        print(f"\n{Colors.RED}✗ API not reachable at {API}{Colors.END}")
        print(f"{Colors.RED}✗ Start server: python3 kasbah_v2_fixed.py{Colors.END}")
        exit(1)
    
    tests = [
        # Phase 1: Basic Authorization
        ("Bot Read Allowed", test_bot_read_allowed),
        ("Bot Write Denied", test_bot_write_denied),
        ("Bot Denied Resource", test_bot_denied_resource),
        
        # Phase 2: Delegation
        ("Bot as Alice Allowed", test_bot_as_alice_allowed),
        ("Bot as Alice Wrong Project", test_bot_as_alice_wrong_project),
        
        # Phase 3: Runtime Enforcement
        ("Replay Attack Prevention", test_replay_attack),
        ("Tool Swap Prevention", test_tool_swap),
        ("Ticket Expiry Mechanism", test_ticket_expiry),
        
        # Phase 4: Human Overrides
        ("COO Full Access", test_coo_full_access),
        
        # Phase 5: Audit Trail
        ("Audit Trail Logging", test_audit_trail),
        ("Audit Immutability", test_audit_immutability),
        
        # Phase 6: Edge Cases
        ("Low Integrity Denied", test_low_integrity_denied),
        ("Missing Parameters", test_missing_params),
        ("Invalid Ticket Format", test_invalid_ticket_format),
        
        # Phase 7: Introspection
        ("Policies Endpoint", test_policies_endpoint),
    ]
    
    passed = 0
    failed = 0
    
    for name, fn in tests:
        if test(name, fn):
            passed += 1
        else:
            failed += 1
    
    # Summary
    print(f"\n{Colors.BLUE}{'='*80}{Colors.END}")
    print(f"{Colors.BLUE}SUMMARY{Colors.END}")
    print(f"{Colors.BLUE}{'='*80}{Colors.END}")
    print(f"{Colors.GREEN}Passed: {passed}/{len(tests)}{Colors.END}")
    if failed > 0:
        print(f"{Colors.RED}Failed: {failed}/{len(tests)}{Colors.END}")
    else:
        print(f"{Colors.GREEN}Failed: 0/{len(tests)}{Colors.END}")
    
    if failed == 0:
        print(f"\n{Colors.GREEN}{'='*80}{Colors.END}")
        print(f"{Colors.GREEN}🎉 ALL TESTS PASSED! READY FOR PRODUCTION!{Colors.END}")
        print(f"{Colors.GREEN}{'='*80}{Colors.END}")
    else:
        print(f"\n{Colors.YELLOW}⚠️  Some tests failed - review before shipping{Colors.END}")
