"""
Kasbah v2.0 - Authorization Layer Test Suite

Tests all authorization scenarios including:
- Policy enforcement
- Bot constraints
- Acting-as delegation
- Shared drive access control
"""

import requests
import json
from typing import Dict

API_URL = "http://localhost:5000"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_test(name: str):
    print(f"\n{Colors.BLUE}{'='*80}{Colors.END}")
    print(f"{Colors.BLUE}TEST: {name}{Colors.END}")
    print(f"{Colors.BLUE}{'='*80}{Colors.END}")

def print_pass(msg: str):
    print(f"{Colors.GREEN}✓ PASS: {msg}{Colors.END}")

def print_fail(msg: str):
    print(f"{Colors.RED}✗ FAIL: {msg}{Colors.END}")

def print_info(msg: str):
    print(f"{Colors.YELLOW}→ {msg}{Colors.END}")

# ============================================================================
# TEST 1: COO Full Access (Human with full permissions)
# ============================================================================

def test_coo_full_access():
    print_test("COO Full Access - Human with full permissions")
    
    # COO should be able to delete anything
    payload = {
        "tool": "shared_drive.delete",
        "agent_id": "bot-assistant",
        "signals": {"consistency": 0.95},
        "principal": {
            "id": "coo@company.com",
            "type": "human",
            "acting_as": None
        },
        "action": "delete",
        "resource": {
            "path": "/finance/reports/q4.pdf",
            "type": "file"
        }
    }
    
    print_info(f"Principal: {payload['principal']['id']} (COO)")
    print_info(f"Action: DELETE on {payload['resource']['path']}")
    
    response = requests.post(f"{API_URL}/api/decide", json=payload)
    
    if response.status_code == 200:
        data = response.json()
        if data['allowed'] and data.get('authorization', {}).get('status') == 'granted':
            print_pass("COO authorized to delete finance file")
            print_info(f"Ticket: {data['ticket'][:60]}...")
            return data['ticket']
        else:
            print_fail("COO should have been authorized")
    else:
        print_fail(f"Expected 200, got {response.status_code}")
        print_info(response.json())
    
    return None

# ============================================================================
# TEST 2: Bot Finance Reader (Bot with read-only access)
# ============================================================================

def test_bot_finance_reader_allowed():
    print_test("Bot Finance Reader - Allowed: Read from /finance/")
    
    payload = {
        "tool": "shared_drive.read",
        "agent_id": "bot-finance",
        "signals": {"consistency": 0.95},
        "principal": {
            "id": "bot-finance",
            "type": "bot",
            "acting_as": None
        },
        "action": "read",
        "resource": {
            "path": "/finance/reports/monthly.xlsx",
            "type": "file"
        }
    }
    
    print_info(f"Principal: {payload['principal']['id']} (Finance Bot)")
    print_info(f"Action: READ on {payload['resource']['path']}")
    
    response = requests.post(f"{API_URL}/api/decide", json=payload)
    
    if response.status_code == 200:
        data = response.json()
        if data['allowed']:
            print_pass("Bot authorized to read finance file (within policy)")
            return data['ticket']
        else:
            print_fail("Bot should have been authorized")
    else:
        print_fail(f"Expected 200, got {response.status_code}")
    
    return None

def test_bot_finance_reader_denied():
    print_test("Bot Finance Reader - Denied: Write to /finance/")
    
    payload = {
        "tool": "shared_drive.write",
        "agent_id": "bot-finance",
        "signals": {"consistency": 0.95},
        "principal": {
            "id": "bot-finance",
            "type": "bot",
            "acting_as": None
        },
        "action": "write",  # NOT ALLOWED (only read/list)
        "resource": {
            "path": "/finance/reports/monthly.xlsx",
            "type": "file"
        }
    }
    
    print_info(f"Principal: {payload['principal']['id']} (Finance Bot)")
    print_info(f"Action: WRITE on {payload['resource']['path']}")
    print_info("Expected: DENIED (bot can only read, not write)")
    
    response = requests.post(f"{API_URL}/api/decide", json=payload)
    
    if response.status_code == 403:
        data = response.json()
        if not data['allowed'] and 'authorization' in data['reason']:
            print_pass("Bot correctly denied write access (policy enforced)")
            print_info(f"Reason: {data['reason']}")
        else:
            print_fail("Wrong denial reason")
    else:
        print_fail(f"Expected 403, got {response.status_code}")

def test_bot_finance_reader_legal_denied():
    print_test("Bot Finance Reader - Denied: Access /legal/ (restricted)")
    
    payload = {
        "tool": "shared_drive.read",
        "agent_id": "bot-finance",
        "signals": {"consistency": 0.95},
        "principal": {
            "id": "bot-finance",
            "type": "bot",
            "acting_as": None
        },
        "action": "read",
        "resource": {
            "path": "/legal/contracts/nda.pdf",  # DENIED RESOURCE
            "type": "file"
        }
    }
    
    print_info(f"Principal: {payload['principal']['id']} (Finance Bot)")
    print_info(f"Action: READ on {payload['resource']['path']}")
    print_info("Expected: DENIED (/legal/ is explicitly denied for this bot)")
    
    response = requests.post(f"{API_URL}/api/decide", json=payload)
    
    if response.status_code == 403:
        data = response.json()
        if not data['allowed'] and 'resource_denied' in data['reason']:
            print_pass("Bot correctly denied access to /legal/ (denied_resources enforced)")
            print_info(f"Reason: {data['reason']}")
        else:
            print_fail("Should have been denied due to denied_resources")
    else:
        print_fail(f"Expected 403, got {response.status_code}")

# ============================================================================
# TEST 3: Bot Acting As Human (Delegation)
# ============================================================================

def test_bot_acting_as_alice_allowed():
    print_test("Bot Acting As Alice - Allowed: Write to /projects/x/")
    
    payload = {
        "tool": "shared_drive.write",
        "agent_id": "bot-assistant",
        "signals": {"consistency": 0.95},
        "principal": {
            "id": "bot-assistant",
            "type": "bot",
            "acting_as": "alice@company.com"  # DELEGATION
        },
        "action": "write",
        "resource": {
            "path": "/projects/x/status.md",
            "type": "file"
        }
    }
    
    print_info(f"Principal: {payload['principal']['id']} (Bot)")
    print_info(f"Acting as: {payload['principal']['acting_as']} (Human)")
    print_info(f"Action: WRITE on {payload['resource']['path']}")
    
    response = requests.post(f"{API_URL}/api/decide", json=payload)
    
    if response.status_code == 200:
        data = response.json()
        if data['allowed']:
            print_pass("Bot authorized to write as Alice to /projects/x/")
            print_info(f"Authorization: {json.dumps(data['authorization'], indent=2)}")
            return data['ticket']
        else:
            print_fail("Bot should have been authorized when acting as Alice")
    else:
        print_fail(f"Expected 200, got {response.status_code}")
    
    return None

def test_bot_acting_as_alice_denied():
    print_test("Bot Acting As Alice - Denied: Write outside /projects/x/")
    
    payload = {
        "tool": "shared_drive.write",
        "agent_id": "bot-assistant",
        "signals": {"consistency": 0.95},
        "principal": {
            "id": "bot-assistant",
            "type": "bot",
            "acting_as": "alice@company.com"
        },
        "action": "write",
        "resource": {
            "path": "/ops/logs/system.log",  # OUTSIDE allowed path
            "type": "file"
        }
    }
    
    print_info(f"Principal: {payload['principal']['id']} acting as {payload['principal']['acting_as']}")
    print_info(f"Action: WRITE on {payload['resource']['path']}")
    print_info("Expected: DENIED (bot-as-alice only allowed in /projects/x/*)")
    
    response = requests.post(f"{API_URL}/api/decide", json=payload)
    
    if response.status_code == 403:
        data = response.json()
        if not data['allowed']:
            print_pass("Bot correctly denied access outside allowed path")
            print_info(f"Reason: {data['reason']}")
        else:
            print_fail("Should have been denied")
    else:
        print_fail(f"Expected 403, got {response.status_code}")

# ============================================================================
# TEST 4: Replay Attack (Even with AuthZ)
# ============================================================================

def test_replay_attack_with_authz():
    print_test("Replay Attack - Ticket with AuthZ claims")
    
    # First, generate a ticket
    payload = {
        "tool": "shared_drive.delete",
        "agent_id": "bot-ops",
        "signals": {"consistency": 0.95},
        "principal": {
            "id": "bot-ops",
            "type": "bot"
        },
        "action": "delete",
        "resource": {
            "path": "/ops/temp/old.log",
            "type": "file"
        }
    }
    
    print_info("Generating ticket with AuthZ claims...")
    response = requests.post(f"{API_URL}/api/decide", json=payload)
    
    if response.status_code != 200:
        print_fail("Failed to generate ticket")
        return
    
    ticket = response.json()['ticket']
    print_info(f"Ticket: {ticket[:60]}...")
    
    # First consumption (should work)
    print_info("\nFirst consumption attempt...")
    consume_payload = {
        "ticket": ticket,
        "tool": "shared_drive.delete"
    }
    
    response = requests.post(f"{API_URL}/api/consume", json=consume_payload)
    
    if response.status_code == 200:
        print_pass("First consumption: ALLOWED")
    else:
        print_fail("First consumption should have been allowed")
        return
    
    # Second consumption (should fail - replay)
    print_info("\nSecond consumption attempt (replay)...")
    response = requests.post(f"{API_URL}/api/consume", json=consume_payload)
    
    if response.status_code == 403:
        data = response.json()
        if 'already_consumed' in data['reason']:
            print_pass("Replay attack blocked (single-use enforcement)")
            print_info(f"Reason: {data['reason']}")
        else:
            print_fail("Should have been blocked as already consumed")
    else:
        print_fail(f"Expected 403, got {response.status_code}")

# ============================================================================
# TEST 5: Complete Flow - COO Use Case
# ============================================================================

def test_complete_coo_workflow():
    print_test("Complete COO Workflow - Shared Drive Authorization")
    
    print_info("\n" + "="*80)
    print_info("SCENARIO: COO wants bot to analyze Q4 financial reports")
    print_info("- Bot needs READ access to /finance/reports/*")
    print_info("- Bot should NOT have WRITE or DELETE")
    print_info("="*80)
    
    # Step 1: Bot requests READ access
    print_info("\nStep 1: Bot requests READ on /finance/reports/q4-summary.xlsx")
    
    payload = {
        "tool": "excel.read",
        "agent_id": "bot-analyst",
        "signals": {"consistency": 0.98, "accuracy": 0.95},
        "principal": {
            "id": "bot-finance",
            "type": "bot"
        },
        "action": "read",
        "resource": {
            "path": "/finance/reports/q4-summary.xlsx",
            "type": "file"
        }
    }
    
    response = requests.post(f"{API_URL}/api/decide", json=payload)
    
    if response.status_code == 200:
        data = response.json()
        print_pass("Authorization: GRANTED")
        print_info(f"Integrity: {data['integrity']}")
        print_info(f"Principal: {data['authorization']['principal']['id']}")
        print_info(f"Action: {data['authorization']['action']}")
        print_info(f"Resource: {data['authorization']['resource']['path']}")
        
        ticket = data['ticket']
        
        # Step 2: Execute with ticket
        print_info("\nStep 2: Execute with ticket")
        consume_response = requests.post(f"{API_URL}/api/consume", json={
            "ticket": ticket,
            "tool": "excel.read",
            "verify_auth": {
                "principal_id": "bot-finance",
                "action": "read",
                "resource_path": "/finance/reports/q4-summary.xlsx"
            }
        })
        
        if consume_response.status_code == 200:
            print_pass("Execution: ALLOWED")
            print_info("✓ Bot successfully read Q4 summary")
        else:
            print_fail("Execution should have been allowed")
    else:
        print_fail(f"Authorization failed: {response.json()}")
    
    # Step 3: Try to DELETE (should fail)
    print_info("\nStep 3: Bot tries to DELETE the file (should be denied)")
    
    payload['action'] = 'delete'
    payload['tool'] = 'excel.delete'
    
    response = requests.post(f"{API_URL}/api/decide", json=payload)
    
    if response.status_code == 403:
        print_pass("DELETE correctly denied (bot can only read)")
        print_info(f"Reason: {response.json()['reason']}")
    else:
        print_fail("DELETE should have been denied")

# ============================================================================
# TEST 6: Policy Listing
# ============================================================================

def test_policy_listing():
    print_test("Policy Listing - View Current Authorization Policies")
    
    response = requests.get(f"{API_URL}/api/policies")
    
    if response.status_code == 200:
        data = response.json()
        print_pass(f"Retrieved {len(data['policies'])} policies")
        
        for policy_name, policy in data['policies'].items():
            print_info(f"\n{policy_name}:")
            print_info(f"  Principal: {policy['principal_type']} - {policy['principal_id']}")
            print_info(f"  Actions: {', '.join(policy['allowed_actions'])}")
            print_info(f"  Allowed: {', '.join(policy['allowed_resources'][:2])}...")
            if policy['denied_resources']:
                print_info(f"  Denied: {', '.join(policy['denied_resources'])}")
    else:
        print_fail("Failed to retrieve policies")

# ============================================================================
# MAIN TEST RUNNER
# ============================================================================

def run_all_tests():
    print(f"\n{Colors.BLUE}")
    print("="*80)
    print("KASBAH v2.0 - AUTHORIZATION LAYER TEST SUITE")
    print("="*80)
    print(f"{Colors.END}\n")
    
    # Health check
    try:
        response = requests.get(f"{API_URL}/api/health")
        if response.status_code == 200:
            data = response.json()
            print_pass("API is running")
            print_info(f"Version: {data['version']}")
            print_info(f"Status: {data['status']}")
        else:
            print_fail("API health check failed")
            return
    except Exception as e:
        print_fail(f"Cannot connect to API at {API_URL}")
        print_info(f"Error: {e}")
        print_info("\nMake sure the API is running:")
        print_info("  python kasbah_api_v2_authz.py")
        return
    
    # Run tests
    tests = [
        test_policy_listing,
        test_coo_full_access,
        test_bot_finance_reader_allowed,
        test_bot_finance_reader_denied,
        test_bot_finance_reader_legal_denied,
        test_bot_acting_as_alice_allowed,
        test_bot_acting_as_alice_denied,
        test_replay_attack_with_authz,
        test_complete_coo_workflow
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            result = test()
            passed += 1
        except Exception as e:
            print_fail(f"Test crashed: {e}")
            failed += 1
    
    # Summary
    print(f"\n{Colors.BLUE}{'='*80}{Colors.END}")
    print(f"{Colors.BLUE}TEST SUMMARY{Colors.END}")
    print(f"{Colors.BLUE}{'='*80}{Colors.END}")
    print(f"{Colors.GREEN}Passed: {passed}{Colors.END}")
    print(f"{Colors.RED}Failed: {failed}{Colors.END}")
    print()

if __name__ == '__main__':
    run_all_tests()
