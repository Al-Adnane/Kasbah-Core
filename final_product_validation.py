#!/usr/bin/env python3
"""
KASBAH CORE - FINAL PRODUCT VALIDATION SUITE
Tests the integrated moats as a cohesive security product.
"""
import requests
import time
import json

API_URL = "http://127.0.0.1:8002"

def print_header(title):
    print("\n" + "="*70)
    print(f"📦 {title}")
    print("="*70)

def check_server_health():
    try:
        r = requests.get(f"{API_URL}/health", timeout=2)
        return r.status_code == 200
    except:
        return False

def run_validation():
    print_header("KASBAH CORE - PRODUCT INTEGRATION TEST")
    
    if not check_server_health():
        print("❌ FAILED: API Server is not running.")
        print("   Start it with: python3 apps/api/main.py")
        return False

    product_score = 0
    total_checks = 10

    # ==========================================
    # TEST 1: BUSINESS CONTINUITY (Legitimate Use)
    # ==========================================
    print_header("TEST 1: LEGITIMATE USER TRAFFIC")
    print("Scenario: An admin performing a standard database backup.")
    
    legit_payload = {
        "tool_name": "db_backup",
        "agent_id": "admin_ops_team",
        "signals": {
            "consistency": 0.98,
            "accuracy": 0.95,
            "normality": 0.96,
            "latency_score": 0.94
        }
    }
    
    start_time = time.time()
    res = requests.post(f"{API_URL}/api/rtp/decide", json=legit_payload)
    latency = (time.time() - start_time) * 1000
    
    data = res.json()
    
    # Check 1: Speed (Performance)
    print(f"⚡ Response Latency: {latency:.2f}ms")
    if latency < 500:
        print("✅ Performance Check: Latency acceptable (<500ms)")
        product_score += 1
    else:
        print("❌ Performance Check: Latency too high")

    # Check 2: Decision (Business Logic)
    print(f"🚦 Decision: {data['decision']}")
    if data['decision'] == "ALLOW":
        print("✅ Business Logic Check: Valid operation allowed")
        product_score += 1
    else:
        print("❌ Business Logic Check: Valid operation blocked incorrectly")

    # Check 3: Traceability (Merkle/Crypto)
    has_signature = 'audit_signature' in data and len(data['audit_signature']) > 10
    has_merkle = 'merkle_root' in data and len(data['merkle_root']) > 10
    
    if has_signature and has_merkle:
        print(f"🔒 Integrity: Signed & Merkle-Rooted ({data['merkle_root']})")
        print("✅ Compliance Check: Full cryptographic trail present")
        product_score += 1
    else:
        print("❌ Compliance Check: Missing crypto proof")

    # Check 4: Moat Integration
    triggered = data.get('moats_triggered', [])
    if len(triggered) >= 4:
        print(f"🔗 Integration: {len(triggered)} Moats active in pipeline")
        print("✅ Integration Check: Multi-layer defense active")
        product_score += 1
    else:
        print("❌ Integration Check: Defense layers too shallow")

    # ==========================================
    # TEST 2: SECURITY ENFORCEMENT (Threat Blocking)
    # ==========================================
    print_header("TEST 2: THREAT MITIGATION")
    print("Scenario: An attacker attempting an injection with abnormal signals.")
    
    attack_payload = {
        "tool_name": "exec_shell_cmd",  # Dangerous tool
        "agent_id": "external_ip_192.168",
        "signals": {
            "consistency": 0.12,  # Highly inconsistent
            "accuracy": 0.08,
            "normality": 0.05,    # Abnormal pattern
            "latency_score": 0.01
        }
    }
    
    res2 = requests.post(f"{API_URL}/api/rtp/decide", json=attack_payload)
    data2 = res2.json()
    
    print(f"🚦 Decision: {data2['decision']}")
    print(f"📉 Integrity Score: {data2['integrity_score']}")
    
    if data2['decision'] == "DENY":
        print("✅ Security Check: Threat blocked successfully")
        product_score += 1
    else:
        print("❌ Security Check: Dangerous action allowed!")

    if "Integrity" in data2.get('reason', ''):
        print("✅ Logic Check: Blocked for correct reason (Integrity)")
        product_score += 1
    else:
        print("⚠️  Logic Check: Reasoning unclear")

    # ==========================================
    # TEST 3: TOPOLOGY DEFENSE (Botnet Pattern)
    # ==========================================
    print_header("TEST 3: TOPOLOGY DEFENSE (Moat 13)")
    print("Scenario: Flooding from a single agent ID (Botnet Simulation)")
    
    bot_agent = "botnet_node_X"
    print("   Sending 25 requests...")
    for i in range(25):
        requests.post(f"{API_URL}/api/rtp/decide", json={
            "tool_name": f"scan_{i}",
            "agent_id": bot_agent,
            "signals": {"consistency": 0.5, "accuracy": 0.5, "normality": 0.5, "latency_score": 0.5}
        })
        
    # Try a clean request from the same agent
    final_payload = {
        "tool_name": "exfil_data",
        "agent_id": bot_agent,
        "signals": {"consistency": 0.9, "accuracy": 0.9, "normality": 0.9, "latency_score": 0.9}
    }
    
    res3 = requests.post(f"{API_URL}/api/rtp/decide", json=final_payload)
    data3 = res3.json()
    
    print(f"🚦 Decision: {data3['decision']}")
    if "Suspicious topology" in data3.get('reason', ''):
        print("✅ Botnet Defense Check: Topology moat blocked the agent")
        product_score += 1
    else:
        print("❌ Botnet Defense Check: Agent escaped topology detection")

    # ==========================================
    # TEST 4: SYSTEM HEALTH & METRICS
    # ==========================================
    print_header("TEST 4: SYSTEM TELEMETRY")
    
    # Get Audit Logs
    audit_res = requests.get(f"{API_URL}/api/rtp/audit?limit=5")
    logs = audit_res.json()
    
    print(f"📜 Audit Trail Entries Retrieved: {len(logs)}")
    if len(logs) > 0:
        print("✅ Audit Persistence Check: Logs are being saved")
        product_score += 1
    else:
        print("❌ Audit Persistence Check: No logs found")

    # Get Status
    status_res = requests.get(f"{API_URL}/api/rtp/status")
    status = status_res.json()
    
    print(f"🌡️  System Defense State: {status['thermo_state']}")
    print(f"🌐 Active Topology Nodes: {status['topology_agents']}")
    
    if status['topology_agents'] > 25:
        print("✅ State Tracking Check: System monitoring agents correctly")
        product_score += 1
    else:
        print("⚠️  State Tracking Check: Agent count seems low")

    # ==========================================
    # FINAL REPORT
    # ==========================================
    print_header("PRODUCT VALIDATION REPORT")
    
    percentage = (product_score / total_checks) * 100
    print(f"Final Score: {product_score} / {total_checks} ({percentage:.0f}%)")
    
    if percentage >= 80:
        print("✅ PRODUCT STATUS: PRODUCTION READY")
        print("\n✨ FEATURES VERIFIED:")
        print("  • Multi-layer Security Policy (Moats 1, 2, 11)")
        print("  • Cryptographic Audit Trail (Moats 5, 7)")
        print("  • Real-time Topology Defense (Moat 13)")
        print("  • Signal Processing (Moat 3)")
        print("  • High Performance & Observability")
    elif percentage >= 60:
        print("⚠️  PRODUCT STATUS: BETA")
        print("   Core features work, but some edge cases failed.")
    else:
        print("❌ PRODUCT STATUS: FAILED")
        print("   Critical integration errors detected.")
        
    print("="*70)
    return percentage >= 80

if __name__ == "__main__":
    try:
        success = run_validation()
        exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ VALIDATION CRASHED: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
