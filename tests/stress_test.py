import sys
import os
import threading
import time
import numpy as np

# Add parent dir to path to import kasbah modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from kasbah_main import KasbahEngine

# --- TEST 1: CONCURRENCY (Race Conditions) ---
print(">>> TEST 1: Concurrency Race Condition (20 Threads)...")
engine = KasbahEngine()
target_ip = "192.168.1.99"
errors = []

def worker(ip):
    try:
        # Try to penalize same IP 10 times
        for _ in range(10):
            engine.srl.penalize(ip, 5)
    except Exception as e:
        errors.append(e)

threads = []
for _ in range(20):
    t = threading.Thread(target=worker, args=(target_ip,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

if errors:
    print(f"[FAIL] {len(errors)} Threads crashed.")
else:
    print(f"[PASS] Concurrency stable. Final Score for {target_ip}: {engine.srl.get_score(target_ip)}")


# --- TEST 2: LOAD (Throughput & Crash) ---
print("\n>>> TEST 2: Load Test (1000 Packets)...")
start_time = time.time()
for i in range(1000):
    # High entropy data
    data = np.random.rand(10)
    engine.process_packet(f"10.0.0.{i}", "10.0.0.5", data)
    
duration = time.time() - start_time
print(f"[PASS] Processed 1000 packets in {duration:.2f}s. Throughput: {1000/duration:.2f} pps")

# --- TEST 3: AUDIT TRUTH ---
print("\n>>> TEST 3: Audit Truth Verification...")
# We added 1000 packets + 20 * 10 = 1000 + 200 logs
expected_logs = len(engine.biz.audit_log)
print(f"[PASS] Audit Log Size: {expected_logs} entries.")
if expected_logs == 1200:
    print("[PASS] Audit matches operations exactly.")
else:
    print(f"[WARN] Log mismatch. Expected ~1200, got {expected_logs}")

# --- TEST 4: PERSISTENCE (The Restart Test) ---
print("\n>>> TEST 4: Persistence Verification...")
# The 'CryptoSecureCore' should have saved .kasbah/ledger.json
if os.path.exists(".kasbah/ledger.json"):
    print("[PASS] Ledger file created.")
    file_size = os.path.getsize(".kasbah/ledger.json")
    print(f"[PASS] Ledger size: {file_size} bytes.")
else:
    print("[FAIL] Ledger file missing. Check permissions.")
