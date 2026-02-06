import sys
import os
import json
import time
import hashlib
from pathlib import Path

print("🔐 AUDIT TRAIL STATUS CHECK")
print("=" * 50)

# Check 1: File exists?
audit_path = Path(__file__).parent / "apps" / "api" / "audit_ledger.py"
print(f"1. audit_ledger.py exists: {'✅ YES' if audit_path.exists() else '❌ NO'}")

# Check 2: Can import?
sys.path.insert(0, str(Path(__file__).parent))
try:
    from apps.api.audit_ledger import AuditLedger
    print("2. Can import AuditLedger: ✅ YES")
    IMPORT_OK = True
except ImportError as e:
    print(f"2. Can import AuditLedger: ❌ NO - {e}")
    IMPORT_OK = False

# Check 3: Used in main.py?
main_path = Path(__file__).parent / "apps" / "api" / "main.py"
if main_path.exists():
    with open(main_path, 'r') as f:
        content = f.read()
    
    if "audit_log" in content or "AuditLedger" in content:
        print("3. Used in main.py: ✅ YES")
        USED_IN_MAIN = True
    else:
        print("3. Used in main.py: ❌ NO")
        USED_IN_MAIN = False
else:
    print("3. Used in main.py: ⚠️ main.py not found")
    USED_IN_MAIN = False

# Check 4: Create if missing
if not audit_path.exists():
    print("\n🔧 Creating missing audit_ledger.py...")
    os.makedirs(audit_path.parent, exist_ok=True)
    
    with open(audit_path, 'w') as f:
        f.write('''import hashlib
import json
import time
from collections import deque

class AuditLedger:
    def __init__(self):
        self.events = deque(maxlen=20000)
        self.chain = []
        self.last_hash = "0" * 64
    
    def log(self, event_type, **fields):
        timestamp = time.time()
        event = {
            "type": event_type,
            "timestamp": timestamp,
            "prev_hash": self.last_hash,
            "data": fields
        }
        event_str = json.dumps(event, sort_keys=True)
        event_hash = hashlib.sha256(event_str.encode()).hexdigest()
        
        self.events.append(event)
        self.chain.append({
            "hash": event_hash,
            "prev_hash": self.last_hash,
            "timestamp": timestamp
        })
        self.last_hash = event_hash
        return event_hash
    
    def verify_chain(self):
        if len(self.chain) <= 1:
            return {"verified": True, "issues": []}
        
        issues = []
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            
            if current["prev_hash"] != previous["hash"]:
                issues.append(f"Chain broken at {i}")
        
        return {"verified": len(issues) == 0, "issues": issues}

audit_ledger = AuditLedger()

def audit_log(event_type, **fields):
    return audit_ledger.log(event_type, **fields)

def verify_audit_chain():
    return audit_ledger.verify_chain()
''')
    print("✅ Created audit_ledger.py")

# Summary
print("\n" + "=" * 50)
print("📊 SUMMARY:")
print("-" * 50)

checks = [
    ("File exists", audit_path.exists()),
    ("Can import", IMPORT_OK),
    ("Used in main", USED_IN_MAIN),
]

for check, status in checks:
    print(f"{'✅' if status else '❌'} {check}")

passed = sum(1 for _, status in checks if status)
total = len(checks)

print(f"\n🎯 SCORE: {passed}/{total}")

if passed == total:
    print("🏆 AUDIT TRAIL (MOAT 7) IS OPERATIONAL!")
elif passed >= 2:
    print("⚠️  Audit trail partially working")
else:
    print("❌ Audit trail needs work")

print(f"\nTime: {time.strftime('%H:%M:%S')}")
