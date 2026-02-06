import hashlib
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
