import time
import json
from pathlib import Path

_STATE_PATH = "/app/.kasbah/rtp_signal_state.jsonl" if Path("/app").exists() else ".kasbah/rtp_signal_state.jsonl"

class SignalTracker:
    def __init__(self):
        self.store = {}
        self._load()
    
    def _load(self):
        if not Path(_STATE_PATH).exists():
            return
        try:
            with open(_STATE_PATH, 'r') as f:
                for line in f:
                    data = json.loads(line)
                    self.store[data['agent_id']] = data['signals']
        except:
            pass
            
    def _persist(self, agent_id: str, signals: dict):
        try:
            entry = {"agent_id": agent_id, "ts": time.time(), "signals": signals}
            with open(_STATE_PATH, 'a') as f:
                f.write(json.dumps(entry) + "\n")
        except:
            pass # Silent fail for demo
            
    def update(self, agent_id: str, raw_signals: dict) -> dict:
        """
        Updates signals with temporal decay.
        Returns effective signals.
        """
        current = self.store.get(agent_id, {})
        
        # Simple exponential smoothing (alpha = 0.1)
        alpha = 0.1
        updated = {}
        for k, v in raw_signals.items():
            prev = current.get(k, v)
            updated[k] = (alpha * v) + ((1 - alpha) * prev)
            
        self.store[agent_id] = updated
        self._persist(agent_id, updated)
        
        return updated
