# Kasbah Adapter Interface (v1)

from typing import Dict, Any

class KasbahAdapter:
    """
    Adapters translate real-world events into kernel decisions.
    Kernel logic MUST NOT live here.
    """

    def describe(self) -> Dict[str, Any]:
        raise NotImplementedError

    def collect_signals(self, raw_event: Dict[str, Any]) -> Dict[str, float]:
        raise NotImplementedError

    def build_decision_request(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def enforce_decision(self, decision: Dict[str, Any], raw_event: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def report_outcome(self, outcome: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError
