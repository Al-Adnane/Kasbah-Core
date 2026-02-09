from .base import KasbahAdapter

class DAOExecAdapter(KasbahAdapter):
    def describe(self):
        return {"actor": "dao_bot", "actions": ["execute_proposal"]}

    def collect_signals(self, raw_event):
        return {
            "quorum_strength": float(raw_event.get("quorum_strength", 0)),
            "proposal_drift": float(raw_event.get("proposal_drift", 0)),
            "execution_delay": float(raw_event.get("execution_delay", 0)),
            "revert_rate": float(raw_event.get("revert_rate", 0)),
        }

    def build_decision_request(self, raw_event):
        return {
            "actor_id": raw_event["dao_id"],
            "action": "execute_proposal",
            "signals": self.collect_signals(raw_event),
            "context": {}
        }

    def enforce_decision(self, decision, raw_event):
        return {"dao_action": decision.get("decision")}

    def report_outcome(self, outcome):
        return outcome
