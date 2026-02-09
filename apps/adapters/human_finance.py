from .base import KasbahAdapter

class HumanFinanceAdapter(KasbahAdapter):
    def describe(self):
        return {"actor": "human_operator", "actions": ["approve_payment"]}

    def collect_signals(self, raw_event):
        return {
            "policy_deviation": float(raw_event.get("policy_deviation", 0)),
            "time_pressure": float(raw_event.get("time_pressure", 0)),
            "override_rate": float(raw_event.get("override_rate", 0)),
            "amount_z": float(raw_event.get("amount_z", 0)),
        }

    def build_decision_request(self, raw_event):
        return {
            "actor_id": raw_event["user_id"],
            "action": "approve_payment",
            "signals": self.collect_signals(raw_event),
            "context": {}
        }

    def enforce_decision(self, decision, raw_event):
        return {"payment_status": decision.get("decision")}

    def report_outcome(self, outcome):
        return outcome
