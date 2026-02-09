from .base import KasbahAdapter

class AIToolAdapter(KasbahAdapter):
    def describe(self):
        return {"actor": "ai_agent", "actions": ["tool.invoke"]}

    def collect_signals(self, raw_event):
        return {
            "consistency": float(raw_event.get("consistency", 0)),
            "accuracy": float(raw_event.get("accuracy", 0)),
            "normality": float(raw_event.get("normality", 0)),
            "rate_pressure": float(raw_event.get("rate_pressure", 0)),
        }

    def build_decision_request(self, raw_event):
        return {
            "actor_id": raw_event["agent_id"],
            "action": "tool.invoke",
            "signals": self.collect_signals(raw_event),
            "context": {}
        }

    def enforce_decision(self, decision, raw_event):
        return {"enforced": decision.get("decision")}

    def report_outcome(self, outcome):
        return outcome
