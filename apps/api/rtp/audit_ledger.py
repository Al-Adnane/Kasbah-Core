class AuditLedger:
    def log_decision(self, agent_id, tool_name, decision, integrity_score, threshold, ticket):
        pass
    def log_consume(self, ticket, ok, reason, tool, agent):
        pass
    def get_latest_signature(self):
        return "mock_signature"
    def get_merkle_root(self):
        return "mock_merkle_root"

def get_audit_logger():
    return AuditLedger()
