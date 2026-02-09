"""
Registry is a stable mapping from adapter_id -> import path.
Adapters remain pluggable and the kernel remains domain-agnostic.

No auto-discovery here: explicit registry prevents supply-chain surprises.
"""

REGISTRY = {
    "ai_tool": "apps.adapters.ai_tool:AIToolAdapter",
    "human_finance": "apps.adapters.human_finance:HumanFinanceAdapter",
    "dao_exec": "apps.adapters.dao_exec:DAOExecAdapter",
}
