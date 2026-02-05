from fastapi import APIRouter, HTTPException
from apps.api.rtp.audit_ledger import latest_by_jti

router = APIRouter()

@router.get("/api/rtp/explain/{jti}")
def rtp_explain(jti: str):
    row = latest_by_jti(jti)
    if not row:
        raise HTTPException(status_code=404, detail="unknown jti")
    p = row["payload"]
    summary = f"{p.get('decision') or p.get('status')}: tool={p.get('tool') or p.get('tool_name')} integrity={p.get('integrity_score') or p.get('integrity')} threshold={p.get('threshold')} state={p.get('defense_state')}"
    return {
        "jti": jti,
        "kind": row["kind"],
        "decision": p.get("decision") or p.get("status") or p.get("allowed"),
        "tool": (p.get("tool_name") or p.get("tool") or (p.get("request", {}) or {}).get("tool_name") or (p.get("request", {}) or {}).get("tool") or (p.get("payload", {}) or {}).get("tool_name") or (p.get("payload", {}) or {}).get("tool")),
        "signals": p.get("signals", {}),
        "policy": p.get("policy") or p.get("policy_mode"),
        "integrity": p.get("integrity"),
        "row_hash": row["row_hash"],
        "prev_hash": row["prev_hash"],
        "ts": row["ts"],
        "summary": summary,
    }
