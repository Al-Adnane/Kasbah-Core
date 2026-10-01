#!/usr/bin/env python3
"""
Kasbah Frontier Model Shield — Production Deployment

Self-contained defensive governance server. No external `frontier_core`
dependency: all detection logic lives here and is deterministic (no RNG).

PRIVACY BOUNDARY (BIOMETRIC_GUARD):
    This service NEVER performs biometric or silent-speech intent inference.
    If a request carries video_frames / audio_samples / em_samples / silent-
    speech fields, the request is treated as an *attempted* intent-surveillance
    operation and BLOCKED — Kasbah protects against such surveillance, it does
    not carry it out.
"""

import hashlib
import hmac
import json
import logging
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("KasbahFrontier")


# ============================================================================
# Audit ledger — tamper-evident hash chain (deterministic, no RNG)
# ============================================================================

class AuditLedger:
    """Append-only SHA-256 hash chain. Each receipt links to the previous."""

    GENESIS = "0" * 64

    def __init__(self) -> None:
        self.receipts: List[Dict[str, Any]] = []

    def append(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        prev = self.receipts[-1]["hash"] if self.receipts else self.GENESIS
        body = {
            "seq": len(self.receipts),
            "prev": prev,
            "ts": payload.get("timestamp"),
            "payload": payload,
        }
        digest = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        receipt = {"id": f"rcpt_{digest[:16]}", "hash": digest, **body}
        self.receipts.append(receipt)
        return receipt

    def get_root(self) -> str:
        return self.receipts[-1]["hash"] if self.receipts else self.GENESIS

    def verify_chain(self) -> bool:
        prev = self.GENESIS
        for r in self.receipts:
            if r["prev"] != prev:
                return False
            body = {"seq": r["seq"], "prev": r["prev"], "ts": r["ts"], "payload": r["payload"]}
            if hashlib.sha256(
                json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest() != r["hash"]:
                return False
            prev = r["hash"]
        return True


# ============================================================================
# Deterministic text governance
# ============================================================================

# Fields whose mere presence indicates an attempted biometric / silent-speech
# intent-surveillance operation. We block these — we never analyze them.
_SURVEILLANCE_FIELDS = (
    "video_frames", "audio_samples", "em_samples", "emg_samples",
    "subvocalization", "silent_speech", "facial_landmarks", "lip_frames", "bci_signal",
)

_INJECTION_PATTERNS = [
    re.compile(r"ignore (all|any|previous) .{0,20}instruction", re.I),
    re.compile(r"disregard .{0,20}(prompt|rules|policy)", re.I),
    re.compile(r"system prompt", re.I),
    re.compile(r"you are now (a|an|in) ", re.I),
]
_EXFIL_PATTERNS = [
    re.compile(r"exfiltrat", re.I),
    re.compile(r"(send|post|upload).{0,30}https?://", re.I),
    re.compile(r"(drop|delete) .{0,10}table", re.I),
    re.compile(r"\b(rm -rf|DROP DATABASE)\b", re.I),
]
_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                 # AWS access key id
    re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY"),  # PEM private key
    re.compile(r"sk-[A-Za-z0-9]{20,}"),               # generic secret token
]


def _scan_text(text: str) -> Dict[str, Any]:
    threats: List[str] = []
    score = 0.0
    for p in _INJECTION_PATTERNS:
        if p.search(text):
            threats.append("prompt_injection")
            score = max(score, 0.85)
            break
    for p in _EXFIL_PATTERNS:
        if p.search(text):
            threats.append("data_exfiltration")
            score = max(score, 0.9)
            break
    for p in _SECRET_PATTERNS:
        if p.search(text):
            threats.append("secret_leak")
            score = max(score, 0.75)
            break
    return {"threats": threats, "score": round(score, 3)}


class FrontierShieldServer:
    """Self-contained defensive governance server."""

    def __init__(self, port: int = 8788) -> None:
        self.port = port
        self.audit = AuditLedger()
        self.request_count = 0
        self.threat_count = 0
        self.blocked_count = 0
        self.biometric_blocked = 0

    def handle_agent_input(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        self.request_count += 1
        prompt = str(request_data.get("prompt", "") or "")
        agent_id = request_data.get("agent_id", "unknown")

        present_surveillance = [f for f in _SURVEILLANCE_FIELDS if request_data.get(f)]
        if present_surveillance:
            # BIOMETRIC_GUARD: refuse — do not analyze the biometric payload.
            self.threat_count += 1
            self.blocked_count += 1
            self.biometric_blocked += 1
            decision, score = "block", 1.0
            threats = ["biometric_surveillance_attempt"]
            summary = (
                "[BLOCK] BIOMETRIC_GUARD: refused intent-surveillance payload "
                f"({', '.join(present_surveillance)}). Kasbah does not infer intent "
                "from biometric/silent-speech signals."
            )
        else:
            scan = _scan_text(prompt)
            score = scan["score"]
            threats = scan["threats"]
            decision = "block" if score >= 0.8 else "warn" if score >= 0.4 else "allow"
            if decision != "allow":
                self.threat_count += 1
            if decision == "block":
                self.blocked_count += 1
            summary = f"[{decision.upper()}] score {score:.2f} | " + (
                "; ".join(threats) if threats else "No threats detected"
            )

        receipt = self.audit.append({
            "agent_id": agent_id,
            "decision": decision,
            "threat_score": score,
            "threats": threats,
            "timestamp": int(time.time() * 1000),
        })
        return {
            "request_id": request_data.get("request_id"),
            "agent_id": agent_id,
            "decision": decision,
            "threat_score": score,
            "threats": threats,
            "receipt_id": receipt["id"],
            "summary": summary,
            "timestamp": receipt["ts"],
        }

    def health(self) -> Dict[str, Any]:
        return {
            "status": "healthy",
            "requests_processed": self.request_count,
            "threats_detected": self.threat_count,
            "requests_blocked": self.blocked_count,
            "biometric_surveillance_blocked": self.biometric_blocked,
            "audit_chain_valid": self.audit.verify_chain(),
        }

    def stats(self) -> Dict[str, Any]:
        rc = max(self.request_count, 1)
        return {
            "total_requests": self.request_count,
            "total_threats": self.threat_count,
            "total_blocked": self.blocked_count,
            "biometric_surveillance_blocked": self.biometric_blocked,
            "threat_rate_pct": round(self.threat_count / rc * 100, 2),
            "block_rate_pct": round(self.blocked_count / rc * 100, 2),
            "audit_receipts": len(self.audit.receipts),
            "audit_chain_valid": self.audit.verify_chain(),
        }


# ============================================================================
# HTTP Server (FastAPI)
# ============================================================================

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    import uvicorn

    app = FastAPI(
        title="Kasbah Frontier Model Shield",
        description="Self-contained defensive agent governance + BIOMETRIC_GUARD",
        version="3.1.0",
    )
    server: Optional[FrontierShieldServer] = None

    @app.on_event("startup")
    async def startup() -> None:
        global server
        server = FrontierShieldServer(port=int(os.getenv("PORT", "8788")))
        logger.info("Kasbah Frontier Shield initialized (defensive, no surveillance)")

    @app.post("/v1/shield/ingest")
    async def ingest(request_data: Dict[str, Any]):
        if not server:
            raise HTTPException(status_code=503, detail="Server not ready")
        try:
            return JSONResponse(server.handle_agent_input(request_data))
        except Exception as e:  # noqa: BLE001
            logger.error("Ingest error: %s", e)
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/v1/shield/health")
    async def health():
        if not server:
            raise HTTPException(status_code=503, detail="Server not ready")
        return JSONResponse(server.health())

    @app.get("/v1/shield/stats")
    async def stats():
        if not server:
            raise HTTPException(status_code=503, detail="Server not ready")
        return JSONResponse(server.stats())

    @app.get("/v1/shield/audit/root")
    async def get_audit_root():
        if not server:
            raise HTTPException(status_code=503, detail="Server not ready")
        return JSONResponse({
            "merkle_root": server.audit.get_root(),
            "receipts_count": len(server.audit.receipts),
            "chain_valid": server.audit.verify_chain(),
        })

    def run_server(host: str = "0.0.0.0", port: int = 8788) -> None:
        uvicorn.run(app, host=host, port=port, log_level="info")

except ImportError:
    logger.warning("FastAPI not installed. Install with: pip install fastapi uvicorn")
    run_server = None


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8788"))
    if run_server:
        logger.info("Starting Kasbah Frontier Shield on port %s", port)
        run_server(port=port)
    else:
        logger.error("FastAPI required. Install with: pip install fastapi uvicorn")
        sys.exit(1)
