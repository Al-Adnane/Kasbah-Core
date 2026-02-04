from __future__ import annotations
from pathlib import Path
"""
Kasbah RTP - Runtime Policy Gate + Audit
"""

from typing import Dict, Optional
from dataclasses import dataclass
import hashlib
import hmac
import json
import time
import os
import uuid
import dataclasses

from .audit import append_audit
from apps.api.rtp.integrity import geometric_integrity
from apps.api.rtp.signals import SignalTracker

_signal_tracker = SignalTracker()

@dataclass
class ExecutionTicket:
    jti: str
    tool_name: str
    args: Dict
    timestamp: int
    issued_mono_ns: int
    ttl: int
    binary_hash: str
    signature: str
    resource_limits: Dict

@dataclass
class TicketValidationResult:
    valid: bool
    reason: str
    remaining_budget: Optional[int] = None

class UsedJtiTracker:
    def __init__(self, path: str):
        self.path = path
        self.used = {}
        self._load()
    
    def _load(self):
        if not Path(self.path).exists():
            return
        with open(self.path, 'r') as f:
            for line in f:
                data = json.loads(line)
                self.used[data['jti']] = data['ts']
    
    def add(self, jti: str):
        self.used[jti] = time.time()
        self._persist()
    
    def _persist(self):
        with open(self.path, 'w') as f:
            for jti, ts in self.used.items():
                f.write(json.dumps({"jti": jti, "ts": ts}) + "\n")

class KernelGate:
    MAX_TTL_NS = 3600 * 1_000_000_000  # 1 hour
    DEFAULT_TTL_NS = int(os.getenv("KASBAH_TICKET_TTL_SECONDS", "120")) * 1_000_000_000

    def __init__(self, tpm_enabled: bool = False, policy: Optional[Dict[str, str]] = None, used_log_path: str = "/app/.kasbah/rtp_used_jti.jsonl"):
        self.global_lock = False
        self.policy = policy or {}
        self.used_log_path = used_log_path
        self.used_jti_tracker = UsedJtiTracker(used_log_path)
        self.ticket_map = {}
    
    def policy_mode(self, tool_name: str) -> str:
        mode = self.policy.get(tool_name, self.policy.get("*", "deny"))
        if mode not in ("allow", "deny", "human_approval"):
            return "deny"
        return mode

    def _canonical_json(self, obj: Dict) -> str:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))

    def _normalize_limits(self, resource_limits: Optional[Dict]) -> Dict:
        limits = dict(resource_limits or {})
        if "maxCostCents" not in limits:
            limits["maxCostCents"] = 0
        if "maxTokens" not in limits:
            limits["maxTokens"] = 10**18
        return limits

    def _signing_payload(self, fields: Dict) -> Dict:
        return {
            "jti": fields["jti"],
            "tool_name": fields["tool_name"],
            "args": fields["args"],
            "timestamp": fields["timestamp"],
            "issued_mono_ns": fields["issued_mono_ns"],
            "ttl": fields["ttl"],
            "binary_hash": fields["binary_hash"],
            "resource_limits": fields["resource_limits"],
        }

    def _compute_binary_hash(self, tool_name: str) -> str:
        return hashlib.sha256(f"binary-{tool_name}".encode()).hexdigest()

    def _sign_with_tpm(self, payload: Dict) -> str:
        data = self._canonical_json(payload)
        return hashlib.sha256(f"kasbah-{data}".encode()).hexdigest()

    def _verify_signature(self, ticket: ExecutionTicket) -> bool:
        payload = self._signing_payload(ticket.__dict__)
        expected = self._sign_with_tpm(payload)
        return hmac.compare_digest(expected, ticket.signature)

    def generate_ticket(self, tool_name: str, args: Dict, system_stable: bool, resource_limits=None, ttl_ns=None):
        if self.global_lock:
            append_audit({"event": "DENY", "reason": "global_lock", "rule_id": "RTP-SYS-LOCK-001", "tool": tool_name})
            return None

        if not system_stable:
            append_audit({"event": "DENY", "reason": "system_unstable", "rule_id": "RTP-SYS-001", "tool": tool_name})
            return None

        mode = self.policy_mode(tool_name)
        if mode != "allow":
            append_audit({"event": "DENY", "reason": mode, "rule_id": "RTP-MODE-001", "tool": tool_name})
            return None

        ttl = int(ttl_ns or self.DEFAULT_TTL_NS)
        now = time.time_ns()
        jti = str(uuid.uuid4())
        limits = self._normalize_limits(resource_limits)
        
        payload = {
            "jti": jti,
            "tool_name": tool_name,
            "args": args,
            "timestamp": now,
            "issued_mono_ns": now,
            "ttl": ttl,
            "binary_hash": self._compute_binary_hash(tool_name),
            "resource_limits": limits
        }
        
        signature = self._sign_with_tpm(payload)
        self.ticket_map[jti] = ExecutionTicket(**payload, signature=signature)
        
        # FIXED: Return dictionary to work with main.py
        return vars(self.ticket_map[jti])

    def validate_ticket(self, ticket: ExecutionTicket, usage: Optional[Dict] = None) -> TicketValidationResult:
        if not self._verify_signature(ticket):
            return TicketValidationResult(False, "invalid_signature")
        
        if usage:
            limits = ticket.resource_limits
            used = int(usage.get("tokens", 0))
            max_tokens = int(limits.get("maxTokens", 10**18))
            
            if used >= max_tokens:
                return TicketValidationResult(False, "token_limit_exceeded")
            
            return TicketValidationResult(True, "OK", max_tokens - used)
        
        return TicketValidationResult(True, "OK")

    def _persist_used(self, jti: str):
        self.used_jti_tracker.add(jti)

    def intercept_execution(self, tool_name: str, jti: str, usage: Dict) -> TicketValidationResult:
        if jti in self.used_jti_tracker.used:
            return TicketValidationResult(False, "replay_attack")
        
        ticket = self.ticket_map.get(jti)
        if not ticket:
            return TicketValidationResult(False, "jti_not_found")
        
        if ticket.tool_name != tool_name:
            return TicketValidationResult(False, "tool_mismatch")
        
        # --- behavior integrity: provenance + decay + geometry ---
        agent_id = usage.get("agent_id") or usage.get("session_id") or "anon"
        raw_signals = usage.get("signals", {}) or {}
        
        eff_signals = _signal_tracker.update(agent_id, raw_signals) if raw_signals else {}
        append_audit({"event":"GEOMETRY_SEEN","agent_id":agent_id,"jti":jti,"raw":raw_signals,"eff":eff_signals})
        
        signals_for_gate = eff_signals or raw_signals
        if signals_for_gate:
            gi = geometric_integrity(signals_for_gate)
            threshold = float(os.getenv("KASBAH_GEOMETRY_THRESHOLD", "70"))
            if gi >= threshold:
                append_audit({
                    "event": "GEOMETRY_BLOCK",
                    "jti": jti,
                    "agent_id": agent_id,
                    "score": gi,
                    "threshold": threshold,
                    "signals_raw": raw_signals,
                    "signals_eff": eff_signals,
                })
                return TicketValidationResult(False, "geometry_block")
            else:
                # FIXED: Log GEOMETRY_ALLOW event
                append_audit({"event":"GEOMETRY_ALLOW","jti":jti,"agent_id":agent_id,"score":gi,"threshold":threshold,"signals_raw":raw_signals,"signals_eff":eff_signals})
        # --- end behavior integrity ---
        
        res = self.validate_ticket(ticket, usage)
        if res.valid:
            self.used_jti_tracker.add(jti)
            del self.ticket_map[jti]
            append_audit({"event": "CONSUME", "tool": tool_name, "jti": jti})
        
        return res

KernelEnforcer = KernelGate
