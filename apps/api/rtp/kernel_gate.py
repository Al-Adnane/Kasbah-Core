"""
Kasbah RTP - Runtime Policy Gate + Audit

Features:
- Default-deny policy
- Explicit allowlist
- Human approval mode (acts as deny for now)
- Global kill switch
- Monotonic TTL
- Replay protection
- Deterministic signature (demo-safe)
- Append-only audit log
"""

from __future__ import annotations

from typing import Dict, Optional
from dataclasses import dataclass
import hashlib
import hmac
import json
import time
import uuid

from .audit import append_audit


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


class KernelGate:
    MAX_TTL_NS = 100_000_000
    DEFAULT_TTL_NS = 75_000_000

    def __init__(self, tpm_enabled: bool = False, policy: Optional[Dict[str, str]] = None):
        self.tpm_enabled = bool(tpm_enabled)
        self.global_lock = False
        self.policy = policy or {}

    def policy_mode(self, tool_name: str) -> str:
        mode = self.policy.get(tool_name, "deny")
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
        if ttl <= 0 or ttl > self.MAX_TTL_NS:
            ttl = self.DEFAULT_TTL_NS

        ts_wall = time.time_ns()
        ts_mono = time.monotonic_ns()
        jti = str(uuid.uuid4())

        limits = self._normalize_limits(resource_limits)
        binary_hash = self._compute_binary_hash(tool_name)

        payload = self._signing_payload({
            "jti": jti,
            "tool_name": tool_name,
            "args": args,
            "timestamp": ts_wall,
            "issued_mono_ns": ts_mono,
            "ttl": ttl,
            "binary_hash": binary_hash,
            "resource_limits": limits,
        })

        sig = self._sign_with_tpm(payload)

        append_audit({"event": "ALLOW", "reason": "ok", "rule_id": "RTP-ALLOW-001", "tool": tool_name, "jti": jti})

        return ExecutionTicket(
            jti=jti,
            tool_name=tool_name,
            args=args,
            timestamp=ts_wall,
            issued_mono_ns=ts_mono,
            ttl=ttl,
            binary_hash=binary_hash,
            signature=sig,
            resource_limits=limits,
        )

    def validate_ticket(self, ticket: ExecutionTicket, current_usage: Dict):
        now = time.monotonic_ns()
        if now - ticket.issued_mono_ns > ticket.ttl:
            return TicketValidationResult(False, "expired")

        if not self._verify_signature(ticket):
            return TicketValidationResult(False, "bad signature")

        used = int(current_usage.get("tokens", 0))
        max_tokens = int(ticket.resource_limits.get("maxTokens", 10**18))

        if used >= max_tokens:
            return TicketValidationResult(False, "budget exceeded")

        return TicketValidationResult(True, "OK", max_tokens - used)


class KernelEnforcer:

    def __init__(self, gate: KernelGate):
        self.gate = gate
        self.ticket_map = {}
        self.used = {}

    def store_ticket(self, ticket: ExecutionTicket):
        self.ticket_map[ticket.jti] = ticket

    def intercept_execution(self, tool_name: str, jti: str, usage: Dict):

        if jti in self.used:
            append_audit({"event": "REPLAY", "jti": jti})
            return TicketValidationResult(False, "replay")

        ticket = self.ticket_map.get(jti)
        if not ticket:
            return TicketValidationResult(False, "missing")

        if ticket.tool_name != tool_name:
            return TicketValidationResult(False, "tool mismatch")

        res = self.gate.validate_ticket(ticket, usage)
        if res.valid:
            self.used[jti] = time.time()
            del self.ticket_map[jti]
            append_audit({"event": "CONSUME", "tool": tool_name, "jti": jti})

        return res

