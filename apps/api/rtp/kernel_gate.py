"""
Kasbah RTP - One Product Runtime Gate (Policy + Tickets)

Buyer-grade additions:
- Default-deny policy for tools (explicit allow list)
- Modes: "allow" | "deny" | "human_approval"
- "human_approval" currently behaves like deny (no ticket) in MVP
- Global kill switch (deny all)

Core properties retained:
- Monotonic TTL enforcement (clock-skew safe)
- Deterministic signature generation + verification (demo-safe)
- One-time use tickets via jti (replay protection)
- In-memory enforcer (swap to kernel/eBPF later)

This module does NOT execute commands.
"""

from __future__ import annotations

from typing import Dict, Optional
from dataclasses import dataclass
import hashlib
import hmac
import json
import time
import uuid


@dataclass
class ExecutionTicket:
    jti: str
    tool_name: str
    args: Dict
    timestamp: int          # wall-clock ns (audit/log)
    issued_mono_ns: int     # monotonic ns (TTL validation)
    ttl: int                # ns
    binary_hash: str
    signature: str
    resource_limits: Dict   # maxTokens, maxCostCents (+ optional maxCost)


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

        # Global kill-switch: when True => deny all tickets
        self.global_lock = False

        # Tool policy: "allow" | "deny" | "human_approval"
        # Default is deny unless explicitly allowed.
        self.policy: Dict[str, str] = policy or {}

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
            if "maxCost" in limits:
                limits["maxCostCents"] = int(float(limits["maxCost"]) * 100)
            else:
                limits["maxCostCents"] = 0
        if "maxCost" not in limits:
            limits["maxCost"] = float(limits["maxCostCents"]) / 100.0
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
        # Demo-safe deterministic “binary” hash. Production would hash on-disk binary.
        return hashlib.sha256(f"binary-{tool_name}".encode("utf-8")).hexdigest()

    def _sign_with_tpm(self, payload: Dict) -> str:
        # Production: TPM signature. Demo: deterministic sha256 signature over canonical payload.
        data_str = self._canonical_json(payload)
        return hashlib.sha256(f"tpm-signature-{data_str}".encode("utf-8")).hexdigest()

    def _verify_signature(self, ticket: ExecutionTicket) -> bool:
        # Demo performs REAL verification by recomputing expected signature.
        try:
            payload = self._signing_payload({
                "jti": ticket.jti,
                "tool_name": ticket.tool_name,
                "args": ticket.args,
                "timestamp": ticket.timestamp,
                "issued_mono_ns": ticket.issued_mono_ns,
                "ttl": ticket.ttl,
                "binary_hash": ticket.binary_hash,
                "resource_limits": ticket.resource_limits,
            })
            expected = self._sign_with_tpm(payload)
            return hmac.compare_digest(expected, ticket.signature)
        except Exception:
            return False

    def generate_ticket(
        self,
        tool_name: str,
        args: Dict,
        system_stable: bool,
        resource_limits: Optional[Dict] = None,
        ttl_ns: Optional[int] = None,
    ) -> Optional[ExecutionTicket]:
        # Kill switch
        if self.global_lock:
            return None

        # System stability gate
        if not system_stable:
            return None

        # Policy gate (default deny)
        mode = self.policy_mode(tool_name)
        if mode != "allow":
            # In MVP, "human_approval" behaves like deny (no ticket).
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

    def validate_ticket(self, ticket: ExecutionTicket, current_usage: Dict) -> TicketValidationResult:
        now_mono = time.monotonic_ns()
        age = now_mono - ticket.issued_mono_ns
        if age > ticket.ttl:
            return TicketValidationResult(
                valid=False,
                reason=f"Ticket expired (age {age/1_000_000:.2f}ms > ttl {ticket.ttl/1_000_000:.2f}ms)",
            )

        tokens_used = int(current_usage.get("tokens", 0) or 0)
        cost_used = current_usage.get("cost", 0) or 0

        max_tokens = int(ticket.resource_limits.get("maxTokens", 10**18))
        max_cost_cents = int(ticket.resource_limits.get("maxCostCents", 10**18))
        cost_used_cents = int(float(cost_used) * 100) if not isinstance(cost_used, int) else int(cost_used)

        if tokens_used >= max_tokens:
            return TicketValidationResult(valid=False, reason=f"Token budget exceeded ({tokens_used} >= {max_tokens})")

        if cost_used_cents >= max_cost_cents:
            return TicketValidationResult(valid=False, reason=f"Cost budget exceeded ({cost_used_cents}c >= {max_cost_cents}c)")

        if not self._verify_signature(ticket):
            return TicketValidationResult(valid=False, reason="Invalid ticket signature")

        return TicketValidationResult(valid=True, reason="OK", remaining_budget=max_tokens - tokens_used)


class KernelEnforcer:
    """
    In-memory simulation of enforcement.
    Tickets are one-time use. Replay is blocked by jti.
    """

    def __init__(self, kernel_gate: KernelGate):
        self.gate = kernel_gate
        self.ticket_map: Dict[str, ExecutionTicket] = {}
        self.used_jtis: Dict[str, int] = {}
        self.used_ttl_ns = 5_000_000_000  # keep used markers for 5s (demo-safe)

    def _gc_used(self) -> None:
        now = time.monotonic_ns()
        dead = [j for j, t in self.used_jtis.items() if (now - t) > self.used_ttl_ns]
        for j in dead:
            del self.used_jtis[j]

    def store_ticket(self, ticket: ExecutionTicket) -> None:
        self._gc_used()
        self.ticket_map[ticket.jti] = ticket

    def intercept_execution(self, tool_name: str, ticket_jti: str, current_usage: Dict) -> TicketValidationResult:
        self._gc_used()

        if ticket_jti in self.used_jtis:
            return TicketValidationResult(valid=False, reason="Ticket replay detected (jti already used)")

        ticket = self.ticket_map.get(ticket_jti)
        if not ticket:
            return TicketValidationResult(valid=False, reason=f"No ticket found for jti={ticket_jti}")

        if ticket.tool_name != tool_name:
            return TicketValidationResult(valid=False, reason="Tool mismatch for provided ticket jti")

        res = self.gate.validate_ticket(ticket, current_usage)
        if res.valid:
            del self.ticket_map[ticket_jti]
            self.used_jtis[ticket_jti] = time.monotonic_ns()
        return res

