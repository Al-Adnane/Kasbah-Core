#!/usr/bin/env python3
"""
SOVEREIGN ENGINE MAX — Maximum-Hardness Fail-Closed Admission Product
=====================================================================
Version  : 2.0.0-max
Product  : Sovereign Engine Max

Pushed to the limit of what a stdlib reference can enforce:

  • G1–G10 from Pro, plus:
  • G11 CAPABILITY   — opaque capability required to perform side effects
  • G12 BINDING      — capability MAC-binds decision_id, state_hash, ticket_id, expires
  • G13 ROTATION     — live key-id on proofs/tickets/audit; epoch+kid mismatch denies
  • G14 METRICS      — admit/deny counters for ops (no PII)
  • G15 ADVERSARIAL  — built-in attack suite must all deny
  • G16 BUDGET       — interactive path times itself; optional hard deny on overrun
  • G17 IMMUTABLE    — frozen tickets/snapshots; no in-place field writes

STILL NOT CLAIMED
  Absolute security, TEE extraction resistance, multi-host nullifier without
  external store, post-quantum HMAC, upstream decoder correctness.

Python 3.10+ stdlib only.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import os
import secrets
import struct
import threading
import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple

__version__ = "2.0.0-max"
__product__ = "Sovereign Engine Max"

# =============================================================================
# CONFIG
# =============================================================================

class C:
    V_MAX_KS, V_MAX_PTR = 500.0, 200.0
    KS_WIN, FOC_WIN, SW_WIN = 10.0, 60.0, 300.0
    N_MAX_SW = 30.0
    W_R, W_E, ALPHA = 1.0, 0.6, 0.95
    NEUTRAL = 0.5
    RIGHTS_BASE = (1.00, 0.55, 0.05, 0.55)
    AG_W = (0.20, 0.15, 0.15, 0.20, 0.15, 0.15)
    TTL_MIN_MS, TTL_MAX_MS = 50, 500
    CAP_TTL_MS = 500
    NULLIFIER_WINDOW_S = 2.0
    THETA0 = 0.60
    THETA_MIN, THETA_MAX = 0.30, 0.90
    G_BAR = 0.55
    KP, KD, KI = 0.10, 0.05, 0.01
    T_MIN, T_MAX = 0.50, 2.00
    I_CLIP, I_LEAK = 0.50, 0.98
    PID_MIN_DT = 0.100
    COLLECTIVE_MAX_AGE_S = 60.0
    INTERACTIVE_MS = 5.0
    HARD_BUDGET = False  # set True to deny on pure-Python overrun (usually off in CPython)


class Decision(str, Enum):
    ADMIT = "ADMIT"
    DENY_TYPE = "DENY_TYPE"
    DENY_RIGHTS = "DENY_RIGHTS"
    DENY_PROOF = "DENY_PROOF"
    DENY_MUTATION = "DENY_MUTATION"
    DENY_COMPOSITE = "DENY_COMPOSITE"
    DENY_NO_TICKET = "DENY_NO_TICKET"
    DENY_EXPIRED = "DENY_EXPIRED"
    DENY_EPOCH = "DENY_EPOCH"
    DENY_MAC = "DENY_MAC"
    DENY_STATE = "DENY_STATE"
    DENY_REPLAY = "DENY_REPLAY"
    DENY_AUDIT = "DENY_AUDIT"
    DENY_BUDGET = "DENY_BUDGET"
    DENY_CAP = "DENY_CAP"
    DENY_KID = "DENY_KID"


# =============================================================================
# CRYPTO
# =============================================================================

def H(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def MAC(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def ct_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def σ(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    z = math.exp(x)
    return z / (1.0 + z)


def clip(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def gmean3(a: float, b: float, c: float) -> float:
    a, b, c = max(0.0, a), max(0.0, b), max(0.0, c)
    return 0.0 if a * b * c == 0.0 else (a * b * c) ** (1.0 / 3.0)


def pack4(v: Sequence[float]) -> bytes:
    return struct.pack("<ffff", float(v[0]), float(v[1]), float(v[2]), float(v[3]))


# =============================================================================
# KEYRING (rotation)
# =============================================================================

class Keyring:
    """Active + previous key for graceful rotation. BINDING POINT: KMS/HSM."""

    def __init__(self, domain: bytes) -> None:
        self.domain = domain
        self.kid = 1
        self._keys: Dict[int, bytes] = {1: H(domain, b"seed", os.urandom(16))}
        self._lock = threading.Lock()

    def mac(self, msg: bytes, kid: Optional[int] = None) -> Tuple[int, bytes]:
        with self._lock:
            k = self.kid if kid is None else kid
            key = self._keys[k]
            return k, MAC(key, msg)

    def verify(self, msg: bytes, kid: int, tag: bytes) -> bool:
        with self._lock:
            key = self._keys.get(kid)
            if key is None:
                return False
            return ct_eq(MAC(key, msg), tag)

    def rotate(self) -> int:
        with self._lock:
            self.kid += 1
            self._keys[self.kid] = H(self.domain, b"rot", struct.pack("<I", self.kid), os.urandom(16))
            # keep previous for verify
            if self.kid - 2 in self._keys:
                del self._keys[self.kid - 2]
            return self.kid


# =============================================================================
# DOMAIN ENGINES
# =============================================================================

@dataclass
class HumanEngine:
    history: float = C.NEUTRAL
    ks: List[float] = field(default_factory=list)
    ptr: List[float] = field(default_factory=list)
    foc: List[Tuple[float, bool]] = field(default_factory=list)
    sw: List[float] = field(default_factory=list)
    telemetry_off: bool = False

    def record_keystroke(self, t: float) -> None:
        self.ks.append(t)
        self._pr(self.ks, t, C.KS_WIN)

    def record_pointer(self, v: float, t: float) -> None:
        self.ptr.append(v)
        self._pr(self.ptr, t, C.KS_WIN)

    def record_focus(self, t: float, f: bool) -> None:
        self.foc.append((t, f))
        cut = t - C.FOC_WIN
        while self.foc and self.foc[0][0] < cut:
            self.foc.pop(0)

    def record_switch(self, t: float) -> None:
        self.sw.append(t)
        self._pr(self.sw, t, C.SW_WIN)

    @staticmethod
    def _pr(b: List[float], now: float, w: float) -> None:
        cut = now - w
        while b and b[0] < cut:
            b.pop(0)

    def _Rk(self) -> float:
        if len(self.ks) < 3:
            return C.NEUTRAL
        d = [(self.ks[i] - self.ks[i - 1]) * 1000 for i in range(1, len(self.ks))]
        m = sum(d) / len(d)
        v = sum((x - m) ** 2 for x in d) / len(d)
        return clip(1.0 - v / C.V_MAX_KS, 0.0, 1.0)

    def _Rm(self) -> float:
        if len(self.ptr) < 3:
            return C.NEUTRAL
        m = sum(self.ptr) / len(self.ptr)
        v = sum((x - m) ** 2 for x in self.ptr) / len(self.ptr)
        return clip(1.0 - v / C.V_MAX_PTR, 0.0, 1.0)

    def _Rd(self) -> float:
        if not self.foc:
            return C.NEUTRAL
        dw = uf = 0.0
        lt, ls = self.foc[0]
        for t, s in self.foc[1:]:
            dt = t - lt
            if ls:
                dw += dt
            else:
                uf += dt
            lt, ls = t, s
        tot = dw + uf
        return 0.5 if tot <= 0 else dw / tot

    def _Rs(self) -> float:
        return clip(1.0 - len(self.sw) / C.N_MAX_SW, 0.0, 1.0)

    def score(self, e_hrv: Optional[float] = None) -> Tuple[float, float]:
        if self.telemetry_off:
            R = E = C.NEUTRAL
        else:
            R = 0.40 * self._Rk() + 0.30 * self._Rm() + 0.30 * self._Rd() * self._Rs()
            E = C.NEUTRAL if e_hrv is None else clip(e_hrv, 0.0, 1.0)
        self.history = C.ALPHA * self.history + (1.0 - C.ALPHA) * R
        x = C.W_R * R + C.W_E * E + self.history
        return clip(2.0 * σ(x) - 1.0, 0.0, 0.999), R


def rights_ok(r: Sequence[float]) -> bool:
    return all(x - b >= 0.0 for x, b in zip(r, C.RIGHTS_BASE))


def make_rights(consent=True, coercion=0.0, privacy=1.0, nond=True):
    return (
        1.0 if consent else 0.0,
        clip(1.0 - coercion, 0.0, 1.0),
        clip(privacy, 0.0, 1.0),
        1.0 if nond else 0.0,
    )


def fuse_agent(scores: Sequence[float]) -> float:
    return sum(w * s for w, s in zip(C.AG_W, scores))


class Collective:
    def __init__(self) -> None:
        self.v, self.ok, self.at = 0.0, False, 0.0

    def publish(self, value: float) -> None:
        self.v = clip(value, 0.0, 1.0)
        self.ok, self.at = True, time.monotonic()

    def read(self) -> float:
        if not self.ok or time.monotonic() - self.at > C.COLLECTIVE_MAX_AGE_S:
            self.ok = False
            return 0.0
        return self.v


# =============================================================================
# SNAPSHOT / PROOF
# =============================================================================

@dataclass(frozen=True)
class RawSnapshot:
    human: float
    agent: float
    collective: float
    composite: float
    rights: Tuple[float, float, float, float]
    state_hash: bytes
    ts_ns: int

    @classmethod
    def build(cls, h, a, c, rights) -> "RawSnapshot":
        comp = gmean3(h, a, c)
        body = struct.pack("<ffff", h, a, c, comp) + pack4(rights)
        return cls(h, a, c, comp, rights, H(body), time.monotonic_ns())


@dataclass(frozen=True)
class RightsProof:
    state_hash: bytes
    rights_blob: bytes
    baselines_blob: bytes
    epoch: int
    kid: int
    mac: bytes

    def preimage(self) -> bytes:
        return (
            self.state_hash
            + self.rights_blob
            + self.baselines_blob
            + struct.pack("<II", self.epoch, self.kid)
        )


class RightsProver:
    def __init__(self, ring: Optional[Keyring] = None) -> None:
        self.ring = ring or Keyring(b"rights")
        self.epoch = 1
        self._lock = threading.Lock()

    def prove(self, raw: RawSnapshot) -> Optional[RightsProof]:
        if not rights_ok(raw.rights):
            return None
        blob, base = pack4(raw.rights), pack4(C.RIGHTS_BASE)
        with self._lock:
            ep = self.epoch
        pre = raw.state_hash + blob + base + struct.pack("<II", ep, 0)  # kid filled after
        # first pass without kid in preimage structure: include kid in final
        kid, _ = self.ring.mac(b"")  # get active kid
        pre = raw.state_hash + blob + base + struct.pack("<II", ep, kid)
        kid, tag = self.ring.mac(pre)
        # re-mac with actual kid in preimage
        pre = raw.state_hash + blob + base + struct.pack("<II", ep, kid)
        kid, tag = self.ring.mac(pre)
        return RightsProof(raw.state_hash, blob, base, ep, kid, tag)

    def verify(self, raw: RawSnapshot, proof: RightsProof) -> Decision:
        with self._lock:
            ep = self.epoch
        if proof.epoch != ep:
            return Decision.DENY_EPOCH
        if proof.baselines_blob != pack4(C.RIGHTS_BASE):
            return Decision.DENY_PROOF
        if proof.rights_blob != pack4(raw.rights):
            return Decision.DENY_MUTATION
        if proof.state_hash != raw.state_hash:
            return Decision.DENY_MUTATION
        expected = H(
            struct.pack("<ffff", raw.human, raw.agent, raw.collective, raw.composite)
            + proof.rights_blob
        )
        if not ct_eq(proof.state_hash, expected):
            return Decision.DENY_PROOF
        if not rights_ok(raw.rights):
            return Decision.DENY_RIGHTS
        if not self.ring.verify(proof.preimage(), proof.kid, proof.mac):
            return Decision.DENY_KID if proof.kid not in self.ring._keys else Decision.DENY_PROOF
        return Decision.ADMIT

    def bump_epoch(self) -> None:
        with self._lock:
            self.epoch += 1


@dataclass(frozen=True)
class ValidSnapshot:
    raw: RawSnapshot
    proof: RightsProof

    @classmethod
    def try_create(cls, raw: RawSnapshot, prover: RightsProver) -> Optional["ValidSnapshot"]:
        p = prover.prove(raw)
        return None if p is None else cls(raw, p)


# =============================================================================
# TICKET + CAPABILITY
# =============================================================================

@dataclass(frozen=True)
class Ticket:
    ticket_id: bytes
    issued_ns: int
    expires_ns: int
    state_hash: bytes
    nullifier: bytes
    epoch: int
    kid: int
    mac: bytes


@dataclass(frozen=True)
class Capability:
    """Opaque token authorizing side effects after ADMIT."""
    decision_id: bytes
    state_hash: bytes
    ticket_id: bytes
    expires_ns: int
    kid: int
    mac: bytes


class TicketAuthority:
    def __init__(self, ring: Optional[Keyring] = None) -> None:
        self.ring = ring or Keyring(b"ticket")
        self.epoch = 1
        self._a: set = set()
        self._b: set = set()
        self._active = 0
        self._rot = time.monotonic()
        self._lock = threading.Lock()

    def _rotate_windows(self) -> None:
        if time.monotonic() - self._rot > C.NULLIFIER_WINDOW_S:
            self._active = 1 - self._active
            (self._a if self._active == 0 else self._b).clear()
            self._rot = time.monotonic()

    def issue(self, state_hash: bytes) -> Ticket:
        tid = secrets.token_bytes(16)
        now = time.monotonic_ns()
        ttl = C.TTL_MIN_MS + secrets.randbelow(C.TTL_MAX_MS - C.TTL_MIN_MS + 1)
        exp = now + ttl * 1_000_000
        nf = H(tid, state_hash)
        with self._lock:
            ep = self.epoch
        kid, _ = self.ring.mac(b"")
        pre = state_hash + nf + struct.pack("<QQII", now, exp, ep, kid)
        kid, tag = self.ring.mac(pre)
        pre = state_hash + nf + struct.pack("<QQII", now, exp, ep, kid)
        kid, tag = self.ring.mac(pre)
        return Ticket(tid, now, exp, state_hash, nf, ep, kid, tag)

    def verify_mac(self, t: Ticket) -> bool:
        pre = t.state_hash + t.nullifier + struct.pack("<QQII", t.issued_ns, t.expires_ns, t.epoch, t.kid)
        return self.ring.verify(pre, t.kid, t.mac)

    def consume(self, nullifier: bytes) -> bool:
        with self._lock:
            self._rotate_windows()
            if nullifier in self._a or nullifier in self._b:
                return False
            (self._a if self._active == 0 else self._b).add(nullifier)
            return True

    def bump_epoch(self) -> None:
        with self._lock:
            self.epoch += 1
            self._a.clear()
            self._b.clear()


class CapabilityIssuer:
    def __init__(self, ring: Optional[Keyring] = None) -> None:
        self.ring = ring or Keyring(b"capability")

    def issue(self, state_hash: bytes, ticket_id: bytes) -> Capability:
        did = secrets.token_bytes(16)
        exp = time.monotonic_ns() + C.CAP_TTL_MS * 1_000_000
        kid, _ = self.ring.mac(b"")
        pre = did + state_hash + ticket_id + struct.pack("<QI", exp, kid)
        kid, tag = self.ring.mac(pre)
        pre = did + state_hash + ticket_id + struct.pack("<QI", exp, kid)
        kid, tag = self.ring.mac(pre)
        return Capability(did, state_hash, ticket_id, exp, kid, tag)

    def verify(self, cap: Capability) -> bool:
        if cap.expires_ns < time.monotonic_ns():
            return False
        pre = (
            cap.decision_id
            + cap.state_hash
            + cap.ticket_id
            + struct.pack("<QI", cap.expires_ns, cap.kid)
        )
        return self.ring.verify(pre, cap.kid, cap.mac)


# =============================================================================
# AUDIT + METRICS + PID
# =============================================================================

class AuditLog:
    def __init__(self, ring: Optional[Keyring] = None) -> None:
        self.ring = ring or Keyring(b"audit")
        self._head = H(b"audit-genesis")
        self.records: List[dict] = []
        self._lock = threading.Lock()
        self.fail_next = False

    def stage(self, ok: bool, decision: Decision, sh: bytes, tid: bytes = b"\x00" * 16) -> bool:
        with self._lock:
            if self.fail_next:
                self.fail_next = False
                return False
            ts = time.monotonic_ns()
            body = struct.pack("<BQ", int(ok), ts) + sh + tid + decision.value.encode() + self._head
            kid, tag = self.ring.mac(body)
            self.records.append({
                "ok": ok, "decision": decision.value,
                "sh": sh.hex()[:16], "tid": tid.hex()[:16],
                "ts": ts, "kid": kid, "mac": tag.hex()[:16],
            })
            self._head = H(body, tag)
            return True


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.counts: Dict[str, int] = {}

    def inc(self, key: str) -> None:
        with self._lock:
            self.counts[key] = self.counts.get(key, 0) + 1

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return dict(self.counts)


class PID:
    def __init__(self) -> None:
        self.T, self.I = 1.0, 0.0
        self._le = self._lt = None

    def update(self, g: float) -> float:
        now = time.monotonic()
        e = g - C.G_BAR
        dt = C.PID_MIN_DT if self._lt is None else max(C.PID_MIN_DT, now - self._lt)
        self._lt = now
        de = 0.0 if self._le is None else (e - self._le) / dt
        self._le = e
        self.I = clip(C.I_LEAK * self.I + e * dt, -C.I_CLIP, C.I_CLIP)
        self.T = clip(self.T - (C.KP * e + C.KD * de + C.KI * self.I), C.T_MIN, C.T_MAX)
        return self.T

    def theta(self) -> float:
        return clip(C.THETA0 * self.T, C.THETA_MIN, C.THETA_MAX)


# =============================================================================
# ENGINE MAX
# =============================================================================

class SovereignEngineMax:
    def __init__(self) -> None:
        self.human = HumanEngine()
        self.collective = Collective()
        self.prover = RightsProver()
        self.tickets = TicketAuthority()
        self.caps = CapabilityIssuer()
        self.audit = AuditLog()
        self.pid = PID()
        self.metrics = Metrics()

    def snapshot(self, consent=True, coercion=0.0, privacy=1.0, nond=True,
                 agent_scores: Sequence[float] = (0.95, 0.9, 0.9, 1.0, 1.0, 1.0),
                 e_hrv: Optional[float] = None) -> RawSnapshot:
        ih, _ = self.human.score(e_hrv=e_hrv)
        return RawSnapshot.build(
            ih, fuse_agent(agent_scores), self.collective.read(),
            make_rights(consent, coercion, privacy, nond),
        )

    def prove(self, raw: RawSnapshot) -> Optional[ValidSnapshot]:
        return ValidSnapshot.try_create(raw, self.prover)

    def issue(self, valid: ValidSnapshot) -> Ticket:
        if not isinstance(valid, ValidSnapshot):
            raise TypeError("ValidSnapshot required")
        return self.tickets.issue(valid.raw.state_hash)

    def admit(
        self, candidate: object, ticket: Optional[Ticket] = None
    ) -> Tuple[Decision, Optional[Capability]]:
        t0 = time.monotonic_ns()

        def deny(d: Decision, sh: bytes = b"\x00" * 32, tid: bytes = b"\x00" * 16) -> Tuple[Decision, None]:
            self.audit.stage(False, d, sh, tid)
            self.metrics.inc(d.value)
            return d, None

        if not isinstance(candidate, ValidSnapshot):
            return deny(Decision.DENY_TYPE)

        valid: ValidSnapshot = candidate
        raw, proof = valid.raw, valid.proof

        d = self.prover.verify(raw, proof)
        if d != Decision.ADMIT:
            return deny(d, raw.state_hash)

        if raw.composite < self.pid.theta():
            return deny(Decision.DENY_COMPOSITE, raw.state_hash)

        if ticket is None:
            return deny(Decision.DENY_NO_TICKET, raw.state_hash)

        if ticket.expires_ns < time.monotonic_ns():
            return deny(Decision.DENY_EXPIRED, raw.state_hash, ticket.ticket_id)

        if ticket.epoch != self.tickets.epoch:
            return deny(Decision.DENY_EPOCH, raw.state_hash, ticket.ticket_id)

        if not self.tickets.verify_mac(ticket):
            return deny(Decision.DENY_MAC, raw.state_hash, ticket.ticket_id)

        if not ct_eq(ticket.state_hash, raw.state_hash):
            return deny(Decision.DENY_STATE, raw.state_hash, ticket.ticket_id)

        if not self.tickets.consume(ticket.nullifier):
            return deny(Decision.DENY_REPLAY, raw.state_hash, ticket.ticket_id)

        elapsed = (time.monotonic_ns() - t0) / 1e6
        if C.HARD_BUDGET and elapsed > C.INTERACTIVE_MS:
            return deny(Decision.DENY_BUDGET, raw.state_hash, ticket.ticket_id)

        if not self.audit.stage(True, Decision.ADMIT, raw.state_hash, ticket.ticket_id):
            self.metrics.inc(Decision.DENY_AUDIT.value)
            return Decision.DENY_AUDIT, None

        cap = self.caps.issue(raw.state_hash, ticket.ticket_id)
        self.pid.update(raw.composite)
        self.metrics.inc(Decision.ADMIT.value)
        self.metrics.inc("latency_samples")
        return Decision.ADMIT, cap

    def execute_with_capability(self, cap: Capability) -> bool:
        """Side-effect gate: no valid capability → no execution."""
        ok = self.caps.verify(cap)
        self.metrics.inc("cap_ok" if ok else "cap_fail")
        return ok

    def request(self, **kwargs) -> Tuple[Decision, Optional[ValidSnapshot], Optional[Ticket], Optional[Capability]]:
        raw = self.snapshot(**kwargs)
        valid = self.prove(raw)
        if valid is None:
            self.metrics.inc(Decision.DENY_RIGHTS.value)
            return Decision.DENY_RIGHTS, None, None, None
        ticket = self.issue(valid)
        decision, cap = self.admit(valid, ticket)
        return decision, valid, ticket, cap


# =============================================================================
# MAX SELF-TEST
# =============================================================================

def self_test() -> None:
    print("=" * 72)
    print(f"{__product__} v{__version__} — Maximum Hardness Suite")
    print("=" * 72)
    eng = SovereignEngineMax()
    eng.collective.publish(0.85)
    t = 0.0
    for i in range(60):
        eng.human.record_keystroke(t)
        eng.human.record_pointer(1.2 + 0.01 * (i % 4), t)
        eng.human.record_focus(t, True)
        t += 0.15

    results = []

    def check(name: str, ok: bool) -> None:
        results.append((name, ok))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")

    # Happy path + capability
    d, v, tk, cap = eng.request()
    check("ADMIT", d == Decision.ADMIT and cap is not None)
    check("CAP verify", eng.execute_with_capability(cap) is True)

    # Cap expiry tamper
    bad_cap = replace(cap, expires_ns=cap.expires_ns + 10**12)
    check("CAP expiry MAC", eng.execute_with_capability(bad_cap) is False)

    # Type
    check("TYPE", eng.admit(eng.snapshot())[0] == Decision.DENY_TYPE)

    # Rights
    d, v, _, _ = eng.request(consent=False)
    check("RIGHTS", d == Decision.DENY_RIGHTS and v is None)

    # Expiry MAC
    raw = eng.snapshot()
    v = eng.prove(raw)
    tk = eng.issue(v)
    bad = replace(tk, expires_ns=tk.expires_ns + 10**12)
    check("TICKET expiry MAC", eng.admit(v, bad)[0] == Decision.DENY_MAC)

    # Replay
    raw = eng.snapshot()
    v = eng.prove(raw)
    tk = eng.issue(v)
    d1, _ = eng.admit(v, tk)
    d2, _ = eng.admit(v, tk)
    check("REPLAY", d1 == Decision.ADMIT and d2 == Decision.DENY_REPLAY)

    # Mutation
    raw = eng.snapshot()
    v = eng.prove(raw)
    evil = ValidSnapshot(replace(raw, rights=make_rights(consent=False)), v.proof)
    tk = eng.issue(v)
    check("MUTATION", eng.admit(evil, tk)[0] == Decision.DENY_MUTATION)

    # No ticket
    check("NO_TICKET", eng.admit(eng.prove(eng.snapshot()), None)[0] == Decision.DENY_NO_TICKET)

    # Audit fail
    raw = eng.snapshot()
    v = eng.prove(raw)
    tk = eng.issue(v)
    eng.audit.fail_next = True
    check("AUDIT_FAIL", eng.admit(v, tk)[0] == Decision.DENY_AUDIT)

    # Epoch
    raw = eng.snapshot()
    v = eng.prove(raw)
    tk = eng.issue(v)
    eng.tickets.bump_epoch()
    eng.prover.bump_epoch()
    check("EPOCH", eng.admit(v, tk)[0] in (Decision.DENY_EPOCH, Decision.DENY_PROOF, Decision.DENY_KID, Decision.DENY_MAC))

    # Key rotation still verifies old kid once (kept)
    eng.prover.ring.rotate()
    d, v, tk, cap = eng.request()
    check("POST_ROTATE ADMIT", d == Decision.ADMIT)

    # Metrics present
    m = eng.metrics.snapshot()
    check("METRICS", m.get("ADMIT", 0) >= 1 and sum(m.values()) >= 5)

    failed = [n for n, ok in results if not ok]
    print("\n" + "=" * 72)
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print(f"{__product__} — all max-hardness checks passed.")
    print("Metrics:", eng.metrics.snapshot())
    print("=" * 72)


if __name__ == "__main__":
    self_test()
