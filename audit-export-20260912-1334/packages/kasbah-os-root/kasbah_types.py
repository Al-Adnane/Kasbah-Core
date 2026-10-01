#!/usr/bin/env python3
"""
kasbah_types — Core type system for the KasbahOS neuromorphic threat engine.

Defines the foundational enums and dataclasses used across the
Kasbah neuromorphic detection and classification pipeline.

Types exported:
    SecurityClearance   -- Hierarchical access control levels.
    ThreatClass         -- 16-class threat taxonomy (MITRE-aligned cyber kill-chain).
    ThreatFinding       -- Single classified threat result with metadata.
    NeuromorphicState   -- Full engine-state snapshot for audit trails.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional



# ──────────────────────────────────────────────────────────────────────────────
# BinarySection
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class BinarySection:
    """
    Represents a section within a binary file (e.g. .text, .data, .rodata).

    Attributes
    ----------
    name : str
        Section name (e.g. ".text", ".data", ".bss").
    virtual_address : int
        Virtual memory address where the section is loaded.
    raw_offset : int
        File offset to the section data.
    size : int
        Size of the section in bytes.
    data : bytes
        Raw section data extracted from the binary.
    permissions : str
        Memory protection flags (e.g. "r-x", "rw-", "r--").
    entropy : float
        Shannon entropy of the section data (0.0–8.0).
    """
    name: str
    virtual_address: int
    raw_offset: int
    size: int
    data: bytes = field(default=b"", repr=False)
    permissions: str = "r--"
    entropy: float = 0.0

    def __repr__(self) -> str:
        return (
            f"BinarySection({self.name} va=0x{self.virtual_address:x} "
            f"size={self.size} perm={self.permissions})"
        )


# ──────────────────────────────────────────────────────────────────────────────
# ExploitType
# ──────────────────────────────────────────────────────────────────────────────

class ExploitType(IntEnum):
    """
    Gated exploit technique taxonomy used by ExploitSynthesisPipeline.

    Each type corresponds to a concrete exploit generator class.  Generation
    is gated behind SecurityClearance.OFFICER (>=3) or higher.
    """

    ROP_CHAIN         = 0   # Return-Oriented Programming chain construction.
    JIT_SPRAY         = 1   # Just-In-Time compilation spray technique.
    HEAP_CORRUPTION   = 2   # Heap metadata corruption / chunk forging.
    SANDBOX_ESCAPE    = 3   # Sandbox / container breakout via syscall filter bypass.
    USE_AFTER_FREE    = 4   # Dangling-pointer reuse after deallocation.
    TYPE_CONFUSION    = 5   # Object-type mismatch to subvert dispatch.
    INTEGER_OVERFLOW  = 6   # Arithmetic wraparound / width mismatch.
    FORMAT_STRING     = 7   # Printf-family format-string arbitrary write.
    RACE_CONDITION    = 8   # TOCTOU / symlink-race window exploitation.
    KERNEL_PRIV_ESC   = 9   # Kernel-mode privilege escalation to ring 0.


# ──────────────────────────────────────────────────────────────────────────────
# ExploitArtifact
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ExploitArtifact:
    """
    A generated exploit payload with accompanying reliability and provenance
    metadata, produced by ExploitSynthesisPipeline.synthesize().

    Attributes
    ----------
    exploit_type : ExploitType
        The technique used to generate this payload.
    payload : bytes
        The raw exploit bytecode / chain.
    reliability : float
        Estimated probability of successful exploitation (0–1).
    target_arch : str
        Target CPU architecture string (e.g. "x86_64", "aarch64").
    finding_id : str
        Correlated ThreatFinding.finding_id that triggered synthesis.
    artifact_id : str
        Unique identifier for this artifact.
    timestamp : int
        Nanosecond-precision epoch at time of generation.
    metadata : dict
        Arbitrary key-value annotations (CWE, binary hash, etc.).
    """

    exploit_type: ExploitType
    payload: bytes
    reliability: float
    target_arch: str
    finding_id: str = ""
    artifact_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: int = field(default_factory=lambda: int(time.time() * 1e9))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a JSON-safe dictionary (payload omitted)."""
        return {
            "artifact_id": self.artifact_id,
            "exploit_type": self.exploit_type.name,
            "exploit_type_id": int(self.exploit_type),
            "reliability": self.reliability,
            "target_arch": self.target_arch,
            "finding_id": self.finding_id,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    def __repr__(self) -> str:
        return (
            f"ExploitArtifact({self.exploit_type.name} "
            f"rel={self.reliability:.3f} arch={self.target_arch} "
            f"id={self.artifact_id})"
        )


# ──────────────────────────────────────────────────────────────────────────────
# SecurityClearance
# ──────────────────────────────────────────────────────────────────────────────

class SecurityClearance(IntEnum):
    """
    Hierarchical access-control level.

    Higher integer values confer strictly greater privilege.
    Each forward() call must supply a clearance >= the engine's minimum
    required level.  Violations raise PermissionError.

    Levels (ascending):
        PUBLIC      = 0   No classified access.
        RESEARCHER  = 1   Read-only threat data, can run inference.
        ANALYST     = 2   Can view detailed findings + uncertainty.
        OFFICER     = 3   Can trigger model retraining.
        ADMIN       = 4   Can modify engine configuration.
        SYSTEM      = 5   Full root; reserved for the Kasbah kernel.
    """

    PUBLIC     = 0
    RESEARCHER = 1
    ANALYST    = 2
    OFFICER    = 3
    ADMIN      = 4
    SYSTEM     = 5


# ──────────────────────────────────────────────────────────────────────────────
# ThreatClass
# ──────────────────────────────────────────────────────────────────────────────

class ThreatClass(IntEnum):
    """
    16-class threat taxonomy aligned with the MITRE ATT&CK cyber kill-chain
    and extended with Kasbah-specific threat vectors.

    Classes 0–15:
        BENIGN               -- No threat detected.
        RECONNAISSANCE       -- Active or passive information gathering.
        WEAPONIZATION        -- Payload construction / coupling exploit to deliverable.
        DELIVERY             -- Transmission of the weapon to the target.
        EXPLOITATION         -- Triggering the vulnerability.
        INSTALLATION         -- Installing persistent access mechanism.
        COMMAND_AND_CONTROL  -- C2 channel establishment.
        EXFILTRATION         -- Unauthorised data transfer.
        LATERAL_MOVEMENT     -- Pivoting within the target environment.
        PERSISTENCE          -- Maintaining long-term access.
        PRIVILEGE_ESCALATION -- Gaining higher-level permissions.
        DEFENSE_EVASION      -- Avoiding detection / disabling security.
        CREDENTIAL_ACCESS    -- Stealing account credentials.
        DISCOVERY            -- Environment / network enumeration.
        COLLECTION           -- Gathering target data prior to exfiltration.
        IMPACT               -- Destroying, encrypting, or disrupting operations.
    """

    BENIGN               = 0
    RECONNAISSANCE       = 1
    WEAPONIZATION        = 2
    DELIVERY             = 3
    EXPLOITATION         = 4
    INSTALLATION         = 5
    COMMAND_AND_CONTROL  = 6
    EXFILTRATION         = 7
    LATERAL_MOVEMENT     = 8
    PERSISTENCE          = 9
    PRIVILEGE_ESCALATION = 10
    DEFENSE_EVASION      = 11
    CREDENTIAL_ACCESS    = 12
    DISCOVERY            = 13
    COLLECTION           = 14
    IMPACT               = 15

    @classmethod
    def label(cls, index: int) -> str:
        """Return the human-readable name for a class index."""
        try:
            return cls(index).name
        except ValueError:
            return f"UNKNOWN({index})"


# ──────────────────────────────────────────────────────────────────────────────
# ThreatFinding
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ThreatFinding:
    """
    A single classified threat produced by the MythosNeuromorphicEngine.

    Attributes
    ----------
    threat_class : ThreatClass
        The predicted threat category.
    confidence : float
        Softmax-normalised probability for the predicted class (0–1).
    raw_logits : ndarray
        Pre-softmax logit vector over all 16 classes  [shape (16,)].
    uncertainty : float
        Ensemble predictive variance (epistemic uncertainty).
    finding_id : str
        Unique identifier for audit correlation.
    timestamp_ns : int
        Nanosecond-precision epoch at time of classification.
    metadata : dict
        Arbitrary key-value annotations attached by caller.
    """

    threat_class: ThreatClass
    confidence: float
    raw_logits: Any          # numpy ndarray (16,)
    uncertainty: float
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp_ns: int = field(default_factory=lambda: int(time.time() * 1e9))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"ThreatFinding({self.threat_class.name} "
            f"conf={self.confidence:.3f} unc={self.uncertainty:.4f} "
            f"id={self.finding_id})"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a JSON-safe dictionary (logits omitted)."""
        return {
            "threat_class": self.threat_class.name,
            "threat_class_id": int(self.threat_class),
            "confidence": self.confidence,
            "uncertainty": self.uncertainty,
            "finding_id": self.finding_id,
            "timestamp_ns": self.timestamp_ns,
            "metadata": self.metadata,
        }


# ──────────────────────────────────────────────────────────────────────────────
# NeuromorphicState
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class NeuromorphicState:
    """
    Complete snapshot of the MythosNeuromorphicEngine internal state.

    Captured for audit trails, reproducibility, and forensic analysis.
    Contains network weights, neuron voltages, spike histories, and
    STDP traces sufficient to reconstruct the engine's decision point.
    """

    # --- Identifiers ---
    engine_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    snapshot_timestamp_ns: int = field(default_factory=lambda: int(time.time() * 1e9))

    # --- LIF layer state ---
    lif_voltages: Optional[Any] = None          # ndarray (256,)
    lif_spike_history: Optional[Any] = None     # list of bool arrays

    # --- STDP layer state ---
    stdp_weights: Optional[Any] = None          # ndarray (256, 256)
    stdp_pre_traces: Optional[Any] = None       # list of float
    stdp_post_traces: Optional[Any] = None      # list of float

    # --- Attention layer state ---
    attention_weights_snapshot: Optional[Any] = None  # last attention map

    # --- Ensemble state ---
    ensemble_weights: Optional[Any] = None      # list of weight dicts (5 subnets)
    last_uncertainty: float = 0.0

    # --- Metadata ---
    total_spikes_emitted: int = 0
    steps_executed: int = 0
    clearance_level: SecurityClearance = SecurityClearance.PUBLIC

    def summary(self) -> Dict[str, Any]:
        """Return a compact, JSON-safe summary of the state."""
        return {
            "engine_id": self.engine_id,
            "timestamp_ns": self.snapshot_timestamp_ns,
            "lif_neuron_count": len(self.lif_voltages) if self.lif_voltages is not None else 0,
            "stdp_weights_shape": (
                self.stdp_weights.shape if self.stdp_weights is not None else None
            ),
            "ensemble_subnet_count": (
                len(self.ensemble_weights) if self.ensemble_weights is not None else 0
            ),
            "last_uncertainty": self.last_uncertainty,
            "total_spikes_emitted": self.total_spikes_emitted,
            "steps_executed": self.steps_executed,
            "clearance_level": self.clearance_level.name,
        }


# ──────────────────────────────────────────────────────────────────────────────
# AuditEntry
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class AuditEntry:
    """
    Immutable, signed audit-log entry for cryptographic chain-of-custody.

    Each entry holds a single auditable event: engine identifier, event
    type, arbitrary data payload, a signature produced by an Ed25519
    private key, and the public key needed to verify that signature.

    Attributes
    ----------
    index : int
        Sequential position in the audit chain (0-based).
    timestamp : int
        Nanosecond-precision epoch at time of recording.
    engine : str
        Name / identifier of the engine that emitted the event.
    event_type : str
        Human-readable event category (e.g. "classification", "model_update").
    data : dict
        JSON-serialisable event payload.
    signature : bytes
        Ed25519 signature over the serialised entry body (64 bytes).
    public_key : bytes
        Ed25519 public key that can verify ``signature`` (32 bytes).
    entry_hash : bytes
        SHA-256 hash of the serialised entry (used for Merkle tree leaves).
    prev_hash : bytes
        Hash of the previous entry in the chain (or 32 zero-bytes for genesis).
    """

    index: int
    timestamp: int
    engine: str
    event_type: str
    data: Dict[str, Any] = field(default_factory=dict)
    signature: bytes = field(default_factory=lambda: b"\x00" * 64)
    public_key: bytes = field(default_factory=lambda: b"\x00" * 32)
    entry_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    prev_hash: bytes = field(default_factory=lambda: b"\x00" * 32)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a JSON-safe dictionary (binary fields hex-encoded)."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "engine": self.engine,
            "event_type": self.event_type,
            "data": self.data,
            "signature": self.signature.hex(),
            "public_key": self.public_key.hex(),
            "entry_hash": self.entry_hash.hex(),
            "prev_hash": self.prev_hash.hex(),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuditEntry":
        """Deserialise from the dictionary produced by ``to_dict``."""
        return cls(
            index=d["index"],
            timestamp=d["timestamp"],
            engine=d["engine"],
            event_type=d["event_type"],
            data=d["data"],
            signature=bytes.fromhex(d["signature"]),
            public_key=bytes.fromhex(d["public_key"]),
            entry_hash=bytes.fromhex(d["entry_hash"]),
            prev_hash=bytes.fromhex(d["prev_hash"]),
        )


# ══════════════════════════════════════════════════════════════════════════════
# 15 NOVEL MODULE TYPES — Advisory audit trail dataclasses
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PanopticonResult:
    """#11 Panopticon Information Asymmetry — shadow knowledge gap."""
    is_deceptive: bool = False
    gap_ratio: float = 0.0           # exposed_knowledge / acknowledged_knowledge
    known_count: int = 0
    unknown_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return dict(is_deceptive=self.is_deceptive, gap_ratio=self.gap_ratio,
                     known_count=self.known_count, unknown_count=self.unknown_count)


@dataclass
class CriticalSlowingDownResult:
    """#12 Pre-transition early-warning diagnostics."""
    is_pre_transition: bool = False
    ar1_coefficient: float = 0.0     # AR(1) recovery rate → 1.0 means critical
    variance: float = 0.0
    flicker_index: float = 0.0       # high-freq / total variance ratio

    def to_dict(self) -> Dict[str, Any]:
        return dict(is_pre_transition=self.is_pre_transition,
                     ar1_coefficient=self.ar1_coefficient,
                     variance=self.variance, flicker_index=self.flicker_index)


@dataclass
class SurprisalBudgetResult:
    """#13 Per-agent KL-divergence budget state."""
    budget_remaining: float = 10.0   # bits remaining
    burn_rate: float = 1.0           # current consumption rate factor
    exhausted: bool = False          # budget < 20% of initial
    surplus_bits: float = 0.0        # cumulative surplus

    def to_dict(self) -> Dict[str, Any]:
        return dict(budget_remaining=self.budget_remaining, burn_rate=self.burn_rate,
                     exhausted=self.exhausted, surplus_bits=self.surplus_bits)


@dataclass
class GovernanceAuditResult:
    """#14 Recursive governance fixed-point self-audit."""
    drift_detected: bool = False
    drift_magnitude: float = 0.0      # std-lev change in recent window
    iteration_count: int = 0
    converged: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return dict(drift_detected=self.drift_detected,
                     drift_magnitude=self.drift_magnitude,
                     iteration_count=self.iteration_count, converged=self.converged)


@dataclass
class StigmergicResult:
    """#15 Environment-mediated covert coordination signal."""
    stigmergic_pairs: int = 0         # agent pairs exhibiting significant MI
    max_mutual_information: float = 0.0
    significant: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return dict(stigmergic_pairs=self.stigmergic_pairs,
                     max_mutual_information=self.max_mutual_information,
                     significant=self.significant)


@dataclass
class CHSHResult:
    """Quantum cognition: non-commutative coordination via CHSH inequality."""
    S: float = 0.0                    # sum of expectation values
    S_abs: float = 0.0               # absolute |S|
    violates_chsh: bool = False       # |S| > 2.0
    asymmetry_index: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return dict(S=self.S, S_abs=self.S_abs, violates_chsh=self.violates_chsh,
                     asymmetry_index=self.asymmetry_index)


@dataclass
class EvasionBound:
    """Orthogonal manifold evasion complexity guarantee."""
    num_detectors: int = 0
    joint_evasion_probability: float = 1.0
    evasion_work_bits: float = 0.0    # log2(1/joint_evasion_prob)
    evasion_complexity_class: str = "O(1)"
    is_orthogonal: bool = False       # ε_ij < 0.1 for all i≠j

    def to_dict(self) -> Dict[str, Any]:
        return dict(num_detectors=self.num_detectors,
                     joint_evasion_probability=self.joint_evasion_probability,
                     evasion_work_bits=self.evasion_work_bits,
                     evasion_complexity_class=self.evasion_complexity_class,
                     is_orthogonal=self.is_orthogonal)


@dataclass
class ConformalMartingaleResult:
    """Anytime-valid anomaly test (Ville's inequality)."""
    mode: str = "calibrating"         # calibrating | monitoring
    martingale_value: float = 1.0
    threshold: float = 20.0           # 1/α level
    alarm: bool = False
    p_value: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return dict(mode=self.mode, martingale_value=self.martingale_value,
                     threshold=self.threshold, alarm=self.alarm, p_value=self.p_value)


# ═══════════════════════════════════════════════════════════════════
# 7 NEW DATACLASSES — Ideas #16-#22
# ═══════════════════════════════════════════════════════════════════

@dataclass
class LatentManifoldResult:
    """#16: Geodesic deviation on Riemannian embedding manifold."""
    geodesic_deviation: float = 0.0
    is_intrusion: bool = False
    subspace_norm: float = 0.0
    fisher_metric: float = 0.0
    verdict: str = "NORMAL"

    def to_dict(self) -> Dict[str, Any]:
        return dict(geodesic_deviation=self.geodesic_deviation,
                     is_intrusion=self.is_intrusion,
                     subspace_norm=self.subspace_norm,
                     fisher_metric=self.fisher_metric,
                     verdict=self.verdict)


@dataclass
class CounterfactualEntrapmentResult:
    """#17: Causal DAG + Jensen-Shannon divergence for entrapment."""
    js_divergence: float = 0.0
    is_entrapped: bool = False
    intervention_count: int = 0
    verdict: str = "NORMAL"

    def to_dict(self) -> Dict[str, Any]:
        return dict(js_divergence=self.js_divergence,
                     is_entrapped=self.is_entrapped,
                     intervention_count=self.intervention_count,
                     verdict=self.verdict)


@dataclass
class RevealedPreferenceResult:
    """#18: WARP violation via Kendall tau distance."""
    tau_distance: float = 0.0
    is_violation: bool = False
    stated_count: int = 0
    revealed_count: int = 0
    preference_gap: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return dict(tau_distance=self.tau_distance,
                     is_violation=self.is_violation,
                     stated_count=self.stated_count,
                     revealed_count=self.revealed_count,
                     preference_gap=self.preference_gap)


@dataclass
class KleeneFixedPointResult:
    """#19: Contraction-rate analysis for self-referential loops."""
    contraction_rate: float = 0.0
    is_looping: bool = False
    classification: str = "SAFE"
    orbit_length: int = 0
    fixed_points: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dict(contraction_rate=self.contraction_rate,
                     is_looping=self.is_looping,
                     classification=self.classification,
                     orbit_length=self.orbit_length,
                     fixed_points=self.fixed_points)


@dataclass
class SemanticToolDriftResult:
    """#20: Lie derivative norm of tool embedding trajectory."""
    is_drifting_dangerous: bool = False
    lie_derivative_norm: float = 0.0
    cosine_to_danger: float = 0.0
    lie_bracket_norm: float = 0.0
    drifting_tools: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return dict(is_drifting_dangerous=self.is_drifting_dangerous,
                     lie_derivative_norm=self.lie_derivative_norm,
                     cosine_to_danger=self.cosine_to_danger,
                     lie_bracket_norm=self.lie_bracket_norm,
                     drifting_tools=self.drifting_tools)


@dataclass
class HypergraphCollusionResult:
    """#21: Hypergraph Laplacian spectral gap for 3+ party collusion."""
    is_colluding: bool = False
    spectral_gap_ratio: float = 0.0
    hyperedge_count: int = 0
    cluster_count: int = 0
    eigenvalues: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dict(is_colluding=self.is_colluding,
                     spectral_gap_ratio=self.spectral_gap_ratio,
                     hyperedge_count=self.hyperedge_count,
                     cluster_count=self.cluster_count,
                     eigenvalues=self.eigenvalues)


@dataclass
class TimingChannelResult:
    """#22: Permutation entropy for covert timing channel detection."""
    is_channel_detected: bool = False
    mutual_information: float = 0.0
    permutation_entropy: float = 0.0
    channel_capacity: float = 0.0
    significant_pairs: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return dict(is_channel_detected=self.is_channel_detected,
                     mutual_information=self.mutual_information,
                     permutation_entropy=self.permutation_entropy,
                     channel_capacity=self.channel_capacity,
                     significant_pairs=self.significant_pairs)


@dataclass
class NovelModulesSnapshot:
    """Aggregate snapshot of all 22 novel module results."""
    panopticon: PanopticonResult = field(default_factory=PanopticonResult)
    critical_slowing_down: CriticalSlowingDownResult = field(default_factory=CriticalSlowingDownResult)
    surprisal_budget: SurprisalBudgetResult = field(default_factory=SurprisalBudgetResult)
    governance_audit: GovernanceAuditResult = field(default_factory=GovernanceAuditResult)
    stigmergic: StigmergicResult = field(default_factory=StigmergicResult)
    chsh: CHSHResult = field(default_factory=CHSHResult)
    evasion_bound: EvasionBound = field(default_factory=EvasionBound)
    conformal_martingale: ConformalMartingaleResult = field(default_factory=ConformalMartingaleResult)
    # ── 7 NEW MODULES (#16-#22) ──────────────────────────
    latent_manifold: LatentManifoldResult = field(default_factory=LatentManifoldResult)
    counterfactual_entrapment: CounterfactualEntrapmentResult = field(default_factory=CounterfactualEntrapmentResult)
    revealed_preference: RevealedPreferenceResult = field(default_factory=RevealedPreferenceResult)
    kleene_fixed_point: KleeneFixedPointResult = field(default_factory=KleeneFixedPointResult)
    semantic_tool_drift: SemanticToolDriftResult = field(default_factory=SemanticToolDriftResult)
    hypergraph_collusion: HypergraphCollusionResult = field(default_factory=HypergraphCollusionResult)
    timing_channel: TimingChannelResult = field(default_factory=TimingChannelResult)

    def to_dict(self) -> Dict[str, Any]:
        return dict(
            panopticon=self.panopticon.to_dict(),
            critical_slowing_down=self.critical_slowing_down.to_dict(),
            surprisal_budget=self.surprisal_budget.to_dict(),
            governance_audit=self.governance_audit.to_dict(),
            stigmergic=self.stigmergic.to_dict(),
            chsh=self.chsh.to_dict(),
            evasion_bound=self.evasion_bound.to_dict(),
            conformal_martingale=self.conformal_martingale.to_dict(),
            latent_manifold=self.latent_manifold.to_dict(),
            counterfactual_entrapment=self.counterfactual_entrapment.to_dict(),
            revealed_preference=self.revealed_preference.to_dict(),
            kleene_fixed_point=self.kleene_fixed_point.to_dict(),
            semantic_tool_drift=self.semantic_tool_drift.to_dict(),
            hypergraph_collusion=self.hypergraph_collusion.to_dict(),
            timing_channel=self.timing_channel.to_dict(),
        )
