"""
KasbahOS v2.0 — Python Core
============================

Production-grade agentic control system with:

- Vectorized neuromorphic detection (NumPy LIF + STDP)
- Shamir's Secret Sharing over GF(2^127-1)
- Merkle-tree + Ed25519 audit receipts
- GC-balanced DNA encoding with parity
- BB84 QKD simulation
- Silent speech detection via optical flow
- Acoustic side-channel defense
- Async orchestrator

Usage:
    from kasbah_os import KasbahOS, KasbahConfig

    kos = KasbahOS()
    result = await kos.ingest_secret("AKIAIOSFODNN7EXAMPLE", source="app")
    print(result["decision"])  # → "block"
"""

from .kasbah_os import (
    KasbahOS,
    KasbahConfig,
    KasbahError,
    SecurityError,
    ReconstructionError,
    DetectionError,
    SecretCategory,
    Decision,
    AuditReceipt,
    VectorizedNeuromorphicDetector,
    DNAStorage,
    QuantumKeyDistribution,
    SwarmSecurity,
    BioSyntheticLayer,
    HolographicStorage,
    AcousticDefense,
    OrbitalSecurity,
    SilentSpeechDetector,
    ZeroTrustAudit,
    MerkleTree,
)

__version__ = "2.0.0"
__all__ = [
    "KasbahOS",
    "KasbahConfig",
    "KasbahError",
    "SecurityError",
    "ReconstructionError",
    "DetectionError",
    "SecretCategory",
    "Decision",
    "AuditReceipt",
    "VectorizedNeuromorphicDetector",
    "DNAStorage",
    "QuantumKeyDistribution",
    "SwarmSecurity",
    "BioSyntheticLayer",
    "HolographicStorage",
    "AcousticDefense",
    "OrbitalSecurity",
    "SilentSpeechDetector",
    "ZeroTrustAudit",
    "MerkleTree",
]
