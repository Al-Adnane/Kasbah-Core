"""
kasbah-core Python Package v3.0.0

Complete Kasbah detection engine with ALL novel features:
- 13 Security Moats (CAIL, Dynamic Thresholds, Brittleness, TOCTOU, etc.)
- Spatial Intelligence (Fei-Fei Li inspired)
- Authority Protocol (identity + attestation)
- Core Detection (secrets, obfuscation, AI text)
- E3 Telemetry (P50/P95/P99)
- Quantum-Safe Cryptography (Dilithium/SPHINCS+)
- Content Passport (C2PA-compatible)
- AI Fingerprint Database (17 generators)

Usage:
    from kasbah_core import KasbahPipeline, CAILLedger, QuantumSafeLedger
    pipeline = KasbahPipeline()
    result = pipeline.detect({'text': 'Your text here'})
"""

from .pipeline import KasbahPipeline
from .moats import (
    CAILLedger,
    DynamicThresholds,
    BrittlenessMonitor,
    PredictiveForecaster,
    TOCTOUPrevention,
    ResourceMonitor,
    AdversarialDetector,
    QIFTDecoder
)
from .spatial import SpatialIntelligence
from .authority import AuthorityProtocol
from .telemetry import get_telemetry, reset_telemetry, record_telemetry
from .quantum_crypto import (
    MerkleTree,
    DilithiumSigner,
    SPHINCSSigner,
    QuantumSafeLedger
)
from .content_passport import ContentPassport, AIFingerprintDatabase

# Research Modules - ALL WILD IDEAS
from .research_modules import (
    ConsciousnessProvenanceEngine,
    NeuralImmuneSystem,
    QuantumEntanglementDetector,
    TemporalParadoxDetector,
    ConfidenceCalibrator,
    CrossModalConsistencyChecker,
    ConsciousnessLevel
)

__version__ = '3.0.0'
__all__ = [
    'KasbahPipeline',
    'CAILLedger',
    'DynamicThresholds',
    'BrittlenessMonitor',
    'PredictiveForecaster',
    'TOCTOUPrevention',
    'ResourceMonitor',
    'AdversarialDetector',
    'QIFTDecoder',
    'SpatialIntelligence',
    'AuthorityProtocol',
    'get_telemetry',
    'reset_telemetry',
    'record_telemetry',
    'MerkleTree',
    'DilithiumSigner',
    'SPHINCSSigner',
    'QuantumSafeLedger',
    'ContentPassport',
    'AIFingerprintDatabase',
    # Research Modules
    'ConsciousnessProvenanceEngine',
    'NeuralImmuneSystem',
    'QuantumEntanglementDetector',
    'TemporalParadoxDetector',
    'ConfidenceCalibrator',
    'CrossModalConsistencyChecker',
    'ConsciousnessLevel'
]
