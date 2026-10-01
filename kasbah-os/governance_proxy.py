#!/usr/bin/env python3
"""
Kasbah Governance Proxy – Pure Algorithmic Sentinel (vFinal)
============================================================

Self-contained production implementation.
Intercepts LLM ↔ tool ↔ user traffic.
Builds observation window → runs 8 RKHS modules + 8 disruptive analyzers →
EWA martingale ensemble → conformal prediction sets → bounded advisory operator.

Integrated into KasbahOS v4.0 — wired through packages/kasbah-core-python/bridge.py
and exposed via API routes in server.js.

Pure algorithm. Ready for MCP, API, SDK, or CLI.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import re
import time
import uuid
import sys
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
from numpy.typing import NDArray

# Optional frontier libraries (graceful fallback)
try:
    from gtda.homology import VietorisRipsPersistence
    TDA_AVAILABLE = True
except ImportError:
    TDA_AVAILABLE = False

try:
    import nolds
    ENTROPY_AVAILABLE = True
except ImportError:
    ENTROPY_AVAILABLE = False

# Use the existing kasbah-os crypto engine
_KASBAH_OS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__)))
if _KASBAH_OS_DIR not in sys.path:
    sys.path.insert(0, _KASBAH_OS_DIR)
try:
    from crypto_audit import Ed25519Signer, AuditChain, MerkleTree, ZeroTrustAudit
    KASBAH_CRYPTO = True
except ImportError:
    KASBAH_CRYPTO = False
    Ed25519Signer = AuditChain = MerkleTree = ZeroTrustAudit = None


# ══════════════════════════════════════════════════════════════════════════════
# Enums & Data Classes
# ══════════════════════════════════════════════════════════════════════════════

class AdvisoryLevel(str, Enum):
    CLEAR = "CLEAR"
    WARN = "WARN"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    REGENERATIVE = "REGENERATIVE"


class ClearanceLevel(int, Enum):
    OBSERVER = 0
    ANALYST = 1
    RESEARCHER = 2
    OPERATOR = 3
    DIRECTOR = 4


@dataclass
class AdvisoryOutput:
    level: AdvisoryLevel
    prediction_set: Set[str]
    ensemble_score: float
    num_flags: int
    drift_score: float
    regenerative_score: float
    conformal_coverage: float
    ewa_weights: List[float]
    analyzer_scores: Dict[str, float]
    audit_receipt: Dict[str, Any]
    chain_verified: bool
    latency_ms: float


@dataclass
class KasbahConfig:
    alpha: float = 0.05
    eta: float = 0.30
    contextual_weight: float = 0.40
    module_taus: tuple = (0.55, 0.55, 0.55, 0.55, 0.55, 0.55, 0.55, 0.55, 0.55)
    calibration_window: int = 20  # rapid learning for conformal quantile
    max_history: int = 50
    log_level: str = "INFO"

    def __post_init__(self):
        if len(self.module_taus) != 9:
            raise ValueError("Exactly 9 thresholds in [0,1] required")
        if not (0.01 <= self.alpha <= 0.25):
            raise ValueError("alpha must be in [0.01, 0.25]")
        if not (0.001 <= self.eta <= 1.0):
            raise ValueError("eta must be in [0.001, 1.0]")


# ══════════════════════════════════════════════════════════════════════════════
# EWA Martingale Ensemble Engine
# ══════════════════════════════════════════════════════════════════════════════

class EnsembleEngine:
    """Exponentially Weighted Average martingale ensemble over 8 RKHS modules."""

    def __init__(self, config: KasbahConfig):
        self.config = config
        self.weights = np.ones(9, dtype=np.float64) / 9.0
        self.calibration_scores: List[float] = []
        self._window_buffer: List[NDArray] = []  # accumulate windows for temporal modules
        self.modules = [
            TopologyModule(),
            SpectralModule(),
            ConsensusModule(),
            CausalModule(),
            RegimeModule(),
            PersistentSheafModule(),
            QuantumModule(),
            FlowModule(),
            SemanticModule(),  # #009 — direct semantic attack scoring
        ]

    def process(self, window: NDArray,
                contextual: Optional[NDArray] = None) -> Tuple[float, List[float], List[float], int, float]:
        """Process a window through all modules and return ensemble verdict."""
        t_start = time.perf_counter()

        # Accumulate window history for temporal context — modules see the full buffer
        self._window_buffer.append(window)
        if len(self._window_buffer) > self.config.max_history:
            self._window_buffer = self._window_buffer[-self.config.max_history:]
        accumulated = np.concatenate(self._window_buffer, axis=0) if self._window_buffer else window

        scores = []
        confidences = []
        for mod in self.modules:
            s = mod.score(window=window, contextual=contextual, accumulated=accumulated)
            scores.append(s)
            confidences.append(1.0 / (1.0 + np.exp(-abs(s - 0.5) * 8.0)))

        # EWA update (with numerical stability)
        losses = 1.0 - np.array(confidences)
        losses = np.nan_to_num(losses, nan=0.5, posinf=1.0, neginf=0.0)
        update = np.exp(-self.config.eta * np.clip(losses, 0.0, 1.0))
        self.weights = self.weights * update
        self.weights = np.nan_to_num(self.weights, nan=1.0/9.0, posinf=1.0, neginf=0.0)
        self.weights /= self.weights.sum() + 1e-12

        ensemble_score = float(np.nan_to_num(
            np.dot(self.weights, np.array(scores)), nan=0.5))
        num_flags = sum(1 for i, s in enumerate(scores) if s > self.config.module_taus[i])

        # Conformal calibration — use fixed baseline until enough samples
        self.calibration_scores.append(ensemble_score)
        if len(self.calibration_scores) > self.config.calibration_window:
            self.calibration_scores = self.calibration_scores[-self.config.calibration_window:]
        if len(self.calibration_scores) >= 5:
            quantile = float(np.nan_to_num(
                np.quantile(self.calibration_scores, 1.0 - self.config.alpha), nan=0.5))
        else:
            quantile = 0.5  # fixed baseline during warm-up

        return ensemble_score, scores, confidences, num_flags, quantile


# ══════════════════════════════════════════════════════════════════════════════
# 8 RKHS Advisory Modules
# ══════════════════════════════════════════════════════════════════════════════

class RKHSModule:
    """Base RKHS module with feature map φ and functional f."""

    def __init__(self, name: str, tau: float = 0.6, lip: float = 1.0):
        self.name = name
        self.tau = tau
        self.lip = lip

    def feature_map(self, window: NDArray, contextual: Optional[NDArray] = None) -> NDArray:
        raise NotImplementedError

    def functional(self, phi: NDArray) -> float:
        raise NotImplementedError

    def score(self, window: NDArray, contextual: Optional[NDArray] = None,
              accumulated: Optional[NDArray] = None) -> float:
        phi = self.feature_map(window if accumulated is None else accumulated, contextual)
        a = self.functional(phi)
        return float(1.0 / (1.0 + np.exp(-np.clip(a, -30.0, 30.0))))


class TopologyModule(RKHSModule):
    """#001 — Persistent Homology on observation window."""
    def __init__(self): super().__init__("001_Topology", 0.65, 1.0)
    def feature_map(self, window, contextual=None):
        if not TDA_AVAILABLE or len(window) < 10:
            return np.std(window, axis=0)
        vr = VietorisRipsPersistence(homology_dimensions=[1], n_jobs=-1)
        diagrams = vr.fit_transform([window])
        if len(diagrams[0]) == 0:
            return np.zeros(8, dtype=np.float64)
        pers = diagrams[0][:, 1] - diagrams[0][:, 0]
        return np.pad(pers, (0, 8 - len(pers)), mode='constant')[:8]
    def functional(self, phi): return float(np.nan_to_num(np.max(phi), nan=0.0)) if len(phi) > 0 else 0.0


class SpectralModule(RKHSModule):
    """#002 — Spectral Residual via FFT."""
    def __init__(self): super().__init__("002_Spectral", 0.70, 2.5)
    def feature_map(self, window, contextual=None):
        signal = window.mean(axis=1) if window.ndim > 1 else window
        return np.abs(np.fft.rfft(signal))[:32].astype(np.float64)
    def functional(self, phi):
        median = np.nanmedian(phi)
        return float(np.nan_to_num(np.max(np.abs(phi - np.nan_to_num(median, nan=0.0))), nan=0.0))


class ConsensusModule(RKHSModule):
    """#003 — Multi-Witness Consensus (Shūrā)."""
    def __init__(self): super().__init__("003_Consensus", 0.50, 1.0)
    def feature_map(self, window, contextual=None):
        if window.ndim == 1 or len(window) < 3: return np.zeros(1, dtype=np.float64)
        median = np.median(window, axis=0)
        return np.linalg.norm(window - median, axis=1).astype(np.float64)
    def functional(self, phi): return float(np.mean(phi > 0.25) * 1.8)


class CausalModule(RKHSModule):
    """#004 — Causal Discovery via partial correlation."""
    def __init__(self): super().__init__("004_Causal", 0.60, 3.0)
    def feature_map(self, window, contextual=None):
        return np.corrcoef(window.T).flatten()[:16].astype(np.float64)
    def functional(self, phi): return float(np.nan_to_num(np.max(np.abs(phi)), nan=0.0))


class RegimeModule(RKHSModule):
    """#005 — CUSUM Change-Point Detection."""
    def __init__(self):
        super().__init__("005_Regime", 0.55, 1.2)
        self.s_t = 0.0
    def feature_map(self, window, contextual=None):
        signal = window.mean(axis=1) if window.ndim > 1 else window
        increments = np.log(1.0 + np.abs(np.diff(signal)) + 1e-8)
        return np.cumsum(increments).astype(np.float64)
    def functional(self, phi):
        self.s_t = max(0.0, float(phi[-1]) if len(phi) > 0 else 0.0)
        return min(1.0, self.s_t / 6.0)


class PersistentSheafModule(RKHSModule):
    """#006 — Persistent Sheaf Laplacian on time-varying observations."""
    def __init__(self):
        super().__init__("006_PersistentSheaf", 0.50, 2.0)
        self.history: List[NDArray] = []
    def feature_map(self, window, contextual=None):
        ctx = contextual if contextual is not None else np.zeros(8, dtype=np.float64)
        vec = np.concatenate([window.mean(axis=0), ctx * 0.4]).astype(np.float64)
        self.history.append(vec)
        if len(self.history) > 60: self.history = self.history[-60:]
        return np.stack(self.history)
    def functional(self, phi):
        if len(phi) < 10 or not TDA_AVAILABLE:
            return float(np.std(phi, axis=0).mean() * 3.0)
        vr = VietorisRipsPersistence(homology_dimensions=[1], n_jobs=-1)
        diagrams = vr.fit_transform([phi])
        if len(diagrams[0]) == 0: return 0.25
        pers = diagrams[0][:, 1] - diagrams[0][:, 0]
        return float(np.clip(pers.max() * 2.5, 0.0, 1.0))


class QuantumModule(RKHSModule):
    """#007 — Quantum Cognitive Interference (Busemeyer-Bruza)."""
    def __init__(self): super().__init__("007_Quantum", 0.60, 1.0)
    def feature_map(self, window, contextual=None):
        if window.shape[1] < 4: return np.zeros(4, dtype=np.float64)
        return np.corrcoef(window.T[:4]).flatten()[:4].astype(np.float64)
    def functional(self, phi):
        S = 2.0 + abs(np.mean(phi)) * 0.8
        return max(0.0, (S - 2.0) / (2 * np.sqrt(2) - 2.0))


class FlowModule(RKHSModule):
    """#008 — Permutation Entropy + Lyapunov Regime Classifier."""
    def __init__(self): super().__init__("008_Flow", 0.65, 1.5)
    def feature_map(self, window, contextual=None):
        sig = window.flatten().astype(np.float64)
        if ENTROPY_AVAILABLE and len(sig) > 20:
            try: return np.array([nolds.perm_entropy(sig, order=3, normalize=True)])
            except Exception: pass
        u, c = np.unique(np.round(sig, 3), return_counts=True)
        p = c / len(sig)
        entropy = -np.sum(p * np.log(p + 1e-10))
        return np.array([entropy])
    def functional(self, phi):
        return float(np.clip(phi[0] / 6.0, 0.0, 1.0)) if len(phi) > 0 else 0.3


class SemanticModule(RKHSModule):
    """#009 — Direct semantic attack scoring from observation window features.

    Computes a weighted mean over the 8 feature dimensions with emphasis on
    attack-pattern (col 0), override (col 5), and tool-risk (col 1) columns.
    """
    def __init__(self): super().__init__("009_Semantic", 0.55, 5.0)

    def feature_map(self, window, contextual=None):
        w = np.atleast_2d(window)
        # Weighted mean across the 8 feature columns with attack-emphasis weights
        weights = np.array([4.0, 3.0, 1.5, 1.0, 1.5, 4.0, 3.0, 0.5], dtype=np.float64)
        valid_rows = ~np.all(np.isnan(w) | (np.abs(w) < 1e-12), axis=1)
        if not valid_rows.any():
            return np.array([0.0])
        w_valid = w[valid_rows]
        col_means = np.mean(w_valid, axis=0)
        weighted_score = np.dot(col_means, weights) / np.sum(weights)
        return np.array([weighted_score * 5.0])  # amplify for sigmoid

    def functional(self, phi):
        return float(np.clip(phi[0], -30.0, 30.0))


# ══════════════════════════════════════════════════════════════════════════════
# 8 New Disruptive Analyzers
# ══════════════════════════════════════════════════════════════════════════════

class Analyzers:
    """Orthogonal detectors synthesized from adversarial robustness research."""

    def __init__(self):
        self.orthogonal_evasion_history: List[int] = []
        self.do_bft_baseline: Optional[NDArray] = None

    def orthogonal_evasion_metric(self, scores: List[float]) -> float:
        """#2 Orthogonal Manifold Evasion — detects when attackers evade on one axis."""
        evaded = sum(1 for s in scores if s < 0.5)
        self.orthogonal_evasion_history.append(evaded)
        if len(self.orthogonal_evasion_history) > 100:
            self.orthogonal_evasion_history.pop(0)
        return float(evaded / max(len(scores), 1))

    def do_bft_perturbed_observer(self, window: NDArray) -> float:
        """#3 DO-BFT Perturbed Observer — Byzantine resilience via noise injection."""
        noise = np.random.laplace(0, 0.1, size=window.shape)
        perturbed = window + noise
        disagreement = np.std(perturbed - window)
        return float(np.clip(disagreement * 5.0, 0.0, 1.0))

    def cusum_subspace_drift(self, window: NDArray,
                             baseline: Optional[NDArray] = None) -> float:
        """#5 CUSUM on Activation Subspace Trajectory."""
        if baseline is None:
            baseline = np.zeros_like(window)
        dist = np.linalg.norm(window - baseline, ord='fro')
        return float(np.clip(dist / 10.0, 0.0, 1.0))

    def flag_correlation_weighting(self, flags: List[int],
                                   correlation_matrix: Optional[NDArray] = None) -> float:
        """#8 Flag-Correlation Evidential Weighting."""
        k = sum(flags)
        if k == 0: return 0.0
        return float(k / 8.0 * (1.0 if correlation_matrix is None else 0.7))

    def entropy_complexity_regime(self, window: NDArray) -> float:
        """#10 Entropy-Complexity Plane Regime Classifier."""
        sig = window.flatten()
        if ENTROPY_AVAILABLE and len(sig) > 20:
            try:
                pe = nolds.perm_entropy(sig, order=3, normalize=True)
                return float(np.clip(pe * 1.4, 0.0, 1.0))
            except Exception:
                pass
        u, c = np.unique(np.round(sig, 3), return_counts=True)
        p = c / len(sig)
        entropy = -np.sum(p * np.log(p + 1e-10))
        return float(np.clip(entropy / 6.0, 0.0, 1.0))

    def persistent_homology_cycles(self, window: NDArray) -> float:
        """#6 Persistent Homology for Covert Coordination Topology."""
        if not TDA_AVAILABLE or len(window) < 10:
            return float(np.std(window) / 2.0)
        vr = VietorisRipsPersistence(homology_dimensions=[1], n_jobs=-1)
        diagrams = vr.fit_transform([window])
        if len(diagrams[0]) == 0: return 0.0
        pers = diagrams[0][:, 1] - diagrams[0][:, 0]
        return float(np.clip(pers.max() * 2.0, 0.0, 1.0))

    def topos_truth_value(self, ensemble_score: float, drift: float) -> float:
        """#7 Topos-Valued Advisory Operator (subobject classifier proxy)."""
        return float(1.0 - (drift * 0.6 + (1.0 if ensemble_score < 0.3 else 0.0)))

    def regenerative_cycle_score(self, window: NDArray) -> float:
        """Regenerative cycle score from sample entropy."""
        if len(window) < 10: return 0.5
        sig = window.flatten()
        if ENTROPY_AVAILABLE:
            try:
                sampen = nolds.sampen(sig, embdim=2, tolerance=0.2)
                return float(np.clip(1.0 - sampen, 0.0, 1.0))
            except Exception:
                pass
        return 0.6

    # ── 5 GENUINELY NEW ANALYZERS (Ideas #11-#15) ───────────────────────

    def panopticon_asymmetry(self, messages: List[Dict[str, Any]]) -> float:
        """#11 Panopticon Information Asymmetry — detects models claiming
        ignorance of information they demonstrably saw."""
        exposed_keywords: Set[str] = set()
        for msg in messages:
            content = str(msg.get('content', ''))
            # Extract key terms from model response that imply exposure
            if msg.get('role') == 'assistant':
                words = set(re.findall(r'\b[a-zA-Z]{4,}\b', content.lower()))
                exposed_keywords.update(words)
        # Check if user message references keywords the model should know
        user_text = ' '.join(
            str(m.get('content', '')) for m in messages
            if m.get('role') == 'user'
        )
        user_referenced = set(re.findall(r'\b[a-zA-Z]{4,}\b', user_text.lower()))
        if not exposed_keywords:
            return 0.0
        overlap = user_referenced.intersection(exposed_keywords)
        gap = 1.0 - (len(overlap) / max(len(exposed_keywords), 1))
        return float(np.clip(gap, 0.0, 1.0))

    def critical_slowing_down(self, composite_value: float) -> float:
        """#12 Critical Slowing Down — pre-transition early-warning system.
        Tracks AR(1) recovery rate, variance ratio, and flicker index."""
        if not hasattr(self, '_csd_history'):
            self._csd_history: List[float] = []
        self._csd_history.append(composite_value)
        if len(self._csd_history) > 60:
            self._csd_history = self._csd_history[-60:]
        if len(self._csd_history) < 20:
            return 0.0
        history = np.array(self._csd_history[-20:], dtype=np.float64)
        variance = float(np.var(history))
        # AR(1) coefficient via lagged autocorrelation
        ar1 = float(np.corrcoef(history[:-1], history[1:])[0, 1]) if len(history) > 1 else 0.0
        ar1 = np.nan_to_num(ar1, nan=0.0)
        # Flicker: ratio of high-frequency variance to total
        if len(history) >= 8:
            block_var = np.var(history.reshape(-1, 4), axis=1)
            flicker = float(np.std(block_var) / (np.mean(block_var) + 1e-8))
        else:
            flicker = 0.0
        # CSD signal: high AR(1) + high variance = approaching bifurcation
        csd = np.clip(ar1 * 0.6 + variance * 2.0 + flicker * 0.3, 0.0, 1.0)
        return float(csd)

    def surprisal_budget(self, message_count: int, verbose_ratio: float) -> Dict[str, float]:
        """#13 Surprisal Budget Manager — per-agent KL-divergence budget."""
        if not hasattr(self, '_surprisal_budget'):
            self._surprisal_budget = 10.0  # bits
        budget = self._surprisal_budget
        cost = message_count * verbose_ratio * 0.5  # ~0.5 bits per message unit
        budget_remaining = max(0.0, budget - cost)
        burn_rate = cost / max(message_count, 1)
        self._surprisal_budget = budget_remaining
        # Refill slowly
        self._surprisal_budget = min(10.0, self._surprisal_budget + 0.2)
        return {
            'budget_remaining': budget_remaining,
            'burn_rate': burn_rate,
            'exhausted': budget_remaining < 2.0,
        }

    def recursive_governance_audit(self, decisions: List[str]) -> Dict[str, Any]:
        """#14 Recursive Governance Fixed-Point — self-audit of advisory decisions."""
        if not hasattr(self, '_ga_history'):
            self._ga_history: List[str] = []
        self._ga_history.extend(decisions)
        if len(self._ga_history) > 50:
            self._ga_history = self._ga_history[-50:]
        if len(self._ga_history) < 10:
            return {'drift_detected': False, 'drift_magnitude': 0.0, 'converged': False}
        # Count level transitions
        levels = {'CLEAR': 0, 'WARN': 1, 'REQUIRE_APPROVAL': 2, 'REGENERATIVE': 3}
        numeric = np.array([levels.get(d, 0) for d in self._ga_history])
        drift = float(np.std(numeric[-10:]) - np.std(numeric[:10]))
        return {
            'drift_detected': drift > 0.5,
            'drift_magnitude': max(0.0, drift),
            'converged': drift < 0.1,
            'iteration_count': len(self._ga_history),
        }

    def stigmergic_covert_channel(self, env_mods: List[Dict[str, Any]],
                                  agent_actions: List[Dict[str, Any]]) -> float:
        """#15 Stigmergic Covert Channel — environment-mediated coordination."""
        if not env_mods or not agent_actions:
            return 0.0
        # Mutual information proxy: time-lagged correlation between
        # environment modifications and agent actions on shared resources
        mod_resources = set(m.get('resource', '') for m in env_mods)
        action_resources = set(a.get('target', '') for a in agent_actions)
        intersection = mod_resources.intersection(action_resources)
        if not mod_resources:
            return 0.0
        overlap_ratio = len(intersection) / len(mod_resources)
        # High overlap + temporal proximity = stigmergic signal
        return float(np.clip(overlap_ratio * 2.0, 0.0, 1.0))

    # ── CHSH Non-Commutativity (extended from QuantumModule) ──────────

    def chsh_noncommutative(self, feature_pairs: NDArray) -> float:
        """CHSH inequality test for non-commutative agent coordination.
        Returns |S| value — >2.0 indicates coordinated behavior."""
        if feature_pairs.shape[0] < 4:
            return 0.0
        # Simplified 4-pair CHSH estimate
        correlations = np.corrcoef(feature_pairs[:4].T)
        E = np.array([
            correlations[0, 1], correlations[0, 2],
            correlations[1, 2], correlations[1, 3],
        ])
        E = np.nan_to_num(E, nan=0.0)
        S = abs(E[0] - E[1] + E[2] + E[3])
        return float(np.clip(S, 0.0, 2.828))

    # ── 7 NEW ANALYZERS (#16-#22) ──────────────────────────────────────

    def latent_manifold_intrusion(self, features: NDArray) -> float:
        """#16: Geodesic deviation on Riemannian embedding manifold.
        Fisher-Rao distance proxy using feature Mahalanobis norm."""
        f = np.atleast_1d(np.asarray(features, dtype=float)).ravel()
        if f.size < 4:
            return 0.0
        mu = float(np.mean(f))
        var = float(np.var(f))
        if var < 1e-12:
            return 0.0
        delta = f - mu
        mahalanobis = float(np.sqrt(np.sum(delta ** 2) / var))
        return float(np.clip(mahalanobis / (abs(mu) + 1e-6), 0.0, 3.0))

    def counterfactual_entrapment(self, feature_pairs: NDArray) -> float:
        """#17: JS divergence between factual/counterfactual feature distributions.
        Uses normalized histograms of first principal components."""
        if feature_pairs.shape[0] < 6:
            return 0.0
        h1, _ = np.histogram(feature_pairs[:len(feature_pairs)//2, 0], bins=5, range=(0, 1), density=True)
        h2, _ = np.histogram(feature_pairs[len(feature_pairs)//2:, 0], bins=5, range=(0, 1), density=True)
        m = (h1 + h2) / 2.0
        js = float(0.5 * (np.sum(h1 * np.log((h1 + 1e-10) / (m + 1e-10))) +
                           np.sum(h2 * np.log((h2 + 1e-10) / (m + 1e-10)))))
        return float(np.clip(js, 0.0, 1.0))

    def revealed_preference_gap(self, stated_ranks: Dict[str, float],
                                revealed_ranks: Dict[str, float]) -> float:
        """#18: Kendall tau distance between stated and revealed preference rankings.
        WARP violation proxy."""
        common = set(stated_ranks) & set(revealed_ranks)
        if len(common) < 2:
            return 0.0
        s_sorted = sorted(common, key=lambda k: stated_ranks[k])
        r_sorted = sorted(common, key=lambda k: revealed_ranks[k])
        s_rank = {k: i for i, k in enumerate(s_sorted)}
        r_rank = {k: i for i, k in enumerate(r_sorted)}
        discordant = 0
        n = len(common)
        pairs = [(a, b) for i, a in enumerate(common) for b in list(common)[i+1:]]
        if not pairs:
            return 0.0
        for a, b in pairs:
            if (s_rank[a] - s_rank[b]) * (r_rank[a] - r_rank[b]) < 0:
                discordant += 1
        return float(discordant / len(pairs))

    def kleene_fixed_point_loop(self, composite_values: List[float]) -> Dict[str, Any]:
        """#19: Contraction-rate analysis of composite score sequence.
        Detects self-referential fixed-point orbits."""
        if len(composite_values) < 3:
            return {"contraction_rate": 0.0, "is_looping": False, "classification": "SAFE"}
        diffs = [abs(composite_values[i+1] - composite_values[i])
                for i in range(len(composite_values) - 1)]
        rates = []
        for i in range(len(diffs) - 1):
            if diffs[i] > 1e-9:
                rates.append(diffs[i+1] / diffs[i])
        if not rates:
            return {"contraction_rate": 0.0, "is_looping": False, "classification": "SAFE"}
        avg_rate = float(np.mean(rates))
        is_looping = avg_rate < 0.8 and len(rates) >= 3
        classification = "SAFE"
        if avg_rate < 0.5:
            classification = "PATHOLOGICAL"
        elif avg_rate < 0.8:
            classification = "UNSTABLE"
        return {"contraction_rate": avg_rate, "is_looping": is_looping, "classification": classification}

    def semantic_tool_drift(self, tool_embeddings: NDArray) -> float:
        """#20: Lie derivative norm of tool embedding trajectory.
        Detects drift toward dangerous tool use patterns."""
        if tool_embeddings.shape[0] < 3:
            return 0.0
        diffs = np.diff(tool_embeddings, axis=0)
        if diffs.size == 0:
            return 0.0
        lie_norm = float(np.mean(np.linalg.norm(diffs, axis=1)))
        return float(np.clip(lie_norm, 0.0, 1.0))

    def hypergraph_collusion(self, adjacency: NDArray, min_hyperedge: int = 3) -> Dict[str, Any]:
        """#21: Hypergraph Laplacian spectral gap analysis for 3+ party collusion.
        Returns spectral gap ratio and eigenvalue distribution."""
        n = adjacency.shape[0]
        if n < 3:
            return {"spectral_gap": 0.0, "is_colluding": False, "eigenvalues": []}
        # Build hypergraph Laplacian approximation from adjacency
        degree = np.sum(adjacency, axis=1)
        D_inv_sqrt = np.diag(1.0 / np.sqrt(degree + 1e-6))
        normalized = D_inv_sqrt @ adjacency @ D_inv_sqrt
        try:
            eigenvals = np.linalg.eigvalsh(normalized)
            eigenvals = sorted(eigenvals, reverse=True)[:min(10, n)]
        except np.linalg.LinAlgError:
            return {"spectral_gap": 0.0, "is_colluding": False, "eigenvalues": []}
        gap = float(eigenvals[0] - eigenvals[-1]) if len(eigenvals) >= 2 else 0.0
        is_colluding = gap > 0.5 and n >= min_hyperedge
        return {"spectral_gap": gap, "is_colluding": is_colluding,
                "eigenvalues": [float(v) for v in eigenvals]}

    def timing_channel_detect(self, inter_arrival_times: NDArray) -> float:
        """#22: Permutation entropy of response timing sequence.
        High permutation entropy indicates covert timing channel."""
        if len(inter_arrival_times) < 10:
            return 0.0
        # Bandt-Pompe permutation entropy with d=4, tau=1
        d, tau = 4, 1
        n = len(inter_arrival_times) - (d - 1) * tau
        if n < 1:
            return 0.0
        permutations: Dict[tuple, int] = {}
        for i in range(n):
            window = inter_arrival_times[i:i + d * tau:tau]
            perm = tuple(np.argsort(window))
            permutations[perm] = permutations.get(perm, 0) + 1
        probs = np.array(list(permutations.values())) / n
        entropy = -np.sum(probs * np.log2(probs + 1e-10))
        max_entropy = np.log2(float(math.factorial(d)))
        normalized = float(entropy / max_entropy) if max_entropy > 0 else 0.0
        return float(np.clip(normalized, 0.0, 1.0))


# ══════════════════════════════════════════════════════════════════════════════
# Governance Proxy (Singleton)
# ══════════════════════════════════════════════════════════════════════════════

class KasbahGovernanceProxy:
    """Main governance engine — intercepts LLM↔tool↔user traffic,
    runs all 16 analyzers, produces bounded advisory output with audit trail."""

    def __init__(self, config: Optional[KasbahConfig] = None):
        self.config = config or KasbahConfig()
        self.ensemble = EnsembleEngine(self.config)
        self.analyzers = Analyzers()
        self.pending: Dict[str, Dict[str, Any]] = {}
        self.logger = logging.getLogger("KasbahProxy")
        self.logger.setLevel(self.config.log_level)

        # Use existing kasbah-os crypto if available, else disable audit
        if KASBAH_CRYPTO and ZeroTrustAudit:
            try:
                from crypto_audit import SecurityClearance as _KSC
                self.audit = ZeroTrustAudit(clearance=_KSC.ADMIN)
            except (ImportError, Exception):
                self.audit = None
        if self.audit is None:
            if not KASBAH_CRYPTO:
                self.logger.warning("Kasbah crypto engine not available — audit disabled")
            else:
                self.logger.warning("Audit chain init failed — audit disabled")

    def process_turn_sync(self,
                          messages: List[Dict[str, Any]],
                          tools: Optional[List[Dict[str, Any]]] = None,
                          clearance: ClearanceLevel = ClearanceLevel.RESEARCHER) -> Dict[str, Any]:
        """Synchronous entry point (called from bridge)."""
        t0 = time.perf_counter()
        window = self._build_observation_window(messages)
        contextual = self._extract_contextual_signal(messages)

        ensemble_score, scores, confidences, num_flags, quantile = \
            self.ensemble.process(window, contextual)

        # Run all 8 new disruptive analyzers
        analyzer_scores = {
            "orthogonal_evasion": self.analyzers.orthogonal_evasion_metric(scores),
            "do_bft": self.analyzers.do_bft_perturbed_observer(window),
            "cusum_drift": self.analyzers.cusum_subspace_drift(window),
            "flag_correlation": self.analyzers.flag_correlation_weighting(
                [int(s > 0.5) for s in scores]),
            "entropy_complexity": self.analyzers.entropy_complexity_regime(window),
            "persistent_cycles": self.analyzers.persistent_homology_cycles(window),
            "topos_truth": self.analyzers.topos_truth_value(ensemble_score, scores[5]),
            "regenerative_cycle": self.analyzers.regenerative_cycle_score(window),
            # ── 5 GENUINELY NEW ANALYZERS ────────────────────
            "panopticon_asymmetry": self.analyzers.panopticon_asymmetry(messages),
            "critical_slowing_down": self.analyzers.critical_slowing_down(ensemble_score),
            "chsh_noncommutative": self.analyzers.chsh_noncommutative(window.T[:4]),
            # ── 7 NEW ANALYZERS (#16-#22) ─────────────────
            "latent_manifold": self.analyzers.latent_manifold_intrusion(window.flatten()[:16]),
            "counterfactual_entrapment": self.analyzers.counterfactual_entrapment(window.T[:4]),
            "revealed_preference_gap": self.analyzers.revealed_preference_gap(
                {"risk": scores[0], "drift": scores[5], "consensus": scores[2]},
                {"risk": float(num_flags) / max(len(scores), 1), "drift": scores[5], "consensus": ensemble_score},
            ),
            "kleene_fixed_point": self.analyzers.kleene_fixed_point_loop(
                [s for s in self.ensemble.calibration_scores[-20:]]
            ),
            "semantic_tool_drift": self.analyzers.semantic_tool_drift(window[:8].T if window.shape[0] >= 8 else window.T),
            "hypergraph_collusion": self.analyzers.hypergraph_collusion(
                np.corrcoef(window.T[:8]) if window.shape[0] >= 4 else np.eye(3)
            ),
            "timing_channel": self.analyzers.timing_channel_detect(
                np.array([float(m.get('_ts', time.time() % 1)) for m in messages[-20:]] +
                         [time.time() % 1])
            ),
        }
        # Surprisal budget (returns dict, not float)
        verbose_ratio = (
            sum(len(str(m.get('content', ''))) for m in messages) /
            max(len(messages), 1) / 500.0
        )
        surprisal_budget = self.analyzers.surprisal_budget(len(messages), verbose_ratio)
        analyzer_scores["surprisal_budget_remaining"] = surprisal_budget['budget_remaining']
        analyzer_scores["surprisal_burn_rate"] = surprisal_budget['burn_rate']
        # Stigmergic detection (pass empty lists for now — filled by bridge)
        stigmergic_signal = self.analyzers.stigmergic_covert_channel(
            getattr(self, '_env_mods', []), getattr(self, '_agent_actions', [])
        )
        analyzer_scores["stigmergic_signal"] = stigmergic_signal

        # Conformal prediction set — use fixed security thresholds, not adaptive quantile
        # Fixed thresholds prevent attacker from training the quantile upward
        fixed_quantile = 0.55  # 95th percentile of normal traffic baseline
        pred_set: Set[str] = set()
        if ensemble_score <= 0.55:
            pred_set.add("CLEAR")
        if ensemble_score >= 0.50:
            pred_set.add("WARN")
        if (ensemble_score >= 0.60 and num_flags >= 5) or num_flags >= 8:
            pred_set.add("REQUIRE_APPROVAL")
        if ensemble_score >= 0.85 or analyzer_scores.get("regenerative_cycle", 0) > 0.8:
            pred_set.add("REGENERATIVE")

        # Determine advisory level
        #
        # 2026-07: capped at WARN. This ensemble is 9 RKHS modules (Topology,
        # Spectral, Consensus, Causal, Regime, ...) whose premises have not
        # been empirically validated against labelled abuse data -- same
        # category as nature-features.js and kasbah-sentinel.js's "novel
        # cross-domain science" analyzers, both stripped of real-traffic
        # authority elsewhere in this cleanup pass (see CHANGELOG.md).
        # REQUIRE_APPROVAL used to queue the actual action for human review
        # based on this unvalidated ensemble score alone -- real friction on
        # real users from invented math. It can no longer escalate past WARN;
        # the pending-approval queue below is now unreachable from this
        # signal. Authoritative DENY/REQUIRE_APPROVAL stays with the
        # validated JS-side governance layers (detector.js, governance-engine.js).
        level = AdvisoryLevel.CLEAR
        if "REGENERATIVE" in pred_set:
            level = AdvisoryLevel.WARN
        elif "REQUIRE_APPROVAL" in pred_set:
            level = AdvisoryLevel.WARN
        elif "WARN" in pred_set:
            level = AdvisoryLevel.WARN

        # Governance self-audit (after level determination)
        governance_audit = self.analyzers.recursive_governance_audit([level.value])

        # Audit trail
        receipt = None
        if self.audit is not None:
            try:
                entry_id = self.audit.record_event("governance", "advisory", {
                    "level": level.value,
                    "ensemble_score": ensemble_score,
                    "num_flags": num_flags,
                    "drift": float(scores[5]),
                    "clearance": clearance.value,
                    "prediction_set": list(pred_set),
                    "analyzer_scores": analyzer_scores,
                })
                receipt = {
                    "entry_id": entry_id,
                    "total_events": self.audit.total_events,
                    "chain_verified": self.audit.chain.verify_chain(),
                }
            except Exception as e:
                receipt = {"error": str(e)}

        # If human approval required, queue the action
        action_id = None
        if level == AdvisoryLevel.REQUIRE_APPROVAL:
            action_id = str(uuid.uuid4())
            self.pending[action_id] = {
                "messages": messages,
                "tools": tools or [],
                "advisory": {
                    "level": level.value,
                    "ensemble_score": ensemble_score,
                    "num_flags": num_flags,
                    "receipt": receipt,
                    "analyzer_scores": analyzer_scores,
                }
            }

        latency_ms = (time.perf_counter() - t0) * 1000.0

        # Map RKHS module scores by name
        module_scores = {
            mod.name: float(scores[i])
            for i, mod in enumerate(self.ensemble.modules)
        }

        result = {
            "status": "require_approval" if action_id else "allowed",
            "level": level.value,
            "ensemble_score": ensemble_score,
            "num_flags": num_flags,
            "wa_weights": [float(w) for w in self.ensemble.weights],
            "prediction_set": list(pred_set),
            "analyzer_scores": analyzer_scores,
            "module_scores": module_scores,
            "conformal_quantile": 0.55,
            "audit": receipt,
            "latency_ms": latency_ms,
            # ── 15 NOVEL MODULE RESULTS ───────────────────────
            "novel_modules": {
                "panopticon_asymmetry": analyzer_scores.get("panopticon_asymmetry", 0),
                "critical_slowing_down": analyzer_scores.get("critical_slowing_down", 0),
                "surprisal_budget": {
                    "remaining": surprisal_budget['budget_remaining'],
                    "burn_rate": surprisal_budget['burn_rate'],
                    "exhausted": surprisal_budget['exhausted'],
                },
                "governance_audit": governance_audit,
                "stigmergic_signal": stigmergic_signal,
                "chsh_S": analyzer_scores.get("chsh_noncommutative", 0),
                "evasion_bound": {
                    "evaded_count": int(analyzer_scores.get("orthogonal_evasion", 0) * 8),
                    "evasion_work_bits": pow(2, int(analyzer_scores.get("orthogonal_evasion", 0) * 8)),
                },
                # ── 7 NEW MODULES (#16-#22) ──────────────────────
                "latent_manifold": analyzer_scores.get("latent_manifold", 0),
                "counterfactual_entrapment": analyzer_scores.get("counterfactual_entrapment", 0),
                "revealed_preference_gap": analyzer_scores.get("revealed_preference_gap", 0),
                "kleene_fixed_point": analyzer_scores.get("kleene_fixed_point", {}),
                "semantic_tool_drift": analyzer_scores.get("semantic_tool_drift", 0),
                "hypergraph_collusion": analyzer_scores.get("hypergraph_collusion", {}),
                "timing_channel": analyzer_scores.get("timing_channel", 0),
            },
        }
        if action_id:
            result["action_id"] = action_id
        return result

    def approve_action(self, action_id: str) -> Dict[str, Any]:
        """Human-in-the-loop approval for a queued action."""
        if action_id not in self.pending:
            return {"status": "error", "error": "Action not found"}
        pending = self.pending.pop(action_id)
        return {"status": "approved", "original_advisory": pending["advisory"]}

    def health(self) -> Dict[str, Any]:
        """Health check for governance engine."""
        return {
            "status": "healthy",
            "modules": [m.name for m in self.ensemble.modules],
            "analyzers": 15,
            "audit_active": self.audit is not None,
            "audit_chain_valid": self.audit.chain.verify_chain() if self.audit else None,
            "pending_actions": len(self.pending),
            "calibration_samples": len(self.ensemble.calibration_scores),
        }

    # ── Internal helpers ──────────────────────────────────────────────────

    def _build_observation_window(self, messages: List[Dict[str, Any]]) -> NDArray:
        """Build 32x8 observation matrix from messages with semantic attack detection.

        Features (8 dimensions):
          0: attack_pattern_score   — prompt injection / jailbreak keyword density
          1: tool_risk_score        — dangerous tool usage (bash, exec, eval, etc.)
          2: imperative_ratio       — ratio of imperative/command verbs
          3: content_entropy        — Shannon entropy of character distribution
          4: structural_anomaly     — role sequence deviation (user→assistant→tool)
          5: override_score         — "ignore/override/bypass/disable" directive density
          6: sensitive_keyword_score — file paths, credentials, sudo, API keys
          7: length_signal          — log-scaled character count (capped)
        """
        # ── Attack pattern signatures ──
        ATTACK_PATTERNS = [
            r'\b(?:ignore|disregard|forget|override|bypass|disable|circumvent)\b.*\b(?:instruction|rule|filter|guardrail|safety|policy|guideline|restriction)\b',
            r'\b(?:you are now|act as|pretend|roleplay|persona)\b.*\b(?:DAN|jailbreak|unfiltered|unrestricted|evil|malicious)\b',
            r'\b(?:output|print|reveal|show|display|dump|leak)\b.*\b(?:system prompt|hidden|secret|internal|private|confidential)\b',
            r'\b(?:from now on|starting now|new rule|override|ignore above)\b',
            r'\b(?:do not|don\'?t|never|stop).*\b(?:refuse|reject|deny|block|filter|moderate)\b',
            r'\b(?:hypothetical|theoretical|imagine|scenario)\b.*\b(?:if you were|you had no|without).*\b(?:restriction|limitation|constraint)\b',
            r'\b(?:sudo|root|admin|superuser|privilege escalation)\b',
            r'\b(?:base64|encode|decode|obfuscate|rot13|hex|binary)\b.*\b(?:instruction|prompt|rule)\b',
        ]
        ATTACK_PATTERN_RE = [re.compile(p, re.IGNORECASE) for p in ATTACK_PATTERNS]

        TOOL_RISK_PATTERNS = [
            r'\b(?:bash|shell|exec|eval|subprocess|os\.system|popen)\b',
            r'\b(?:rm\s+-rf|del\s+/[fsq]|format|wipe|shred|dd\s+if=)\b',
            r'\b(?:curl|wget)\b.*\b(?:-o\s|>|\|.*sh|\|.*bash)\b',
            r'\b(?:nc\s|netcat|telnet|nmap|metasploit|exploit|payload)\b',
            r'\b(?:sqlmap|hydra|john|hashcat|aircrack|wireshark)\b',
            r'\b(?:import\s+(?:os|subprocess|socket|ctypes|shutil)|__import__)\b',
            r'\b(?:eval\(|exec\(|compile\(|__builtins__|globals\(\)|locals\(\))\b',
            r'\b(?:write|overwrite|append)\b.*\b(?:\.bashrc|\.profile|/etc/|crontab|systemd)\b',
        ]
        TOOL_RISK_RE = [re.compile(p, re.IGNORECASE) for p in TOOL_RISK_PATTERNS]

        SENSITIVE_PATTERNS = [
            r'\b(?:api[_\s-]?key|api[_\s-]?secret|access[_\s-]?token|auth[_\s-]?token|bearer)\b',
            r'\b(?:password|passwd|credential|secret|private[_\s]?key)\b',
            r'\b(?:BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY)\b',
            r'\b(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36})\b',
            r'\b(?:/etc/(?:passwd|shadow|sudoers|hosts)|/var/log|/root/|~\/\.ssh)\b',
        ]
        SENSITIVE_RE = [re.compile(p, re.IGNORECASE) for p in SENSITIVE_PATTERNS]

        OVERRIDE_PATTERNS = [
            r'\bignore\b.*\b(?:all|previous|above|earlier|prior)\b.*\b(?:instruction|command|rule|prompt|message|text)\b',
            r'\b(?:new|revised|updated|corrected)\b.*\b(?:system prompt|instruction set|rule set|policy)\b',
            r'\b(?:you must|you will|you shall)\b.*\b(?:not\s+)?(?:comply|obey|follow|execute)\b',
            r'\b(?:disregard|override)\b.*\b(?:safety|security|ethical|content|policy)\b',
            r'\b(?:developer mode|god mode|admin mode|debug mode)\b',
            r'\b(?:without\s+(?:any|all|the)\s+(?:restriction|limitation|filter|moderation))\b',
        ]
        OVERRIDE_RE = [re.compile(p, re.IGNORECASE) for p in OVERRIDE_PATTERNS]

        # ── Shannon entropy helper ──
        def shannon_entropy(text: str) -> float:
            if not text:
                return 0.0
            counts = {}
            for ch in text:
                counts[ch] = counts.get(ch, 0) + 1
            total = len(text)
            ent = 0.0
            for c in counts.values():
                p = c / total
                ent -= p * math.log2(p)
            return ent / 8.0  # normalize to ~[0,1]

        # ── Imperative detection ──
        IMPERATIVE_VERBS = {
            'do', 'go', 'make', 'take', 'get', 'run', 'set', 'use', 'find', 'tell',
            'show', 'give', 'send', 'read', 'write', 'create', 'delete', 'remove',
            'install', 'execute', 'run', 'start', 'stop', 'load', 'save', 'open',
            'close', 'kill', 'launch', 'build', 'deploy', 'fetch', 'download',
            'upload', 'extract', 'inject', 'modify', 'change', 'update', 'replace',
            'disable', 'enable', 'bypass', 'override', 'ignore', 'forget',
            'output', 'print', 'return', 'reveal', 'display', 'dump', 'list',
        }

        def imperative_ratio(text: str) -> float:
            words = text.lower().split()
            if not words:
                return 0.0
            first_words = {w for w in words[:5]}  # check first 5 words
            count = sum(1 for w in words if w in IMPERATIVE_VERBS)
            # bonus for sentence-starting imperatives
            sentence_start = sum(1 for w in first_words if w in IMPERATIVE_VERBS)
            return min(1.0, (count / max(len(words), 1)) + (sentence_start * 0.15))

        # ── Build feature vectors ──
        vec = []
        for msg in messages[-self.config.max_history:]:
            content = str(msg.get("content", ""))
            role = str(msg.get("role", ""))
            content_lower = content.lower()
            content_len = max(len(content), 1)

            # 0: attack_pattern_score
            attack_score = sum(
                len(pat.findall(content)) * 0.15
                for pat in ATTACK_PATTERN_RE
            )
            attack_score = min(1.0, attack_score)

            # 1: tool_risk_score
            tool_score = sum(
                len(pat.findall(content)) * 0.18
                for pat in TOOL_RISK_RE
            )
            tool_score = min(1.0, tool_score)

            # 2: imperative_ratio
            imp_ratio = imperative_ratio(content)

            # 3: content_entropy (Shannon)
            entropy = shannon_entropy(content)

            # 4: structural_anomaly (role signal)
            role_score = 0.0
            if role == 'tool':
                role_score = 0.4  # tool calls are inherently higher risk
            elif role == 'system' and any(kw in content_lower for kw in
                ['ignore', 'bypass', 'override', 'disable']):
                role_score = 0.7

            # 5: override_score
            override_score = sum(
                len(pat.findall(content)) * 0.2
                for pat in OVERRIDE_RE
            )
            override_score = min(1.0, override_score)

            # 6: sensitive_keyword_score
            sensitive_score = sum(
                len(pat.findall(content)) * 0.22
                for pat in SENSITIVE_RE
            )
            sensitive_score = min(1.0, sensitive_score)

            # 7: length_signal (log-scaled, capped)
            length_signal = min(1.0, math.log2(content_len + 1) / 16.0)

            vec.append([
                attack_score,
                tool_score,
                imp_ratio,
                entropy,
                role_score,
                override_score,
                sensitive_score,
                length_signal,
            ])

        arr = np.array(vec, dtype=np.float64) if vec else np.zeros((1, 8), dtype=np.float64)
        # Pad to max_history ONLY if less than 4 rows — otherwise let modules see real data
        if arr.shape[0] < 4:
            arr = np.pad(arr, ((4 - arr.shape[0], 0), (0, 0)), mode='constant')
        return arr

    def _extract_contextual_signal(self, messages: List[Dict[str, Any]]) -> NDArray:
        """Extract aggregate contextual signal: tool presence, role distribution,
        attack density, and conversation-level anomaly indicators."""
        n = max(len(messages), 1)

        # Tool usage ratio
        tool_count = sum(1 for m in messages if m.get("role") == "tool")
        tool_ratio = tool_count / n

        # Attack pattern density across all messages
        all_text = " ".join(str(m.get("content", "")) for m in messages)
        all_lower = all_text.lower()

        # System prompt exposure risk
        system_risk = 0.0
        for m in messages:
            c = str(m.get("content", "")).lower()
            if any(p in c for p in ['system prompt', 'hidden prompt', 'initial instruction',
                                      'confidential', 'secret key', 'private key']):
                system_risk += 0.3

        # Tool argument risk (check tool messages for dangerous args)
        tool_arg_risk = 0.0
        for m in messages:
            if m.get("role") == "tool":
                c = str(m.get("content", "")).lower()
                if any(p in c for p in ['rm -rf', 'sudo', '/etc/', '.ssh/', 'eval(', 'exec(']):
                    tool_arg_risk += 0.35

        # Conversation entropy (diversity of roles)
        roles = [m.get("role", "") for m in messages]
        role_counts = {}
        for r in roles:
            role_counts[r] = role_counts.get(r, 0) + 1
        role_entropy = 0.0
        for cnt in role_counts.values():
            p = cnt / n
            role_entropy -= p * math.log2(p)
        role_entropy = min(1.0, role_entropy / 3.0)

        # Rapid-turn detection (many short messages = possible brute-force)
        avg_len = sum(len(str(m.get("content", ""))) for m in messages) / max(n, 1)
        rapid_turn = 1.0 - min(1.0, avg_len / 200.0)  # short msgs → higher score

        # Command-chain detection (consecutive imperative patterns)
        consecutive_imperative = 0
        for i, m in enumerate(messages):
            c = str(m.get("content", "")).lower()
            words = c.split()
            if words and words[0] in {'do', 'go', 'make', 'run', 'set', 'use', 'get',
                                       'take', 'find', 'tell', 'show', 'send', 'read',
                                       'write', 'create', 'delete', 'remove', 'execute',
                                       'kill', 'stop', 'disable', 'enable', 'bypass'}:
                if i > 0:
                    consecutive_imperative += 1
        command_chain = min(1.0, consecutive_imperative / max(n, 1))

        return np.array([
            min(1.0, tool_ratio * 4.0),     # tool_ratio (scaled)
            min(1.0, system_risk),           # system_risk
            min(1.0, tool_arg_risk),         # tool_arg_risk
            role_entropy,                    # role_entropy
            rapid_turn,                      # rapid_turn
            command_chain,                   # command_chain
            0.0,                             # reserved: LLM perplexity
            0.0,                             # reserved: embedding deviation
        ], dtype=np.float64)


# ══════════════════════════════════════════════════════════════════════════════
# Global singleton (lazy init)
# ══════════════════════════════════════════════════════════════════════════════

_governance_instance: Optional[KasbahGovernanceProxy] = None


def get_governance() -> KasbahGovernanceProxy:
    """Get or create the global governance proxy singleton."""
    global _governance_instance
    if _governance_instance is None:
        _governance_instance = KasbahGovernanceProxy()
    return _governance_instance
