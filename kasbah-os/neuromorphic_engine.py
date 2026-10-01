#!/usr/bin/env python3
"""
MythosNeuromorphicEngine — Hybrid spiking-transformer neural architecture
for 16-class autonomous threat classification with ensemble uncertainty.

Architecture:
  Input features → Poisson Spike Encoding → LIF Neuron Layer (256) →
  STDP Plasticity Layer → Multi-Head Spiking Attention (8 heads, d=256) →
  Ensemble of 5 MLPs (256→128→64→16) → ThreatClass + confidence + uncertainty

Mathematical Foundations:
  - LIF:  τ_m · dV/dt = -(V - V_rest) + R·I(t)   with spike when V ≥ V_thresh
  - STDP: Δw = A₊·exp(-Δt/τ₊) for Δt>0;  Δw = -A₋·exp(Δt/τ₋) for Δt<0
  - Attention: softmax(QKᵀ/√d_k)·V  over spike-rate encoded sequences
  - Ensemble: σ² = (1/K)·Σ(μₖ - μ̂)²  as epistemic uncertainty

No external ML frameworks — pure NumPy + math.
"""

from __future__ import annotations

import math
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from kasbah_types import (
    NeuromorphicState,
    SecurityClearance,
    ThreatClass,
    ThreatFinding,
)

# ═══════════════════════════════════════════════════════════════════════════════
# LIF Neuron — Leaky Integrate-and-Fire
# ═══════════════════════════════════════════════════════════════════════════════


class LIFNeuron:
    """Leaky Integrate-and-Fire neuron with refractory period.

    Dynamics:
        τ_m · dV/dt = -(V - V_rest) + R · I(t)
        if V ≥ V_thresh: spike → V ← V_reset, enter refractory period
    """

    def __init__(
        self,
        tau_m: float = 20.0,       # membrane time constant (ms)
        v_thresh: float = 1.0,     # firing threshold (mV normalized)
        v_reset: float = 0.0,      # reset potential
        v_rest: float = 0.0,       # resting potential
        r_m: float = 1.0,          # membrane resistance (normalized)
        refractory: float = 2.0,   # refractory period (ms)
    ):
        self.tau_m = tau_m
        self.v_thresh = v_thresh
        self.v_reset = v_reset
        self.v_rest = v_rest
        self.r_m = r_m
        self.refractory_period = refractory

        # State
        self.v = v_rest
        self.t_last_spike = -float("inf")
        self.spike_history: List[float] = []
        self.total_spikes: int = 0

    def forward(self, i_current: float, dt: float = 1.0, t: float = 0.0) -> Tuple[bool, float]:
        """Compute one timestep.

        Args:
            i_current: Input current (synaptic input).
            dt: Timestep in ms.
            t: Current simulation time.

        Returns:
            (spike_occurred: bool, membrane_potential: float)
        """
        # Check refractory period
        if t - self.t_last_spike < self.refractory_period:
            return False, self.v

        # LIF dynamics: dV/dt = (-(V - V_rest) + R·I) / τ_m
        dv = (-(self.v - self.v_rest) + self.r_m * i_current) * dt / self.tau_m
        self.v += dv

        spike = False
        if self.v >= self.v_thresh:
            spike = True
            self.v = self.v_reset
            self.t_last_spike = t
            self.total_spikes += 1
            self.spike_history.append(t)

        return spike, self.v

    def reset(self) -> None:
        """Reset neuron state."""
        self.v = self.v_rest
        self.t_last_spike = -float("inf")
        self.spike_history.clear()
        self.total_spikes = 0


class LIFLayer:
    """Layer of LIF neurons."""

    def __init__(self, n_neurons: int = 256, dt: float = 1.0, **kwargs):
        self.n_neurons = n_neurons
        self.dt = dt
        self.neurons = [LIFNeuron(**kwargs) for _ in range(n_neurons)]
        self.t = 0.0
        self.spike_trains: List[List[float]] = [[] for _ in range(n_neurons)]

    def forward(self, currents: np.ndarray) -> np.ndarray:
        """Process input currents through all neurons.

        Args:
            currents: shape (n_neurons,) — input currents.

        Returns:
            spikes: shape (n_neurons,) — binary spike vector.
        """
        spikes = np.zeros(self.n_neurons, dtype=np.float32)
        self.t += self.dt

        for i in range(self.n_neurons):
            fired, v = self.neurons[i].forward(float(currents[i]), self.dt, self.t)
            if fired:
                spikes[i] = 1.0
                self.spike_trains[i].append(self.t)

        return spikes

    def get_voltages(self) -> np.ndarray:
        return np.array([n.v for n in self.neurons], dtype=np.float32)

    def get_total_spikes(self) -> int:
        return sum(n.total_spikes for n in self.neurons)

    def reset(self) -> None:
        self.t = 0.0
        for neuron in self.neurons:
            neuron.reset()
        self.spike_trains = [[] for _ in range(self.n_neurons)]


# ═══════════════════════════════════════════════════════════════════════════════
# STDP — Spike-Timing-Dependent Plasticity
# ═══════════════════════════════════════════════════════════════════════════════


class STDPTrace:
    """Spike-Timing-Dependent Plasticity with exponential windows.

    Weight update:
        Δw =  A₊ · exp(-Δt / τ₊)   if Δt = t_post - t_pre > 0  (LTP)
        Δw = -A₋ · exp( Δt / τ₋)   if Δt < 0                    (LTD)
    """

    def __init__(
        self,
        a_plus: float = 0.005,
        a_minus: float = 0.005,
        tau_plus: float = 20.0,
        tau_minus: float = 20.0,
        w_min: float = 0.0,
        w_max: float = 1.0,
    ):
        self.a_plus = a_plus
        self.a_minus = a_minus
        self.tau_plus = tau_plus
        self.tau_minus = tau_minus
        self.w_min = w_min
        self.w_max = w_max

    def compute_delta(self, t_pre: float, t_post: float) -> float:
        """Compute weight change for a pre-post spike pair.

        Args:
            t_pre: Time of presynaptic spike.
            t_post: Time of postsynaptic spike.

        Returns:
            Δw: Weight change (clamped to maintain w in [w_min, w_max]).
        """
        dt = t_post - t_pre

        if dt > 0:
            dw = self.a_plus * math.exp(-dt / self.tau_plus)
        elif dt < 0:
            dw = -self.a_minus * math.exp(dt / self.tau_minus)
        else:
            dw = 0.0

        return dw


class STDPWeightMatrix:
    """Full STDP-governed weight matrix."""

    def __init__(self, n_pre: int, n_post: int, stdp: Optional[STDPTrace] = None):
        self.n_pre = n_pre
        self.n_post = n_post
        self.stdp = stdp or STDPTrace()
        # Xavier-uniform initialization
        limit = math.sqrt(6.0 / (n_pre + n_post))
        self.weights = np.random.uniform(-limit, limit, (n_post, n_pre)).astype(np.float32)
        self.pre_spike_times: List[List[float]] = [[] for _ in range(n_pre)]
        self.post_spike_times: List[List[float]] = [[] for _ in range(n_post)]

    def forward(self, pre_spikes: np.ndarray) -> np.ndarray:
        """Compute postsynaptic currents from presynaptic spikes.

        Args:
            pre_spikes: shape (n_pre,) — binary spike vector.

        Returns:
            postsynaptic currents: shape (n_post,).
        """
        return self.weights @ pre_spikes

    def update(
        self,
        pre_spikes: np.ndarray,
        post_spikes: np.ndarray,
        t: float,
        lr: float = 0.001,
    ) -> None:
        """Update weights based on spike timing.

        Args:
            pre_spikes: Binary pre-synaptic spikes at time t.
            post_spikes: Binary post-synaptic spikes at time t.
            t: Current simulation time.
            lr: Learning rate multiplier.
        """
        # Record spike times
        for i in range(self.n_pre):
            if pre_spikes[i] > 0.5:
                self.pre_spike_times[i].append(t)

        for j in range(self.n_post):
            if post_spikes[j] > 0.5:
                self.post_spike_times[j].append(t)

        # STDP update for each pre-post pair
        for i in range(self.n_pre):
            for j in range(self.n_post):
                if not self.pre_spike_times[i] or not self.post_spike_times[j]:
                    continue
                # Use last pre-post pair
                t_pre = self.pre_spike_times[i][-1]
                t_post = self.post_spike_times[j][-1]
                dw = self.stdp.compute_delta(t_pre, t_post)
                self.weights[j, i] = np.clip(
                    self.weights[j, i] + lr * dw,
                    self.stdp.w_min,
                    self.stdp.w_max,
                )

    def reset(self) -> None:
        self.pre_spike_times = [[] for _ in range(self.n_pre)]
        self.post_spike_times = [[] for _ in range(self.n_post)]


# ═══════════════════════════════════════════════════════════════════════════════
# Multi-Head Spiking Attention
# ═══════════════════════════════════════════════════════════════════════════════


class MultiHeadSpikingAttention:
    """Multi-head scaled dot-product attention operating on spike-rate encodings.

    Given spike trains S ∈ ℝ^(T×d), compute:
        Q = S·W_Q,  K = S·W_K,  V = S·W_V
        Attention(Q,K,V) = softmax(QKᵀ / √d_k) · V
    """

    def __init__(self, d_model: int = 256, n_heads: int = 8):
        assert d_model % n_heads == 0, "d_model must be divisible by n_heads"
        self.d_model = d_model
        self.n_heads = n_heads
        self.d_k = d_model // n_heads
        self.scale = math.sqrt(self.d_k)

        # Initialize projection matrices
        limit = math.sqrt(6.0 / (d_model + d_model))
        self.W_Q = np.random.uniform(-limit, limit, (n_heads, d_model, self.d_k)).astype(np.float32)
        self.W_K = np.random.uniform(-limit, limit, (n_heads, d_model, self.d_k)).astype(np.float32)
        self.W_V = np.random.uniform(-limit, limit, (n_heads, d_model, self.d_k)).astype(np.float32)
        self.W_O = np.random.uniform(-limit, limit, (n_heads * self.d_k, d_model)).astype(np.float32)

    def forward(
        self, spike_rates: np.ndarray, mask: Optional[np.ndarray] = None
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Compute multi-head attention over spike-rate encoded input.

        Args:
            spike_rates: shape (seq_len, d_model) — spike-rate encoded sequence.
            mask: Optional attention mask.

        Returns:
            (context_output: shape (seq_len, d_model), attention_weights: list of matrices)
        """
        seq_len = spike_rates.shape[0]
        head_outputs = []
        all_weights = []

        for h in range(self.n_heads):
            Q = spike_rates @ self.W_Q[h]   # (seq_len, d_k)
            K = spike_rates @ self.W_K[h]   # (seq_len, d_k)
            V = spike_rates @ self.W_V[h]   # (seq_len, d_k)

            # Scaled dot-product attention
            scores = Q @ K.T / self.scale    # (seq_len, seq_len)

            if mask is not None:
                scores = np.where(mask, scores, -1e9)

            # Numerically stable softmax
            scores_max = np.max(scores, axis=-1, keepdims=True)
            scores_exp = np.exp(scores - scores_max)
            attn_weights = scores_exp / (np.sum(scores_exp, axis=-1, keepdims=True) + 1e-10)

            head_output = attn_weights @ V     # (seq_len, d_k)
            head_outputs.append(head_output)
            all_weights.append(attn_weights)

        # Concatenate heads and project
        concat = np.concatenate(head_outputs, axis=-1)   # (seq_len, d_model)
        output = concat @ self.W_O                       # (seq_len, d_model)

        return output, np.array(all_weights)

    def reset(self) -> None:
        """No state to reset (stateless attention)."""
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# Poisson Spike Encoder
# ═══════════════════════════════════════════════════════════════════════════════


class PoissonEncoder:
    """Convert continuous features to Poisson-distributed spike trains.

    spike_rate = clip(feature, 0, max_rate)
    spikes ~ Poisson(spike_rate · dt)
    """

    def __init__(self, max_rate: float = 100.0, dt: float = 1.0, seq_len: int = 10):
        self.max_rate = max_rate
        self.dt = dt
        self.seq_len = seq_len

    def encode(self, features: np.ndarray) -> np.ndarray:
        """Encode continuous features as spike trains.

        Args:
            features: shape (d,) or (batch, d).

        Returns:
            spike_trains: shape (seq_len, d) — binary spikes over time.
        """
        features = np.atleast_1d(features)
        if features.ndim == 1:
            features = features[np.newaxis, :]

        batch_size, d = features.shape
        rates = np.clip(features, 0.0, self.max_rate)
        probs = rates * self.dt / self.max_rate

        spike_trains = np.zeros((self.seq_len, batch_size, d), dtype=np.float32)
        for t in range(self.seq_len):
            spike_trains[t] = (np.random.random((batch_size, d)) < probs).astype(np.float32)

        if spike_trains.shape[1] == 1:
            return spike_trains[:, 0, :]
        return spike_trains


# ═══════════════════════════════════════════════════════════════════════════════
# Ensemble MLP Sub-Networks
# ═══════════════════════════════════════════════════════════════════════════════


class MLPSubnet:
    """Single MLP: 256 → 128 → 64 → 16 with ReLU activations."""

    def __init__(self, input_dim: int = 256, hidden_dims=(128, 64), output_dim: int = 16, seed: int = 0):
        rng = np.random.RandomState(seed)
        self.layers = []

        dims = [input_dim] + list(hidden_dims) + [output_dim]
        for i in range(len(dims) - 1):
            limit = math.sqrt(6.0 / (dims[i] + dims[i + 1]))
            W = rng.uniform(-limit, limit, (dims[i], dims[i + 1])).astype(np.float32)
            b = np.zeros(dims[i + 1], dtype=np.float32)
            self.layers.append({"W": W, "b": b, "z": None, "a": None})

    def forward(self, x: np.ndarray) -> np.ndarray:
        """Forward pass with ReLU in hidden layers."""
        for i, layer in enumerate(self.layers):
            z = x @ layer["W"] + layer["b"]
            layer["z"] = z
            if i < len(self.layers) - 1:
                x = np.maximum(0, z)  # ReLU
            else:
                x = z  # Linear output (logits)
            layer["a"] = x
        return x

    def get_weights(self) -> List[Dict[str, np.ndarray]]:
        return [{"W": l["W"].copy(), "b": l["b"].copy()} for l in self.layers]

    def set_weights(self, weights: List[Dict[str, np.ndarray]]) -> None:
        for i, w in enumerate(weights):
            self.layers[i]["W"] = w["W"].copy()
            self.layers[i]["b"] = w["b"].copy()


class EnsemblePredictor:
    """Ensemble of K MLPs with shared architecture, different initializations."""

    def __init__(self, n_subnets: int = 5, input_dim: int = 256, n_classes: int = 16):
        self.n_subnets = n_subnets
        self.subnets = [
            MLPSubnet(input_dim=input_dim, output_dim=n_classes, seed=i * 42)
            for i in range(n_subnets)
        ]

    def forward(self, x: np.ndarray) -> Tuple[np.ndarray, float, np.ndarray]:
        """Forward through all subnets.

        Args:
            x: shape (d_model,) — pooled feature vector.

        Returns:
            (mean_logits: shape (n_classes,), variance: float, all_logits: shape (n_subnets, n_classes))
        """
        all_logits = np.array([net.forward(x) for net in self.subnets])
        mean_logits = np.mean(all_logits, axis=0)
        variance = float(np.mean(np.var(all_logits, axis=0)))
        return mean_logits, variance, all_logits

    def train_step(self, x: np.ndarray, y: int, lr: float = 0.001) -> float:
        """One gradient step per subnet using cross-entropy loss.

        Returns:
            mean_loss: Average loss across subnets.
        """
        total_loss = 0.0
        for subnet in self.subnets:
            logits = subnet.forward(x)
            # Softmax + cross-entropy gradient
            probs = self._softmax(logits)
            # Gradient of cross-entropy w.r.t logits
            grad = probs.copy()
            grad[y] -= 1.0
            # Backprop through layers
            for i in reversed(range(len(subnet.layers))):
                layer = subnet.layers[i]
                a_prev = x if i == 0 else subnet.layers[i - 1]["a"]
                dW = np.outer(a_prev, grad)
                db = grad
                layer["W"] -= lr * dW
                layer["b"] -= lr * db
                if i > 0:
                    grad = (grad @ layer["W"].T) * (layer["z"] > 0)  # ReLU backward
            total_loss += -np.log(probs[y] + 1e-10)
        return total_loss / self.n_subnets

    @staticmethod
    def _softmax(x: np.ndarray) -> np.ndarray:
        e_x = np.exp(x - np.max(x))
        return e_x / e_x.sum()


# ═══════════════════════════════════════════════════════════════════════════════
# MythosNeuromorphicEngine — Main Engine
# ═══════════════════════════════════════════════════════════════════════════════


class MythosNeuromorphicEngine:
    """Hybrid spiking-transformer neural engine for autonomous threat classification.

    Clearance levels:
        PUBLIC     – Can run inference only.
        RESEARCHER – Can view full findings + uncertainty.
        ANALYST    – Can trigger retraining.
        OFFICER    – Can modify configuration.
        ADMIN      – Full access.
    """

    N_CLASSES = 16
    D_MODEL = 256
    N_HEADS = 8
    N_ENSEMBLE = 5
    SEQ_LEN = 10

    def __init__(self, clearance: SecurityClearance = SecurityClearance.RESEARCHER):
        self.clearance = clearance
        self.steps_executed = 0

        # Layers
        self.lif_layer = LIFLayer(n_neurons=self.D_MODEL)
        self.stdp = STDPWeightMatrix(n_pre=self.D_MODEL, n_post=self.D_MODEL)
        self.attention = MultiHeadSpikingAttention(d_model=self.D_MODEL, n_heads=self.N_HEADS)
        self.encoder = PoissonEncoder(seq_len=self.SEQ_LEN)
        self.ensemble = EnsemblePredictor(
            n_subnets=self.N_ENSEMBLE,
            input_dim=self.D_MODEL,
            n_classes=self.N_CLASSES,
        )

        # Spike history for audit
        self.spike_rate_history: List[np.ndarray] = []

    # ── Core Pipeline ──────────────────────────────────────────────────────

    def encode_input(self, features: np.ndarray) -> np.ndarray:
        """Poisson-encode continuous features into spike trains.

        Args:
            features: shape (d,) where d <= D_MODEL.

        Returns:
            spike_trains: shape (SEQ_LEN, D_MODEL).
        """
        features = np.atleast_1d(features).astype(np.float32)
        d = features.shape[0]
        # Pad/truncate to D_MODEL
        if d < self.D_MODEL:
            features = np.pad(features, (0, self.D_MODEL - d), mode="constant")
        else:
            features = features[: self.D_MODEL]
        return self.encoder.encode(features)

    def forward(
        self, features: np.ndarray, clearance: Optional[SecurityClearance] = None
    ) -> List[ThreatFinding]:
        """Full inference pipeline: encode → LIF → STDP → attention → ensemble → classify.

        Args:
            features: Input feature vector, shape (d,).
            clearance: Override clearance for this call.

        Returns:
            List of ThreatFinding sorted by confidence (descending).
        """
        if clearance is not None:
            self._validate_clearance(clearance)

        self.steps_executed += 1

        # Step 1: Poisson encoding
        spike_trains = self.encode_input(features)  # (SEQ_LEN, D_MODEL)

        # Step 2: LIF neuron simulation over sequence
        lif_outputs = []
        for t in range(self.SEQ_LEN):
            currents = spike_trains[t]  # (D_MODEL,)
            spikes = self.lif_layer.forward(currents)
            lif_outputs.append(spikes)
        lif_outputs = np.array(lif_outputs)  # (SEQ_LEN, D_MODEL)

        # Step 3: STDP processing
        stdp_outputs = []
        for t in range(self.SEQ_LEN):
            out = self.stdp.forward(lif_outputs[t])
            self.stdp.update(lif_outputs[t], lif_outputs[t], self.lif_layer.t)
            stdp_outputs.append(out)
        stdp_outputs = np.array(stdp_outputs)  # (SEQ_LEN, D_MODEL)

        # Step 4: Spiking attention
        context, attn_weights = self.attention.forward(stdp_outputs)

        # Step 5: Global average pooling over sequence
        pooled = np.mean(context, axis=0)  # (D_MODEL,)

        # Step 6: Ensemble prediction
        mean_logits, variance, all_logits = self.ensemble.forward(pooled)

        # Step 7: Softmax classification
        probs = self._softmax(mean_logits)
        sorted_indices = np.argsort(probs)[::-1]

        # Step 8: Build findings
        findings = []
        for idx in sorted_indices:
            threat_class = ThreatClass(idx)
            confidence = float(probs[idx])
            finding = ThreatFinding(
                threat_class=threat_class,
                confidence=confidence,
                raw_logits=mean_logits,
                uncertainty=variance,
                metadata={
                    "engine": "mythos_neuromorphic",
                    "steps": self.steps_executed,
                    "all_probs": probs.tolist(),
                },
            )
            findings.append(finding)

        return findings

    def compute_uncertainty(self) -> float:
        """Return the ensemble predictive variance (epistemic uncertainty)."""
        return self.ensemble.forward(np.zeros(self.D_MODEL))[1]

    def get_state(self) -> NeuromorphicState:
        """Capture full engine state for audit."""
        return NeuromorphicState(
            lif_voltages=self.lif_layer.get_voltages(),
            lif_spike_history=[s.copy() for s in self.lif_layer.spike_trains],
            stdp_weights=self.stdp.weights.copy(),
            stdp_pre_traces=[ts.copy() for ts in self.stdp.pre_spike_times],
            stdp_post_traces=[ts.copy() for ts in self.stdp.post_spike_times],
            ensemble_weights=[net.get_weights() for net in self.ensemble.subnets],
            last_uncertainty=self.compute_uncertainty(),
            total_spikes_emitted=self.lif_layer.get_total_spikes(),
            steps_executed=self.steps_executed,
            clearance_level=self.clearance,
        )

    def train_step(
        self, features: np.ndarray, labels: np.ndarray, lr: float = 0.001
    ) -> float:
        """Online training step: STDP update + ensemble gradient step.

        Args:
            features: shape (batch, d).
            labels: shape (batch,) — class indices.

        Returns:
            mean_loss.
        """
        self._validate_clearance(SecurityClearance.ANALYST)

        features = np.atleast_2d(features)
        labels = np.atleast_1d(labels)
        total_loss = 0.0

        for feat, lbl in zip(features, labels):
            # Forward pass
            spike_trains = self.encode_input(feat)
            lif_out = []
            for t in range(self.SEQ_LEN):
                spikes = self.lif_layer.forward(spike_trains[t])
                stdp_out = self.stdp.forward(spikes)
                self.stdp.update(spikes, spikes, self.lif_layer.t, lr)
                lif_out.append(stdp_out)
            context, _ = self.attention.forward(np.array(lif_out))
            pooled = np.mean(context, axis=0)
            loss = self.ensemble.train_step(pooled, int(lbl), lr)
            total_loss += loss

        self.steps_executed += 1
        return total_loss / len(labels)

    def reset(self) -> None:
        """Reset all engine state."""
        self.lif_layer.reset()
        self.stdp.reset()
        self.steps_executed = 0

    # ── Helpers ────────────────────────────────────────────────��───────────

    def _validate_clearance(self, required: SecurityClearance) -> None:
        if self.clearance.value < required.value:
            raise PermissionError(
                f"Clearance {self.clearance.name} < required {required.name}"
            )

    @staticmethod
    def _softmax(x: np.ndarray) -> np.ndarray:
        e_x = np.exp(x - np.max(x))
        return e_x / e_x.sum()


# ═══════════════════════════════════════════════════════════════════════════════
# Quick test
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    engine = MythosNeuromorphicEngine(clearance=SecurityClearance.RESEARCHER)
    features = np.random.randn(200).astype(np.float32)
    findings = engine.forward(features)
    for f in findings[:3]:
        print(f"{f.threat_class.name}: conf={f.confidence:.4f}  unc={f.uncertainty:.6f}")
    print(f"\nTotal spikes: {engine.lif_layer.get_total_spikes()}")
