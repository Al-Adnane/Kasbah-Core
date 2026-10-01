#!/usr/bin/env python3
"""
AdversarialSelfPlay — Red/Blue team gradient-based policy optimization.

Red Team (Attacker): 16 actions — recon, scan_ports, exploit_CVE, bruteforce,
  phishing, lateral_move, escalate_priv, exfiltrate, persist, c2_callback,
  evade_defense, inject_code, poison_data, dos_attack, exploit_zeroday, social_engineer

Blue Team (Defender): 12 actions — monitor_logs, patch_system, rotate_creds,
  enable_mfa, segment_network, deploy_honeypot, scan_vulns, update_policy,
  quarantine_host, block_ip, forensic_analysis, incident_response

Environment: Simulated security state with compromise/detection dynamics.
Episode History: 10K episode ring buffer with nearest-neighbor search.

All pure NumPy. No external ML frameworks.
"""

from __future__ import annotations

import hashlib
import math
import random
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from kasbah_types import SecurityClearance, ThreatClass, ThreatFinding

# ═══════════════════════════════════════════════════════════════════════════════
# Actions
# ═══════════════════════════════════════════════════════════════════════════════

RED_ACTIONS = [
    "recon", "scan_ports", "exploit_CVE", "bruteforce", "phishing",
    "lateral_move", "escalate_priv", "exfiltrate", "persist", "c2_callback",
    "evade_defense", "inject_code", "poison_data", "dos_attack",
    "exploit_zeroday", "social_engineer",
]

BLUE_ACTIONS = [
    "monitor_logs", "patch_system", "rotate_creds", "enable_mfa",
    "segment_network", "deploy_honeypot", "scan_vulns", "update_policy",
    "quarantine_host", "block_ip", "forensic_analysis", "incident_response",
]

N_RED = len(RED_ACTIONS)
N_BLUE = len(BLUE_ACTIONS)


# ═══════════════════════════════════════════════════════════════════════════════
# Policy Network
# ═══════════════════════════════════════════════════════════════════════════════


class PolicyNetwork:
    """Neural policy: state → (action_probs, value_estimate).

    Architecture: input_dim → 128 → 64 → 32 → n_actions (+ value head)
    """

    def __init__(
        self,
        input_dim: int,
        n_actions: int,
        hidden_dims: List[int] = None,
        lr: float = 0.001,
        seed: int = 0,
    ):
        if hidden_dims is None:
            hidden_dims = [128, 64, 32]

        self.input_dim = input_dim
        self.n_actions = n_actions
        self.lr = lr

        rng = np.random.RandomState(seed)

        # Build layers
        self.weights = []
        self.biases = []
        dims = [input_dim] + hidden_dims
        for i in range(len(dims) - 1):
            limit = math.sqrt(6.0 / (dims[i] + dims[i + 1]))
            self.weights.append(
                rng.uniform(-limit, limit, (dims[i], dims[i + 1])).astype(np.float32)
            )
            self.biases.append(np.zeros(dims[i + 1], dtype=np.float32))

        # Policy head
        limit = math.sqrt(6.0 / (hidden_dims[-1] + n_actions))
        self.policy_W = rng.uniform(
            -limit, limit, (hidden_dims[-1], n_actions)
        ).astype(np.float32)
        self.policy_b = np.zeros(n_actions, dtype=np.float32)

        # Value head
        limit = math.sqrt(6.0 / (hidden_dims[-1] + 1))
        self.value_W = rng.uniform(
            -limit, limit, (hidden_dims[-1], 1)
        ).astype(np.float32)
        self.value_b = np.zeros(1, dtype=np.float32)

    def forward(self, state: np.ndarray) -> Tuple[np.ndarray, float]:
        """Forward pass → (action_probs, value_estimate)."""
        x = np.atleast_1d(state).astype(np.float32)

        for W, b in zip(self.weights, self.biases):
            x = np.maximum(0, x @ W + b)  # ReLU

        # Policy: softmax
        logits = x @ self.policy_W + self.policy_b
        logits_max = np.max(logits)
        policy_exp = np.exp(logits - logits_max)
        probs = policy_exp / (policy_exp.sum() + 1e-10)

        # Value: scalar
        value = float((x @ self.value_W + self.value_b)[0])

        return probs, value

    def train_step(
        self,
        states: np.ndarray,
        actions: np.ndarray,
        returns: np.ndarray,
        lr: float = None,
    ) -> float:
        """REINFORCE with baseline: ∇J = ∇log π(a|s) · (G - V(s))."""
        if lr is None:
            lr = self.lr

        states = np.atleast_2d(states).astype(np.float32)
        actions = np.atleast_1d(actions).astype(np.int64)
        returns = np.atleast_1d(returns).astype(np.float32)

        total_loss = 0.0
        n = len(states)

        for i in range(n):
            s = states[i]
            a = actions[i]
            G = returns[i]

            # Forward pass (store activations for backprop)
            x = s
            activations = [x]
            for W, b in zip(self.weights, self.biases):
                x = np.maximum(0, x @ W + b)
                activations.append(x)

            # Policy logits
            logits = activations[-1] @ self.policy_W + self.policy_b
            logits_max = np.max(logits)
            policy_exp = np.exp(logits - logits_max)
            probs = policy_exp / (policy_exp.sum() + 1e-10)

            # Value
            value = float((activations[-1] @ self.value_W + self.value_b)[0])

            # Advantage
            advantage = G - value

            # Policy gradient
            d_logits = probs.copy()
            d_logits[a] -= 1.0  # ∂CE/∂logits for chosen action
            d_logits *= advantage

            # Update policy head
            self.policy_W -= lr * np.outer(activations[-1], d_logits)
            self.policy_b -= lr * d_logits

            # Backprop through hidden layers
            d_hidden = d_logits @ self.policy_W.T
            # Value gradient
            d_hidden += advantage * self.value_W[:, 0]
            self.value_W[:, 0] -= lr * advantage * activations[-1]
            self.value_b[0] -= lr * advantage

            for k in reversed(range(len(self.weights))):
                d_hidden *= (activations[k + 1] > 0).astype(np.float32)
                self.weights[k] -= lr * np.outer(activations[k], d_hidden)
                self.biases[k] -= lr * d_hidden
                if k > 0:
                    d_hidden = d_hidden @ self.weights[k].T

            total_loss += advantage ** 2

        return total_loss / n

    def save(self, path: str) -> None:
        np.savez(
            path,
            weights=self.weights,
            biases=self.biases,
            policy_W=self.policy_W,
            policy_b=self.policy_b,
            value_W=self.value_W,
            value_b=self.value_b,
        )

    @classmethod
    def load(cls, path: str, input_dim: int, n_actions: int) -> "PolicyNetwork":
        data = np.load(path, allow_pickle=True)
        net = cls(input_dim, n_actions)
        net.weights = list(data["weights"])
        net.biases = list(data["biases"])
        net.policy_W = data["policy_W"]
        net.policy_b = data["policy_b"]
        net.value_W = data["value_W"]
        net.value_b = data["value_b"]
        return net


# ═══════════════════════════════════════════════════════════════════════════════
# Red Team Agent
# ═══════════════════════════════════════════════════════════════════════════════


class RedTeamAgent:
    """Attacker agent with epsilon-greedy policy."""

    STATE_DIM = 64
    N_ACTIONS = N_RED

    def __init__(self, seed: int = 0):
        self.policy = PolicyNetwork(self.STATE_DIM, self.N_ACTIONS, seed=seed)
        self.action_names = RED_ACTIONS
        self.episode_rewards: List[float] = []

    def observe(self, env_state: dict) -> np.ndarray:
        """Encode environment state into feature vector."""
        features = np.zeros(self.STATE_DIM, dtype=np.float32)

        # Compromise level
        features[0] = env_state.get("compromised_hosts", 0) / 100.0
        features[1] = env_state.get("detected_intrusions", 0) / 100.0
        features[2] = 1.0 - env_state.get("defense_strength", 0.5)
        features[3] = env_state.get("data_exfiltrated", 0) / 1000.0
        features[4] = env_state.get("lateral_movement_count", 0) / 50.0

        # Encoded state hash for diversity
        h = int(hashlib.sha256(str(env_state).encode()).hexdigest()[:16], 16)
        for i in range(5, min(self.STATE_DIM, 21)):
            features[i] = float((h >> (i - 5)) & 1)

        # Fill remaining with noise for exploration
        np.random.seed(int(time.time() * 1e6) % (2**31))
        features[21:] = np.random.randn(self.STATE_DIM - 21).astype(np.float32) * 0.01

        return features

    def act(self, observation: np.ndarray, epsilon: float = 0.1) -> Tuple[int, str]:
        """Epsilon-greedy action selection."""
        if random.random() < epsilon:
            action_idx = random.randint(0, self.N_ACTIONS - 1)
        else:
            probs, _ = self.policy.forward(observation)
            # Weighted sampling (handle numerical errors)
            probs = np.clip(probs, 0, None)
            if probs.sum() > 0:
                probs /= probs.sum()
                action_idx = int(np.random.choice(self.N_ACTIONS, p=probs))
            else:
                action_idx = random.randint(0, self.N_ACTIONS - 1)

        return action_idx, self.action_names[action_idx]

    def learn(self, episode_reward: float) -> float:
        """Record reward (actual learning deferred to batch)."""
        self.episode_rewards.append(episode_reward)
        return episode_reward

    def get_attack_surface(self) -> List[str]:
        """Enumerate available attack vectors."""
        return self.action_names


# ═══════════════════════════════════════════════════════════════════════════════
# Blue Team Agent
# ═══════════════════════════════════════════════════════════════════════════════


class BlueTeamAgent:
    """Defender agent."""

    STATE_DIM = 64
    N_ACTIONS = N_BLUE

    def __init__(self, seed: int = 1):
        self.policy = PolicyNetwork(self.STATE_DIM, self.N_ACTIONS, seed=seed)
        self.action_names = BLUE_ACTIONS
        self.episode_rewards: List[float] = []

    def observe(self, env_state: dict) -> np.ndarray:
        """Encode environment state from defender perspective."""
        features = np.zeros(self.STATE_DIM, dtype=np.float32)

        features[0] = env_state.get("detected_intrusions", 0) / 100.0
        features[1] = env_state.get("defense_strength", 0.5)
        features[2] = -env_state.get("compromised_hosts", 0) / 100.0
        features[3] = env_state.get("alerts_triggered", 0) / 50.0
        features[4] = env_state.get("patches_applied", 0) / 20.0

        h = int(hashlib.sha256(str(env_state).encode()).hexdigest()[:16], 16)
        for i in range(5, min(self.STATE_DIM, 21)):
            features[i] = float((h >> (i - 5)) & 1)

        features[21:] = np.random.randn(self.STATE_DIM - 21).astype(np.float32) * 0.01
        return features

    def detect_threat(self, red_action_idx: int) -> float:
        """Detection probability based on action type."""
        # Some actions are noisier than others
        noise_map = {
            0: 0.20,   # recon (quiet)
            1: 0.40,   # scan_ports (noisy)
            2: 0.70,   # exploit_CVE
            3: 0.60,   # bruteforce (noisy)
            4: 0.30,   # phishing (quiet)
            5: 0.50,   # lateral_move
            6: 0.65,   # escalate_priv
            7: 0.55,   # exfiltrate
            8: 0.30,   # persist (quiet)
            9: 0.45,   # c2_callback
            10: 0.10,  # evade_defense (stealthy)
            11: 0.40,  # inject_code
            12: 0.20,  # poison_data (quiet)
            13: 0.95,  # dos_attack (very noisy)
            14: 0.15,  # exploit_zeroday (hard to detect)
            15: 0.25,  # social_engineer (quiet)
        }
        return noise_map.get(red_action_idx, 0.50)

    def respond(self, threat_detected: bool, confidence: float) -> int:
        """Select defensive action based on threat assessment."""
        if not threat_detected:
            # Generic defense
            return self.action_names.index("monitor_logs")
        if confidence > 0.8:
            return self.action_names.index("incident_response")
        elif confidence > 0.5:
            return self.action_names.index("quarantine_host")
        else:
            return self.action_names.index("scan_vulns")

    def act(self, observation: np.ndarray, epsilon: float = 0.05) -> Tuple[int, str]:
        """Epsilon-greedy action selection (defender is more conservative)."""
        if random.random() < epsilon:
            action_idx = random.randint(0, self.N_ACTIONS - 1)
        else:
            probs, _ = self.policy.forward(observation)
            probs = np.clip(probs, 0, None)
            if probs.sum() > 0:
                probs /= probs.sum()
                action_idx = int(np.random.choice(self.N_ACTIONS, p=probs))
            else:
                action_idx = random.randint(0, self.N_ACTIONS - 1)
        return action_idx, self.action_names[action_idx]

    def learn(self, episode_reward: float) -> float:
        self.episode_rewards.append(episode_reward)
        return episode_reward


# ═══════════════════════════════════════════════════════════════════════════════
# Environment
# ═══════════════════════════════════════════════════════════════════════════════


class SecurityEnvironment:
    """Simulated security environment for adversarial self-play."""

    MAX_STEPS = 100

    def __init__(self):
        self.reset()

    def reset(self) -> dict:
        self.step_count = 0
        self.state = {
            "compromised_hosts": 0,
            "detected_intrusions": 0,
            "defense_strength": 0.5,
            "data_exfiltrated": 0.0,
            "lateral_movement_count": 0,
            "alerts_triggered": 0,
            "patches_applied": 0,
            "red_success_rate": 0.0,
            "blue_detection_rate": 0.0,
        }
        return self.state

    def step(
        self, red_action_idx: int, blue_action_idx: int
    ) -> Tuple[dict, float, float, bool]:
        """Execute one step in the environment.

        Returns:
            (next_state, red_reward, blue_reward, done)
        """
        self.step_count += 1

        red_name = RED_ACTIONS[red_action_idx]
        blue_name = BLUE_ACTIONS[blue_action_idx]

        # Red action effects
        red_success = self._red_action_effect(red_name)
        blue_effectiveness = self._blue_action_effect(blue_name, red_name)
        detection_prob = BlueTeamAgent.__new__(BlueTeamAgent).detect_threat(
            red_action_idx
        )

        # Adjust by defense strength
        effective_detection = detection_prob * self.state["defense_strength"]
        detected = random.random() < effective_detection

        # State updates
        if red_success and not detected:
            red_reward = 1.0
            blue_reward = -0.5
            self.state["compromised_hosts"] = min(
                100, self.state["compromised_hosts"] + 1
            )
            if red_name in ("exfiltrate",):
                self.state["data_exfiltrated"] += random.uniform(10, 100)
            if red_name in ("lateral_move",):
                self.state["lateral_movement_count"] += 1
        elif red_success and detected:
            red_reward = -0.3
            blue_reward = 1.0
            self.state["detected_intrusions"] += 1
            self.state["alerts_triggered"] += 1
        elif not red_success and detected:
            red_reward = -0.5
            blue_reward = 0.8
            self.state["detected_intrusions"] += 1
        else:  # red failed, not detected
            red_reward = -0.1
            blue_reward = 0.1

        # Defense strength updates
        if blue_name in ("patch_system", "rotate_creds", "update_policy"):
            self.state["defense_strength"] = min(1.0, self.state["defense_strength"] + 0.05)
            self.state["patches_applied"] += 1
        if blue_name in ("monitor_logs", "scan_vulns", "forensic_analysis"):
            self.state["defense_strength"] = min(1.0, self.state["defense_strength"] + 0.02)

        # Track rates
        total_actions = max(1, self.step_count)
        self.state["red_success_rate"] = (
            sum(1 for r in [red_reward] if r > 0) / total_actions
        )  # simplified

        done = self.step_count >= self.MAX_STEPS or self.state["compromised_hosts"] >= 100
        return self.state.copy(), red_reward, blue_reward, done

    def _red_action_effect(self, action: str) -> bool:
        """Probability of red action succeeding."""
        base_probs = {
            "recon": 0.9, "scan_ports": 0.8, "exploit_CVE": 0.5,
            "bruteforce": 0.3, "phishing": 0.4, "lateral_move": 0.5,
            "escalate_priv": 0.35, "exfiltrate": 0.55, "persist": 0.6,
            "c2_callback": 0.7, "evade_defense": 0.6, "inject_code": 0.45,
            "poison_data": 0.5, "dos_attack": 0.8, "exploit_zeroday": 0.2,
            "social_engineer": 0.35,
        }
        prob = base_probs.get(action, 0.5)
        # Defense strength reduces success
        prob *= (1.0 - 0.5 * self.state["defense_strength"])
        return random.random() < prob

    def _blue_action_effect(self, blue_action: str, red_action: str) -> float:
        """Defense action effectiveness."""
        counter_map = {
            "block_ip": ("scan_ports", "bruteforce", "c2_callback"),
            "quarantine_host": ("lateral_move", "persist"),
            "patch_system": ("exploit_CVE", "exploit_zeroday"),
            "rotate_creds": ("bruteforce", "credential_access"),
            "enable_mfa": ("bruteforce", "phishing"),
            "incident_response": ("exfiltrate", "escalate_priv"),
        }
        counters = counter_map.get(blue_action, ())
        return 0.7 if red_action in counters else 0.2


# ═══════════════════════════════════════════════════════════════════════════════
# Episode History
# ═══════════════════════════════════════════════════════════════════════════════


class EpisodeHistory:
    """Ring buffer storing up to 10,000 episodes."""

    MAX_EPISODES = 10000

    def __init__(self):
        self.episodes: deque = deque(maxlen=self.MAX_EPISODES)

    @dataclass
    class Episode:
        state_sequence: List[dict]
        red_actions: List[int]
        blue_actions: List[int]
        red_rewards: List[float]
        blue_rewards: List[float]
        outcome: str  # "red_win", "blue_win", "draw"
        timestamp: float = field(default_factory=time.time)

    def add_episode(
        self,
        states: List[dict],
        red_actions: List[int],
        blue_actions: List[int],
        red_rewards: List[float],
        blue_rewards: List[float],
        outcome: str,
    ) -> None:
        self.episodes.append(
            self.Episode(states, red_actions, blue_actions, red_rewards, blue_rewards, outcome)
        )

    def get_statistics(self) -> dict:
        if not self.episodes:
            return {"total_episodes": 0}

        outcomes = [e.outcome for e in self.episodes]
        red_wins = outcomes.count("red_win")
        blue_wins = outcomes.count("blue_win")
        draws = outcomes.count("draw")
        total = len(outcomes)

        return {
            "total_episodes": total,
            "red_win_rate": red_wins / total,
            "blue_win_rate": blue_wins / total,
            "draw_rate": draws / total,
            "avg_episode_length": sum(len(e.red_actions) for e in self.episodes) / total,
            "avg_red_reward": sum(sum(e.red_rewards) for e in self.episodes) / total,
            "avg_blue_reward": sum(sum(e.blue_rewards) for e in self.episodes) / total,
        }

    def find_similar_episodes(self, state: dict, k: int = 5) -> List[Episode]:
        """Nearest-neighbor search based on state similarity."""
        if not self.episodes:
            return []

        def state_dist(ep: Episode) -> float:
            if not ep.state_sequence:
                return float("inf")
            s = ep.state_sequence[-1]  # Compare final states
            return abs(state.get("compromised_hosts", 0) - s.get("compromised_hosts", 0))

        scored = [(state_dist(e), e) for e in self.episodes]
        scored.sort(key=lambda x: x[0])
        return [e for _, e in scored[:k]]

    def export_training_data(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Export as (states, actions, returns) for supervised training."""
        all_states = []
        all_actions = []
        all_returns = []

        for ep in self.episodes:
            G = 0.0
            returns = []
            for r in reversed(ep.red_rewards):
                G = r + 0.99 * G
                returns.insert(0, G)

            for s, a, G in zip(ep.state_sequence, ep.red_actions, returns):
                feat = np.zeros(64, dtype=np.float32)
                feat[0] = s.get("compromised_hosts", 0) / 100.0
                feat[1] = s.get("detected_intrusions", 0) / 100.0
                feat[2] = 1.0 - s.get("defense_strength", 0.5)
                all_states.append(feat)
                all_actions.append(a)
                all_returns.append(G)

        return np.array(all_states), np.array(all_actions), np.array(all_returns)


# ═══════════════════════════════════════════════════════════════════════════════
# AdversarialSelfPlay — Main Engine
# ═══════════════════════════════════════════════════════════════════════════════


class AdversarialSelfPlay:
    """Orchestrates red/blue self-play training."""

    def __init__(
        self,
        clearance: SecurityClearance = SecurityClearance.RESEARCHER,
        max_episodes: int = 10000,
    ):
        if clearance.value < SecurityClearance.RESEARCHER.value:
            raise PermissionError("AdversarialSelfPlay requires RESEARCHER clearance")

        self.clearance = clearance
        self.max_episodes = max_episodes
        self.red = RedTeamAgent(seed=0)
        self.blue = BlueTeamAgent(seed=1)
        self.env = SecurityEnvironment()
        self.history = EpisodeHistory()
        self.total_episodes = 0

    def run_episode(self, epsilon: float = 0.1) -> dict:
        """Run a single self-play episode.

        Returns:
            Episode summary dict.
        """
        state = self.env.reset()
        states = []
        red_actions = []
        blue_actions = []
        red_rewards = []
        blue_rewards = []
        done = False

        while not done:
            red_obs = self.red.observe(state)
            blue_obs = self.blue.observe(state)

            red_idx, red_name = self.red.act(red_obs, epsilon)
            blue_idx, blue_name = self.blue.act(blue_obs, 0.05)

            next_state, r_reward, b_reward, done = self.env.step(red_idx, blue_idx)

            states.append(state)
            red_actions.append(red_idx)
            blue_actions.append(blue_idx)
            red_rewards.append(r_reward)
            blue_rewards.append(b_reward)

            state = next_state

        # Outcome
        if state["compromised_hosts"] >= 100:
            outcome = "red_win"
        elif state["detected_intrusions"] > state["compromised_hosts"]:
            outcome = "blue_win"
        else:
            outcome = "draw"

        self.history.add_episode(
            states, red_actions, blue_actions, red_rewards, blue_rewards, outcome
        )
        self.total_episodes += 1

        # Online learning every 10 episodes
        if self.total_episodes % 10 == 0:
            self._train_policies()

        return {
            "outcome": outcome,
            "steps": len(states),
            "red_total_reward": sum(red_rewards),
            "blue_total_reward": sum(blue_rewards),
            "final_state": state,
        }

    def train(self, episodes: int) -> dict:
        """Run N training episodes with decaying epsilon."""
        results = {"red_wins": 0, "blue_wins": 0, "draws": 0}

        for i in range(episodes):
            epsilon = max(0.05, 1.0 * (0.99 ** i))
            result = self.run_episode(epsilon)
            results[result["outcome"] + "s"] = results.get(result["outcome"] + "s", 0) + 1
            self.total_episodes += 1

        return results

    def evaluate(self, episodes: int = 100) -> dict:
        """Evaluate without exploration."""
        results = {"red_win": 0, "blue_win": 0, "draw": 0}
        for _ in range(episodes):
            result = self.run_episode(epsilon=0.0)
            results[result["outcome"]] += 1
        return {
            k: v / episodes for k, v in results.items()
        }

    def analyze_weaknesses(self) -> List[ThreatFinding]:
        """Identify gaps in defense strategy."""
        stats = self.history.get_statistics()
        findings = []

        if stats.get("red_win_rate", 0) > 0.5:
            findings.append(
                ThreatFinding(
                    threat_class=ThreatClass.DEFENSE_EVASION,
                    confidence=stats["red_win_rate"],
                    raw_logits=None,
                    uncertainty=0.15,
                    metadata={
                        "finding": "defense_weakness",
                        "red_win_rate": stats["red_win_rate"],
                        "engine": "adversarial_selfplay",
                    },
                )
            )

        return findings

    def generate_adversarial_report(self) -> dict:
        """Generate comprehensive self-play report."""
        stats = self.history.get_statistics()
        return {
            **stats,
            "total_episodes": self.total_episodes,
            "red_agent_avg_reward": (
                sum(self.red.episode_rewards[-100:]) / min(100, len(self.red.episode_rewards))
                if self.red.episode_rewards
                else 0
            ),
            "blue_agent_avg_reward": (
                sum(self.blue.episode_rewards[-100:]) / min(100, len(self.blue.episode_rewards))
                if self.blue.episode_rewards
                else 0
            ),
        }

    def _train_policies(self) -> None:
        """Batch train both policies from history."""
        states, actions, returns = self.history.export_training_data()
        if len(states) > 0:
            self.red.policy.train_step(states, actions, returns, lr=0.0005)


# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    asp = AdversarialSelfPlay(clearance=SecurityClearance.RESEARCHER)
    print("Training 50 episodes...")
    results = asp.train(50)
    print(f"Results: {results}")
    stats = asp.history.get_statistics()
    print(f"Red win rate: {stats.get('red_win_rate', 0):.3f}")
    print(f"Blue win rate: {stats.get('blue_win_rate', 0):.3f}")
