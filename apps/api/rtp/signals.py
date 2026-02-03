from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

DEFAULT_SIGNALS = {
    "consistency": 0.95,
    "pred_accuracy": 0.95,
    "normality": 0.95,
}

def _now() -> float:
    return time.time()

def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x

@dataclass
class SignalTracker:
    """
    Maintains per-agent exponentially-decayed signals with half-life.
    Append-only persistence to survive restarts.
    """
    path: Path = field(default_factory=lambda: Path(
        os.getenv("KASBAH_SIGNAL_LOG_PATH")
        or ("/app/.kasbah/rtp_signal_state.jsonl" if Path("/app").exists() else ".kasbah/rtp_signal_state.jsonl")
    ))
    half_life_s: float = field(default_factory=lambda: float(os.getenv(
        "KASBAH_SIGNAL_HALFLIFE_SECONDS",
        "600"  # 10 minutes
    )))
    state: Dict[str, Dict[str, float]] = field(default_factory=dict)
    last_ts: Dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            for line in self.path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    agent_id = str(obj.get("agent_id") or "anon")
                    ts = float(obj.get("ts") or 0.0)
                    sig = obj.get("signals") or {}
                    if isinstance(sig, dict):
                        self.state[agent_id] = {k: float(sig.get(k, DEFAULT_SIGNALS[k])) for k in DEFAULT_SIGNALS}
                        self.last_ts[agent_id] = ts or self.last_ts.get(agent_id, 0.0)
                except Exception:
                    continue
        except Exception:
            return

    def _persist(self, agent_id: str, signals: Dict[str, float], ts: float) -> None:
        try:
            obj = {"agent_id": agent_id, "ts": ts, "signals": signals}
            line = json.dumps(obj, separators=(",", ":")) + "\n"
            with self.path.open("a") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            # Never crash enforcement on logging failure
            pass

    def _decay_factor(self, dt: float) -> float:
        # Half-life decay: after half_life_s seconds, weight of old value halves
        if self.half_life_s <= 0:
            return 0.0
        return 0.5 ** (dt / self.half_life_s)

    def update(self, agent_id: Optional[str], raw: Dict[str, float]) -> Dict[str, float]:
        agent = str(agent_id or "anon")
        ts = _now()

        prev = self.state.get(agent, DEFAULT_SIGNALS.copy())
        prev_ts = self.last_ts.get(agent, ts)

        dt = max(0.0, ts - prev_ts)
        decay = self._decay_factor(dt)

        # EMA with decay:
        # new = prev*decay + raw*(1-decay)
        out: Dict[str, float] = {}
        for k in DEFAULT_SIGNALS:
            r = _clamp01(float(raw.get(k, DEFAULT_SIGNALS[k])))
            p = _clamp01(float(prev.get(k, DEFAULT_SIGNALS[k])))
            out[k] = _clamp01(p * decay + r * (1.0 - decay))

        self.state[agent] = out
        self.last_ts[agent] = ts
        self._persist(agent, out, ts)
        return out
