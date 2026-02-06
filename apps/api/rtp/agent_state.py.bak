from __future__ import annotations
import os, json, time
from typing import Any, Dict

EMA_ALPHA = float(os.environ.get("KASBAH_EMA_ALPHA", "0.25"))
COOLDOWN_SEC = float(os.environ.get("KASBAH_EMA_COOLDOWN_SEC", "90"))

DATA_DIR = os.environ.get("KASBAH_DATA_DIR", "/app/data")
FALLBACK_PATH = os.path.join(DATA_DIR, "agent_state.json")

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")

def _now() -> float:
    return time.time()

def _decay_factor(dt: float) -> float:
    if dt <= 0:
        return 1.0
    if COOLDOWN_SEC <= 0:
        return 1.0
    k = dt / COOLDOWN_SEC
    if k < 0: k = 0
    if k > 10: k = 10
    return 1.0 / (1.0 + k)

def _redis_client():
    try:
        import redis  # type: ignore
        return redis.Redis.from_url(REDIS_URL, decode_responses=True)
    except Exception:
        return None

def _redis_key(agent_id: str) -> str:
    return f"kasbah:agent_state:{agent_id}"

def _file_load_all() -> Dict[str, Any]:
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(FALLBACK_PATH):
        return {}
    try:
        with open(FALLBACK_PATH, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}

def _file_save_all(all_state: Dict[str, Any]) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = FALLBACK_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(all_state, f, separators=(",", ":"), sort_keys=True)
    os.replace(tmp, FALLBACK_PATH)

def get_state(agent_id: str) -> Dict[str, Any]:
    agent_id = str(agent_id or "unknown")
    r = _redis_client()
    if r is not None:
        raw = r.get(_redis_key(agent_id))
        if not raw:
            return {"agent_id": agent_id, "ema": 0.0, "last_ts": None, "n": 0, "trend": "flat"}
        try:
            d = json.loads(raw)
            d["agent_id"] = agent_id
            return d
        except Exception:
            return {"agent_id": agent_id, "ema": 0.0, "last_ts": None, "n": 0, "trend": "flat"}

    all_state = _file_load_all()
    d = all_state.get(agent_id)
    if not isinstance(d, dict):
        return {"agent_id": agent_id, "ema": 0.0, "last_ts": None, "n": 0, "trend": "flat"}
    d = dict(d)
    d["agent_id"] = agent_id
    return d

def update_state(agent_id: str, brittleness_now: float, alpha: float = EMA_ALPHA) -> Dict[str, Any]:
    agent_id = str(agent_id or "unknown")
    prev = get_state(agent_id)

    ts = _now()
    last_ts = prev.get("last_ts")
    prev_ema = float(prev.get("ema") or 0.0)
    prev_n = int(prev.get("n") or 0)

    dt = 0.0 if last_ts is None else (ts - float(last_ts))
    cooled = prev_ema * _decay_factor(dt)

    a = float(alpha)
    if a < 0.01: a = 0.01
    if a > 0.95: a = 0.95

    b = float(brittleness_now)
    if b < 0.0: b = 0.0
    if b > 1.0: b = 1.0

    ema = (1.0 - a) * cooled + a * b

    trend = "flat"
    if ema > cooled + 1e-6: trend = "rising"
    if ema < cooled - 1e-6: trend = "falling"

    out = {"ema": ema, "last_ts": ts, "n": prev_n + 1, "trend": trend, "b_last": b}

    r = _redis_client()
    if r is not None:
        r.set(_redis_key(agent_id), json.dumps(out, separators=(",", ":"), sort_keys=True))
    else:
        all_state = _file_load_all()
        all_state[agent_id] = out
        _file_save_all(all_state)

    out["agent_id"] = agent_id
    return out
