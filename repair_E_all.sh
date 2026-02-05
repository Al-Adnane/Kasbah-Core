#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "==[1/7] sanity: repo root = $(pwd)"
ls -la docker-compose.yml >/dev/null

echo "==[2/7] ensure data dir exists (host)"
mkdir -p data

echo "==[3/7] write safe agent_state (Redis if available, else file)"
mkdir -p apps/api/rtp
cat <<'PY' > apps/api/rtp/agent_state.py
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
PY

echo "==[4/7] write state endpoint router"
cat <<'PY' > apps/api/rtp/state_api.py
from fastapi import APIRouter
from apps.api.rtp.agent_state import get_state

router = APIRouter()

@router.get("/api/rtp/agent/{agent_id}/state")
def agent_state(agent_id: str):
    return get_state(agent_id)
PY

echo "==[5/7] patch kernel_gate.py (single source of truth for decide payload)"
python3 - <<'PY'
from pathlib import Path
import re

p = Path("apps/api/rtp/kernel_gate.py")
s = p.read_text(errors="ignore")

# ensure import
imp = "from apps.api.rtp.agent_state import update_state"
if imp not in s:
    lines = s.splitlines()
    ins = 0
    for i,l in enumerate(lines[:140]):
        if l.startswith("import ") or l.startswith("from "):
            ins = i+1
    lines.insert(ins, imp)
    s = "\n".join(lines)

# ensure response dict includes agent_state + agent_state_error
if '"pre_defense_state"' not in s:
    raise SystemExit("kernel_gate.py: cannot find pre_defense_state response dict")

if '"agent_state"' not in s:
    s = s.replace(
        '"pre_defense_state": pre_defense_state,',
        '"pre_defense_state": pre_defense_state,\n            "agent_state": agent_state,\n            "agent_state_error": agent_state_error,',
        1
    )
elif '"agent_state_error"' not in s:
    s = s.replace(
        '"pre_defense_state": pre_defense_state,',
        '"pre_defense_state": pre_defense_state,\n            "agent_state_error": agent_state_error,',
        1
    )

# Replace/insert the E hook in a controlled way:
# - define agent_state + agent_state_error before returning
hook = """
        # --- E: per-agent stateful risk (EMA brittleness) ---
        agent_state_error = None
        try:
            _aid = str(agent_id or "unknown")

            _sig = signals
            _n = None

            if isinstance(_sig, dict):
                for k in ("normality", "normality_score", "normalityScore"):
                    if k in _sig:
                        _n = _sig.get(k)
                        break
            else:
                for k in ("normality", "normality_score", "normalityScore"):
                    if hasattr(_sig, k):
                        _n = getattr(_sig, k)
                        break

            if _n is None:
                _n = 1.0
            try:
                _n = float(_n)
            except Exception:
                _n = 1.0

            _b = 1.0 - _n
            if _b < 0.0: _b = 0.0
            if _b > 1.0: _b = 1.0

            agent_state = update_state(_aid, _b)
        except Exception as e:
            agent_state = None
            agent_state_error = repr(e)
"""

# remove any previous E hook block we added (best-effort)
s = re.sub(r"\n\s*# --- E: per-agent stateful risk.*?\n\s*agent_state = None\s*\n", "\n", s, flags=re.S)
s = re.sub(r"\n\s*# --- E: per-agent stateful risk.*?agent_state_error\s*=.*?\n", "\n", s, flags=re.S)

# insert hook right before return { ... "decision": ... } for decide response
m = re.search(r"\n(\s*)return\s*\{\s*\n\s*\"decision\"", s)
if not m:
    raise SystemExit("kernel_gate.py: cannot locate return dict start")
insert_at = m.start()
s = s[:insert_at] + hook + s[insert_at:]

p.write_text(s)
print("OK kernel_gate.py")
PY

echo "==[6/7] include state router in main.py (idempotent)"
python3 - <<'PY'
from pathlib import Path
p = Path("apps/api/main.py")
s = p.read_text(errors="ignore")
if "apps.api.rtp.state_api" not in s:
    s += "\nfrom apps.api.rtp.state_api import router as rtp_state_router\napp.include_router(rtp_state_router)\n"
p.write_text(s)
print("OK main.py router include")
PY

echo "==[7/7] rebuild + hard restart"
docker compose down
docker compose up -d --build

echo "== health =="
curl -sS http://localhost:8002/health ; echo

echo "== decide (expect agent_state not null, b_last ~0.99, ema > 0) =="
curl -sS -X POST http://localhost:8002/api/rtp/decide \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"read.me","agent_id":"smoke","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.01,"latency_score":0.99}}' \
| python3 - <<'PY'
import sys,json
d=json.load(sys.stdin)
print("agent_state_error=", d.get("agent_state_error"))
print("agent_state=", d.get("agent_state"))
PY

echo "== state endpoint (must be 200) =="
curl -sS http://localhost:8002/api/rtp/agent/smoke/state ; echo

echo "DONE: E++++ baseline stabilized"
