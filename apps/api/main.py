
import base64
import hashlib
import hmac
import json
import os
import time
import fcntl
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field


# __KASBAH_REPLAY_GUARD_V1__
def _ticket_fp(ticket: str) -> str:
    return hashlib.sha256(ticket.encode("utf-8")).hexdigest()

def _remaining_ttl_from_payload(payload: dict, default_ttl: int = 600) -> int:
    """
    Computes remaining TTL seconds from verified ticket payload.
    Expected keys (best-effort):
      - ttl_sec (int)
      - issued_ns (int nanoseconds)
    Falls back to default_ttl if missing/invalid.
    """
    try:
        ttl = int(payload.get("ttl_sec") or default_ttl)
    except Exception:
        ttl = int(default_ttl)
    try:
        issued_ns = int(payload.get("issued_ns") or 0)
    except Exception:
        issued_ns = 0
    if issued_ns > 0:
        issued_s = issued_ns / 1e9
        remaining = int((issued_s + ttl) - time.time())
        return max(1, remaining)
    return max(1, ttl)

def _mark_consumed_once(ticket: str, payload: dict) -> bool:
    """
    Returns True if ticket is newly marked consumed, False if replay.
    Atomic in Redis. Fail-closed if Redis unavailable.
    """
    ttl = _remaining_ttl_from_payload(payload, 600)
    key = "kasbah:ticket:consumed:" + _ticket_fp(ticket)
    try:
        rc = _redis_client()  # exists in this file
    except Exception:
        rc = None
    if rc is None:
        return False
    try:
        ok = rc.set(key, "1", nx=True, ex=ttl)
        return bool(ok)
    except Exception:
        return False

APP_NAME = "Kasbah Core"
APP_VERSION = os.environ.get("KASBAH_VERSION", "dev")

API_KEY = os.environ.get("API_KEY", "dev-master-key").encode("utf-8")
TICKET_TTL_SEC = int(os.environ.get("TICKET_TTL_SEC", "600"))
KASBAH_AUTHZ = os.environ.get("KASBAH_AUTHZ", "1").strip().lower() in ("1", "true", "yes", "on")

DATA_DIR = Path(os.environ.get("KASBAH_DATA_DIR", ".kasbah"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
AUDIT_PATH = DATA_DIR / "audit.jsonl"
AUDIT_LOCK_PATH = (DATA_DIR_PATH / "audit.lock")


REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")

# __KASBAH_BEARER_AUTH_V1__
KASBAH_REQUIRE_BEARER = os.environ.get("KASBAH_REQUIRE_BEARER", "0").strip().lower() in ("1","true","yes","on")
KASBAH_BEARER_TOKENS = [t.strip() for t in os.environ.get("KASBAH_BEARER_TOKENS","").split(",") if t.strip()]

def _check_bearer(request: "Request") -> None:
    """
    Identity gate (optional). This is NOT the same as tickets.
    If enabled, requires Authorization: Bearer <token> for /api/*.
    """
    if not KASBAH_REQUIRE_BEARER:
        return
    if request.method.upper() == "OPTIONS":
        return
    path = request.url.path or ""
    if not path.startswith("/api/"):
        return

    auth = request.headers.get("authorization") or request.headers.get("Authorization") or ""
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = auth.split(" ", 1)[1].strip()
    allowed = KASBAH_BEARER_TOKENS[:] if KASBAH_BEARER_TOKENS else [API_KEY.decode("utf-8", errors="ignore")]
    ok = any(hmac.compare_digest(token, t) for t in allowed)
    if not ok:
        raise HTTPException(status_code=401, detail="invalid bearer token")

# __KASBAH_THERMO_LOCKDOWN_V1__
KASBAH_THERMO_FORCE = os.environ.get("KASBAH_THERMO_FORCE","0").strip().lower() in ("1","true","yes","on")
KASBAH_THERMO_EMA_MS_THRESHOLD = float(os.environ.get("KASBAH_THERMO_EMA_MS_THRESHOLD","300"))
KASBAH_THERMO_ALPHA = float(os.environ.get("KASBAH_THERMO_ALPHA","0.20"))
KASBAH_THERMO_COOLDOWN_SEC = int(os.environ.get("KASBAH_THERMO_COOLDOWN_SEC","10"))

def _thermo_keys() -> tuple[str,str]:
    return ("kasbah:thermo:ema_ms", "kasbah:thermo:lock_until")

def _thermo_is_locked() -> bool:
    if KASBAH_THERMO_FORCE:
        return True
    rc = _redis_client()
    if rc is None:
        return False  # don't fail closed on thermo; thermo is a safety brake, not core security
    _, k_lock = _thermo_keys()
    try:
        v = rc.get(k_lock)
        if not v:
            return False
        return float(v) > time.time()
    except Exception:
        return False

def _thermo_update(lat_ms: float) -> None:
    rc = _redis_client()
    if rc is None:
        return
    k_ema, k_lock = _thermo_keys()
    try:
        cur = rc.get(k_ema)
        if cur is None:
            ema = float(lat_ms)
        else:
            ema0 = float(cur)
            ema = (KASBAH_THERMO_ALPHA * float(lat_ms)) + ((1.0 - KASBAH_THERMO_ALPHA) * ema0)
        rc.set(k_ema, str(ema), ex=3600)

        if ema >= KASBAH_THERMO_EMA_MS_THRESHOLD:
            rc.set(k_lock, str(time.time() + float(KASBAH_THERMO_COOLDOWN_SEC)), ex=max(2, KASBAH_THERMO_COOLDOWN_SEC + 2))
    except Exception:
        return

# __KASBAH_BRITTLENESS_V1__
KASBAH_BRITTLE_ENABLE = os.environ.get("KASBAH_BRITTLE_ENABLE","1").strip().lower() in ("1","true","yes","on")
KASBAH_BRITTLE_STRIKES = int(os.environ.get("KASBAH_BRITTLE_STRIKES","5"))
KASBAH_BRITTLE_WINDOW_SEC = int(os.environ.get("KASBAH_BRITTLE_WINDOW_SEC","600"))
KASBAH_BRITTLE_LOCK_SEC = int(os.environ.get("KASBAH_BRITTLE_LOCK_SEC","120"))

def _brittle_lock_key(agent_id: str) -> str:
    return f"kasbah:brittle:lock:{agent_id}"

def _brittle_strike_key(agent_id: str) -> str:
    return f"kasbah:brittle:strikes:{agent_id}"

def _brittle_is_locked(agent_id: str) -> bool:
    if not KASBAH_BRITTLE_ENABLE:
        return False
    rc = _redis_client()
    if rc is None:
        return False
    try:
        v = rc.get(_brittle_lock_key(agent_id))
        if not v:
            return False
        return float(v) > time.time()
    except Exception:
        return False

def _brittle_add_strike(agent_id: str) -> None:
    if not KASBAH_BRITTLE_ENABLE:
        return
    rc = _redis_client()
    if rc is None:
        return
    try:
        k = _brittle_strike_key(agent_id)
        n = rc.incr(k)
        rc.expire(k, KASBAH_BRITTLE_WINDOW_SEC)
        if int(n) >= KASBAH_BRITTLE_STRIKES:
            rc.set(_brittle_lock_key(agent_id), str(time.time() + float(KASBAH_BRITTLE_LOCK_SEC)), ex=max(2, KASBAH_BRITTLE_LOCK_SEC + 2))
    except Exception:
        return




def _redis_client():
    try:
        import redis  # type: ignore
        return redis.Redis.from_url(REDIS_URL, decode_responses=True)
    except Exception:
        return None





# __KASBAH_MOATS_V2__
KASBAH_RL_DECIDE_LIMIT = int(os.environ.get("KASBAH_RL_DECIDE_LIMIT", "60"))
KASBAH_RL_DECIDE_WINDOW_SEC = int(os.environ.get("KASBAH_RL_DECIDE_WINDOW_SEC", "60"))
KASBAH_RL_CONSUME_LIMIT = int(os.environ.get("KASBAH_RL_CONSUME_LIMIT", "120"))
KASBAH_RL_CONSUME_WINDOW_SEC = int(os.environ.get("KASBAH_RL_CONSUME_WINDOW_SEC", "60"))

def _admin_token_ok(authorization: Optional[str]) -> bool:
    if not authorization:
        return False
    if not authorization.lower().startswith("bearer "):
        return False
    token = authorization.split(" ", 1)[1].strip()
    try:
        key_txt = API_KEY.decode("utf-8")
    except Exception:
        key_txt = "dev-master-key"
    return hmac.compare_digest(token, key_txt)

def _require_admin(authorization: Optional[str]) -> None:
    if not _admin_token_ok(authorization):
        raise HTTPException(status_code=403, detail="admin denied")

def _rl_check(bucket: str, limit: int, window_sec: int) -> int:
    """Returns remaining requests in the current window; fail-open if Redis unavailable."""
    rc = _redis_client()
    if rc is None:
        return limit
    key = f"kasbah:rl:{bucket}"
    try:
        n = int(rc.incr(key, 1))
        if n == 1:
            rc.expire(key, max(1, int(window_sec)))
        return int(limit) - n
    except Exception:
        return limit

def _em_key_all() -> str:
    return "kasbah:emergency:all"

def _em_key_tool(tool_name: str) -> str:
    return f"kasbah:emergency:tool:{tool_name}"

def _em_key_principal(principal: str) -> str:
    return f"kasbah:emergency:principal:{principal}"

def _emergency_blocked(tool_name: str, principal: Optional[str]) -> Optional[str]:
    rc = _redis_client()
    if rc is None:
        return None
    try:
        if rc.get(_em_key_all()):
            return "emergency:all"
        if tool_name and rc.get(_em_key_tool(tool_name)):
            return "emergency:tool"
        if principal and rc.get(_em_key_principal(principal)):
            return "emergency:principal"
    except Exception:
        return None
    return None

def _audit_hash_line(prev_hex: str, line: str) -> str:
    h = hashlib.sha256()
    h.update((prev_hex or "").encode("utf-8"))
    h.update(b"\n")
    h.update(line.encode("utf-8"))
    return h.hexdigest()

app = FastAPI(title=APP_NAME, version=APP_VERSION)

@app.middleware("http")
async def kasbah_security_middleware(request: Request, call_next):
    _check_bearer(request)

    # thermo gate (optional)
    if (request.url.path or "").startswith("/api/") and request.method.upper() != "OPTIONS":
        if _thermo_is_locked():
            raise HTTPException(status_code=503, detail="thermo lockdown")

    t0 = time.time()
    resp = await call_next(request)
    lat_ms = (time.time() - t0) * 1000.0

    # update thermo after response
    if (request.url.path or "").startswith("/api/") and request.method.upper() != "OPTIONS":
        _thermo_update(lat_ms)

    return resp



def _now_ns() -> int:
    return time.time_ns()


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _sign(payload_b64: str) -> str:
    sig = hmac.new(API_KEY, payload_b64.encode("utf-8"), hashlib.sha256).digest()
    return _b64url_encode(sig)


def _hash_tool_args(tool_name: str, args: Any) -> str:
    try:
        s = json.dumps({"tool": tool_name, "args": args}, sort_keys=True, separators=(",", ":"))
    except Exception:
        s = json.dumps({"tool": tool_name, "args": str(args)}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def append_audit(event: str, agent_id: str, jti: Optional[str], extra: Optional[Dict[str, Any]] = None) -> None:
    """
    Append hash-chained audit record.
    IMPORTANT: This must be globally serialized; otherwise concurrent requests create many chain breaks.
    """
    rec = {
        "ts_ns": _now_ns(),
        "event": event,
        "agent_id": agent_id,
        "jti": jti,
        "extra": extra or {},
    }

    # Ensure dir exists
    try:
        DATA_DIR_PATH.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    # Global critical section: lock -> read last hash -> append line -> fsync -> unlock
    prev = ""
    tmp = dict(rec)
    tmp.pop("hash", None)
    line = json.dumps(tmp, separators=(",", ":"), sort_keys=True)

    try:
        with open(AUDIT_LOCK_PATH, "a+", encoding="utf-8") as lockf:
            try:
                fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
            except Exception:
                # If lock fails, fail-open (still write, but chain might break)
                pass

            try:
                if AUDIT_PATH.exists():
                    try:
                        lines = AUDIT_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
                        if lines:
                            try:
                                last = json.loads(lines[-1])
                                if isinstance(last, str):
                                    last = json.loads(last)
                                prev = str(last.get("hash", ""))[:64]
                            except Exception:
                                prev = ""
                    except Exception:
                        prev = ""
            except Exception:
                prev = ""

            rec["prev_hash"] = prev
            rec["hash"] = _audit_hash_line(prev, line)

            out_line = json.dumps(rec, separators=(",", ":"), sort_keys=True)

            with open(AUDIT_PATH, "a", encoding="utf-8") as f:
                f.write(out_line + "\n")
                try:
                    f.flush()
                    import os
                    os.fsync(f.fileno())
                except Exception:
                    pass

            try:
                fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
    except Exception:
        # ultimate fail-open: do not crash request path
        return


@app.get("/")
def root():
    return {"name": APP_NAME, "status": "running", "version": APP_VERSION}


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/api/rtp/decide", response_model=DecisionResponse)
def rtp_decide(req: DecisionRequest):
    agent_id = req.agent_id or "anon"

    if _brittle_is_locked(agent_id):
        raise HTTPException(status_code=403, detail="brittle lock")

    args = (req.usage or {}).get("args", {}) if isinstance(req.usage, dict) else {}

    rl_rem = _rl_check(
        f"decide:{agent_id}",
        KASBAH_RL_DECIDE_LIMIT,
        KASBAH_RL_DECIDE_WINDOW_SEC,
    )
    if rl_rem < 0:
        raise HTTPException(status_code=429, detail="rate limited (decide)")

    claims = {}

    if KASBAH_AUTHZ:
        principal = req.principal or agent_id
        action = req.action
        resource = req.resource
        acting_as = req.acting_as

        if not principal or not action or not resource:
            append_audit(
                "AUTHZ_DENY",
                agent_id=agent_id,
                jti=None,
                extra={"reason": "missing principal/action/resource"},
            )
            raise HTTPException(
                status_code=403,
                detail="missing principal/action/resource",
            )

        az = _authz_check(
            principal=principal,
            action=action,
            resource=resource,
            acting_as=acting_as,
        )

        if not az.allow:
            append_audit(
                "AUTHZ_DENY",
                agent_id=agent_id,
                jti=None,
                extra={
                    "principal": principal,
                    "action": action,
                    "resource": resource,
                    "acting_as": acting_as,
                    "reason": az.reason,
                },
            )
            raise HTTPException(
                status_code=403,
                detail=f"authz deny: {az.reason}",
            )

        claims = {
            "principal": principal,
            "action": action,
            "resource": resource,
            "acting_as": acting_as,
        }

    em = _emergency_blocked(req.tool_name, req.principal or agent_id)
    if em:
        append_audit(
            "DECIDE_DENY",
            agent_id=agent_id,
            jti=None,
            extra={"tool_name": req.tool_name, "reason": em},
        )
        raise HTTPException(status_code=403, detail=em)

    token = generate_ticket(req.tool_name, agent_id, args, claims)

    try:
        payload = json.loads(
            _b64url_decode(token.split(".", 1)[0]).decode("utf-8")
        )
        append_audit(
            "DECIDE",
            agent_id=agent_id,
            jti=payload.get("jti"),
            extra={"tool_name": req.tool_name},
        )
    except Exception:
        pass

    return DecisionResponse(
        decision="ALLOW",
        decision_kind="DECIDE_ALLOW",
        reason="ok",
        rule_id="RTP-ALLOW-001",
        ticket=token,
        explain="Policy checks passed.",
    )




@app.get("/api/rtp/audit/export")
def rtp_audit_export(limit: int = 2000, authorization: Optional[str] = Header(default=None)):
    """
    Admin-only export of hash-chained audit log lines (newline-delimited JSON records).
    """
    _require_admin(authorization)
    try:
        if not AUDIT_PATH.exists():
            return {"meta": {"exported_at_ns": _now_ns(), "version": APP_VERSION}, "lines": [], "last_hash": ""}
        lines = AUDIT_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
        if limit and limit > 0:
            lines = lines[-int(limit):]
        last_hash = ""
        if lines:
            try:
                last = json.loads(lines[-1])
                last_hash = str(last.get("hash", ""))
            except Exception:
                last_hash = ""
        return {
            "meta": {"exported_at_ns": _now_ns(), "version": APP_VERSION},
            "lines": lines,
            "last_hash": last_hash,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/rtp/consume", response_model=ConsumeResponse)
def rtp_consume(req: ConsumeRequest, authorization: Optional[str] = Header(default=None)):
    ticket = req.ticket
    tool_name = req.tool_name or "unknown"
    agent_id = req.agent_id or "anon"
    if _brittle_is_locked(agent_id):
        raise HTTPException(status_code=403, detail="brittle lock")
    args = (req.usage or {}).get("args", {}) if isinstance(req.usage, dict) else {}

    rl_rem = _rl_check(f"consume:{agent_id}", KASBAH_RL_CONSUME_LIMIT, KASBAH_RL_CONSUME_WINDOW_SEC)
    if rl_rem < 0:
        raise HTTPException(status_code=429, detail="rate limited (consume)")
    try:
              # __BRITTLE_STRIKE_ON_VERIFY_FAIL_V1__
      try:
          payload = verify_ticket(ticket, tool_name, args)
      except HTTPException as e:
          # Any ticket failure is a strike for this agent_id (tamper / swap / expiry / format).
          try:
              _brittle_add_strike(agent_id, reason=str(getattr(e, 'detail', 'verify_fail')))
              append_audit("BRITTLE_STRIKE", agent_id=agent_id, jti=None, extra={"reason": str(getattr(e, 'detail', 'verify_fail')), "status": int(getattr(e, 'status_code', 0) or 0)})
          except Exception:
              pass
          raise

    except HTTPException as e:
        if int(getattr(e, "status_code", 0)) in (400, 401, 403):
            _brittle_add_strike(agent_id)
        raise
    # emergency gate (consume)
    _claims = payload.get("claims", {}) or {}
    _principal = _claims.get("principal") or agent_id
    em = _emergency_blocked(tool_name, str(_principal))
    if em:
        append_audit("CONSUME_DENY", agent_id=agent_id, jti=payload.get("jti"), extra={"tool_name": tool_name, "reason": em})
        raise HTTPException(status_code=403, detail=em)
    # replay protection: consume once (fail-closed)
    if not _mark_consumed_once(req.ticket, payload):
        raise HTTPException(status_code=403, detail="replay")
    if KASBAH_AUTHZ:
        claims = payload.get("claims", {}) or {}
        principal = claims.get("principal")
        action = claims.get("action")
        resource = claims.get("resource")
        acting_as = claims.get("acting_as")
        if not principal or not action or not resource:
            raise HTTPException(status_code=403, detail="missing authz claims")
        az = _authz_check(principal=str(principal), action=str(action), resource=str(resource), acting_as=(str(acting_as) if acting_as else None))
        if not az.allow:
            raise HTTPException(status_code=403, detail=f"authz deny: {az.reason}")

    try:
        append_audit("CONSUME", agent_id=agent_id, jti=payload.get("jti"), extra={"tool_name": tool_name})
    except Exception:
        pass

    return ConsumeResponse(status="ALLOWED", action="execute", tool=tool_name, consumed_at=time.time())



@app.get("/api/system/emergency/status")
def emergency_status(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_admin(authorization)
    rc = _redis_client()
    if rc is None:
        return {"redis": False, "all": False}
    return {"redis": True, "all": bool(rc.get(_em_key_all()))}

@app.post("/api/system/emergency/disable_all")
def emergency_disable_all(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_admin(authorization)
    rc = _redis_client()
    if rc is None:
        raise HTTPException(status_code=500, detail="redis unavailable")
    rc.set(_em_key_all(), "1")
    return {"ok": True, "all": True}

@app.post("/api/system/emergency/enable_all")
def emergency_enable_all(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_admin(authorization)
    rc = _redis_client()
    if rc is None:
        raise HTTPException(status_code=500, detail="redis unavailable")
    rc.delete(_em_key_all())
    return {"ok": True, "all": False}

@app.post("/api/system/emergency/disable_tool/{tool_name}")
def emergency_disable_tool(tool_name: str, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_admin(authorization)
    rc = _redis_client()
    if rc is None:
        raise HTTPException(status_code=500, detail="redis unavailable")
    rc.set(_em_key_tool(tool_name), "1")
    return {"ok": True, "tool": tool_name, "disabled": True}

@app.post("/api/system/emergency/enable_tool/{tool_name}")
def emergency_enable_tool(tool_name: str, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_admin(authorization)
    rc = _redis_client()
    if rc is None:
        raise HTTPException(status_code=500, detail="redis unavailable")
    rc.delete(_em_key_tool(tool_name))
    return {"ok": True, "tool": tool_name, "disabled": False}


@app.get("/api/rtp/explain/{jti}")
def rtp_explain(jti: str, limit: int = 200) -> Dict[str, Any]:
    if not AUDIT_PATH.exists():
        return {"jti": jti, "found": False, "trace": []}
    lines = AUDIT_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    trace = []
    for ln in lines[-max(1, min(limit, 2000)):]:
        try:
            rec = json.loads(ln)
        except Exception:
            continue
        if str(rec.get("jti") or "") == str(jti):
            trace.append(rec)
    return {"jti": jti, "found": bool(trace), "trace": trace}


@app.get("/api/rtp/audit")
def rtp_audit(limit: int = 200, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    try:
        if not AUDIT_PATH.exists():
            return {"events": []}
        lines = AUDIT_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
        out = []
        for ln in lines[-max(1, min(limit, 2000)):]:
            try:
                out.append(json.loads(ln))
            except Exception:
                continue
        return {"events": out}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


try:
    from apps.api.rtp.authz_api import router as authz_router  # type: ignore
    app.include_router(authz_router, prefix="/api/authz")
except Exception:
    pass
