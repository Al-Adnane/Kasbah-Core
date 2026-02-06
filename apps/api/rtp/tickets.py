import time, secrets

def _sign(payload: dict) -> str:
    import hashlib, json
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()

def mint_ticket(tool_name: str, args: dict, ttl_seconds: int = 60, agent_id: str = "anonymous", ema: float = 0.0, geom: float = 0.0) -> dict:
    now = int(time.time())
    ticket = {
        "jti": secrets.token_hex(16),
        "tool_name": str(tool_name),
        "agent_id": str(agent_id),
        "ema": float(ema),
        "geom": float(geom),
        "args": args or {},
        "iat": now,
        "exp": now + max(1, int(ttl_seconds)),
        "nonce": secrets.token_hex(16),
        "v": 1,
    }
    ticket["sig"] = _sign({k: ticket[k] for k in ("jti","tool_name","agent_id","ema","geom","args","iat","exp","nonce","v")})
    return ticket

def _replay_key(jti: str) -> str:
    return f"kasbah:rtp:consumed:{jti}"

def _replay_lock_redis(jti: str, ttl_seconds: int) -> bool:
    import os
    host = os.environ.get("REDIS_HOST", "redis")
    port = int(os.environ.get("REDIS_PORT", "6379"))
    try:
        import redis
        r = redis.Redis(host=host, port=port, db=0, socket_timeout=1, socket_connect_timeout=1)
        key = _replay_key(jti)
        ok = r.set(name=key, value="1", nx=True, ex=max(1, int(ttl_seconds)))
        return bool(ok)
    except Exception:
        return False

def _replay_lock_sqlite(jti: str, exp_ts: int) -> bool:
    import os, sqlite3
    db = os.environ.get("KASBAH_REPLAY_DB", "/app/data/rtp_replay.sqlite")
    con = sqlite3.connect(db)
    cur = con.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS consumed (jti TEXT PRIMARY KEY, exp INTEGER)")
    now = int(time.time())
    cur.execute("DELETE FROM consumed WHERE exp < ?", (now,))
    try:
        cur.execute("INSERT INTO consumed (jti, exp) VALUES (?, ?)", (jti, int(exp_ts)))
        con.commit()
        return True
    except Exception:
        con.rollback()
        return False
    finally:
        con.close()

def consume_ticket(ticket: dict, tool_name: str):
    now = int(time.time())
    exp = int(ticket.get("exp", 0))
    if now > exp:
        return False, "expired"
    if str(ticket.get("tool_name")) != str(tool_name):
        return False, "tool mismatch"

    expected_agent = ticket.get("agent_id")
    provided_agent = ticket.get("provided_agent_id")
    if expected_agent is not None and provided_agent is not None:
        if str(expected_agent) != str(provided_agent):
            return False, "agent mismatch"

    expected = _sign({k: ticket[k] for k in ("jti","tool_name","agent_id","ema","geom","args","iat","exp","nonce","v")})
    if expected != str(ticket.get("sig")):
        return False, "bad signature"

    jti = str(ticket.get("jti"))
    ttl = max(1, exp - now)

    if _replay_lock_redis(jti, ttl):
        return True, "consumed"

    if _replay_lock_sqlite(jti, exp):
        return True, "consumed"

    return False, "replay_or_store_failure"
