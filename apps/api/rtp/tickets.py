import time, secrets

_CONSUMED = set()

def _sign(payload: dict) -> str:
    # demo signature: deterministic-ish
    # replace with ed25519/hmac in production
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

def consume_ticket(ticket: dict, tool_name: str):
    now = int(time.time())
    if now > int(ticket.get("exp", 0)):
        return False, "expired"
    if str(ticket.get("tool_name")) != str(tool_name):
        return False, "tool mismatch"
    # session binding: agent_id must match when provided by caller
    expected_agent = ticket.get("agent_id")
    provided_agent = ticket.get("provided_agent_id")
    if expected_agent is not None and provided_agent is not None:
        if str(expected_agent) != str(provided_agent):
            return False, "agent mismatch"
    expected = _sign({k: ticket[k] for k in ("jti","tool_name","agent_id","ema","geom","args","iat","exp","nonce","v")})
    if expected != str(ticket.get("sig")):
        return False, "bad signature"
    jti = str(ticket.get("jti"))
    if jti in _CONSUMED:
        return False, "replay"
    _CONSUMED.add(jti)
    return True, "consumed"
