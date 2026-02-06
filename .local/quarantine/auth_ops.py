import os, time, hashlib, sqlite3
from typing import Optional, Dict

# Role ordering
_ROLE_RANK = {"observer": 1, "operator": 2, "admin": 3}

# Simple path → minimum role mapping (RBAC perimeter)
PATH_MIN_ROLE = {
    "/api/operators/create": "admin",
    "/api/operators/rotate": "admin",
    "/api/operators/revoke": "admin",
    "/api/operators/list": "admin",

    "/api/agents/register": "operator",
    "/api/agents/list": "observer",

    "/api/rtp/status": "observer",
    "/api/rtp/audit": "observer",
    "/api/rtp/audit/verify": "observer",
    "/api/rtp/decide": "operator",
    "/api/rtp/consume": "operator",
}

def _db_path() -> str:
    return os.environ.get("KASBAH_AUDIT_DB", "/app/data/rtp_audit.sqlite")

def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()

def lookup_operator(api_key: str) -> Optional[Dict]:
    if not api_key:
        return None

    # Dev bootstrap admin (do NOT use in real production)
    bootstrap = os.environ.get("KASBAH_BOOTSTRAP_API_KEY", "")
    if bootstrap and api_key == bootstrap:
        return {"id": 0, "name": "bootstrap-admin", "role": "admin", "created_at": time.time()}

    try:
        db_path = _db_path()
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        con = sqlite3.connect(db_path)

        cur = con.cursor()
        # Ensure schema exists
        cur.execute("""
        CREATE TABLE IF NOT EXISTS operators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            api_key_hash TEXT UNIQUE NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        )
        """)
        con.commit()

        h = _hash_key(api_key)
        cur.execute(
            "SELECT id, name, role, revoked, created_at FROM operators WHERE api_key_hash=? LIMIT 1",
            (h,),
        )
        row = cur.fetchone()
        con.close()

        if not row:
            return None
        if int(row[3]) == 1:
            return None
        return {"id": row[0], "name": row[1], "role": row[2], "created_at": row[4]}
    except Exception:
        return None

def role_allows(actual_role: str, min_role: str) -> bool:
    return _ROLE_RANK.get(actual_role, 0) >= _ROLE_RANK.get(min_role, 999)

def min_role_for_path(path: str) -> Optional[str]:
    if path in PATH_MIN_ROLE:
        return PATH_MIN_ROLE[path]
    if path.startswith("/api/operators/"):
        return "admin"
    if path.startswith("/api/rtp/"):
        return "operator"
    if path.startswith("/api/agents/"):
        return "operator"
    return None
