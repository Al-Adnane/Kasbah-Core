import hashlib
import secrets
import time
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import json

class OperatorKeyManager:
    def __init__(self, db_path=".kasbeth_keys.db"):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_db()
    
    def _init_db(self):
        """Initialize the operator keys database"""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS operator_keys (
                key_id TEXT PRIMARY KEY,
                operator_id TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                description TEXT DEFAULT '',
                created_at REAL NOT NULL,
                expires_at REAL,
                revoked_at REAL,
                last_used_at REAL,
                last_used_from TEXT,
                usage_count INTEGER DEFAULT 0,
                metadata TEXT DEFAULT '{}',
                
                FOREIGN KEY (operator_id) REFERENCES operators(id)
            )
        """)
        
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS key_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                operator_id TEXT NOT NULL,
                key_id TEXT,
                action TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                details TEXT DEFAULT '{}'
            )
        """)
        
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS operators (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE,
                role TEXT DEFAULT 'operator',
                created_at REAL NOT NULL,
                last_active REAL,
                is_active INTEGER DEFAULT 1
            )
        """)
        
        self.conn.commit()
    
    def create_operator(self, operator_id: str, name: str, email: Optional[str] = None, role: str = "operator") -> bool:
        """Create a new operator"""
        try:
            self.conn.execute(
                "INSERT INTO operators (id, name, email, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (operator_id, name, email, role, time.time())
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def create_key(self, operator_id: str, ttl_days: int = 90, description: str = "") -> Tuple[Optional[str], Optional[str]]:
        """Create a new API key for an operator"""
        
        # Verify operator exists
        cur = self.conn.execute("SELECT 1 FROM operators WHERE id = ? AND is_active = 1", (operator_id,))
        if not cur.fetchone():
            return None, "Operator not found or inactive"
        
        # Generate key
        key = f"kasbah_sk_live_{secrets.token_urlsafe(32)}"
        key_id = key[:12]  # First 12 chars as key ID
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        expires_at = time.time() + (ttl_days * 86400)
        
        try:
            self.conn.execute("""
                INSERT INTO operator_keys 
                (key_id, operator_id, key_hash, description, created_at, expires_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (key_id, operator_id, key_hash, description, time.time(), expires_at, json.dumps({"created_via": "api"})))
            
            # Log the creation
            self._audit_log(
                operator_id=operator_id,
                key_id=key_id,
                action="key_created",
                details={"ttl_days": ttl_days, "description": description}
            )
            
            self.conn.commit()
            return key, key_id
        except sqlite3.IntegrityError:
            return None, "Key already exists"
    
    def revoke_key(self, operator_id: str, key_id: str) -> bool:
        """Revoke an operator key"""
        cur = self.conn.execute(
            "UPDATE operator_keys SET revoked_at = ? WHERE key_id = ? AND operator_id = ? AND revoked_at IS NULL",
            (time.time(), key_id, operator_id)
        )
        
        if cur.rowcount > 0:
            self._audit_log(
                operator_id=operator_id,
                key_id=key_id,
                action="key_revoked"
            )
            self.conn.commit()
            return True
        return False
    
    def rotate_key(self, operator_id: str, key_id: str, ttl_days: int = 90) -> Optional[str]:
        """Rotate a key (revoke old, create new)"""
        if not self.revoke_key(operator_id, key_id):
            return None
        
        new_key, new_key_id = self.create_key(operator_id, ttl_days, f"Rotated from {key_id}")
        
        if new_key:
            self._audit_log(
                operator_id=operator_id,
                key_id=new_key_id,
                action="key_rotated",
                details={"old_key_id": key_id}
            )
        
        return new_key
    
    def validate_key(self, key_hash: str) -> Optional[Dict]:
        """Validate an API key"""
        cur = self.conn.execute("""
            SELECT 
                k.key_id, k.operator_id, k.created_at, k.expires_at, 
                k.revoked_at, k.last_used_at, k.usage_count,
                o.name, o.role, o.is_active as operator_active
            FROM operator_keys k
            JOIN operators o ON k.operator_id = o.id
            WHERE k.key_hash = ? 
                AND (k.expires_at IS NULL OR k.expires_at > ?)
                AND k.revoked_at IS NULL
                AND o.is_active = 1
        """, (key_hash, time.time()))
        
        result = cur.fetchone()
        if result:
            # Update last used
            self.conn.execute(
                "UPDATE operator_keys SET last_used_at = ?, usage_count = usage_count + 1 WHERE key_id = ?",
                (time.time(), result['key_id'])
            )
            self.conn.commit()
            
            return dict(result)
        return None
    
    def list_keys(self, operator_id: str) -> List[Dict]:
        """List all keys for an operator"""
        cur = self.conn.execute("""
            SELECT 
                key_id, description, created_at, expires_at, revoked_at,
                last_used_at, usage_count,
                CASE 
                    WHEN revoked_at IS NOT NULL THEN 'revoked'
                    WHEN expires_at < ? THEN 'expired'
                    ELSE 'active'
                END as status
            FROM operator_keys 
            WHERE operator_id = ?
            ORDER BY created_at DESC
        """, (time.time(), operator_id))
        
        return [dict(row) for row in cur]
    
    def _audit_log(self, operator_id: str, action: str, key_id: Optional[str] = None, 
                  ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                  details: Optional[Dict] = None):
        """Log key management actions"""
        self.conn.execute("""
            INSERT INTO key_audit_log 
            (timestamp, operator_id, key_id, action, ip_address, user_agent, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (time.time(), operator_id, key_id, action, ip_address, user_agent, 
              json.dumps(details or {})))
    
    def get_audit_log(self, operator_id: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Get audit log entries"""
        if operator_id:
            cur = self.conn.execute("""
                SELECT timestamp, operator_id, key_id, action, ip_address, details
                FROM key_audit_log
                WHERE operator_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (operator_id, limit))
        else:
            cur = self.conn.execute("""
                SELECT timestamp, operator_id, key_id, action, ip_address, details
                FROM key_audit_log
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
        
        return [dict(row) for row in cur]
    
    def cleanup_expired_keys(self) -> int:
        """Clean up expired keys (mark as expired if not already revoked)"""
        cur = self.conn.execute("""
            UPDATE operator_keys 
            SET revoked_at = ?
            WHERE expires_at < ? 
                AND revoked_at IS NULL
        """, (time.time(), time.time()))
        
        self.conn.commit()
        return cur.rowcount

# FastAPI endpoints for key management
from fastapi import APIRouter, HTTPException, Depends, Header, Request
from .request_models import OperatorKeyRequest

router = APIRouter(prefix="/api/operators", tags=["operators"])
key_manager = OperatorKeyManager()

@router.post("/{operator_id}/keys")
async def create_operator_key(
    operator_id: str,
    request: OperatorKeyRequest,
    user_agent: Optional[str] = Header(None),
    x_forwarded_for: Optional[str] = Header(None)
):
    """Generate new API key for operator"""
    key, key_id = key_manager.create_key(
        operator_id=operator_id,
        ttl_days=request.ttl_days,
        description=request.description
    )
    
    if not key:
        raise HTTPException(status_code=400, detail="Failed to create key")
    
    return {
        "key": key,  # Show only once!
        "key_id": key_id,
        "operator_id": operator_id,
        "expires_at": time.time() + (request.ttl_days * 86400),
        "ttl_days": request.ttl_days,
        "warning": "Save this key now. It will not be shown again."
    }

@router.get("/{operator_id}/keys")
async def list_operator_keys(operator_id: str):
    """List all keys for an operator"""
    keys = key_manager.list_keys(operator_id)
    return {"operator_id": operator_id, "keys": keys}

@router.delete("/{operator_id}/keys/{key_id}")
async def revoke_operator_key(operator_id: str, key_id: str):
    """Revoke an operator key"""
    if key_manager.revoke_key(operator_id, key_id):
        return {"status": "revoked", "key_id": key_id}
    raise HTTPException(status_code=404, detail="Key not found or already revoked")

@router.post("/{operator_id}/keys/{key_id}/rotate")
async def rotate_operator_key(operator_id: str, key_id: str, ttl_days: int = 90):
    """Rotate key (revoke old, create new)"""
    new_key = key_manager.rotate_key(operator_id, key_id, ttl_days)
    if new_key:
        return {
            "new_key": new_key,
            "old_key_id": key_id,
            "status": "rotated"
        }
    raise HTTPException(status_code=400, detail="Failed to rotate key")

@router.get("/{operator_id}/audit")
async def get_operator_audit(operator_id: str, limit: int = 50):
    """Get audit log for operator"""
    audit_log = key_manager.get_audit_log(operator_id, limit)
    return {"operator_id": operator_id, "audit_log": audit_log}
