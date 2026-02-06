import redis
import sqlite3
import os
import time
import json
from typing import Dict, Any, Optional

class KasbahState:
    def __init__(self):
        self.redis_enabled = os.getenv('KASBAH_USE_REDIS', 'false').lower() == 'true'
        self.redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
        
        if self.redis_enabled:
            try:
                self.redis = redis.Redis.from_url(self.redis_url, decode_responses=True)
                self.redis.ping()
            except:
                self.redis_enabled = False
                self._init_sqlite()
        else:
            self._init_sqlite()
    
    def _init_sqlite(self):
        self.conn = sqlite3.connect('.kasbah_state.db', check_same_thread=False)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS tickets (
                id TEXT PRIMARY KEY,
                tool TEXT NOT NULL,
                agent_id TEXT,
                integrity REAL,
                created_at REAL,
                expires_at REAL,
                consumed BOOLEAN DEFAULT 0,
                consumed_at REAL
            )
        """)
        self.conn.commit()
    
    def save_ticket(self, ticket_id: str, tool: str, agent_id: Optional[str], 
                   integrity: float, ttl: int = 300) -> bool:
        expires_at = time.time() + ttl
        
        if self.redis_enabled:
            ticket_data = {
                'tool': tool,
                'agent_id': agent_id or '',
                'integrity': str(integrity),
                'created_at': str(time.time()),
                'expires_at': str(expires_at),
                'consumed': '0'
            }
            key = f"ticket:{ticket_id}"
            self.redis.hset(key, mapping=ticket_data)
            self.redis.expire(key, ttl)
            return True
        else:
            try:
                self.conn.execute("""
                    INSERT OR REPLACE INTO tickets 
                    (id, tool, agent_id, integrity, created_at, expires_at, consumed)
                    VALUES (?, ?, ?, ?, ?, ?, 0)
                """, (ticket_id, tool, agent_id, integrity, time.time(), expires_at))
                self.conn.commit()
                return True
            except Exception as e:
                return False
    
    def consume_ticket(self, ticket_id: str) -> bool:
        if self.redis_enabled:
            key = f"ticket:{ticket_id}"
            if not self.redis.exists(key):
                return False
            
            self.redis.hset(key, 'consumed', '1')
            self.redis.hset(key, 'consumed_at', str(time.time()))
            return True
        else:
            try:
                self.conn.execute("""
                    UPDATE tickets 
                    SET consumed = 1, consumed_at = ?
                    WHERE id = ? AND consumed = 0
                """, (time.time(), ticket_id))
                self.conn.commit()
                return self.conn.total_changes > 0
            except Exception as e:
                return False
    
    def is_consumed(self, ticket_id: str) -> bool:
        if self.redis_enabled:
            key = f"ticket:{ticket_id}"
            consumed = self.redis.hget(key, 'consumed')
            return consumed == '1'
        else:
            cursor = self.conn.execute(
                "SELECT consumed FROM tickets WHERE id = ?",
                (ticket_id,)
            )
            row = cursor.fetchone()
            return row and row[0] == 1
    
    def get_ticket(self, ticket_id: str) -> Optional[Dict[str, Any]]:
        if self.redis_enabled:
            key = f"ticket:{ticket_id}"
            data = self.redis.hgetall(key)
            if not data:
                return None
            
            return {
                'tool': data.get('tool', ''),
                'agent_id': data.get('agent_id'),
                'integrity': float(data.get('integrity', 0)),
                'created_at': float(data.get('created_at', 0)),
                'expires_at': float(data.get('expires_at', 0)),
                'consumed': data.get('consumed') == '1'
            }
        else:
            cursor = self.conn.execute(
                "SELECT tool, agent_id, integrity, created_at, expires_at, consumed FROM tickets WHERE id = ?",
                (ticket_id,)
            )
            row = cursor.fetchone()
            if row:
                return {
                    'tool': row[0],
                    'agent_id': row[1],
                    'integrity': row[2],
                    'created_at': row[3],
                    'expires_at': row[4],
                    'consumed': bool(row[5])
                }
            return None
    
    def cleanup_expired(self) -> int:
        now = time.time()
        if self.redis_enabled:
            return 0
        else:
            cursor = self.conn.execute(
                "DELETE FROM tickets WHERE expires_at < ? AND consumed = 0",
                (now,)
            )
            self.conn.commit()
            return cursor.rowcount

state = KasbahState()
