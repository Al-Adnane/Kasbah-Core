import sqlite3
import os
from typing import Dict, Any, Optional

class StatePersistence:
    def __init__(self, db_path=".kasbah_state.db", use_redis=True):
        self.use_redis = use_redis
        
        if use_redis and os.getenv("PRODUCTION"):
            import redis
            self.redis_client = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))
        else:
            # Fallback to SQLite for development
            self.conn = sqlite3.connect(db_path)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS active_tickets (
                    ticket_id TEXT PRIMARY KEY,
                    tool TEXT,
                    agent_id TEXT,
                    expires_at REAL,
                    integrity REAL,
                    created_at REAL DEFAULT (strftime('%s', 'now'))
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS consumed_tickets (
                    ticket_id TEXT PRIMARY KEY,
                    consumed_at REAL DEFAULT (strftime('%s', 'now'))
                )
            """)
    
    def save_ticket(self, ticket_id: str, meta: Dict[str, Any]) -> None:
        if self.use_redis and os.getenv("PRODUCTION"):
            # Redis implementation
            key = f"ticket:{ticket_id}"
            self.redis_client.hset(key, mapping={
                'tool': meta['tool'],
                'agent_id': meta.get('agent_id', ''),
                'expires_at': str(meta['expires_at']),
                'integrity': str(meta['integrity']),
                'created_at': str(meta.get('created_at', time.time()))
            })
            self.redis_client.expire(key, int(meta['expires_at'] - time.time()))
        else:
            # SQLite implementation
            self.conn.execute(
                "INSERT OR REPLACE INTO active_tickets (ticket_id, tool, agent_id, expires_at, integrity) VALUES (?, ?, ?, ?, ?)",
                (ticket_id, meta['tool'], meta.get('agent_id'), meta['expires_at'], meta['integrity'])
            )
            self.conn.commit()
    
    def load_tickets(self) -> Dict[str, Dict[str, Any]]:
        if self.use_redis and os.getenv("PRODUCTION"):
            # Get all ticket keys
            keys = self.redis_client.keys("ticket:*")
            tickets = {}
            for key in keys:
                ticket_data = self.redis_client.hgetall(key)
                ticket_id = key.decode().split(":")[1]
                tickets[ticket_id] = {
                    'tool': ticket_data.get(b'tool', b'').decode(),
                    'agent_id': ticket_data.get(b'agent_id', b'').decode(),
                    'expires_at': float(ticket_data.get(b'expires_at', b'0').decode()),
                    'integrity': float(ticket_data.get(b'integrity', b'0').decode())
                }
            return tickets
        else:
            # SQLite implementation
            cursor = self.conn.execute("SELECT ticket_id, tool, agent_id, expires_at, integrity FROM active_tickets")
            return {row[0]: {'tool': row[1], 'agent_id': row[2], 'expires_at': row[3], 'integrity': row[4]} for row in cursor}
    
    def mark_consumed(self, ticket_id: str) -> None:
        if self.use_redis and os.getenv("PRODUCTION"):
            # Move to consumed set
            consumed_key = f"consumed:{ticket_id}"
            self.redis_client.setex(consumed_key, 86400, "1")  # 24-hour TTL
        else:
            self.conn.execute(
                "INSERT OR REPLACE INTO consumed_tickets (ticket_id) VALUES (?)",
                (ticket_id,)
            )
            self.conn.commit()
    
    def is_consumed(self, ticket_id: str) -> bool:
        if self.use_redis and os.getenv("PRODUCTION"):
            return self.redis_client.exists(f"consumed:{ticket_id}") > 0
        else:
            cursor = self.conn.execute("SELECT 1 FROM consumed_tickets WHERE ticket_id = ?", (ticket_id,))
            return cursor.fetchone() is not None

# Production requirement check
if os.getenv("PRODUCTION") and os.getenv("REPLAY_LOCK_MODE") != "redis":
    raise RuntimeError("Production requires Redis for state persistence. Set REPLAY_LOCK_MODE=redis and REDIS_URL")
