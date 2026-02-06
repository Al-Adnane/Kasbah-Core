import sqlite3
import json
from typing import Dict, List, Optional, Set
from datetime import datetime

class AgentAllowlistManager:
    def __init__(self, db_path=".kasbah_agents.db"):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_db()
    
    def _init_db(self):
        """Initialize agent configuration database"""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT DEFAULT '',
                allowed_tools TEXT DEFAULT '[]',  -- JSON array of tool names
                rate_limit_per_minute INTEGER DEFAULT 1000,
                max_ttl_seconds INTEGER DEFAULT 3600,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                is_active INTEGER DEFAULT 1,
                metadata TEXT DEFAULT '{}'
            )
        """)
        
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                agent_id TEXT NOT NULL,
                action TEXT NOT NULL,
                tool_name TEXT,
                decision TEXT,
                reason TEXT,
                ip_address TEXT,
                user_agent TEXT,
                details TEXT DEFAULT '{}'
            )
        """)
        
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_agent_allowed_tools 
            ON agents(agent_id) WHERE is_active = 1
        """)
        
        self.conn.commit()
    
    def register_agent(self, agent_id: str, name: str, description: str = "",
                      allowed_tools: Optional[List[str]] = None,
                      rate_limit: int = 1000,
                      max_ttl: int = 3600,
                      metadata: Optional[Dict] = None) -> bool:
        """Register a new agent or update existing one"""
        allowed_tools_json = json.dumps(allowed_tools or [])
        metadata_json = json.dumps(metadata or {})
        now = datetime.now().timestamp()
        
        try:
            self.conn.execute("""
                INSERT OR REPLACE INTO agents 
                (agent_id, name, description, allowed_tools, rate_limit_per_minute, 
                 max_ttl_seconds, created_at, updated_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, 
                        COALESCE((SELECT created_at FROM agents WHERE agent_id = ?), ?),
                        ?, ?)
            """, (
                agent_id, name, description, allowed_tools_json, rate_limit, max_ttl,
                agent_id, now, now, metadata_json
            ))
            
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error registering agent: {e}")
            return False
    
    def get_agent_config(self, agent_id: str) -> Optional[Dict]:
        """Get configuration for an agent"""
        cur = self.conn.execute("""
            SELECT agent_id, name, description, allowed_tools, 
                   rate_limit_per_minute, max_ttl_seconds, created_at,
                   updated_at, is_active, metadata
            FROM agents
            WHERE agent_id = ? AND is_active = 1
        """, (agent_id,))
        
        row = cur.fetchone()
        if row:
            config = dict(row)
            config['allowed_tools'] = json.loads(config['allowed_tools'])
            config['metadata'] = json.loads(config['metadata'])
            return config
        return None
    
    def can_use_tool(self, agent_id: str, tool_name: str) -> Dict[str, any]:
        """Check if agent can use a specific tool"""
        config = self.get_agent_config(agent_id)
        
        if not config:
            return {
                "allowed": False,
                "reason": "agent_not_registered",
                "message": f"Agent '{agent_id}' is not registered or inactive"
            }
        
        allowed_tools = config['allowed_tools']
        
        # Check if tool is explicitly allowed
        if allowed_tools and tool_name not in allowed_tools:
            return {
                "allowed": False,
                "reason": "tool_not_in_allowlist",
                "message": f"Agent '{agent_id}' not allowed to use '{tool_name}'",
                "allowed_tools": allowed_tools
            }
        
        # Check rate limiting (simplified - in production, use Redis)
        # Check TTL limits
        return {
            "allowed": True,
            "reason": "allowed",
            "agent_config": {
                "rate_limit": config['rate_limit_per_minute'],
                "max_ttl": config['max_ttl_seconds']
            }
        }
    
    def update_allowed_tools(self, agent_id: str, allowed_tools: List[str]) -> bool:
        """Update the allowed tools for an agent"""
        allowed_tools_json = json.dumps(allowed_tools)
        
        cur = self.conn.execute("""
            UPDATE agents 
            SET allowed_tools = ?, updated_at = ?
            WHERE agent_id = ? AND is_active = 1
        """, (allowed_tools_json, datetime.now().timestamp(), agent_id))
        
        if cur.rowcount > 0:
            self.conn.commit()
            return True
        return False
    
    def add_tool_to_agent(self, agent_id: str, tool_name: str) -> bool:
        """Add a tool to agent's allowlist"""
        config = self.get_agent_config(agent_id)
        if not config:
            return False
        
        allowed_tools = set(config['allowed_tools'])
        allowed_tools.add(tool_name)
        
        return self.update_allowed_tools(agent_id, list(allowed_tools))
    
    def remove_tool_from_agent(self, agent_id: str, tool_name: str) -> bool:
        """Remove a tool from agent's allowlist"""
        config = self.get_agent_config(agent_id)
        if not config:
            return False
        
        allowed_tools = set(config['allowed_tools'])
        allowed_tools.discard(tool_name)
        
        return self.update_allowed_tools(agent_id, list(allowed_tools))
    
    def deactivate_agent(self, agent_id: str) -> bool:
        """Deactivate an agent"""
        cur = self.conn.execute("""
            UPDATE agents SET is_active = 0, updated_at = ? WHERE agent_id = ?
        """, (datetime.now().timestamp(), agent_id))
        
        if cur.rowcount > 0:
            self.conn.commit()
            return True
        return False
    
    def list_agents(self, active_only: bool = True) -> List[Dict]:
        """List all agents"""
        if active_only:
            cur = self.conn.execute("""
                SELECT agent_id, name, description, allowed_tools, 
                       rate_limit_per_minute, created_at, updated_at
                FROM agents
                WHERE is_active = 1
                ORDER BY created_at DESC
            """)
        else:
            cur = self.conn.execute("""
                SELECT agent_id, name, description, allowed_tools, 
                       rate_limit_per_minute, created_at, updated_at, is_active
                FROM agents
                ORDER BY created_at DESC
            """)
        
        agents = []
        for row in cur:
            agent = dict(row)
            agent['allowed_tools'] = json.loads(agent['allowed_tools'])
            agents.append(agent)
        
        return agents
    
    def log_agent_decision(self, agent_id: str, action: str, tool_name: Optional[str] = None,
                          decision: Optional[str] = None, reason: Optional[str] = None,
                          ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                          details: Optional[Dict] = None):
        """Log agent actions for audit"""
        self.conn.execute("""
            INSERT INTO agent_audit_log 
            (timestamp, agent_id, action, tool_name, decision, reason, 
             ip_address, user_agent, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().timestamp(), agent_id, action, tool_name, decision, reason,
            ip_address, user_agent, json.dumps(details or {})
        ))
        self.conn.commit()

# Integration with main.py
def check_agent_allowlist(agent_id: str, tool_name: str, allowlist_manager: AgentAllowlistManager):
    """Check if agent is allowed to use tool - call this from main.py decide()"""
    result = allowlist_manager.can_use_tool(agent_id, tool_name)
    
    # Log the check
    allowlist_manager.log_agent_decision(
        agent_id=agent_id,
        action="tool_check",
        tool_name=tool_name,
        decision="ALLOW" if result["allowed"] else "DENY",
        reason=result.get("reason"),
        details={"tool": tool_name}
    )
    
    return result

# FastAPI endpoints for agent management
from fastapi import APIRouter, HTTPException
from typing import List

router = APIRouter(prefix="/api/agents", tags=["agents"])
allowlist_manager = AgentAllowlistManager()

@router.post("/register")
async def register_agent(
    agent_id: str,
    name: str,
    description: str = "",
    allowed_tools: List[str] = [],
    rate_limit: int = 1000,
    max_ttl: int = 3600
):
    """Register a new agent"""
    success = allowlist_manager.register_agent(
        agent_id=agent_id,
        name=name,
        description=description,
        allowed_tools=allowed_tools,
        rate_limit=rate_limit,
        max_ttl=max_ttl
    )
    
    if success:
        return {"status": "registered", "agent_id": agent_id}
    raise HTTPException(status_code=400, detail="Failed to register agent")

@router.get("/{agent_id}")
async def get_agent(agent_id: str):
    """Get agent configuration"""
    config = allowlist_manager.get_agent_config(agent_id)
    if config:
        return config
    raise HTTPException(status_code=404, detail="Agent not found")

@router.put("/{agent_id}/tools")
async def update_agent_tools(agent_id: str, allowed_tools: List[str]):
    """Update allowed tools for an agent"""
    success = allowlist_manager.update_allowed_tools(agent_id, allowed_tools)
    if success:
        return {"status": "updated", "agent_id": agent_id, "allowed_tools": allowed_tools}
    raise HTTPException(status_code=404, detail="Agent not found or inactive")

@router.post("/{agent_id}/tools/{tool_name}")
async def add_agent_tool(agent_id: str, tool_name: str):
    """Add a tool to agent's allowlist"""
    success = allowlist_manager.add_tool_to_agent(agent_id, tool_name)
    if success:
        return {"status": "added", "agent_id": agent_id, "tool": tool_name}
    raise HTTPException(status_code=404, detail="Agent not found or inactive")

@router.delete("/{agent_id}/tools/{tool_name}")
async def remove_agent_tool(agent_id: str, tool_name: str):
    """Remove a tool from agent's allowlist"""
    success = allowlist_manager.remove_tool_from_agent(agent_id, tool_name)
    if success:
        return {"status": "removed", "agent_id": agent_id, "tool": tool_name}
    raise HTTPException(status_code=404, detail="Agent not found or inactive")

@router.get("/")
async def list_all_agents(active_only: bool = True):
    """List all agents"""
    agents = allowlist_manager.list_agents(active_only)
    return {"agents": agents, "count": len(agents)}
