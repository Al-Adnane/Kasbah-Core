import requests
import time
from functools import wraps
from typing import Callable, Dict, Any

class KasbahClient:
    """Client for Kasbah runtime enforcement"""
    
    def __init__(self, api_url: str = "http://localhost:5000", api_key: str = None):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
    
    def decide(self, tool: str, agent_id: str = "default", signals: Dict[str, float] = None) -> Dict[str, Any]:
        """Request permission to execute a tool"""
        response = requests.post(
            f"{self.api_url}/api/decide",
            json={
                "tool": tool,
                "agent_id": agent_id,
                "signals": signals or {}
            }
        )
        response.raise_for_status()
        return response.json()
    
    def consume(self, ticket: str, tool: str) -> Dict[str, Any]:
        """Consume a ticket (single-use enforcement)"""
        response = requests.post(
            f"{self.api_url}/api/consume",
            json={
                "ticket": ticket,
                "tool": tool
            }
        )
        
        if response.status_code == 403:
            data = response.json()
            raise PermissionError(f"Kasbah blocked execution: {data.get('reason')}")
        
        response.raise_for_status()
        return response.json()

def protect_tool(kasbah_url: str = "http://localhost:5000", signals_fn: Callable = None):
    """
    Decorator to protect a tool with Kasbah runtime enforcement.
    
    Usage:
        @protect_tool(kasbah_url="http://localhost:5000")
        def dangerous_database_operation(customer_id: str):
            return db.delete_customer(customer_id)
    """
    def decorator(func: Callable) -> Callable:
        client = KasbahClient(api_url=kasbah_url)
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get signals (if custom function provided)
            signals = signals_fn(*args, **kwargs) if signals_fn else {}
            
            # Phase 1: Decide
            decision = client.decide(
                tool=func.__name__,
                agent_id="python-agent",
                signals=signals
            )
            
            if not decision.get('allowed'):
                raise PermissionError(f"Kasbah denied execution: integrity too low")
            
            # Phase 2: Execute with ticket
            ticket = decision['ticket']
            
            try:
                result = func(*args, **kwargs)
                
                # Phase 3: Consume ticket
                client.consume(ticket, func.__name__)
                
                return result
            except Exception as e:
                # Still consume ticket even on error (prevent retry abuse)
                try:
                    client.consume(ticket, func.__name__)
                except:
                    pass
                raise e
        
        return wrapper
    return decorator
