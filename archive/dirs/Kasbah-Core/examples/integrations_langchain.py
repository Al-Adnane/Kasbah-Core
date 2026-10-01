"""
Kasbah Integration - LangChain
How to use Kasbah authorization with LangChain agents
"""

from langchain.agents import Tool, AgentExecutor, create_react_agent
from langchain_openai import ChatOpenAI
from langchain import hub
import requests
import json

KASBAH_API = "http://localhost:5001"

# =============================================================================
# KASBAH WRAPPER FOR LANGCHAIN TOOLS
# =============================================================================

class KasbahProtectedTool:
    """Wraps any LangChain tool with Kasbah authorization"""
    
    def __init__(self, tool: Tool, principal_id: str, principal_type: str = "bot"):
        self.tool = tool
        self.principal_id = principal_id
        self.principal_type = principal_type
        self.kasbah_api = KASBAH_API
    
    def _get_authorization(self, action: str, resource: str) -> dict:
        """Request authorization from Kasbah"""
        response = requests.post(f"{self.kasbah_api}/api/decide", json={
            "tool": self.tool.name,
            "agent_id": self.principal_id,
            "signals": {"consistency": 0.95},
            "principal": {
                "id": self.principal_id,
                "type": self.principal_type
            },
            "action": action,
            "resource": {
                "path": resource,
                "type": "tool"
            }
        })
        
        if response.status_code == 200:
            return response.json()
        else:
            raise PermissionError(f"Kasbah denied: {response.json()['reason']}")
    
    def _consume_ticket(self, ticket: str) -> bool:
        """Consume the authorization ticket"""
        response = requests.post(f"{self.kasbah_api}/api/consume", json={
            "ticket": ticket,
            "tool": self.tool.name
        })
        
        if response.status_code == 200:
            return True
        else:
            raise PermissionError(f"Ticket consumption failed: {response.json()['reason']}")
    
    def run(self, query: str) -> str:
        """Execute tool with Kasbah protection"""
        # 1. Request authorization
        auth = self._get_authorization("execute", f"/tools/{self.tool.name}")
        ticket = auth['ticket']
        
        # 2. Consume ticket
        self._consume_ticket(ticket)
        
        # 3. Execute tool
        result = self.tool.func(query)
        
        return result

# =============================================================================
# EXAMPLE: PROTECTED CALCULATOR TOOL
# =============================================================================

def calculator(query: str) -> str:
    """Simple calculator (dangerous if misused!)"""
    try:
        # WARNING: eval is dangerous - this is just for demo
        result = eval(query)
        return f"Result: {result}"
    except Exception as e:
        return f"Error: {e}"

# Create LangChain tool
calculator_tool = Tool(
    name="calculator",
    func=calculator,
    description="Useful for math calculations. Input should be a math expression."
)

# Wrap with Kasbah protection
protected_calculator = KasbahProtectedTool(
    tool=calculator_tool,
    principal_id="bot-langchain",
    principal_type="bot"
)

# =============================================================================
# EXAMPLE USAGE
# =============================================================================

if __name__ == "__main__":
    print("="*80)
    print("KASBAH + LANGCHAIN INTEGRATION EXAMPLE")
    print("="*80)
    
    # First, create policy for this bot
    print("\n1. Creating Kasbah policy for bot-langchain...")
    policy_response = requests.post(f"{KASBAH_API}/api/admin/policies", json={
        "id": "bot-langchain-policy",
        "name": "LangChain Bot - Calculator Access",
        "principal_type": "bot",
        "principal_id": "bot-langchain",
        "allowed_actions": ["execute"],
        "allowed_resources": ["/tools/calculator"],
        "denied_resources": [],
        "rate_limit_per_hour": 100
    })
    
    if policy_response.status_code == 201:
        print("   ✓ Policy created")
    else:
        print(f"   ℹ Policy exists: {policy_response.json()}")
    
    # Use the protected tool
    print("\n2. Using protected calculator tool...")
    try:
        result = protected_calculator.run("2 + 2")
        print(f"   ✓ Result: {result}")
    except PermissionError as e:
        print(f"   ✗ Denied: {e}")
    
    # Try to use it again (should work - within rate limit)
    print("\n3. Using again (testing rate limit)...")
    try:
        result = protected_calculator.run("10 * 5")
        print(f"   ✓ Result: {result}")
    except PermissionError as e:
        print(f"   ✗ Denied: {e}")
    
    print("\n" + "="*80)
    print("✅ Integration working! Every tool use requires Kasbah authorization.")
    print("="*80)
