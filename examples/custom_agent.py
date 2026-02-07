"""
Example: Custom agent with Kasbah
"""

from kasbah import KasbahClient

class SafeAgent:
    """Example custom agent with Kasbah runtime enforcement"""
    
    def __init__(self, kasbah_url="http://localhost:5000"):
        self.kasbah = KasbahClient(api_url=kasbah_url)
        self.tools = {
            "refund": self.refund_customer,
            "delete": self.delete_data,
            "search": self.search_customer
        }
    
    def refund_customer(self, customer_id: str):
        """Dangerous operation"""
        print(f"Refunding {customer_id}")
        return f"Refunded {customer_id}"
    
    def delete_data(self, user_id: str):
        """Dangerous operation"""
        print(f"Deleting {user_id}")
        return f"Deleted {user_id}"
    
    def search_customer(self, query: str):
        """Safe operation - no Kasbah needed"""
        return f"Found: {query}"
    
    def execute_tool(self, tool_name: str, **kwargs):
        """Execute a tool with Kasbah enforcement"""
        
        # Check if this tool needs protection
        dangerous_tools = ["refund", "delete"]
        
        if tool_name in dangerous_tools:
            # Get permission from Kasbah
            decision = self.kasbah.decide(
                tool=tool_name,
                signals={"consistency": 0.95}
            )
            
            if not decision['allowed']:
                raise PermissionError(f"Kasbah blocked {tool_name}")
            
            ticket = decision['ticket']
        
        # Execute tool
        result = self.tools[tool_name](**kwargs)
        
        # Consume ticket if it was a dangerous operation
        if tool_name in dangerous_tools:
            self.kasbah.consume(ticket, tool_name)
        
        return result

# Usage
agent = SafeAgent()

# This will require Kasbah approval
result = agent.execute_tool("refund", customer_id="customer-123")
print(result)

# This is safe, no Kasbah needed
result = agent.execute_tool("search", query="John Doe")
print(result)
