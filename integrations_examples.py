"""
Kasbah Integration Examples - NO DEPENDENCIES REQUIRED
Works with any AI framework: OpenAI, Claude, LangChain, AutoGPT, etc.
"""

import requests
import json
from typing import Callable, Any
from functools import wraps

KASBAH_API = "http://localhost:5001"

# =============================================================================
# 1. DECORATOR PATTERN (Universal - works with any function)
# =============================================================================

def kasbah_protect(principal_id: str, action: str, resource_path: str):
    """
    Decorator to protect any function with Kasbah authorization
    
    Usage:
        @kasbah_protect("bot-finance", "execute", "/tools/database")
        def query_database(sql):
            return execute_sql(sql)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # 1. Request authorization
            auth_response = requests.post(f"{KASBAH_API}/api/decide", json={
                "tool": func.__name__,
                "agent_id": principal_id,
                "signals": {"consistency": 0.95},
                "principal": {"id": principal_id, "type": "bot"},
                "action": action,
                "resource": {"path": resource_path, "type": "function"}
            })
            
            if auth_response.status_code != 200:
                raise PermissionError(f"Kasbah denied: {auth_response.json()['reason']}")
            
            ticket = auth_response.json()['ticket']
            
            # 2. Consume ticket
            consume_response = requests.post(f"{KASBAH_API}/api/consume", json={
                "ticket": ticket,
                "tool": func.__name__
            })
            
            if consume_response.status_code != 200:
                raise PermissionError(f"Ticket invalid: {consume_response.json()['reason']}")
            
            # 3. Execute function
            return func(*args, **kwargs)
        
        return wrapper
    return decorator

# =============================================================================
# 2. CLASS-BASED WRAPPER (For object-oriented code)
# =============================================================================

class KasbahClient:
    """Client for integrating Kasbah into any application"""
    
    def __init__(self, api_url: str = KASBAH_API):
        self.api_url = api_url
    
    def authorize(self, principal_id: str, action: str, resource: str, tool_name: str) -> str:
        """
        Request authorization and return ticket
        
        Returns:
            ticket (str): Authorization ticket to use for execution
        
        Raises:
            PermissionError: If authorization is denied
        """
        response = requests.post(f"{self.api_url}/api/decide", json={
            "tool": tool_name,
            "agent_id": principal_id,
            "signals": {"consistency": 0.95},
            "principal": {"id": principal_id, "type": "bot"},
            "action": action,
            "resource": {"path": resource, "type": "api"}
        })
        
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Authorized: {action} on {resource}")
            if 'rate_limit' in data:
                print(f"  Rate limit: {data['rate_limit']['remaining']}/{data['rate_limit']['limit']} remaining")
            return data['ticket']
        else:
            error = response.json()
            raise PermissionError(f"Denied: {error['reason']}")
    
    def execute(self, ticket: str, tool_name: str, action: Callable, *args, **kwargs) -> Any:
        """
        Execute action with ticket
        
        Args:
            ticket: Authorization ticket from authorize()
            tool_name: Name of the tool
            action: Function to execute
            *args, **kwargs: Arguments to pass to action
        
        Returns:
            Result of action()
        """
        # Consume ticket
        response = requests.post(f"{self.api_url}/api/consume", json={
            "ticket": ticket,
            "tool": tool_name
        })
        
        if response.status_code != 200:
            raise PermissionError(f"Ticket invalid: {response.json()['reason']}")
        
        print(f"✓ Ticket consumed, executing...")
        
        # Execute
        return action(*args, **kwargs)
    
    def authorize_and_execute(self, principal_id: str, action_name: str, 
                            resource: str, tool_name: str, 
                            action: Callable, *args, **kwargs) -> Any:
        """Convenience method: authorize + execute in one call"""
        ticket = self.authorize(principal_id, action_name, resource, tool_name)
        return self.execute(ticket, tool_name, action, *args, **kwargs)

# =============================================================================
# 3. OPENAI FUNCTION CALLING INTEGRATION
# =============================================================================

def create_kasbah_tool_schema(tool_name: str, description: str, parameters: dict):
    """
    Create OpenAI function schema with Kasbah authorization
    
    Usage with OpenAI:
        tools = [
            create_kasbah_tool_schema(
                "delete_file",
                "Delete a file from storage",
                {"filename": {"type": "string"}}
            )
        ]
        
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=messages,
            tools=tools
        )
    """
    return {
        "type": "function",
        "function": {
            "name": tool_name,
            "description": f"{description}\n\nNOTE: This action requires Kasbah authorization.",
            "parameters": {
                "type": "object",
                "properties": parameters,
                "required": list(parameters.keys())
            }
        }
    }

def execute_openai_tool_with_kasbah(tool_name: str, arguments: dict, 
                                    principal_id: str, kasbah_action: str,
                                    actual_function: Callable):
    """
    Execute OpenAI tool call with Kasbah authorization
    
    Usage:
        # When OpenAI returns a tool call:
        tool_call = response.choices[0].message.tool_calls[0]
        
        result = execute_openai_tool_with_kasbah(
            tool_name=tool_call.function.name,
            arguments=json.loads(tool_call.function.arguments),
            principal_id="gpt-4-agent",
            kasbah_action="delete",
            actual_function=delete_file
        )
    """
    kasbah = KasbahClient()
    
    # Extract resource from arguments
    resource = f"/files/{arguments.get('filename', 'unknown')}"
    
    return kasbah.authorize_and_execute(
        principal_id=principal_id,
        action_name=kasbah_action,
        resource=resource,
        tool_name=tool_name,
        action=actual_function,
        **arguments
    )

# =============================================================================
# 4. CLAUDE TOOL USE INTEGRATION
# =============================================================================

def create_claude_tool_with_kasbah(tool_name: str, description: str, input_schema: dict):
    """
    Create Claude tool definition with Kasbah note
    
    Usage with Claude API:
        tools = [
            create_claude_tool_with_kasbah(
                "delete_customer",
                "Delete a customer record",
                {
                    "type": "object",
                    "properties": {
                        "customer_id": {"type": "string"}
                    }
                }
            )
        ]
        
        response = anthropic.messages.create(
            model="claude-3-5-sonnet-20241022",
            tools=tools,
            messages=messages
        )
    """
    return {
        "name": tool_name,
        "description": f"{description}\n\nSECURITY: Protected by Kasbah authorization layer.",
        "input_schema": input_schema
    }

# =============================================================================
# EXAMPLE USAGE & TESTS
# =============================================================================

def delete_file(filename: str) -> str:
    """Example dangerous function"""
    return f"DELETED: {filename}"

def refund_customer(customer_id: str, amount: float) -> str:
    """Example financial function"""
    return f"REFUNDED: ${amount} to customer {customer_id}"

if __name__ == "__main__":
    print("="*80)
    print("KASBAH INTEGRATION EXAMPLES")
    print("="*80)
    
    # Setup: Create policy
    print("\n📋 SETUP: Creating policy for demo-bot...")
    policy_response = requests.post(f"{KASBAH_API}/api/admin/policies", json={
        "id": "demo-bot-policy",
        "name": "Demo Bot Policy",
        "principal_type": "bot",
        "principal_id": "demo-bot",
        "allowed_actions": ["delete", "refund"],
        "allowed_resources": ["/files/*", "/customers/*"],
        "denied_resources": [],
        "rate_limit_per_hour": 10
    })
    print(f"   Status: {policy_response.status_code}")
    
    # =================================================================
    # EXAMPLE 1: Decorator Pattern
    # =================================================================
    print("\n" + "="*80)
    print("EXAMPLE 1: DECORATOR PATTERN")
    print("="*80)
    
    @kasbah_protect("demo-bot", "delete", "/files/report.pdf")
    def delete_report():
        return delete_file("report.pdf")
    
    try:
        result = delete_report()
        print(f"✅ {result}")
    except PermissionError as e:
        print(f"❌ {e}")
    
    # =================================================================
    # EXAMPLE 2: Class-Based Client
    # =================================================================
    print("\n" + "="*80)
    print("EXAMPLE 2: CLASS-BASED CLIENT")
    print("="*80)
    
    kasbah = KasbahClient()
    
    try:
        result = kasbah.authorize_and_execute(
            principal_id="demo-bot",
            action_name="refund",
            resource="/customers/cust-123",
            tool_name="refund_customer",
            action=refund_customer,
            customer_id="cust-123",
            amount=50.00
        )
        print(f"✅ {result}")
    except PermissionError as e:
        print(f"❌ {e}")
    
    # =================================================================
    # EXAMPLE 3: Two-Step Authorization (for async workflows)
    # =================================================================
    print("\n" + "="*80)
    print("EXAMPLE 3: TWO-STEP AUTHORIZATION (Async Pattern)")
    print("="*80)
    
    try:
        # Step 1: Get authorization (can be done in one service)
        ticket = kasbah.authorize(
            principal_id="demo-bot",
            action="delete",
            resource="/files/temp.log",
            tool_name="delete_file"
        )
        print(f"   Ticket: {ticket[:60]}...")
        
        # Step 2: Execute later (can be in different service/time)
        # This is useful for: queues, webhooks, delayed execution
        result = kasbah.execute(
            ticket=ticket,
            tool_name="delete_file",
            action=delete_file,
            filename="temp.log"
        )
        print(f"✅ {result}")
    except PermissionError as e:
        print(f"❌ {e}")
    
    # =================================================================
    # EXAMPLE 4: Rate Limit Demonstration
    # =================================================================
    print("\n" + "="*80)
    print("EXAMPLE 4: RATE LIMITING IN ACTION")
    print("="*80)
    
    for i in range(12):
        try:
            result = kasbah.authorize_and_execute(
                principal_id="demo-bot",
                action_name="delete",
                resource=f"/files/temp-{i}.txt",
                tool_name="delete_file",
                action=delete_file,
                filename=f"temp-{i}.txt"
            )
            print(f"   Request {i+1}: ✓")
        except PermissionError as e:
            print(f"   Request {i+1}: ✗ {e}")
            break
    
    # Cleanup
    print("\n🧹 CLEANUP: Deleting demo policy...")
    requests.delete(f"{KASBAH_API}/api/admin/policies/demo-bot-policy")
    
    print("\n" + "="*80)
    print("✅ ALL INTEGRATION PATTERNS DEMONSTRATED!")
    print("="*80)
    print("\nYou can use these patterns with:")
    print("  • OpenAI function calling")
    print("  • Claude tool use")
    print("  • LangChain agents")
    print("  • AutoGPT")
    print("  • Custom AI agents")
    print("  • Any Python code that needs authorization")
