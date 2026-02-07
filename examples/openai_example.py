"""
Example: Using Kasbah with OpenAI function calling
"""

from openai import OpenAI
from kasbah import KasbahClient
import json

client_openai = OpenAI()
client_kasbah = KasbahClient(api_url="http://localhost:5000")

# Define functions
def refund_customer(customer_id: str, amount: float):
    """Actually process the refund"""
    print(f"Processing ${amount} refund for {customer_id}")
    return {"status": "success", "customer_id": customer_id, "amount": amount}

# Function schema for OpenAI
functions = [
    {
        "name": "refund_customer",
        "description": "Process a customer refund",
        "parameters": {
            "type": "object",
            "properties": {
                "customer_id": {"type": "string"},
                "amount": {"type": "number"}
            },
            "required": ["customer_id", "amount"]
        }
    }
]

# Run agent
messages = [{"role": "user", "content": "Please refund customer-123 for $49.99"}]

response = client_openai.chat.completions.create(
    model="gpt-4",
    messages=messages,
    functions=functions,
    function_call="auto"
)

# Agent wants to call a function
if response.choices[0].message.function_call:
    function_name = response.choices[0].message.function_call.name
    function_args = json.loads(response.choices[0].message.function_call.arguments)
    
    # Gate with Kasbah BEFORE executing
    decision = client_kasbah.decide(
        tool=function_name,
        signals={"consistency": 0.95}  # You'd calculate these from context
    )
    
    if decision['allowed']:
        # Execute
        if function_name == "refund_customer":
            result = refund_customer(**function_args)
            
            # Mark ticket as consumed
            client_kasbah.consume(decision['ticket'], function_name)
            
            print(f"✓ Function executed: {result}")
    else:
        print("✗ Kasbah blocked execution")
