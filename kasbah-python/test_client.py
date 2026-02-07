"""
Quick test of the Kasbah client
Run this with: python test_client.py
"""

from kasbah import protect_tool, KasbahClient
import time

# Test 1: Direct client usage
print("Test 1: Direct client usage")
client = KasbahClient(api_url="http://localhost:5000")

decision = client.decide(tool="test.action", signals={"consistency": 0.95})
print(f"Decision: {decision}")

try:
    client.consume(decision['ticket'], "test.action")
    print("✓ First consume: Success")
except Exception as e:
    print(f"✗ First consume failed: {e}")

try:
    client.consume(decision['ticket'], "test.action")
    print("✗ Second consume: Should have failed!")
except PermissionError as e:
    print(f"✓ Second consume blocked: {e}")

print()

# Test 2: Decorator usage
print("Test 2: Decorator usage")

@protect_tool(kasbah_url="http://localhost:5000")
def dangerous_operation(customer_id: str):
    print(f"Executing operation for customer: {customer_id}")
    return f"Processed {customer_id}"

try:
    result = dangerous_operation("customer-123")
    print(f"✓ Protected function executed: {result}")
except Exception as e:
    print(f"✗ Protected function failed: {e}")

print()
print("All tests complete!")
