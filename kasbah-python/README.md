# Kasbah Python Client

Runtime enforcement for AI agents.

## Installation
```bash
pip install kasbah
```

## Quick Start
```python
from kasbah import protect_tool

# Protect a dangerous function
@protect_tool(kasbah_url="http://localhost:5000")
def refund_customer(customer_id: str, amount: float):
    """This will require Kasbah approval before executing"""
    return billing.process_refund(customer_id, amount)

# Use normally - Kasbah gates it automatically
refund_customer("customer-123", 49.99)
```

## How it Works

1. **Decide**: Kasbah evaluates if action should be allowed
2. **Ticket**: Returns cryptographic proof if allowed
3. **Execute**: Your function runs
4. **Consume**: Ticket is marked as used (prevents replay)

## Advanced Usage

### Custom signals
```python
def get_safety_signals(customer_id, amount):
    return {
        "consistency": check_consistency(customer_id),
        "accuracy": verify_amount(amount)
    }

@protect_tool(kasbah_url="...", signals_fn=get_safety_signals)
def refund_customer(customer_id: str, amount: float):
    return billing.process_refund(customer_id, amount)
```

### Direct client usage
```python
from kasbah import KasbahClient

client = KasbahClient(api_url="http://localhost:5000")

# Request permission
decision = client.decide(
    tool="database.delete",
    signals={"consistency": 0.95}
)

if decision['allowed']:
    # Execute your action
    result = db.delete(record_id)
    
    # Mark ticket as consumed
    client.consume(decision['ticket'], "database.delete")
```

## License

MIT
