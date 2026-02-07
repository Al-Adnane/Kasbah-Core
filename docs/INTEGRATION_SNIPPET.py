# Minimal example: where Kasbah sits in a real workflow.
# Goal: make execution depend on proof, not just authentication.

# 1) agent proposes an action (tool + target + intent)
decision = kasbah.decide(
    tool="billing.refund",
    target={"customer_id": customer_id, "invoice_id": invoice_id},
    intent={"reason": "duplicate charge", "amount": amount},
)

# 2) only execute if Kasbah issued a valid, tool-bound, time-boxed ticket
if decision.allowed:
    billing.refund(
        customer_id=customer_id,
        invoice_id=invoice_id,
        amount=amount,
        kasbah_ticket=decision.ticket,
    )
else:
    raise PermissionError(f"Kasbah denied: {decision.reason}")
