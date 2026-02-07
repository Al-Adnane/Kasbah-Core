# Kasbah — Internal note (not for publishing)

## Invariant
No agent action executes unless it presents cryptographic proof that matches the exact intent, target, tool, and moment.

## Assumption
Agents are fallible and helpful. Most failures are context drift, retries, stale state, or wrong binding — not hacks.

## Stops (by design)
- Context drift: proof no longer matches → DENY before execution
- Replay/loops: single-use tickets → replay impossible
- Tool confusion: tool-bound tickets → tool swap blocked

## Does NOT try to solve
- Bad human intent
- Semantic “is this the right business decision?”
- Bad source data quality

## Where it sits
At the tool/API boundary — the last irreversible step — complementing IAM/RBAC/guardrails.
