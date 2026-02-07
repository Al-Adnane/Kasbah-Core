# Common Objections & Responses

## Objection #1: "This adds latency"

**Response:**
```
Good question. Measured in production:

- decide(): 8-12ms (Redis lookup + HMAC sign)
- consume(): 4-6ms (Redis mark consumed + append)
- Total: ~15ms overhead per tool execution

Context:
- Claude API call: 200-800ms
- Database query: 10-50ms  
- Kasbah overhead: 15ms (7-10% of total execution time)

We optimize for correctness, not pure speed.

For high-frequency tools (>100 calls/sec), you can:
- Batch decide() calls
- Use ticket pools
- Cache decisions for idempotent operations

Want to see benchmarks? I can share our test suite.
```

---

## Objection #2: "What if Kasbah goes down?"

**Response:**
```
Fair concern. Three deployment modes:

**1. Sidecar (recommended - 90% of users):**
- Kasbah runs on same host as your agent
- No network hop, sub-10ms latency
- If Kasbah down → your agent is down anyway
- Same failure domain

**2. Fail-open mode (dev/testing):**
- If Kasbah unreachable → log warning, allow execution
- Only for non-critical environments
- Helps with gradual rollout

**3. Fail-closed mode (production):**
- If Kasbah unreachable → deny all tool executions
- High-security environments
- SLA: 99.9% uptime (self-hosted)

Most teams run sidecar. No external dependency.

Which mode fits your setup?
```

---

## Objection #3: "Can't I just use better prompts?"

**Response:**
```
Prompts help with intent. Kasbah enforces at runtime.

Example that prompts can't prevent:

1. Agent gets correct intent: "refund customer A"  
2. Context window fills during execution
3. New message arrives mid-run
4. Pagination loads customer B's record
5. Agent executes refund on customer B

**This isn't a prompt problem. It's a runtime state problem.**

What happened:
- ✅ Prompt worked (agent understood intent)
- ✅ Auth worked (agent had valid credentials)  
- ❌ Runtime action was wrong (stale context)

Traditional stack:
- Prompts → Intent layer
- Auth → Identity layer
- ??? → Execution layer ← THIS IS THE GAP

Kasbah fills the execution layer.

You need:
- Good prompts (intent)
- Good auth (identity)
- Runtime proof (execution) ← Kasbah

They're complementary, not alternatives.
```

---

## Objection #4: "This seems like overkill for my use case"

**Response:**
```
Fair. Kasbah is overkill for:
- Read-only agents
- Agents with no tool access
- Personal projects / prototypes
- Non-critical workflows

Kasbah makes sense for:
- Customer-facing agents (support, sales)
- Agents with write access (DB, billing, email)
- Multi-step workflows with state
- Compliance requirements (audit trails)

What does your agent do? I can tell you if Kasbah is relevant.

Rule of thumb:
"If this agent does the wrong thing, what's the worst outcome?"
- Annoying bug → Probably don't need Kasbah
- Lost revenue / angry customer → Consider Kasbah  
- Legal liability / data breach → Definitely need Kasbah
```

---

## Objection #5: "How is this different from [X]?"

### vs Function calling / Tool use:
```
Function calling: Agent CAN call a tool
Kasbah: Agent SHOULD call this tool right now

Example:
- Function calling gives agent capability: "You have access to refund_customer()"
- Kasbah adds runtime gate: "You can refund THIS customer with THIS ticket"

Complementary, not competitive.
```

### vs API rate limiting:
```
Rate limiting: Prevent too many calls
Kasbah: Prevent wrong calls

Example:
- Rate limit: "Only 100 API calls per minute"
- Kasbah: "This specific API call is bound to this specific context"

Different problems.
```

### vs Audit logs:
```
Audit logs: What happened (after the fact)
Kasbah: What should happen (before execution)

Example:
- Audit log: "Agent refunded $500 to customer B at 3:42pm"
- Kasbah: "Agent requested refund for customer B, but ticket was for customer A → DENY"

Prevention vs detection.
```

---

## Objection #6: "I don't trust a third-party security layer"

**Response:**
```
Totally valid. That's why Kasbah is:

1. **Open source (MIT):**
   - Full source code on GitHub
   - Audit it yourself
   - Fork it if you want

2. **Self-hosted:**
   - Run on your infrastructure  
   - No data leaves your network
   - You control the keys

3. **Sidecar deployment:**
   - Runs next to your agent
   - No external calls
   - Same trust boundary

You're not trusting us. You're trusting the code you can audit.

Want to see the core verification logic? It's ~200 lines:
https://github.com/Al-Adnane/Kasbah-Core/blob/main/src/verify.py
```

---

## Objection #7: "My agent already has safety checks"

**Response:**
```
Great! What checks do you have?

Common patterns:
- Prompt-level: "Never delete user data"
- Schema validation: "customer_id must be UUID"  
- Permission checks: "User X can access resource Y"

Kasbah adds:
- **Temporal binding:** This action is valid NOW (not 5 seconds from now)
- **Single-use:** This permission can't be replayed/retried
- **Context binding:** This action applies to THIS specific entity
- **Audit chain:** Tamper-proof history

Example gap in traditional checks:

Your safety check: "Verify customer_id is valid UUID"
✅ customer_id = "550e8400-e29b-41d4-a716-446655440000"

But which customer is that?
- Customer A from 5 seconds ago?
- Customer B loaded by pagination?
- Customer C from a retry?

Kasbah binds the action to specific runtime context.

Want to walk through your current checks? I can show you where Kasbah fits.
```
