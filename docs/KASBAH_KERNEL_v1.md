# Kasbah Kernel v1.0 — FROZEN SPEC

## PURPOSE
Kasbah Kernel governs delegated execution via cryptographic tickets,
risk aggregation, and state transitions.

Kernel is domain-agnostic and invariant.

---

## CORE RESPONSIBILITIES
- Ticket issuance
- Ticket verification
- Ticket consumption
- Risk aggregation
- State transitions
- Append-only audit

---

## FORBIDDEN
Kernel MUST NOT:
- Know actor type (AI, human, DAO, etc.)
- Interpret signal semantics
- Encode business logic
- Contain domain thresholds

---

## API (FROZEN)

### POST /kernel/decide
Input:
- actor_id: string
- action: string
- signals: map[string]number
- context: opaque

Output:
- decision: ALLOW | DENY | ESCALATE
- decision_kind: string
- risk_score: number
- threshold: number
- ticket: optional
- kernel_state: NORMAL | WATCH | LOCKDOWN

---

### POST /kernel/ticket/verify
Input:
- ticket

Output:
- valid: bool
- scope
- expiry

---

### POST /kernel/ticket/consume
Input:
- ticket
- actor_id
- action
- usage

State-changing.

---

### GET /kernel/audit/export
Read-only. Append-only.

---

## INVARIANTS
- Deterministic decisions
- Monotonic state tightening
- No adapter override
- Unknown signals never crash kernel
- Lockdown is absolute

Version: v1.0
