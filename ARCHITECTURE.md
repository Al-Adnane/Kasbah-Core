# Kasbah Core — Architecture Overview

## High-Level Flow

Client / Agent
    |
    v
POST /api/rtp/decide
    |
    v
+-----------------------------+
|        Kernel Gate         |
+-----------------------------+
        |
        +--> Signal Validation
        |
        +--> Persona Binding
        |
        +--> Geometry Scoring
        |
        +--> Integrity Scoring
        |
        +--> Brittleness Detection
        |
        +--> Policy Evaluation
        |
        v
Decision Engine
(ALLOW / DENY)

If ALLOW:
    |
    v
Cryptographic Ticket Minting
    |
    v
Signed Execution Ticket
    |
    v
Client executes tool
    |
    v
POST /api/rtp/consume
    |
    v
Ticket Verification:
    - Signature check
    - Replay check
    - Tool binding
    - Agent binding
    |
    v
Execution Authorized

All stages append to:

Audit Chain (append-only, verifiable)

Agent State updated after every decision.

---

## Core Components

- KernelGate: orchestration + policy enforcement
- QIFTProcessor: signal transformation
- Geometry: behavioral distance + thresholds
- Integrity: consistency scoring
- Brittleness: instability detection
- Persona: agent classification
- Ticketing: cryptographic execution authorization
- Audit: append-only decision log
- State Store: agent continuity

---

## Design Principle

No execution without a ticket.
No ticket without geometry + integrity.
No reuse without detection.
No action without audit.

