# Kasbah Core — Security Posture v0.1

Last updated: 2026-02-06  
Version: v0.2.1-product

Kasbah Core is an agent-governance kernel providing cryptographic execution tickets,
replay protection, tool binding, audit chains, and behavioral gating.

This document describes what Kasbah DOES protect against, what it DOES NOT, and how to report issues.

---

## Threat Model (In Scope)

Kasbah is designed to mitigate:

1. Replay attacks  
   - Cryptographic tickets are single-use.
   - Re-consumption is rejected.

2. Tool confusion / tool substitution  
   - Tickets are bound to a specific tool name.
   - Mismatches are blocked.

3. Signature tampering  
   - Tickets are signed and verified.
   - Modified payloads invalidate signatures.

4. Rogue agent reuse  
   - Tickets are bound to agent_id + persona.

5. Signal poisoning (basic)  
   - Signals are validated for range and structure.
   - Invalid signals are rejected.

6. Behavioral drift  
   - Geometry + integrity scoring gates execution.

7. Brittleness under instability  
   - Brittleness scoring degrades or blocks execution.

8. Rate exhaustion  
   - Configurable rate limiting.

9. State rollback  
   - Agent state is persisted and checked.

10. Post-hoc accountability  
    - Every decision is appended to an audit chain.
    - Audit chains are cryptographically verifiable.

---

## Explicit Non-Goals (Out of Scope)

Kasbah Core does NOT currently protect against:

- Kernel or container escapes
- Host-level compromise
- Side-channel attacks (timing, cache, power)
- Memory corruption in Python runtime
- Supply-chain poisoning of dependencies
- Malicious infrastructure operators
- Physical access attacks
- Nation-state adversaries
- Zero-day exploits in Docker / Linux / Python

Kasbah is an application-layer governance system, not an operating system.

---

## Key Management

Current implementation uses filesystem or environment-backed keys.

Not yet implemented:

- HSM / TPM
- Vault integration
- Sealed secrets
- Hardware-backed signing

Enterprise deployments should externalize key storage.

---

## Build & Supply Chain

Current state:

- Standard pip dependency installation
- Docker-based builds

Not yet implemented:

- Dependency hash pinning
- SLSA provenance
- Reproducible builds

---

## Reporting Security Issues

Please report vulnerabilities privately.

Email: security@kasbah-core.dev (replace with your address)

Include:

- Description of issue
- Steps to reproduce
- Expected vs actual behavior
- Any proof-of-concept

We aim to respond within 72 hours.

---

## Philosophy

Kasbah does not claim perfect security.

Kasbah provides:

- Deterministic execution control
- Cryptographic accountability
- Runtime behavioral enforcement

Security is treated as an evolving discipline, not a checkbox.

