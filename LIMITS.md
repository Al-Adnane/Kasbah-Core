# Kasbah Core — Known Limits (v0.2.1)

Kasbah Core enforces execution governance at the application layer.

The following are known limitations:

---

## Runtime

- Python runtime (no memory isolation)
- No syscall sandboxing
- No seccomp profiles by default

---

## Cryptography

- Software-based signing only
- No hardware root of trust

---

## Infrastructure

- Assumes honest host OS
- Assumes honest container runtime
- No protection against root compromise

---

## Signals

- Statistical gating only
- No ML adversarial robustness
- No certified robustness guarantees

---

## Networking

- No built-in TLS termination
- Must be provided by reverse proxy (Caddy/Nginx/etc)

---

## Scale

- Single-node by default
- No distributed consensus
- No byzantine replication

---

## Threat Classes Not Covered

- Nation-state actors
- Supply-chain poisoning
- Physical access attacks
- Hypervisor compromise

---

Kasbah focuses on:

- Agent execution control
- Cryptographic accountability
- Runtime policy enforcement

Not on:

- OS security
- Hardware security
- Network perimeter defense

