# Security policy

## Supported versions

| Branch | Supported |
|---|---|
| `main` (Node.js monorepo) | Yes |
| Legacy Python archive (`Al-Adnane/Kasbah-Core` pre-May 2026) | No |

## Reporting a vulnerability

Email **adnaneaddioui@gmail.com** with subject `[SECURITY] Kasbah`.

Include:
- A clear description of the issue
- Steps to reproduce
- Impact assessment (what an attacker could do)
- Any suggested fix

You will receive an acknowledgement within 48 hours. We aim to ship a fix within 14 days for critical issues.

Please do not open a public GitHub issue for security vulnerabilities until a fix has been released.

## Scope

In scope:

- **Consent gate bypass** — an agent approving its own request without a registered human approver
- **Receipt forgery** — producing a verifiable Ed25519 receipt without a legitimate decision
- **Replay attacks** — reusing a spent receipt or attestation counter
- **Privilege escalation** — a renderer process or agent gaining main-process or admin-key access
- **Injection through scanned content** — prompt injection that alters the verdict or leaks the engine key
- **Credential solicitation bypass** — a prompt containing credential-harvesting language passing as ALLOW
- **Local privilege escalation via the desktop bridge** — accessing IPC endpoints beyond the declared allowlist

Out of scope:

- Host-level compromise (malware with the user's own privileges can do anything the user can do)
- Denial of service against the local engine
- Vulnerabilities in third-party dependencies not introduced by Kasbah
- The archived Python implementation (`archive/`)

## Security architecture summary

Kasbah's threat model is an untrusted agent running with the user's own OS privileges. The defence layers are:

1. **Scan and govern** — every prompt and tool call is inspected for injection, secrets and credential harvesting before it leaves the machine
2. **Consent gate** — risky tool calls require a signed attestation from a registered approver key; the gate fails closed on missing or invalid signatures
3. **Human-bound approval** — the desktop app holds the approver key in the main process; a native dialog is the only path to a signature; the renderer and agent cannot access the key
4. **Monotonic counter** — the counter is written to disk before the signature is produced, preventing replay via crash and restore
5. **Signed receipts** — every decision is an Ed25519-signed, tamper-evident record that verifies offline without trusting Kasbah

Cryptography used: Ed25519 (receipts, approver attestations), SHA-256 (challenge hashes, receipt chain), AES-256-GCM (safeStorage-backed key wrapping on macOS).
