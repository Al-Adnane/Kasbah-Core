# Kasbah Security Kingdom – Implementation Manifesto

**Objective:** Integrate all unique security elements discovered across Desktop scan into Kasbah production codebase, preserving existing seatbelt/receipts/ZK pipeline.

**Source:** `/Users/mac/Desktop/KasbahFinal/extracted` MCISE OS + desktop scan findings
**Target:** `/Users/mac/Desktop/KasbahFinal/packages/mcise-core`, `packages/api-server`, `packages/desktop`

---

## 1. Architecture Overview

```
Kasbah Security Kingdom
├─ packages/mcise-core/src/
│  ├─ fixed-core.js          # HMAC-signed constitutional core
│  ├─ audit.js               # HMAC chained audit
│  ├─ ladder.js              # Autonomy Ladder
│  ├─ agent-runtime.js       # Adversarial agents
│  ├─ mfa.js                 # TOTP MFA
│  ├─ vc.js                  # W3C Verifiable Credentials
│  ├─ model-gateway.js       # Constitutional prompt stripping
│  ├─ witness.js             # Witness checkpoint
│  ├─ siem.js                # SIEM export
│  ├─ consent.js             # Consent/DSR
│  ├─ hisbah-scan.js         # Hisbah integrity scan
│  └─ voice-security.js      # ASR command sanitization
├─ packages/api-server/server.js  # /v1/mcise/* routes
└─ packages/desktop/src/main-features.js  # IPC handlers
```

---

## 2. Component Manifests

### 2.1 HMAC-Signed Fixed Core
**Source:** `extracted/src/lib/services/fixed-core.ts`
**Target:** `packages/mcise-core/src/fixed-core.js` – already scaffolded

**Spec:**
- Store: in-memory Map + persistent JSON file `data/fixed-core.json`
- Keys: `vision, mission, refusals[], evidence_hierarchy, paradox_watch`
- Operations:
  - `list()` → array of records
  - `get(key)` → verify HMAC signature on read
  - `update(key, value, actor, boardToken)` → HMAC sign, version bump
- Security: `KASBAH_BOARD_TOKEN` required for writes
- API: `GET /v1/mcise/fixed-core`, `GET /v1/mcise/fixed-core/:key`, `POST /v1/mcise/fixed-core/:key`
- IPC: `mcise:fixed-core:list`
- Tests: signature tamper detection, board token rejection

### 2.2 HMAC Chained Audit with Verification
**Source:** `extracted/src/lib/services/audit.ts`
**Target:** `packages/mcise-core/src/audit.js`

**Spec:**
- Log file: `data/audit-chain.jsonl`
- Entry schema: id, sequence, occurredAt, actorType, actorId, action, entityType, entityId, payload, traceId, previousHash, entryHash
- `append({...})` → computes HMAC over canonical payload + previousHash
- `verify()` → replays chain, detects hash_mismatch / chain_break
- `list(limit)` → recent entries
- Integration: every MCISE operation appends audit entry
- API: `POST /v1/mcise/audit/append`, `GET /v1/mcise/audit/verify`, `GET /v1/mcise/audit/list`
- IPC: `mcise:audit:verify`
- Migration: import existing `audit.jsonl` → re-chain with HMAC

### 2.3 TOTP MFA + Session Revocation
**Source:** `extracted/src/lib/services/mfa.ts`
**Target:** `packages/mcise-core/src/mfa.js`

**Spec:**
- TOTP secret generation RFC6238, QR code URI
- `enroll(userId)`, `verify(userId, code)`, `revoke(userId)`
- JWT HS256 with `jti`, session table with revocation flag
- Middleware: `requireMFA` for sensitive routes
- API: `POST /v1/mcise/mfa/enroll`, `POST /v1/mcise/mfa/verify`, `POST /v1/mcise/mfa/revoke`
- Desktop IPC: `mcise:mfa:status`

### 2.4 W3C Verifiable Credentials
**Source:** `extracted/src/lib/services/vc.ts`, `src/app/api/vc`
**Target:** `packages/mcise-core/src/vc.js`

**Spec:**
- Issuer DID: `did:kasbah:issuer`
- Issue VC for agent passport, audit receipt, fixed core update
- Verify VC signature offline
- Public verifier endpoint
- API: `POST /v1/mcise/vc/issue`, `POST /v1/mcise/vc/verify`, `GET /v1/mcise/vc/:id`
- Storage: `data/vcs.jsonl`

### 2.5 Model Gateway with Constitutional Stripping
**Source:** `extracted/src/lib/services/model-gateway.ts`
**Target:** `packages/mcise-core/src/model-gateway.js`

**Spec:**
- Wrapper around LLM calls
- Before prompt send: strip Fixed Core data, redact refusals
- After response: log audit entry
- Fallback deterministic mock for tests
- API: `POST /v1/mcise/gateway/ask`

### 2.6 Witness Checkpoint Co-Sign
**Source:** `extracted/src/app/api/witness/checkpoint`
**Target:** `packages/mcise-core/src/witness.js`

**Spec:**
- Checkpoint payload: timestamp, audit head hash, fixed core hash
- Co-sign with Kasbah private key + Witness public key
- Store checkpoints `data/witness-checkpoints.jsonl`
- API: `POST /v1/mcise/witness/checkpoint`, `GET /v1/mcise/witness/checkpoints`

### 2.7 SIEM Export
**Source:** `extracted/src/app/api/siem`
**Target:** `packages/mcise-core/src/siem.js`

**Spec:**
- Export audit chain + agent actions to NDJSON
- Filters by time range, actor, severity
- API: `GET /v1/mcise/siem/export?from=&to=`

### 2.8 Consent & DSR Workflow
**Source:** `extracted/src/app/api/consent`
**Target:** `packages/mcise-core/src/consent.js`

**Spec:**
- Consent records: purpose, legal basis, timestamp, signature
- Revocation handling
- DSR export: compile user data from audit, VC, fixed core logs
- API: `POST /v1/mcise/consent/capture`, `POST /v1/mcise/consent/revoke`, `GET /v1/mcise/dsr/:userId`

### 2.9 Hisbah Scan Service
**Source:** `extracted/src/lib/services/hisbah-scan.ts`
**Target:** `packages/mcise-core/src/hisbah-scan.js`

**Spec:**
- Scan text for integrity violations
- Rules engine with configurable policies
- Returns score + violations
- API: `POST /v1/mcise/hisbah/scan`

### 2.10 Voice Security – ASR Command Sanitization
**Source:** `extracted/src/lib/services/voice.ts`
**Target:** `packages/mcise-core/src/voice-security.js`

**Spec:**
- Whitelist voice commands: `kill <agent>`, `verify chain`, `approve escalation`
- Sanitize transcription, block injection
- Audit every voice command
- API: `POST /v1/mcise/voice/command`

### 2.11 Security Panel UI
**Source:** `extracted/src/components/mcise/security-panel.tsx`
**Target:** Desktop renderer component

**Spec:**
- Tabs: Fixed Core, Audit Verify, Ladder, MFA, VC, Witness
- Role-gated visibility

### 2.12 Quantum Crypto Helpers
**Source:** `products/kasbah-core-python/kasbah_core/quantum_crypto.py`
**Target:** Node port `packages/mcise-core/src/quantum-crypto.js`

**Spec:**
- Post-quantum key generation helpers for future receipts
- Integration point for ZK proofs

---

## 3. API Routes Summary

All under `/v1/mcise/*` in `packages/api-server/server.js`

| Route | Method | Purpose |
|-------|--------|---------|
| /fixed-core | GET | List |
| /fixed-core/:key | GET/POST | Get/Update |
| /audit/append | POST | Append entry |
| /audit/verify | GET | Verify chain |
| /audit/list | GET | List entries |
| /ladder/register | POST | Register agent |
| /ladder/evaluate | POST | Record eval/promote |
| /ladder/:id | GET | Status |
| /agents/register | POST | Register agent |
| /agents/pair | POST | Set adversary |
| /agents/trigger | POST | Trigger agent |
| /mfa/enroll | POST | Enroll TOTP |
| /mfa/verify | POST | Verify TOTP |
| /vc/issue | POST | Issue VC |
| /vc/verify | POST | Verify VC |
| /witness/checkpoint | POST | Create checkpoint |
| /siem/export | GET | Export NDJSON |
| /consent/capture | POST | Capture consent |
| /dsr/:userId | GET | Data subject export |
| /hisbah/scan | POST | Run Hisbah scan |
| /voice/command | POST | Voice command |

---

## 4. Desktop IPC Handlers

Add to `packages/desktop/src/main-features.js`

- `mcise:fixed-core:list`
- `mcise:audit:verify`
- `mcise:ladder:status`
- `mcise:mfa:status`
- `mcise:vc:issue`
- `mcise:witness:checkpoint`

---

## 5. Data Schema

`data/`
- `fixed-core.json`
- `audit-chain.jsonl`
- `mfa-secrets.json`
- `vcs.jsonl`
- `witness-checkpoints.jsonl`
- `consent-records.jsonl`

---

## 6. Tests & Verification

- Unit tests for HMAC verification tamper detection
- Audit chain break simulation
- MFA TOTP accuracy
- VC signature verification
- Model gateway stripping test
- Witness checkpoint co-sign test

---

## 7. Rollout Phases

**Phase 1 – Core Crypto:** Fixed Core + Audit Chain
**Phase 2 – Identity:** MFA + VC
**Phase 3 – Agents:** Ladder + Adversarial Runtime
**Phase 4 – Compliance:** Witness, SIEM, Consent/DSR
**Phase 5 – Advanced:** Hisbah, Voice Security, Quantum Crypto

---

## 8. Risks & Mitigations

- Secret leakage: store `KASBAH_RECEIPT_SECRET`, `KASBAH_BOARD_TOKEN` in env, never commit
- Audit log bloat: rotate monthly, archive to S3
- MFA usability: fallback recovery codes
- VC revocation: maintain revocation list

---

**Manifesto Owner:** Kasbah Security Kingdom
**Created:** 2026
**Status:** Implementation Ready
