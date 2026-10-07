# Kasbah Consent Stone — Hardware Build Blueprint (v1)

Target: a physical tap-to-sign token that plugs into the existing gate
with **zero gate changes**. Software today (`signer: soft-stone`);
hardware tomorrow (`signer: hw-stone`). The verify path already
dispatches on `signer` (`consent-gate.js: stoneVerify`), and the BLE
grace window (`GRACE_MS = 5000`) is already enforced server-side.

## 1. What the hardware must do (contract)

1. Hold one Ed25519 private key per agent Stone, generated **inside**
   the secure element, never exportable.
2. On tap: sign the exact `canonical` string the server built
   (`canonicalGate({id, action, tool, S, n, agree, ah, ts, agentId, stoneId})`)
   and return `{ signer:'hw-stone', alg:'ed25519', signature: base64url, hardware:true, stoneId, agentId, pubkey }`.
3. Prove physical liveness: signature is only produced within ~2 s of
   a capacitive-touch interrupt. No touch ⇒ no signature, ever.
4. Attest over BLE with replay protection (per-request challenge).

Non-goals: no display, no biometrics, no network stack on-device.
The Stone is a signer, not a computer.

## 2. Bill of materials (per unit, ~$18–28 @100 units)

| Part | Spec | Why |
|---|---|---|
| Secure element | Infineon OPTIGA™ Trust M (I2C) **or** NXP SE050 | True HW keystore, Ed25519/ECDSA, CC EAL6+ |
| MCU | Nordic nRF52832 (BLE 5, ARM M4) | BLE + I2C master + <5 µA sleep |
| Touch | Capacitive pad → MCU GPIO interrupt (e.g. AT42QT1012 or nRF capacitive) | Physical-liveness gate |
| LED + haptics | 1× RGB LED, 1× LRA/ERM driver (DRV2605) | Tap acknowledged / grace-expiry feedback |
| Battery | 110 mAh LiPo + MCP73831 charger, USB-C | ~30-day standby |
| Enclosure | 42 × 42 × 9 mm, anodized Al + stone inlay | "Stone" identity; RF window for BLE |
| Debug | pogo-pin SWD, locked before ship | No open debug on production units |

Alternative (v1-lite, no BLE): USB-C HID FIDO2-style token using the
SE for sign + a side button for liveness. Same `hw-stone` attestation,
transport over USB instead of BLE. Cheaper, faster to ship.

## 3. Firmware architecture (nRF52832)

```
[BLE GATT service 0xKASB] ←→ [host (api-server / desktop main)]
        │
[challenge-response] → [touch ISR] → [SE sign over I2C] → [response]
```

GATT service (custom 128-bit UUID):
- `CHALLENGE` (write, 20 B server nonce + tap-id hash)
- `ATTEST` (notify/read, attestation JSON, ≤ 512 B)
- `PUBKEY` (read, Ed25519 pubkey + stoneId, provisioned once)
- `STATUS` (notify: idle / awaiting-tap / tapped / expired / low-batt)

Sign flow (mirrors `tap()` server-side):
1. Host writes CHALLENGE = `{ tapId, canonicalSha256, nonce, expiryMs }`.
2. Stone lights LED, starts 5 s window (matches `GRACE_MS`).
3. Capacitive ISR within window → MCU sends sign APDU to SE over I2C
   with `sha256(canonical)`; SE returns 64 B Ed25519 signature.
4. Stone notifies ATTEST = `{ signer:'hw-stone', signature, stoneId, tapId, nonce }`.
5. No touch in 5 s → notify `{ status:'expired' }`, LED off. Fail-closed.

Key provisioning (factory, once):
1. Generate Ed25519 keypair **inside SE** (`GenerateKeyPair`, non-exportable).
2. Read pubkey → print QR on device card → operator registers
   `stoneId ↔ pubkey ↔ agentId` via `POST /v1/consent/stone`.
3. Lock SE policy: sign-only, no export, no delete without factory reset
   (which wipes the key and orphans the stoneId — matches `revokeStone`).

## 4. Host integration (code changes, minimal)

- `stoneVerify()`: replace the `hw-stone` stub with real Ed25519 verify
  against the provisioned per-agent pubkey (already keyed by
  `att.agentId`; reject cross-agent — already implemented).
- New `stoneTransport` module (BLE GATT via Noble/`@abandonware/noble`
  on desktop main; USB-HID for v1-lite): `requestHwTap({ tapId,
  canonical }) → Promise<attestation | expired>`.
- `tap()` gains a `transport: 'soft' | 'hw'` branch: soft path signs
  in-process (today); hw path awaits the BLE round-trip inside the
  existing `GRACE_MS` timer (already the timeout owner).
- Server routes unchanged: `/v1/consent/*` already carry
  `agentId/stoneId`; add `transport` field to `stoneStatus()` output.

## 5. Electrical / mechanical notes

- SE on dedicated I2C bus with 4.7 kΩ pull-ups; MCU is sole master.
- Touch pad isolated from Al shell (ground ring); tune threshold so
  pocket-touch does not fire — require 80–300 ms press, not tap-edge.
- LED window + touch pad co-located: light = "press here now".
- Battery fuel-gauge via nRF SAADC; `<15%` → slow amber blink on STATUS read.
- RF: keep BLE antenna clearance ≥ 8 mm from Al; stone inlay must be
  non-conductive (ceramic/resin, not metal-flake).

## 6. Bring-up and acceptance tests

1. `hw self-test`: factory jig asserts SE keygen → sign → verify with
   known vector; touch ISR latency < 50 ms; sleep current < 8 µA.
2. `gate interop`: `stoneStatus()` reports `hardware:true`; request tap
   → touch → `TAP_AUTHORIZED, A:1, MODEL → RULE`; no touch → `DISCONNECT_TIMEOUT`.
3. `cross-agent`: Stone-A attestation presented for agent B → denied
   (`TAP_CROSS_AGENT_DENIED`), matching software behavior.
4. `replay`: captured ATTEST replayed on a new tapId → verify fails
   (nonce + canonical binding).
5. `revoke`: `DELETE /v1/consent/stone/:agent` → old Stone's taps denied,
   new session gets new stoneId; old signatures still verify for audit.
6. `fuzz`: 10k random CHALLENGE writes → no crash, no signature without touch.

## 7. Build order

1. v1-lite USB token first (2–3 weeks): SE + MCU + button, USB-HID,
   host `stoneTransport-usb`. Proves the whole gate path end-to-end.
2. BLE variant (4–6 weeks after): add nRF BLE, battery, enclosure.
3. Pilot 25 units → feed `taps/day` metric (`/v1/consent/stats`,
   target ≤ 3/day) to tune consequence tiers before mass run.

## 8. Mapping to current code

| Blueprint piece | Code anchor |
|---|---|
| `stoneSign` HW branch | `consent-gate.js: stoneSign()` (+ new `stoneTransport`) |
| `hw-stone` verify | `consent-gate.js: stoneVerify()` `hw-stone` branch (stub today) |
| 5 s grace | `GRACE_MS = 5000`, enforced by tap timer |
| Per-user stones | `stoneIdFor()`, `stoneStatus()`, `revokeStone()` |
| Kill-switch block | `killSwitchGuard()`, `denied-killswitch`, cross-agent 403 |
| Tap metrics | `GET /v1/consent/stats` (taps/day ≤ 3 target) |
| Risk tiers | `ssi-gate.js: classifyRisk()` (PHYSICAL_TOUCH ⇒ Stone lights) |
