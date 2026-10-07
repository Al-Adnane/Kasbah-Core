# Kasbah Consent Stone — Hardware Build Blueprint (v1.1)

> Rev 1.1: adopts the concrete pendant spec (nRF52840, $25 BOM → $99
> retail, Qi, IP68), four form factors (pendant hero / ring / clip /
> wristband), monotonic-counter attestations, and the dated build
> roadmap. Prior rev specified nRF52832/110 mAh — superseded below.

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
   and return `{ signer:'hw-stone', alg:'ed25519', signature: base64url, hardware:true, stoneId, agentId, pubkey, counter }`.
   The SE bumps a **monotonic counter per signature**; the host rejects
   any attestation with `counter <= cached` (`checkCounter()` in
   physical-products.js) — anti-replay beyond nonce binding.
3. Prove physical liveness: signature is only produced within ~2 s of
   a capacitive-touch interrupt. No touch ⇒ no signature, ever.
   SE sign time ~300 ms; end-to-end (BLE round-trip) < 5 s grace.
4. Attest over BLE with replay protection (per-request challenge).

Non-goals: no display, no biometrics, no network stack on-device.
The Stone is a signer, not a computer.

## 2. Bill of materials — pendant hero (28 × 32 × 8 mm, 12 g, IP68)

Concrete costing ($25.00 BOM → $99 retail, ~75% margin):

| Part | Spec | Cost |
|---|---|---|
| MCU | Nordic nRF52840 (BLE 5, Cortex-M4F 64 MHz) | $5.20 |
| Secure element | Infineon OPTIGA Trust M (ECDSA P-256, monotonic counter) | $2.10 |
| Touch | Capacitive touch controller (proximity + gesture) | $0.85 |
| Haptic | LRA actuator (touch feedback) | $1.40 |
| LED | SK6812 RGB ring ×16 (idle/prompt/allow/deny) | $0.90 |
| Battery | 120 mAh LiPo (~7-day standby, ~200 touches) | $1.80 |
| Charging | Qi coil (wireless, no port) | $1.20 |
| Face | Zirconia ceramic, engraved (IP68, scratch-proof) | $3.40 |
| Rim | Anodized aluminum 6061-T6 | $2.20 |
| PCB + assembly | 4-layer flex-rigid, SMT + reflow | $3.50 |
| Strap | Silicone lanyard + clip | $0.85 |
| Test + provisioning | SE keygen, BLE pairing, QC | $1.60 |

## 2b. Form factors — same SE, same firmware, four ways to wear it

| Form | Weight | Carry | Best for |
|---|---|---|---|
| **Pendant (hero)** | 12 g | lanyard / chain | everyday carry, canonical Stone |
| Ring | 6 g | finger | always-on, lowest-friction touch |
| Clip | 9 g | lapel / bag | enterprise badge, desk worker |
| Wristband | 18 g | wrist | active / clinical, biometric-close |

All four are registered in `physical-products.js` PRODUCTS
(stone-pendant / stone-ring / stone-clip / stone-band).

## 2c. Build roadmap (9 months to first 10k)

| Phase | Window | Items |
|---|---|---|
| Prototype | Week 1–4 | nRF52840 dev kit + OPTIGA breakout; BLE handshake + sign/verify; capacitive touch → SE sign; 3D-printed pendant enclosure |
| Pilot | Month 2–3 | 10 units to one design partner; MCP server; field-test BLE grace; FCC pre-scan |
| Production | Month 4–9 | Zirconia + rim tooling; SMT line; SE provisioning + QC station; 10k run |
| Patent + Scale | Month 6–18 | Parent filing; CE/RoHS/REACH; direct + distro channel; enterprise on-prem SDK |
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
