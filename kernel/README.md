# KasbahGuard Kernel Extension

Kernel-side component of Kasbah's biometric watch: real-time monitoring of
camera and microphone device-open events, published to user space through an
IOKit event ring.

## Honest scope — read this first

Modern macOS (12+) deliberately removed kernel-level hooks for camera and
microphone capture: capture authorization lives in user-space TCC and
AVFoundation, and Apple signs off only what it reviews. What this kext does:

1. **Monitor IOKit device-open/close events** for camera and audio input
   devices in real time (vs. the sentinels' 8-second poll).
2. **Publish events to user space** via an IOUserClient event ring, so
   `kasbah-kextd` and the desktop app see capture attempts instantly.
3. **Kernel-resident enforce flag** — records every open attempt with the
   requesting process identity for the user-space enforcer to act on.
4. **Tamper detection** — records an event if TCC.db is modified while
   enforce is set.

This kext **deliberately does NOT kill processes or drop syscalls from kernel
context** — enforcement happens in user space (`src/kasbah-enforcer.js`) where
it can be audited, signed, and reversed. The kernel's job is: see everything,
miss nothing, tell the truth.

## Three-tier architecture

| Tier | Component | Availability | Role |
|------|-----------|--------------|------|
| 1 | User-space sentinels (`mic-sentinel.js`, `camera-sentinel.js`) | Always on | TCC + lsof — observe & alert |
| 2 | This kext (`KasbahGuard.kext`) | When signed & loaded | Real-time kernel event ring |
| 3 | User-space enforcer (`kasbah-enforcer.js`) | When ENFORCE mode on | terminate / tcc-reset actions, audit-logged |

The desktop app auto-detects the highest available tier and degrades
gracefully — Tier 1 remains fully active regardless of the kext state.

## Build

Requires Xcode with the macOS Kernel Development SDK:

```bash
cd kernel
make          # builds build/KasbahGuard.kext (unsigned)
make status   # shows whether the kext is loaded
```

## Sign & install (requires Apple Developer ID with kext entitlement)

```bash
make sign      # codesign with Developer ID + kext entitlement
make install   # kmutil install (may require reduced security + user approval)
```

On macOS 12+, loading an unsigned or self-signed kext requires:

```bash
# 1. Lower security (reboot into recovery: csrutil disable)
# 2. Install
sudo kmutil install -v build/KasbahGuard.kext
# 3. Approve in System Settings > Privacy & Security
```

## User-space bridge

The kernel extension streams events to user space via an IOUserClient. The lightweight daemon `kextd.c` connects to the running kext and forwards events as JSON lines to stdout (ideal for SIEM tail, the desktop app, or log aggregation).

```
kernel/
├── Makefile                          # build / sign / install / status / kextd
├── kextd.c                           # Tier-2 user-space daemon (IOKit bridge)
└── KasbahGuard.kext/
    └── Contents/
        ├── Info.plist                # kext metadata + IOKit personalities
        └── MacOS/
            └── KasbahGuard.c         # kernel-side monitor (C)
```

Build the daemon (requires Command Line Tools; Xcode SDK for kext build):

```bash
cd kernel
make kextd      # → build/kextd
sudo build/kextd   # prints {"kextd":"exit","reason":"KasbahGuard kext not loaded …"} when kext is not loaded
```

When the kext is signed and loaded, `kextd` will print one JSON line per kernel event:

```json
{"type":"camera-open","pid":4242,"identity":"Chrome Helper","ts":123456}
```

The desktop app auto-detects kernel events when `kextd` is running and logs them with the same audit trail as Tier-1 sentinels.

## File layout
