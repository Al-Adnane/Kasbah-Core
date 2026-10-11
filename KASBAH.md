# Kasbah — strategy

**Status:** canonical. Rewritten 2026-10-11 after the full audit (`docs/audits/KASBAH-FULL-AUDIT-2026-10-11.md`). The earlier version of this file was lost; this one replaces it and changes the positioning.

## 1. Position: three pillars, one app

Kasbah does not try to beat any single competitor at their own product. It is defined by three pillars that are normally bought separately, or not available to an individual at all:

> **Privacy first. An AI control tower. Proof you can hand to anyone.**

| Pillar | The promise | What it is made of |
|---|---|---|
| **1. Privacy first** | Your data stays yours. Everything runs on your machine; nothing is uploaded to be checked. | Local-first engine, private browser with shields, VPN, password vault, secret and personal-data checks before anything leaves |
| **2. AI control tower** | One place to see and control every AI on your machine. Nothing risky happens without you. | Prompt and agent-action guard, agent and MCP inventory, tool blocking, cost limits, kill switch, human approval in a system dialog |
| **3. SSI proof** | Hard rules that cannot be traded away, and a signed record that they held. | Sovereign admission gate (one failed rule is a refusal, one-time permits, audit written first), signed offline-verifiable receipts, tamper-evident log, human-bound approvals |

**Privacy first is the foundation, not a feature.** The control tower and the proof are only trustworthy because they run locally and belong to the user. That is also what separates Kasbah from enterprise AI security, which inspects traffic in a vendor's cloud.

Where each neighbour stops:

| Neighbour | Privacy first | Control tower | SSI proof |
|---|---|---|---|
| Privacy browsers and VPNs (Brave, DuckDuckGo) | Yes | No | No |
| Enterprise AI security (Palo Alto, Check Point, SentinelOne) | No, cloud inspection | Yes, for companies | Logs, not proof |
| Agent and MCP gateways (Noma, Lasso, MintMCP) | No | Partly | No |
| Receipt and approval tools (IETF drafts, agent-receipts, CoSig, Ledger) | Varies | No | One piece each |
| **Kasbah** | **Yes** | **Yes, for one person** | **Yes** |

Kasbah is the mix. That is the outlier claim, and it is the only one we make. Short form for a privacy audience: *Brave, plus a control tower for your AI, plus proof.*

## 2. What this position requires

A bundle is judged by its weakest part, and the first pillar carries the name. So:

1. **Privacy claims must be literally true.** "Nothing is uploaded" has to hold for every default: the CLI, both SDKs and the MCP server must default to the local engine, and any remote call must be announced. (CLI, SDK and MCP defaults are local as of 2026-10-11.)
2. **Never claim to be a Brave replacement.** The Kasbah browser is an Electron webview with real shields. It is not a Chromium fork and has not been independently tested. Say "private browsing built in".
3. **A control tower has to control.** As of 2026-10-11 an agent that calls the consent tool is held until the person answers, and unknown tools need approval by default. An agent that never calls the tool is still not stopped; closing that needs the proxy or host integration to enforce it.
4. **"SSI proof" means two things, and both must be shown:** the admission gate decided by hard rules, and a receipt proves it. Say plainly that body-signal inputs are reference values and that the hardware device is not built.
5. **Each pillar stands on evidence** (section 4). Anything without evidence is labelled Labs in the app and left out of every pitch.

## 3. The product, in five places

One app, five pages, grouped by pillar. Everything else is Labs or removed.

| Pillar | Page | The one job |
|---|---|---|
| Privacy first | **Browse** | A private browser that also checks pages and prompts |
| Privacy first | **Vault & VPN** | Passwords and a private connection |
| AI control tower | **Check** | Paste or type anything bound for an AI; get Safe / Caution / Blocked |
| AI control tower | **Tower** | Every AI helper on this Mac: what it is doing, what it may do, and your approvals |
| SSI proof | **Proofs** | Every decision and approval as a receipt you can verify and hand to someone else |

The current "AI helpers" page becomes **Tower**. It already holds the admission gate card and the approvals card.

## 4. Evidence index

Only what is in this table may be claimed. Status is as of 2026-10-11.

| Pillar | Claim | Evidence | Status |
|---|---|---|---|
| Tower | Blocks hostile input before it leaves the machine | `/v1/scan`, `/v1/govern` verified live; benchmark F1 0.89 on a 77-case home corpus | **Proven, modest.** Never headline detection quality. |
| Proof | Receipts verify offline with a published key | Independent Ed25519 check; forgery and replay rejected; `kasbah-receipts` 18 tests | **Proven** |
| Proof | Tamper-evident decision log | Audit chain verified; survives restart | **Proven** (single signer) |
| Tower | Approval is bound to a human | 43 adversarial tests, 21 approver tests, attacker scenario over HTTP 17/17 | **Proven in software.** Same-user malware is out of scope until hardware. |
| Proof | One failed hard rule is a refusal | SSI: 29 tests, JavaScript and Python agree | **Proven as a gate.** Not yet in the path of real agent actions. |
| Privacy | Private browsing shields | Code read; not independently tested this cycle | **Unverified** |
| Privacy | VPN and kill switch | Config generation unit-tested; no live tunnel tested | **Unverified** |
| Privacy | Password vault | Unit tests only | **Unverified** |
| Tower | Hardware approval device | Blueprint and host-side verification only | **Not built** |
| Privacy | Checks run locally; nothing uploaded by default | CLI, both SDKs and the MCP server default to `127.0.0.1` (verified). The MCP server prints a hosted verify link but does not call it. | **Proven for defaults** |
| Tower | An agent's risky action waits for the person | End to end 2026-10-11: real MCP call → engine → desktop approval → agent. Allow, deny, read-only, unknown-tool and no-approver cases all correct | **Proven for agents that call the consent tool.** An agent that skips the tool is not stopped. |
| — | Runs from a clean download | Fresh clone, one `npm install` (about a minute), all 25 suites pass, and the UI test passes 17 of 17 in production mode | **Proven on this Mac** (macOS, Node 25, Python 3.14) |
| — | The app is honest about its own state | UI test: engine accepts the app, badge matches reality, no page shows error text, the page cannot approve its own request | **Proven** |
| — | Paid plans | 1 of 10 entitlements enforced | **Not ready to sell** |

Forbidden until evidence exists: "exclusive", "no competitor has this", "military grade", any detection superlative, any claim about the hardware device as a product, and anything from the removed research detectors.

## 5. Why this can win

- **Privacy is the trust anchor.** People will not hand an AI control tower to a vendor's cloud. Running locally is what makes the other two pillars acceptable.
- **Different buyer.** Enterprise AI security was bought up in 2025 (Protect AI, Lakera, Prompt Security, CalypsoAI) and now sells to security teams. Nobody is selling a guard, an approval gate and proof to the individual who uses AI all day.
- **Local-first is the wedge.** The competitors' model is cloud inspection. Kasbah's promise is that the check happens on your machine and the proof is yours.
- **Standards help rather than hurt.** Receipts are being standardised. Aligning with the IETF drafts makes Kasbah an implementation of something others will need, instead of a proprietary format.
- **The pieces reinforce each other.** A guard verdict becomes a receipt; an approval becomes part of that receipt; the browser and VPN are where the guard runs. The combination is worth more than the parts, which is the only real defence for a small team.

## 6. What must be true first

In order. Nothing later matters until the earlier item is done.

1. **It runs and tells the truth.** Done for running from source (2026-10-11): scans work in production mode and the badge is truthful. Still needed: a signed, notarised build, and the installed app matching the source.
2. **Agent actions actually pass through the tower.** The MCP server and proxy call the gate for every risky tool call.
3. **Hardware approval without a custom device.** Add Touch ID and security keys (WebAuthn) as an approver kind. The registry already supports multiple kinds.
4. **Receipts align with the public drafts**, with a public verifier page.
5. **Five pages.** Cut the rest to Labs.
6. **The private layer earns its place.** Independent test of the browser shields and one real VPN tunnel test, or those move to Labs too.
7. **Then money.** One entitlement model, a test per plan, and only then take payment.

## 7. How we talk about it

- Three words each: **Privacy first. AI control tower. SSI proof.**
- One sentence: *"A private place to use AI, where you control what every AI may do, and you can prove what happened."*
- To a privacy user: *"Your private browser stops trackers. Kasbah also stops your secrets reaching an AI, and stops an AI acting without you."*
- To a developer: *"One tower for every agent on your machine: they ask before they act, you approve with a click, and every decision is a signed receipt."*
- To a compliance buyer: *"Hard rules that cannot be overridden, and evidence an auditor can verify without trusting you."*

We compare ourselves to the combination, never to a single vendor.
