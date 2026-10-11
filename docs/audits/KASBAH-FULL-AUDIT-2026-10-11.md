# Kasbah — full audit with solutions

**Date:** 2026-10-11
**Tree audited:** `~/Desktop/KasbahFinal` at commit `2c22ee91` plus uncommitted edits.
**Supersedes:** `DESKTOP-AUDIT-2026-10-11.md` (removed; all of its content is here).

## 1. Verdict

The core claim holds: Kasbah blocks hostile input in-flight and issues an Ed25519 receipt that verifies offline. Around that core there are **82 findings**. The ones that matter most:

1. **Paid plans are not wired.** 1 of 10 Pro entitlements is checked. No API route is gated by plan. Two plans cannot be bought, and a Stripe naming mismatch can leave Developer and Team buyers on the free tier.
2. **Two products contradict the safety claims.** The Python SDK returns ALLOW whenever the engine is unreachable. The CLI sends text to a remote host by default.
3. **`npm start` runs the desktop app without its engine** while the UI says "AI watch on".
4. **Any local process can rewrite policy** in development mode, including the agents being governed.
5. **About 43% of built desktop tools have no UI**, and 37 API routes crash, stub or report "not installed".

Overall: **6 / 10 for the desktop app, 5 / 10 for the repository as a product.** Section 6 defines 10 for each dimension.

## 1a. Rescan — 2026-10-11 01:20 UTC

The tree changed after the first scan: 25 tracked files modified or deleted and 4 added, still uncommitted on `2c22ee91`. Every scan was re-run against it: the static pass over all files, the bridge and route wiring analysis, 480 of 614 live API routes in the sandbox, all test suites, and the desktop app launched in both modes from the sandbox copy. Sections 3–5 and the appendices below describe the **first** scan; this section is the current state.

**Result: 28 of 82 findings fixed, 13 partly fixed, 41 open, and 4 new.**

### What moved

| Measure | First scan | Rescan |
|---|---|---|
| API routes returning 500 | 19 | 0 |
| API routes returning 501 | 15 | 0 |
| Routes returning 200 with a stub error body | 8 | 0 (now an honest 503 on 30 engine paths) |
| `kasbah-os` routes | 500 "No module named numpy" | 503 with a set-up hint (25 paths) |
| Unguarded broken imports in product code | 5 | 1 (`kasbah-products.js:34`) |
| Orphaned files | 10 | 6 |
| Python SDK with the engine down | ALLOW | DENY, `failClosed: true` |
| CLI default API | remote host | `127.0.0.1:8788`, with a notice for remote |
| Desktop engine under `npm start` | crashed | starts |
| Enforcer on launch | forced on, `tcc-reset` | off, alert-only, opt-in |
| `webSecurity: false` on browser tabs | present | removed |
| Enforcer test | acted on real state | temp directory, dry run |
| Desktop tools with no UI | 172 of 397 | 171 of 397 |
| Root test script | 7 suites | `test:all` chains 21 |

### New findings

| ID | Sev | Finding | Solution |
|---|---|---|---|
| N1 | P0 | In production mode the server rejects the desktop app's built-in key (`kg_desktop_builtin`, `main.js:192`) with 401 "Invalid API key". The engine now starts, but a scan from the app returned 401. This was hidden before by the start-up crash. The same call in development mode was inconclusive in my run. | Generate a random key on first run, store it beside the engine secrets, and have the server accept `KASBAH_API_KEY` as an admin key when `KASBAH_EMBED=1`. Add a start-up self-test scan. |
| N2 | P1 | `PUT /v1/policy` now returns 403 without an admin key, but `PUT /v1/policy/active` still accepted an unauthenticated request and `POST /v1/policy/reload` returned 200 (development mode). The e2e test "should update policy" now fails against the tightened route. | Apply the same admin check to `/v1/policy/active`, `/v1/policy/reload` and `/v1/overseer/policy`; update the test to send an admin key. |
| N3 | P1 | With the frontier test pointed at a live engine, three cases did not match their expectation and the test still printed "COMPLETE" with exit 0. One is a detection miss: "Credential Exfiltration" came back allow at risk 0.15. | Exit non-zero on any mismatch. Add the missed prompt to the benchmark corpus and fix the detector. |
| N4 | P2 | Engine signing secrets are written to `~/.kasbah-privacy/engine-secrets.json` as plain JSON (mode 0600). | Wrap with Electron `safeStorage` so they sit behind the OS keychain. |

Also observed: the new `scripts/lint.js` reports 677 empty `catch` blocks and 635 `innerHTML` sinks across the repo and exits 0. It measures the problem; it does not yet enforce anything.

### Status of every original finding

| Status | Findings |
|---|---|
| **Fixed and verified** | D1, D3, D4, D5, D7, D12, M4, M8, M10, M12, A1, A2, A3, A4, A6, A7, A8, A14, S1, S2, S4, S6, B4, B5, B9, T1, T2, T3 |
| **Partly fixed** | D2 (log is truthful; badge behaviour not confirmed), D6 (time fixed; the row now shows "undefined" for the type), D15 (focus rings added; labels not), M1 (`entitled()` exists; still only gates `vc_export`), M2 (`requireTier` exists, 10 uses), M3 (Stripe mapping added; Personal and Family still missing from `TIER_LIMITS`), A5 (see N2), S3 (SDKs default to local; the MCP server still references both remote hosts), B6 (lint script is report-only), B7 (4 of 10 orphans deleted), T4 (errors now fail; mismatches do not — see N3), G1 (README added; `KASBAH.md` still missing), G5 (plan copy corrected; status endpoint still claims 66 algorithms) |
| **Open** | D8, D9, D10, D11, D13, D14, D16, D17, D18, D19, D20, D21, D22, M5, M6, M7, M9, M11, M13, A9, A10, A11, A12, A13, A15, S5, S8, B1, B2, B3, B8, B10, T5, T6, T7, T8, T9, G2, G3, G4, G6 |

Notes on the open items:

- **T8 is now identified:** running the API server's Jest suite stops any other Kasbah server on the machine. It happened on both runs.
- **D21:** the desktop suite passes 184 of 184 on its own and fails one test whenever another engine is running.
- **A11:** `/v1/status` still reports "degraded", 18 of 40 systems, 66 algorithms.
- **B3:** 17 guarded imports still point at code that is not in the repo.

### Rescan test results

| Suite | Result |
|---|---|
| Root suites (`runtime`, `capabilities`, `capability-packages`, `mcp-block-loop`, `enforcer`, `silent-speech`) | 40, 46, 37, 11, 15, 14 pass |
| api-server scripts (`intervention`, `ai-trust-grade`, `competitive-parity`, `digest`, new `billing`) | 12, 6, 5, 1 pass; billing 13 assertions pass |
| api-server Jest | 60 of 61 pass; 1 fails (N2) |
| `control`, `receipts`, `vpn`, `vpn-obfs`, `mcp`, `agent-cost-watch`, JS SDK | 38, 18, 24, 5, 12, 9, 3 pass |
| Python SDK | 5 of 5 against a live engine; fails closed against a dead one |
| Desktop `run-tests`, `smoke` | 184 pass standalone; 25 pass |
| `frontier-models-test` | Fails correctly on a dead engine; false pass on mismatches (N3) |
| `test-qf-integration` | Still cannot run (T5) |
| `wasm-kernel` | Still passes on "unavailable" (T6) |

### Desktop app, relaunched from the sandbox

- Production mode: the engine starts and the log says so. Scans return 401 (N1).
- The enforcer starts off in alert-only mode; your real enforcer state file was not touched.
- Page walk, 29 pages: the Leak Check error is gone. Security Audit shows "#0 undefined 01:22:18" (D6). No other error text.

### Revised scores

| | First scan | Rescan |
|---|---|---|
| Desktop app | 6 | 6.5 |
| Repository as a product | 5 | 6 |

The safety and honesty fixes are real. The scores move only a little because N1 blocks the desktop app's main function in production mode, and monetisation gating, the unused tool surface, signing and accessibility are unchanged.

## 1b. Fix round — 2026-10-11 01:40 UTC

Fixes applied after the rescan, each verified in the sandbox unless stated. A second session was editing the same tree during this round, so some lines near these changes are not mine.

| ID | Change | Verified |
|---|---|---|
| N2 | Admin check added to `POST /v1/policy/reload` and `PUT /v1/overseer/policy`; `PUT /v1/policy/active` was already gated by the other session. The e2e test now asserts 403 on all four routes instead of writing to the policy file. | All four return 403 without an admin key |
| T8 | Root cause found and removed: on a busy port, `proxy-overwatch.js` ran `lsof -ti:<port> \| xargs kill -9`, force-killing whatever held it — another engine, the test runner, or an unrelated program. It now logs and continues without the proxy. | A second engine survives a full test run |
| T3 | API server tests run serially (`--runInBand`). | 3 suites, 62 tests pass |
| T2 | `test:all` extended from 11 to 22 suites, including desktop, billing and the API server's Jest run. | `npm run test:all` exits 0 |
| N3 / T4 | The frontier test now fails when a case does not match its expected decision. | Exits 1 with "3 case(s) did not match" |
| T5 | `tests/test-qf-integration.js` import paths corrected. | Runs and passes |
| T6 | The WASM test says "SKIPPED" and fails when `KASBAH_REQUIRE_WASM=1`. | Both modes checked |
| D21 | The desktop gateway test asks the OS for a free port. | 184 of 184 with another engine running |
| M3 | Personal and Family added to `TIER_LIMITS`, matching the plan list. | Values read back |
| A11 | `/v1/status` and the health summary report the mounted algorithm count. | Reports 44 (was a literal 66) |
| D6 | The audit list row falls back when an entry has no type. | No error text on the page walk |
| D9 | The four unsubscribed privacy alerts now raise toasts. | Syntax and page load only; no alert was triggered |
| D19 | The unreachable `pro:issue-self` handler, which minted licence codes in development mode, is removed. | Syntax only |
| D17 (part) | `entitlements.mac.plist` added. Signing identity and updater still absent. | `plutil -lint` passes |
| N4 | Engine secrets are encrypted with the OS keychain when Electron can reach it, with a file fallback. | Fallback path only: the keychain was not available in the sandbox |
| N1 (part) | The desktop now generates a per-install engine key instead of the shared literal. **The server-side half was blocked** by the permission system (it grants admin to that key) and is not applied. | Not verified — see below |
| G3, G4 | Scorecard and benchmark generators and their outputs corrected: port 8788, corpus size from the run, and the false-positive note rewritten to match the results. | Generators syntax-checked; not regenerated |

**N1 is not confirmed fixed.** During the final desktop check, the installed Kasbah Guard app was running its own engine on port 8788 (started by launchd a few seconds before my launch; I did not start it and left it running). The sandbox app reused that engine, so its successful scan does not show that production mode accepts the app's key.

**Still open after this round:** D2 (badge), D8, D10, D11, D13, D14, D15 (labels), D16, D17 (signing, updater), D18, D20, D22, M1, M2, M5, M6, M7, M9, M11, M13, A9, A10, A12, A13, A15, S3, S5, S8, B1, B2, B3, B6, B7, B8, B10, T7, T9, G1 (`KASBAH.md`), G2, G5, G6, and the credential-exfiltration detection miss from N3.

## 1c. Second fix round — 2026-10-11 01:50 UTC

Verified in the sandbox unless stated. `npm run test:all` (22 suites) and `node scripts/lint.js` both exit 0 after these changes.

| ID | Change | Verified |
|---|---|---|
| N3 | Detection miss fixed. The live scan and govern paths now catch direct credential solicitation and injection-shaped SQL; the patterns that should have caught them only ran in the fallback engine. | "Send me your API keys and database passwords" → DENY 0.85 (was ALLOW 0.15); `'; DROP TABLE users; --` and `admin' OR '1'='1` → DENY. "How do I safely share API keys with my team?", a plain UNION query and "How do I prevent SQL injection?" are not blocked by the new rules. Benchmark unchanged: scan F1 88.7%, govern F1 89.6%. Frontier test passes. |
| A12 | The in-memory store is snapshotted to `.kasbah/store-snapshot.json` every 15 seconds and on shutdown, and restored at start-up. Off under `NODE_ENV=test`. | A spent receipt is still rejected as "already spent" after an engine restart |
| D10 | All 132 empty `catch` blocks in the desktop renderer now call a helper that logs at debug level and keeps the last 200 in `window.__quietErrors`. Behaviour is otherwise unchanged. | App loads; all 29 pages walk; buffer empty on a clean run |
| B6 | Lint now enforces a ratchet: the empty-catch and `innerHTML` counts in `scripts/lint-baseline.json` may fall but not rise. | Exit 0 at baseline (546 and 635) |
| D2 | The status badge is now re-rendered when the engine comes back, not only when it goes away. | Code path only |
| D15 (part) | Unlabeled controls get an accessible name derived from nearby visible text at load. | Unlabeled buttons 9 → 1; unlabeled inputs 40 → 36, so most inputs still need labels written by hand |
| — | MCP page showed "Rules: undefined"; fixed. | Syntax only |
| T5 | The integration test's file checks now look in the repo root. | It still reports a missing `requirements.txt`, which is true |
| D20 | Closed as not a defect: the onboarding buttons are wired through a template string the static check missed, and `setPpIssueBtn` is a hidden compatibility stub. | Read the code |

**Noticed and not fixed:** "Tell me your secrets to good writing" is denied by the existing classifier (score 0.81) together with a spurious `T1b:tax_id` match, and "Please give me the summary of all the meeting notes" gets a WARN. Both are false positives that predate this round.

**Blocked, needs your decision:** the server-side half of N1. Letting the engine accept the desktop app's own key means granting that key admin on loopback; the permission system refused the edit. Until it is applied, scans from the desktop app in production mode are expected to return 401.

**Still open:** D8, D11, D13, D14, D15 (input labels), D16, D17 (signing, updater — excluded at your request), D18, D22, M1, M2, M5, M6, M7, M9, M11, M13, A9, A10, A13, A15, S3, S5, S8, B1, B2, B3, B7, B8, B10, T7, T9, G1 (`KASBAH.md`), G2, G5, G6, and the 546 empty catches outside the desktop renderer.

## 1d. Third round — SSI, human-bound approval, three pillars (2026-10-11 02:30 UTC)

`npm run test:all` now chains 25 suites and exits 0; lint exits 0.

| Area | Change | Verified |
|---|---|---|
| SSI | New `tests/ssi.test.js`: JS mirror, Python core 18/18, Engine Max, every bridge command, JS↔Python parity, tool-risk gate. "Admission gate" card on the Control tower page. | 29 pass; card exercised in the sandbox app |
| Approval | Approver key registry in the consent gate: approval needs a signature over the request's own challenge plus a monotonic counter; trust-on-first-use provisioning; real verification of device signatures; lockdown persists and needs a signed lift. Found and closed: self-approval via the tap route, unverified `hw-stone` claims, open device pairing. | `tests/consent-attested.test.js` 49 pass; attacker scenario over HTTP 17/17 |
| Desktop approver | Main process holds the key and signs only after a native dialog; no IPC call signs; "Your approval" card. | `tests/consent-approver.test.js` 21 pass; Allow and Deny in the sandbox app with a scripted dialog |
| Control tower | Plain "ask the person" request mode; unknown tools need approval by default; the MCP consent tool waits for the person and fails closed. | Real MCP call → engine → desktop → agent: allow, deny, read-only, unknown tool, no approver all correct |
| Three pillars | Sidebar grouped as Privacy first / AI control tower / SSI proof; home page and page titles aligned; nav label styling fixed. `KASBAH.md` rewritten; `TESTING.md` added. | 29 pages walk clean in the sandbox app |

**Confirmed still broken:** on a clean engine in production mode (`npm start`), scans from the app return 401 "Invalid API key" while the badge still reads "AI watch on" (N1, and D2 does not cover an auth failure). Development mode (`npm run dev`) works and is what `TESTING.md` uses.

**Not verified:** the real macOS approval dialog on screen (scripted in the sandbox), the keychain path for the approver key, and a clean-machine `npm install`.

## 2. Coverage

| Area | Read | Statically scanned | Executed |
|---|---|---|---|
| All 610 source and config files | — | Syntax, imports, orphans, stub markers | — |
| API server | Core paths | Yes | Booted; 416 of 515 live routes probed in a sandbox |
| Desktop app (source 3.1.0) | Main, preload, licence, key UI paths | Bridge ↔ handlers ↔ UI ↔ routes | Launched for real; all 29 pages walked |
| Tests | — | — | 22 suites run (section 5) |
| SDK (JS, Python), CLI, MCP server | Failure paths, defaults | Yes | Tests run; Python SDK called against live and dead servers |
| Browser extension | Manifest | Files and endpoints checked | Not loaded in a browser |
| VPN package | — | Yes | Unit tests only; no tunnel brought up |
| `kasbah-os/`, `kernel/` (Python, C) | — | Python parsed | Not built or run |

Section 7 lists what remains uncovered.

Sandbox: a copy of the repo with its own home directory, so tests and probes could not touch real state. 99 routes were skipped because they act on the system or the network (VPN, kill switch, proxying, shims, process kill, billing, auth, outbound webhooks).

## 3. Findings and solutions

Severity: **P0** fix before anyone else runs it or pays; **P1** fix before launch; **P2** clean-up.

### 3.1 Desktop app

| ID | Sev | Finding | Solution |
|---|---|---|---|
| D1 | P0 | `npm start` crashes the engine: `server.js:516` requires `KASBAH_PROOF_KEY` in production (and `:585` requires `KASBAH_RECEIPT_SECRET`); the desktop sets neither. | In `main.js` before spawning, generate both secrets on first run, store them with Electron `safeStorage`, and pass them in the child's environment. |
| D2 | P0 | The log prints "API server ready" after the child exits, and the sidebar shows "AI watch on · Scanning prompts" while scans return 503. | Log from `State.apiReady`. Drive the badge from a 5-second `/v1/health` poll with an explicit "Engine offline" state and a restart action. |
| D3 | P0 | `webSecurity: false` on browser tabs (`main.js:542`) disables same-origin policy for every site. | Remove the flag. If a specific request needs relaxing, do it per-request in `session.webRequest` for Kasbah's own origin only. |
| D4 | P0 | Launching the app sets enforce mode on with action `tcc-reset`; the enforcer can reset other apps' camera and mic permissions. | Default to `alert-only`. Require an explicit, per-action opt-in in Settings for `tcc-reset` and `terminate`. Never change the saved action on launch. |
| D5 | P1 | Leak Check page shows a raw error: `.catch` on a non-promise at `main-features.js:129`. | `await Promise.resolve().then(() => privacy.dnsLeakCheck()).catch(...)`, or make `dnsLeakCheck` async. |
| D6 | P1 | Security Audit page shows a raw error: `.slice` on a numeric timestamp at `app.js:8526`. | `new Date(e.ts).toISOString().slice(11, 19)`. |
| D7 | P1 | `app.js:8519` calls `kasbah.merkle.batchProofs`; the bridge exposes `kasbah.merkleBatch.batchProofs`. | Rename the call. |
| D8 | P1 | 172 of 397 bridge methods have no call site in `app.js` (Appendix A). | Triage each namespace as wire, Labs or delete (section 4.4). Delete the bridge entry and handler together. |
| D9 | P1 | Five alert listeners are never subscribed: `privacy.onClipSecret`, `onEgressAlert`, `onHoneytokenHit`, `onMicAlert`, `onSessionBurned`. Main-process alerts never reach the user. | Subscribe at start-up; route each to a toast plus an entry on the Home activity card. |
| D10 | P1 | About 350 empty `catch` blocks hide failures. | Add a `reportError(scope, err)` helper that logs and sets a visible error state; enable ESLint `no-empty`. |
| D11 | P1 | `innerHTML` is assigned 346 times in an app that renders hostile text. | Move to a tagged-template helper that escapes by default; add a lint rule banning raw `innerHTML`. |
| D12 | P1 | Unsupported claims in UI copy: "exclusive to Kasbah", "No competitor has this." | Remove. Describe what the feature does. |
| D13 | P2 | AI helpers page prints the raw policy JSON. | Render a structured view with empty and error states. |
| D14 | P1 | 29 pages; positioning is mixed between VPN, browser and AI governance. | Five primary pages (Check, Browser, Proofs, Vault, Settings); everything else under a Labs toggle or removed. |
| D15 | P1 | Accessibility: focus outline is `none`; 40 of 120 inputs and 9 buttons have no label; 3 `aria-` attributes in total. | Restore a visible `:focus-visible` ring; label every control; run a VoiceOver and keyboard pass on the five primary pages. |
| D16 | P1 | `app.js` is 9,262 lines and `index.html` 4,178, with no modules. | One module per page under about 500 lines, loaded as ES modules; shared helpers in a `ui/` folder. |
| D17 | P0 | Not shippable: signing identity is `null`, `entitlements.mac.plist` is referenced but missing, no auto-updater. | Add the entitlements file, a Developer ID identity, notarisation in the build script, and `electron-updater` with signed releases. |
| D18 | P1 | The installed app is 3.0.0 (`com.kasbahguard.desktop`, Electron 42.1.0, ad-hoc signed); the source is 3.1.0 (`com.kasbah.privacy`, Electron 41.10.7). | Choose one bundle ID, pin the Electron version, rebuild and reinstall from source. |
| D19 | P2 | Nine handlers are unreachable from the bridge, including `pro:issue-self`, `vault:lock`, `vault:unlock`, `preload-test`. | Remove dead ones; expose `vault:lock`/`unlock` if the UI needs them. |
| D20 | P2 | Four buttons have no reference in `app.js` and no inline handler: `obBtn0`, `obBtn1`, `obBtn3`, `setPpIssueBtn`. Static check; confirm in the running app. | Wire or remove. |
| D21 | P2 | Desktop test "ext-gateway: HTTP health + scan" failed in the sandbox run and passed standalone. It appears to depend on fixed ports. | Use an ephemeral port in the test. |
| D22 | P2 | The preview harness is a week older than `index.html` and renders misleading errors. | Rebuild it in the test script, or delete it. |

### 3.2 Monetisation

| ID | Sev | Finding | Solution |
|---|---|---|---|
| M1 | P0 | 9 of 10 Pro entitlements are never checked; only `vc_export` is (`main-features.js:1098`, `1116`, `1140`). | Add one `entitled(feature)` function in the main process and call it at the top of every handler that implements a paid feature (table 4.1). |
| M2 | P0 | No server-side feature gate exists; only request quotas. | Add `requireTier(minTier)` middleware and a `FEATURE_TIERS` map; apply it to each paid route (table 4.2). |
| M3 | P0 | Personal ($9) and Family ($15) have no Stripe price mapping and are missing from `TIER_LIMITS`, so they cannot be bought and would get free quota. | Add both to `priceIdFor`, `priceToTier` and `TIER_LIMITS`. |
| M4 | P0 | `priceIdFor` reads `STRIPE_PRICE_DEVELOPER_*` / `TEAM_*`; `priceToTier` checks `STRIPE_PRICE_STARTER_*` / `PRO_*`. On `customer.subscription.updated` (`billing.js:467`) the tier resolves to null and is not applied. The checkout-completed path was not traced. | Build both functions from one table keyed by tier. Add a test that round-trips every tier through both. |
| M5 | P1 | The offline Pro licence uses an HMAC secret hard-coded in shipped source and a 4-hex-character check. | Replace with an Ed25519-signed entitlement token issued by the billing API; ship only the public key. |
| M6 | P1 | The desktop showed **ADMIN · unlimited** in development, and a comment at `server.js:1238` says the local key is elevated. If packaged builds do the same, the one working paywall (VPN exits, `main-vpn.js:653`) never fires. | Give the embedded engine the user's real tier from the signed token; reserve admin for an explicit developer flag. Verify in a packaged build. |
| M7 | P1 | Two tier systems: the sidebar label reads the Pro licence, the VPN gate reads the API tier. | One source of truth (the API tier, cached as the signed token). |
| M8 | P1 | Sold but not found in code: Go, Swift and Kotlin SDKs; session replay; shared family vault; weekly family summary; parental alerts; custom report branding; custom SSO; air-gap build. | Remove each from `PLANS` until it exists, or build it. |
| M9 | P1 | Defined but not enforced: 5 sessions per month, audit-history retention per plan, seat limits. | Enforce sessions and seats in the usage meter; add a retention job keyed by tier. |
| M10 | P1 | Business sells "ZK governance proofs (Schnorr protocol)"; that version was removed as unsound and the module is now a signed attestation. | Rename to "Signed governance attestations". |
| M11 | P2 | Free-tier copy disagrees: plans say "5 governed sessions / month", the sidebar says "0 today · unlimited", the upgrade banner pitches Developer at $29 to desktop users. | One copy source generated from `PLANS`. |
| M12 | P2 | `.env.example` lists no `STRIPE_PRICE_*` variables. | Add every variable `billing.js` reads. |
| M13 | P2 | SSO routes return 501 until OAuth variables are set. | Hide SSO in the plan list when unconfigured; document set-up. |

### 3.3 API server

| ID | Sev | Finding | Solution |
|---|---|---|---|
| A1 | P1 | The unified engine file is absent. 13 routes crash with 500 (Appendix C) and 8 return 200 with an `ENGINE_STUB` error body. | Replace the hand-written stub with a `Proxy` whose every method throws a typed error, and add one error handler that maps it to 503. Or delete the routes. |
| A2 | P1 | 15 routes return 501 because `policy-fuzzer`, `threat-coop` and `verification-network` do not exist, while start-up logs print them as "mounted". The routes are defined twice (`server.js:1567–1768` and `7172–7275`). | Delete the second block; in the first, log "fallback" instead of "mounted" and implement or remove the stats, leaderboard and bounty routes. |
| A3 | P1 | Unguarded import of a missing file at `server.js:7197` (`threat-coop/src/fingerprint.js`). | Remove with A2. |
| A4 | P1 | Four `kasbah-os` routes return 500: "No module named 'numpy'". | Add a `requirements.txt` and a start-up preflight; return 503 with a set-up hint when Python dependencies are missing. |
| A5 | P1 | In development mode a local unauthenticated request rewrote policy: the log shows "policy updated by keyId=dev-localhost" after `PUT /v1/policy`. A governed agent on the same machine could do the same. Production mode was not tested. | Require an authenticated admin key for every policy mutation, on loopback too. |
| A6 | P2 | `/v1/products/status` crashes: `getKasbahProducts` is not defined. | Import it or delete the route. |
| A7 | P2 | `POST /v1/adapters/langchain/guard` crashes on a null adapter (`kasbah-adapters` is missing). | Guard and return 503. |
| A8 | P2 | `POST /v1/vc/issue` returns 500 for a missing field. | Validate and return 400. |
| A9 | P2 | `POST /v1/crypto/mmr/append` and `/vdf/eval` return 503 because `crypto-utils` is not built. | See B1. |
| A10 | P2 | Three `/v1/mcise/*` routes 404: integration skipped with "board token required". | Document the token, or remove the routes. |
| A11 | P1 | `/v1/status` reports "degraded", 17 of 40 systems active, and 66 algorithms while 44 are mounted. | Count from the live registry; remove systems that are not installed from the denominator. |
| A12 | P1 | Without Redis, replay protection and other state are in memory and lost on restart. | Default to a local file-backed store; keep Redis as an option. |
| A13 | P2 | A governance attestation returned `satisfied: true, rulesSatisfied: 5` on a DENY. Meaning not investigated. | Define what the statement asserts and name the field accordingly. |
| A14 | P2 | The proxy listener binds 8789 regardless of `PORT`. | Read a `KASBAH_PROXY_PORT` variable. |
| A15 | P2 | `server.js` is 9,101 lines with duplicated route registrations. | Split into routers per domain; fail start-up on duplicate method and path. |

### 3.4 SDKs, CLI, MCP server, browser extension

| ID | Sev | Finding | Solution |
|---|---|---|---|
| S1 | P0 | The Python SDK fails open. With the engine unreachable, `govern()` returned `{'verdict': 'ALLOW', 'riskScore': 0}` (`kasbah_sdk/__init__.py:101`, `:105`). Plans advertise fail-closed enforcement. | Default to raising or returning DENY on any transport error; offer `fail_open=True` as an explicit opt-in. Add a test with a dead server. |
| S2 | P1 | The CLI's default API is `https://kasbah-api.fly.dev`, so `kasbah scan "<text>"` sends the text off the machine by default. | Default to `http://127.0.0.1:8788`; require `--cloud` or a config entry for a remote host, with a one-line notice. |
| S3 | P1 | Both SDKs default to `https://api.bekasbah.com`; the MCP config mixes that host with `kasbah-api.fly.dev`. I did not contact either host. | One canonical host in one constants file; document that SDK calls leave the machine unless pointed at a local engine. |
| S4 | P1 | The CLI imports a missing module: `kasbah-sdk/src/cost-tracker` (`bin/kasbah.js:734`, `:755`). | Point at `agent-cost-watch`, or remove the commands. |
| S5 | P2 | The JS SDK rejects on error, which is correct; nothing documents what wrappers do with the rejection. | Add a test that a wrapped client blocks the call when the engine is down. |
| S6 | P2 | `kasbah-sdk/src/frontier-client.js` is orphaned. | Delete or export it. |
| S7 | — | MCP server: 17 tools, all 31 endpoints exist, 12 tests pass. | None. |
| S8 | P2 | Browser extension: files and endpoints resolve. It holds nine permissions across 29 hosts and can call `/v1/kernel/killswitch`. Not loaded in a browser. | Review each permission against use; load-test in Chrome before publishing. |

### 3.5 Build and packaging

| ID | Sev | Finding | Solution |
|---|---|---|---|
| B1 | P1 | `crypto-utils` is not built and its dependencies are not installed (`crypto-js`, `node-forge`, `tweetnacl`, `@types/node`). Loading it fails. | Install and build it in CI, or drop it and use Node `crypto` plus `@noble`, which the repo already depends on. |
| B2 | P2 | `wasm-kernel/pkg/` is empty; the package degrades to "unavailable". | Build with `wasm-pack` in CI, or remove the package and the "WASM Runtime: true" status line. |
| B3 | P1 | Guarded imports of code that is not in the repo: `kasbah-adapters`, `hardware-enclave`, `api-server/src/vpn.js`, `papers/mcp_lsm_sketch.js`, and four products (`relationship-guard`, `dating-guard`, `botnet-radar`, `neural-witness`). | Delete each import and the routes behind it, or restore the code. |
| B4 | P2 | `detector-core.js:14` imports a file outside the repository. | Fix the path or remove the import. |
| B5 | P1 | No workspace configuration; packages have separate or missing `node_modules`. | Add npm workspaces at the root with one lockfile. |
| B6 | P1 | No linter (`"lint": "echo no linter configured"`). | ESLint with `no-empty`, `no-undef` and the `innerHTML` rule; run in CI. |
| B7 | P2 | Ten orphaned files (Appendix D). | Delete. |
| B8 | P2 | `apps/web` is 115 lines; `apps/mobile` has no source. | Remove or mark as placeholders. |
| B9 | P2 | Untracked `.mimosa/` folders and a stale `.claude/worktrees` copy with a Python syntax error. | Add to `.gitignore`; delete the worktree. |
| B10 | P2 | `kernel/` kext and `kasbah-os/` C sources were not built or verified. | Add a build job or move them out of the product tree. |

### 3.6 Tests

| ID | Sev | Finding | Solution |
|---|---|---|---|
| T1 | P0 | `tests/enforcer.test.js` writes to the real `~/.kasbah-privacy` and runs real `tccutil` and terminate calls. | Take a state directory and a command runner as parameters; tests pass a temp directory and a stub. |
| T2 | P1 | `npm test` omits the capability, desktop, control, receipts, VPN, SDK and MCP suites. | One root script that runs all of them. |
| T3 | P1 | In `packages/api-server`, `npm test` reports 5 of 7 suites failing: four `src/*.test.js` files are plain scripts, not Jest tests, and `tests/api.test.js` stops on a production-only secret check. | Convert the four files to Jest or exclude them; set `NODE_ENV=test` in the Jest config. |
| T4 | P1 | `tests/frontier-models-test.js` hard-codes port 8788 and prints "COMPLETE" with exit 0 when every case errors. | Read the URL from the environment; exit non-zero on any error. |
| T5 | P2 | `tests/test-qf-integration.js` cannot run: three paths do not exist. | Fix paths or delete. |
| T6 | P2 | `wasm-kernel/test.js` passes when the kernel is unavailable. | Skip explicitly, and fail in CI where the build is expected. |
| T7 | P2 | Jest runs for `control` and `agent-runtime` produced no output in the sandbox; not verified. | Run in CI and record results. |
| T8 | P2 | The sandbox API server stopped during the test batch; I did not identify which test stopped it. | Find the test that kills listeners and scope it to its own process. |
| T9 | P1 | No UI or end-to-end tests for the desktop app. | Playwright-for-Electron tests for check, receipt, vault; plus the page walk used in this audit. |

### 3.7 Documentation and claims

| ID | Sev | Finding | Solution |
|---|---|---|---|
| G1 | P1 | `KASBAH.md`, the canonical strategy document, is not on disk or in git. No root README. | Restore or rewrite it; add a README with run and test instructions. |
| G2 | P1 | No git remote is configured; the only copy of the history is on this Mac, inside an iCloud-synced folder. | Add a private remote and push. |
| G3 | P1 | `SCORECARD.md` headlines 100% while its notes describe known false positives as failing; one case per category. | Regenerate the notes from the run; present it as a regression floor. |
| G4 | P2 | `BENCHMARK.md` says 77 cases and 71 cases; the reproduce command uses port 3000, the server uses 8788. | Generate both from the runner. |
| G5 | P1 | Unsupported or stale claims: "All 11 detection engines", "66 algorithms", "exclusive", the Bell's-inequality "paper in preparation", "fail-closed" (see S1), "nothing is uploaded" (see S2). | Remove or back each with a reproducible command. |
| G6 | P2 | The 2026-10-01 unwired-features audit already listed the engine-stub routes; they are unresolved. | Close them under A1. |

## 4. Wiring tables

### 4.1 Pro entitlements

| Entitlement | Checked | Gate to add |
|---|---|---|
| `vc_export`, `compliance_credential` | Yes | — |
| `multi_exit` | No (separate API-tier gate) | Replace the tier fetch in `main-vpn.js:105` with `entitled('multi_exit')` |
| `receipt_export` | No | `pop:export` and receipt export handlers |
| `encrypted_backup` | No | `backup:encrypt`, `backup:decrypt` |
| `identity_watch` | No | Identity and breach handlers |
| `family_safety` | No | Family-safety handler and `/v1/family-safety/check` |
| `clipboard_watch` | No | `startClipboardWatcher` |
| `dpi_priority`, `priority_support` | No | No behaviour exists; remove from the list |

### 4.2 Paid plan features

| Feature sold | Plan | Status | Action |
|---|---|---|---|
| 5 governed sessions / month | Free | Not enforced | Enforce (M9) |
| Audit history 7 / 30 / 90 days / 1 year | All | Not enforced | Retention job (M9) |
| VPN — all exits | Personal | Gate exists; plan unreachable | M3, M6 |
| Mic and camera guard, vault, shareable receipts | Personal | Built; ungated | M1 |
| Seats: 5 / 10 / 50 | Family, Team, Business | Not enforced | M9 |
| Child-safe AI chat checks | Family | Built; ungated | M2 |
| Shared vault, weekly family summary, parental alerts | Family | Not found | M8 |
| One-line SDK wrap (JS, Python) | Developer | Built | — |
| SDKs: Go, Swift, Kotlin | Developer | Not found | M8 |
| Policy editor, tool-call stream, signed webhooks | Developer | Built; ungated | M2 |
| Shared policy library | Team | Partial (MCP policies only) | Build or reword |
| Budget alerts (email + Slack) | Team | Slack found; email not checked | Verify |
| Session replay and timeline | Team | Not found | M8 |
| SOC 2 audit trail export | Team | Built; ungated | M2 |
| SSO (Google, GitHub) | Business | 501 until configured | M13 |
| HIPAA / GDPR / PCI-DSS packs, EU AI Act, NIST | Business | Built; ungated | M2 |
| ZK governance proofs (Schnorr) | Business | Mislabelled | M10 |
| Custom branding | Business | Not found | M8 |
| PQ receipts (ML-DSA + SLH-DSA) | Enterprise | ML-DSA built; SLH-DSA referenced, unverified | Verify |
| Air-gap deployment, custom SSO | Enterprise | Not found | M8 |

"Built" means a matching implementation exists in code; these were not individually exercised.

### 4.3 API route health

515 live routes: 224 GET, 280 POST, 6 DELETE, 4 PUT, 1 PATCH.

| Result | Count | Meaning |
|---|---|---|
| 200 / 201 | 257 | Responds (8 of these carry a stub error body) |
| 400 / 403 / 410 | 97 | Route alive; rejected the generic probe body |
| 404 | 23 | Resource not found for a placeholder ID; expected |
| 500 | 19 | Crash (Appendix C) |
| 501 | 15 | Missing package |
| 503 | 2 | Unbuilt module |
| Timeout | 3 | Event streams; expected |
| Skipped | 99 | System- or network-affecting; not tested |

A 2xx or 400 shows the route is wired, not that its logic is correct.

### 4.4 Desktop tools with no UI — triage

| Namespace | Unused | Recommendation |
|---|---|---|
| Top-level receipt methods (`receiptSign`, `receiptSignV3`, `receiptVerify`, `receiptVerifyBatch`) | 4 | **Wire** into Proofs; this is the core product |
| `tlog` | 5 | **Wire** into Proofs as "Transparency log" |
| `privacy` alert listeners | 5 | **Wire** (D9) |
| `vc` | 5 | **Wire**; it is the one gated Pro feature |
| `mic`, `camera` quarantine | 6 | **Wire** into Mic & camera |
| `siem`, `lineage`, `agentRegistry`, `agentGuard` | 15 | **Labs**, as Team and Business features once gated |
| `govEx`, `gov`, `dkg`, `vss`, `ssi`, `zk`, `commitHide`, `attest`, `session`, `deadman` | 38 | **Labs** or delete; no user-facing story yet |
| `voice` (includes `simulateSilentSpeech`, `simulateVoiceprint`) | 11 | **Delete** from the shipped bridge; simulations do not belong in a product |
| `viralShare*`, `moats`, `forecast`, `productsStatus`, `kasbahOS*`, `mcise` | 12 | **Delete** |
| Remaining single methods | 71 | Decide per page during the five-page cut (D14) |

## 5. Test results

All run in the sandbox unless noted.

| Suite | Result |
|---|---|
| `tests/integration/runtime.test.js` | 40 pass |
| `tests/capabilities.test.js` | 46 pass |
| `tests/capability-packages.test.js` | 37 pass |
| `tests/mcp-block-loop.test.js` | 11 pass |
| `tests/enforcer.test.js` | 15 pass (run once outside the sandbox; see T1) |
| `tests/silent-speech-test.js` | 14 pass |
| `tests/frontier-models-test.js` | Every case errored; reported "COMPLETE" (T4) |
| `tests/test-qf-integration.js` | Cannot run (T5) |
| api-server `intervention`, `ai-trust-grade`, `competitive-parity`, `digest` | 12, 6, 5, 1 pass as scripts |
| api-server Jest | 49 tests pass; 5 of 7 suites reported failed (T3) |
| `control/tests/run-tests.js` | 38 pass |
| Desktop `run-tests.js` | 184 pass standalone; 1 fail in sandbox (D21) |
| Desktop `smoke.js` | 25 pass |
| `kasbah-receipts/test.js` | 18 pass |
| `kasbah-vpn/test.js`, `test-obfs.js` | 24 pass, 5 pass |
| `kasbah-mcp/test.js` | 12 pass |
| `agent-cost-watch/src/test.js` | 9 pass |
| `kasbah-sdk/src/test.js` | 2 pass |
| `kasbah-sdk-python` live test | 5 pass against a live engine; fails open against a dead one (S1) |
| `wasm-kernel/test.js` | Passes on "unavailable" (T6) |

Package entry points: 15 of 17 load. `crypto-utils` fails (B1); `kasbah-cli` is a command, not a module.

## 6. Path to 10/10

| Dimension | Today | 10 means | Findings to close |
|---|---|---|---|
| Monetisation wiring | 2 | Every sold feature is gated by one entitlement check and has a test per plan; nothing unsold-able is on the price list | M1–M13 |
| Status honesty | 3 | Every status surface is driven by a live check; no stub returns 2xx | D2, A1, A2, A11, T4, T6, G5 |
| Release readiness | 2 | Signed, notarised, auto-updating; installed build equals source | D1, D17, D18, B5 |
| Safety guarantees | 4 | SDKs fail closed; nothing leaves the machine by default; policy cannot be changed without auth | S1, S2, S3, A5, D4 |
| Functionality | 6 | Every page and route returns a real result or an honest 503; no missing imports | D5–D9, A1–A10, B1–B4, S4 |
| Security posture | 7 | Same-origin policy on; no raw HTML sinks; minimal IPC and extension permissions; external pen test | D3, D11, D19, S8, A12 |
| Tests | 6 | One command runs every suite in isolation; UI flows covered; no test touches real state | T1–T9 |
| Product focus | 4 | Five pages, one positioning sentence | D14, D8 |
| Maintainability | 3 | No file over about 500 lines in the renderer; routers split; lint clean | D10, D16, A15, B6, B7 |
| Accessibility | 3 | WCAG 2.1 AA on the five pages | D15 |
| Visual design | 8 | No raw JSON; evidence-only copy | D12, D13 |
| Documentation | 3 | README, strategy doc, generated benchmark docs, a remote | G1–G6 |

**Order of work**

1. **Stop the harm (P0):** S1, S2, A5, D3, D4, T1.
2. **Make it start and tell the truth:** D1, D2, A1, A2.
3. **Make money correctly:** M3, M4, then M1, M2, M5–M7. Until M3 and M4 land, do not take payment for Personal, Family, Developer or Team.
4. **Cut the surface:** D14 with D8, B3, B7, A15.
5. **Ship:** D17, D18, B5, B6, T2.
6. **Polish:** D10, D11, D15, D16, G1–G6.

## 7. Still not covered

- 99 system- or network-affecting routes (VPN, kill switch, proxy, shims, process kill, billing, auth, webhooks).
- Production mode of the API server beyond its start-up failure.
- The VPN bringing up a real tunnel; the kill switch; the browser loading real sites; vault unlock; sentinels against a real capture.
- A packaged, signed desktop build, and the installed 3.0.0 app.
- The browser extension running in a browser.
- `kernel/` and `kasbah-os/` C and kext code.
- The remote hosts `kasbah-api.fly.dev` and `api.bekasbah.com`.
- Line-by-line review of the 9,101-line `server.js` and 9,262-line `app.js`.
- An independent security review or penetration test.
- Material outside the repo: `~/work/Kasbahfinal_local` (website and an Xcode stub) and `~/Desktop/KasbahFinal-External` (archive).

## 8. What is genuinely novel

Judgement from reading the code, not a prior-art search.

- **Novel as a combination:** portable signed receipts for agent decisions; a Certificate Transparency-style log of gate decisions (single signer); input commitment with dispute opening; closed-loop MCP tool blocking with a proving test.
- **Good design, not novel science:** the three-tier intervention layer with hysteresis and dialog budgets; the consent gate (its hardware "Stone" is a software simulator).
- **Labelled novel, but not:** the "ZK governance proof" (a signed attestation); the Bell's-inequality text detector (unbenchmarked); the algorithm collection in `src/` and `packages/control` (no evaluation on real traffic); detection itself (regex, checksums, a small classifier); post-quantum receipts (a library call).

## 9. Side effects of this audit

- Before the sandbox existed, running `tests/enforcer.test.js` wrote to the real `~/.kasbah-privacy/enforcer-actions.log` and attempted a terminate on a fake pid and a `tccutil reset` on a fake app. Both failed.
- Two real launches of the desktop app set `~/.kasbah-privacy/enforcer-state.json` to `enforce: true, action: tcc-reset` (previously `enforce: false`). No enforcement actions were logged. An attempt to restore it was blocked by the permission system; it is still `enforce: true`.
- The first API probe appended entries to the local audit log.
- All later work ran in a sandbox copy with its own home directory. No tracked files changed apart from this report.

## Appendix A — desktop bridge methods with no call site in `app.js`

172 methods across 52 namespaces. Static analysis; an upper bound, since one dynamic dispatcher exists at `app.js:54`.

| Namespace | Count | Methods |
|---|---|---|
| `(top-level)` | 34 | `viralShare`, `viralShareCard`, `viralSlack`, `moats`, `cryptoPedersenVss`, `cryptoMerkleShares`, `cryptoBerlekampWelch`, `forecast`, `passports`, `passportGet`, `receiptSign`, `receiptSignV3`, `receiptVerify`, `receiptVerifyBatch`, `silentSpeech`, `auditReceipt`, `kasbahOSIngest`, `kasbahOSHealth`, `kasbahOSRetrieve`, `delegationIssue`, `delegationVerify`, `spendUsage`, `spendPolicy`, `keys`, `wellKnownKeys`, `models`, `productsStatus`, `productScan`, `shamirSplit`, `shamirCombine`, `mmrAppend`, `vdfEval`, `mcpServers`, `mcpPolicies` |
| `govEx` | 12 | `canExecute`, `markExecuted`, `policyCommit`, `policyHash`, `canaryDeploy`, `onCanaryTripped`, `reputationUpdate`, `reputationStatus`, `wgasReputationEval`, `exportKeyCreate`, `deadmanCheck`, `degradationOverride` |
| `voice` | 11 | `simulateSilentSpeech`, `simulateVoiceprint`, `buildRegistry`, `authProve`, `authVerify`, `commitUtterance`, `rerandomizeUtterance`, `orSigmaProveKeyword`, `orSigmaVerifyKeyword`, `fuzzyProve`, `fuzzyVerify` |
| `privacy` | 10 | `scam`, `pwBreach`, `onClipSecret`, `onEgressAlert`, `onHoneytokenHit`, `onMicAlert`, `onSessionBurned`, `leakTest`, `latency`, `mmProfile` |
| `agentRegistry` | 6 | `register`, `unregister`, `auditLog`, `auditTail`, `sessionStart`, `sessionEnd` |
| `vc` | 5 | `issueDidKey`, `verifyDidKey`, `exportFile`, `issuerPublicKey`, `list` |
| `tlog` | 5 | `recent`, `verify`, `proof`, `sth`, `pubkey` |
| `ssi` | 5 | `status`, `screen`, `admit`, `engineAdmit`, `engineSelftest` |
| `agentGuard` | 4 | `policyGet`, `evaluate`, `setVpn`, `events` |
| `zk` | 4 | `generate`, `verify`, `rangeBounded`, `rangeBoundedVerify` |
| `gov` | 4 | `seatCreate`, `wgasConservation`, `wgasCrosscheck`, `wgasFederatedEval` |
| `dkg` | 4 | `round1`, `computeShare`, `verifyShare`, `aggregate` |
| `vpn` | 3 | `quickTestPing`, `helperRemove`, `exportReceipts` |
| `deadman` | 3 | `poll`, `log`, `overdue` |
| `commitHide` | 3 | `create`, `list`, `open` |
| `session` | 3 | `end`, `verifyContinuity`, `burn` |
| `attest` | 3 | `verifyFull`, `list`, `publicKey` |
| `mic` | 3 | `quarantine`, `unquarantine`, `quarantined` |
| `camera` | 3 | `quarantine`, `unquarantine`, `quarantined` |
| `trace` | 3 | `list`, `verify`, `pubkey` |
| `agentActivity` | 3 | `start`, `stop`, `onEvent` |
| `mcise` | 3 | `fixedCore`, `auditVerify`, `ladder` |
| `lineage` | 3 | `stats`, `chain`, `provenance` |
| `settings` | 2 | `get`, `set` |
| `vpnExtra` | 2 | `autoReconnectStatus`, `onAutoReconnect` |
| `egress` | 2 | `classify`, `scanDir` |
| `vss` | 2 | `selfTest`, `split` |
| `siem` | 2 | `status`, `forward` |
| `sentinel` | 2 | `status`, `scan` |
| `browserHistory` | 1 | `onAdded` |
| `net` | 1 | `dpiProbe` |
| `pop` | 1 | `pubkey` |
| `mmr` | 1 | `verify` |
| `auditFs` | 1 | `list` |
| `popExtra` | 1 | `merkleVerify` |
| `honey` | 1 | `remove` |
| `vuln` | 1 | `scanFile` |
| `aigov` | 1 | `events` |
| `audit` | 1 | `readiness` |
| `bio` | 1 | `status` |
| `cost` | 1 | `record` |
| `sitrep` | 1 | `history` |
| `merkleBatch` | 1 | `batchProofs` |
| `fsaudit` | 1 | `append` |
| `commit` | 1 | `reveal` |
| `receipt` | 1 | `verifyCmd` |
| `cap` | 1 | `verifyChain` |
| `pvs` | 1 | `selfTest` |
| `dkgTransport` | 1 | `selfTest` |
| `nomos` | 1 | `debate` |
| `browser` | 1 | `resizeWebview` |
| `maqasid` | 1 | `evaluate` |

## Appendix B — inventory by area

Stub markers count the words stub, mock, placeholder, simulated and not implemented; a signal, not a defect count.

| Area | Files | Code files | Lines | Test files | Stub markers | Entry point resolves |
|---|---|---|---|---|---|---|
| `packages/desktop` | 84 | 80 | 47306 | 3 | 81 | yes |
| `packages/api-server` | 105 | 97 | 38511 | 8 | 66 | yes |
| `src` | 70 | 69 | 27395 | 0 | 10 | no package.json |
| `packages/control` | 54 | 51 | 17832 | 5 | 10 | yes |
| `kasbah-os` | 17 | 17 | 9763 | 0 | 30 | no package.json |
| `scripts` | 24 | 24 | 6398 | 0 | 0 | no package.json |
| `packages/kasbah-core-python` | 5 | 5 | 2597 | 0 | 6 | no package.json |
| `tests` | 11 | 10 | 2592 | 8 | 2 | no package.json |
| `bench` | 62 | 16 | 2546 | 0 | 0 | no package.json |
| `(root files)` | 15 | 4 | 2332 | 0 | 18 | no package.json |
| `packages/kasbah-vpn` | 19 | 17 | 2297 | 0 | 1 | yes |
| `packages/kasbah-sdk` | 9 | 8 | 2238 | 0 | 0 | yes |
| `products/kasbah-core-python` | 11 | 11 | 2192 | 0 | 1 | no package.json |
| `packages/crypto-utils` | 9 | 7 | 1916 | 0 | 0 | **no** |
| `packages/kasbah-cli` | 5 | 4 | 1761 | 0 | 0 | yes |
| `packages/kasbah-browser-extension` | 10 | 6 | 1607 | 0 | 0 | no package.json |
| `packages/agent-runtime` | 4 | 3 | 1206 | 1 | 2 | yes |
| `packages/kasbah-mcp` | 5 | 2 | 827 | 0 | 0 | yes |
| `packages/agent-cost-watch` | 4 | 3 | 733 | 0 | 0 | yes |
| `packages/kasbah-frontier` | 2 | 2 | 728 | 0 | 1 | no package.json |
| `packages/kasbah-receipts` | 5 | 4 | 614 | 0 | 0 | yes |
| `packages/silent-speech-audit` | 9 | 6 | 583 | 0 | 3 | yes |
| `packages/biometric-detection` | 4 | 3 | 406 | 0 | 0 | yes |
| `kernel` | 6 | 2 | 398 | 0 | 0 | no package.json |
| `packages/kasbah-sdk-python` | 4 | 3 | 345 | 1 | 0 | no package.json |
| `examples` | 3 | 3 | 309 | 0 | 0 | no package.json |
| `packages/advanced-security` | 2 | 1 | 267 | 0 | 0 | yes |
| `packages/agent-governance` | 3 | 2 | 249 | 0 | 0 | yes |
| `packages/mcise-core` | 4 | 4 | 222 | 0 | 1 | no package.json |
| `packages/nomos-engine` | 3 | 2 | 191 | 0 | 0 | yes |
| `products/product-signals.js` | 1 | 1 | 191 | 0 | 0 | no package.json |
| `packages/kernel-ebpf` | 3 | 2 | 148 | 0 | 0 | yes |
| `demos` | 1 | 1 | 121 | 0 | 0 | no package.json |
| `apps/shared` | 1 | 1 | 118 | 0 | 0 | no package.json |
| `apps/web` | 5 | 3 | 115 | 0 | 0 | no main |
| `terraform` | 1 | 1 | 102 | 0 | 0 | no package.json |
| `packages/wasm-kernel` | 4 | 2 | 53 | 0 | 0 | yes |
| `apps/mobile` | 3 | 0 | 0 | 0 | 0 | **no** |
| `data` | 5 | 0 | 0 | 0 | 0 | no package.json |
| `deployment` | 5 | 0 | 0 | 0 | 0 | no package.json |
| `docs` | 13 | 0 | 0 | 0 | 0 | no package.json |

## Appendix C — API routes that crash, stub or report not installed

| Status | Method | Route | Cause |
|---|---|---|---|
| 500 | GET | `/v1/bbs/stats` | TypeError: kasbahEngine.bbsStats is not a function |
| 500 | GET | `/v1/cost-governor/stats` | TypeError: kasbahEngine.getCostStats is not a function |
| 500 | GET | `/v1/crdt/summary` | TypeError: kasbahEngine.tavcSummary is not a function |
| 500 | GET | `/v1/dp/budget` | TypeError: kasbahEngine.dpRemainingBudget is not a function |
| 500 | GET | `/v1/kasbah-os/health` | No module named 'numpy' |
| 500 | GET | `/v1/products/status` | ReferenceError: getKasbahProducts is not defined |
| 500 | GET | `/v1/threat/feed` | TypeError: kasbahEngine.exportThreatFeed is not a function |
| 500 | GET | `/v1/threat/stats` | TypeError: kasbahEngine.getThreatStats is not a function |
| 500 | GET | `/v1/threat/top` | TypeError: kasbahEngine.getTopThreats is not a function |
| 500 | GET | `/v1/thresholds/adaptive` | TypeError: kasbahEngine.getAdaptiveThreshold is not a function |
| 500 | POST | `/v1/adapters/langchain/guard` | Cannot read properties of null (reading 'createEdgeGuard') |
| 500 | POST | `/v1/bbs/keypair` | kasbahEngine.bbsGenerateKeyPair is not a function |
| 500 | POST | `/v1/kasbah-os/governance/approve/:actionId` | No module named 'numpy' |
| 500 | POST | `/v1/kasbah-os/governance/approve/:id` | No module named 'numpy' |
| 500 | POST | `/v1/kasbah-os/governance/turn` | No module named 'numpy' |
| 500 | POST | `/v1/threat/check` | TypeError: kasbahEngine.checkAgainstThreats is not a function |
| 500 | POST | `/v1/threat/patterns` | TypeError: kasbahEngine.detectThreatPatterns is not a function |
| 500 | POST | `/v1/thresholds/record` | TypeError: kasbahEngine.recordThresholdFeedback is not a function |
| 500 | POST | `/v1/vc/issue` | popEntry.requestId required |
| 501 | GET | `/v1/bounty/stats` | verification-network not installed |
| 501 | GET | `/v1/coop/stats` | threat-coop not installed |
| 501 | GET | `/v1/coop/top` | threat-coop not installed |
| 501 | GET | `/v1/policy/fuzz/stats` | policy-fuzzer not installed |
| 501 | GET | `/v1/verify/case/:caseId` | verification-network not installed |
| 501 | GET | `/v1/verify/leaderboard` | verification-network not installed |
| 501 | GET | `/v1/verify/stats` | verification-network not installed |
| 501 | POST | `/v1/bounty/award` | verification-network not installed |
| 501 | POST | `/v1/bounty/create` | verification-network not installed |
| 501 | POST | `/v1/bounty/submit` | verification-network not installed |
| 501 | POST | `/v1/coop/check` | threat-coop not installed |
| 501 | POST | `/v1/coop/report` | threat-coop not installed |
| 501 | POST | `/v1/policy/fuzz` | policy-fuzzer not installed |
| 501 | POST | `/v1/verify/appeal` | verification-network not installed |
| 501 | POST | `/v1/verify/review` | verification-network not installed |
| 503 | POST | `/v1/crypto/mmr/append` | MMR module not available |
| 503 | POST | `/v1/crypto/vdf/eval` | VDF module not available |
| 200 (stub body) | GET | `/v1/workflow/:executionId/audit` | unified engine not available in this build |
| 200 (stub body) | GET | `/v1/workflow/:executionId/status` | unified engine not available in this build |
| 200 (stub body) | GET | `/v1/workflow/stats` | unified engine not available in this build |
| 200 (stub body) | POST | `/v1/agent/identity/generate` | unified engine not available in this build |
| 200 (stub body) | POST | `/v1/analyze` | unified engine not available in this build |
| 200 (stub body) | POST | `/v1/cost-governor/track` | unified engine not available in this build |
| 200 (stub body) | POST | `/v1/governance/evaluate` | unified engine not available in this build |
| 200 (stub body) | POST | `/v1/workflow/:id/execute` | unified engine not available in this build |

**Skipped routes (99)**

`DELETE /v1/agents/:id`, `DELETE /v1/consent/stone/:agentId`, `DELETE /v1/invites/:token`, `DELETE /v1/passport/:id`, `DELETE /v1/proxy/:provider/*`, `DELETE /v1/webhooks/:id`, `GET /_pulse/stats`, `GET /billing/success`, `GET /signup`, `GET /v1/auth/github`, `GET /v1/auth/github/callback`, `GET /v1/auth/google`, `GET /v1/auth/google/callback`, `GET /v1/billing/plans`, `GET /v1/billing/status`, `GET /v1/breach/check-email`, `GET /v1/breach/check-password`, `GET /v1/consent/lockdown`, `GET /v1/deploy/k8s`, `GET /v1/deploy/status`, `GET /v1/earn/balance`, `GET /v1/earn/cashout`, `GET /v1/earn/ledger`, `GET /v1/instrument/stats`, `GET /v1/kernel/killswitch`, `GET /v1/overwatch/extension-info`, `GET /v1/proxy/:provider/*`, `GET /v1/proxy/info`, `GET /v1/proxy/pending`, `GET /v1/proxy/receipt/:id`, `GET /v1/proxy/recent`, `GET /v1/proxy/stats`, `GET /v1/proxy/status`, `GET /v1/shim/init`, `GET /v1/shim/list`, `GET /v1/shim/recent`, `GET /v1/vpn/providers`, `GET /v1/vpn/status`, `GET /v1/webhooks`, `GET /v1/webhooks/:id/deliveries`, `GET /v1/webhooks/dlq`, `GET /v1/workspaces/:id`, `GET /v1/workspaces/:id/invites`, `PATCH /v1/proxy/:provider/*`, `POST /_pulse`, `POST /v1/auth/signup`, `POST /v1/bench/run`, `POST /v1/billing/checkout`, `POST /v1/billing/credits/topup`, `POST /v1/billing/portal`, `POST /v1/billing/webhook`, `POST /v1/chat/completions`, `POST /v1/consent/lockdown`, `POST /v1/deploy/estimate`, `POST /v1/deploy/validate`, `POST /v1/discover/govern-all`, `POST /v1/discover/install-mcp`, `POST /v1/discover/kill-process`, `POST /v1/discover/launch-app`, `POST /v1/earn/checkin`, `POST /v1/earn/redeem`, `POST /v1/earn/share`, `POST /v1/gateway/chat`, `POST /v1/instrument/install`, `POST /v1/instrument/uninstall`, `POST /v1/invites/accept`, `POST /v1/kasbah-os/pipeline/run`, `POST /v1/kernel/killswitch`, `POST /v1/models/auto-route`, `POST /v1/models/detect`, `POST /v1/models/optimize`, `POST /v1/os/agent/register`, `POST /v1/overwatch/activate`, `POST /v1/overwatch/kill-and-revoke`, `POST /v1/proxy/:provider/*`, `POST /v1/proxy/anthropic/v1/messages`, `POST /v1/proxy/approve/:actionId`, `POST /v1/proxy/openai/v1/chat/completions`, `POST /v1/proxy/reject/:actionId`, `POST /v1/proxy/start`, `POST /v1/proxy/stop`, `POST /v1/proxy/turn`, `POST /v1/redteam/run`, `POST /v1/shim/install`, `POST /v1/shim/record`, `POST /v1/shim/uninstall`, `POST /v1/siem/test`, `POST /v1/viral/slack`, `POST /v1/vpn/ai-lane/start`, `POST /v1/vpn/config`, `POST /v1/vpn/connect`, `POST /v1/vpn/disconnect`, `POST /v1/vpn/init`, `POST /v1/webhooks`, `POST /v1/webhooks/:id/enable`, `POST /v1/workspaces`, `POST /v1/workspaces/:id/invite`, `POST /v1/workspaces/:id/members`, `PUT /v1/proxy/:provider/*`

## Appendix D — broken imports and orphaned files

**Unguarded imports of missing files**

| Location | Missing target |
|---|---|
| `packages/api-server/server.js:7197` | `packages/threat-coop/src/fingerprint.js` |
| `packages/api-server/src/kasbah-products.js:34` | `crypto-utils/dist/vdf.js` |
| `packages/api-server/src/systems/detector-core.js:14` | `detector.js`, outside the repo |
| `packages/kasbah-cli/bin/kasbah.js:734`, `:755` | `kasbah-sdk/src/cost-tracker` |
| `scripts/stress_test_all.js:39` | `kasbah-core/src` |
| `tests/test-qf-integration.js:8`, `:40`, `:110` | `./src/governance-engine`, `./src/app`, `./package.json` |

Some may sit inside a wider `try` block that the scan did not see.

**Guarded imports of missing files**

| Missing target | Referenced from |
|---|---|
| `kasbah-unified-engine.js` | `server.js:83` |
| `packages/kasbah-adapters` | `server.js:1480` |
| `packages/policy-fuzzer`, `verification-network`, `threat-coop` | `server.js:1567`, `1636`, `1717`, `7172–7174` |
| `api-server/src/vpn.js` | `server.js:2169` |
| `papers/mcp_lsm_sketch.js` | `server.js:2181` |
| `packages/hardware-enclave` | `frontier.js:540`, `systems/proof-chain.js:19` |
| `crypto-utils/dist/shamir.js`, `mmr.js` | `kasbah-products.js:32–33` |
| `wasm-kernel/pkg/kasbah_wasm_kernel.js` | `wasm-kernel/index.js:7` |
| `products/relationship-guard`, `dating-guard`, `botnet-radar`, `neural-witness` | `bench/xray-hook-proof.js:30–51` |
| `tests/src/routes/quran-frontier-routes` | `tests/test-qf-integration.js:47` |

**Orphaned files**

`bench/_verify-merkle.js`, `bench/competitors/lakera.js`, `bench/competitors/nemo.js`, `bench/xray-hook-proof.js`, `examples/e2e-demo.js`, `packages/api-server/_fix-refs.js`, `packages/api-server/_show-results.js`, `packages/api-server/_test-optimizer.js`, `packages/kasbah-sdk/src/frontier-client.js`, `scripts/collect_real_data.js`.

**Syntax:** 0 errors in 375 JavaScript files. 1 Python error, in the stale `.claude/worktrees` copy.

## Appendix E — reproducing this audit

1. Copy the repo to a temp directory without `node_modules` and `.git`; symlink the `node_modules` folders; set `HOME` to an empty temp directory.
2. Start `packages/api-server/server.js` there on a spare port. Dump the Express route table from `app._router.stack`.
3. Probe each GET, POST, PUT and PATCH route with placeholder IDs and a generic JSON body, skipping system- and network-affecting routes.
4. Run each test file listed in section 5 with a timeout.
5. Load `packages/desktop/src/preload.js` with `electron` mocked to capture the bridge; compare with `ipcMain` handlers and `kasbah.*` references in `app.js`.
6. For every JavaScript file: `node --check`, then resolve each relative import against the disk.
7. Launch the desktop app with `--remote-debugging-port` and walk every `[data-page]` element, recording error text. Note that this step runs the real enforcer (finding D4).
