# Testing Kasbah — guide for early testers

Thank you for trying this. Kasbah is an early build. This page tells you how to run it, what to try, and what is known not to work yet, so your time goes on things we do not already know.

**Kasbah in one line:** privacy first, a control tower for your AI, and proof you can keep.

## Before you start

- **A Mac** (macOS 12 or later). Windows and Linux are untested.
- **Node.js 20 or later.**
- **Python 3.10 or later** — only for the "Admission gate" card. Everything else works without it.
- This build is **not signed by Apple**. You run it from source; there is no installer yet.
- Everything runs on your Mac. Nothing you type is sent to us. See "What is stored" below.

## Run it

```bash
npm install
```

```bash
npm install --prefix packages/api-server
```

```bash
npm install --prefix packages/desktop
```

```bash
npm run dev --prefix packages/desktop
```

A developer-tools window opens alongside the app; you can close it.

## What to try

Please try each of these and note anything confusing, slow or wrong. About 20 minutes.

### 1. Privacy first

1. **Private browser** — open a news site. Does it load and feel normal? Does anything break?
2. **Passwords** — create a vault and save one entry. Close the app, reopen, unlock it.
3. **VPN** — look at the page. *Please tell us what you expected it to do before pressing anything.* Connecting needs your Mac password and is the least tested part; skip it if you prefer.

### 2. AI control tower

4. **Check a message** — paste something harmless, then something containing a made-up password or API key. Are the verdicts clear? Did anything get flagged that should not have been?
5. **Control tower → Admission gate** — press the three buttons. Do the one-line answers make sense?
6. **Control tower → Your approval** — connect an AI helper (next section) and ask it to do something risky. A system dialog should appear. Try **Deny** first, then **Allow**. Was it clear what you were approving?

### 3. SSI proof

7. **Proofs** — after step 6, is there a record of what you approved and denied? Would you know how to show it to someone else?

## Connect an AI helper (for step 6)

Add this to your agent's MCP configuration (for Claude Code, a `.mcp.json` in your project). Use the full path to this folder.

```json
{
  "mcpServers": {
    "kasbah": {
      "command": "node",
      "args": ["/FULL/PATH/TO/KasbahFinal/packages/kasbah-mcp/src/index.js"],
      "env": { "KASBAH_API": "http://127.0.0.1:8788", "KASBAH_AGENT": "my-agent" }
    }
  }
}
```

With the Kasbah app open, ask the agent something like: *"Use the kasbah_consent tool to ask my permission, then delete the folder ./tmp-test."* Read-only requests are allowed without asking; anything that writes, deletes, sends or runs a command waits for you. If you do not answer within about a minute, the answer is no.

## Known limits — no need to report these

- **Not signed, no installer, no auto-update.**
- **An agent is only held if it asks.** Kasbah stops an agent that uses the consent tool. It cannot yet stop one that ignores it.
- **Approval is as strong as your Mac login.** Software approval protects against an agent approving itself. It does not protect against malware already running as you. Hardware keys are planned.
- **Detection is good, not perfect.** It will miss things and will sometimes flag harmless text. Examples of either are very useful to us.
- **The Admission gate uses fixed reference inputs**, not live sensors. It demonstrates the rules; it is not yet in the path of real actions.
- **Paid plans are not active.** Ignore any upgrade prompts and the "ADMIN / PRO" label.
- **"More tools"** holds many experimental pages. They are not part of this test.
- **The first approver wins.** The app registers itself as your approver on first launch. If you see "Another approver is already registered", tell us.

## What is stored, and where

- `~/.kasbah-privacy/` — your vault, approval key, settings and local logs. Private to your user account.
- `.kasbah/` inside this folder — the engine's local records and receipts.
- Nothing is uploaded. The command-line tool, SDKs and MCP server all default to the engine on your own Mac.

To remove everything Kasbah stored, quit the app and delete those two folders.

## How to report

For each issue, please send:

1. What you were trying to do.
2. What you expected.
3. What happened instead (a screenshot helps).
4. For a wrong verdict: the exact text you checked, **with any real secret replaced**.

Send to hello@bekasbah.com. The questions we most want answered:

- In your own words, what is Kasbah for?
- Which of the three parts would you actually use?
- Was there a moment you did not trust what it told you?
