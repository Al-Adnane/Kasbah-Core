# @kasbah/sdk

[![npm version](https://img.shields.io/npm/v/@kasbah/sdk.svg?color=cc3300)](https://www.npmjs.com/package/@kasbah/sdk)
[![KasbahOS Governed](https://api.bekasbah.com/v1/badge/global.svg)](https://bekasbah.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-Full%20Types-blue.svg)](https://bekasbah.com)

Official Node.js SDK for [KasbahOS](https://bekasbah.com) — govern any AI agent in 5 lines. Cryptographic receipts, 37 detection systems, drop-in proxy for OpenAI and Anthropic.

## Install

```bash
npm install @kasbah/sdk
```

## 5-line quick start

```js
const Kasbah = require('@kasbah/sdk');

const k = new Kasbah({ apiKey: process.env.KASBAH_API_KEY });

const result = await k.govern({ prompt: userInput, agent: 'my-agent' });
if (result.verdict === 'DENY') throw new Error('Blocked: ' + result.threats.join(', '));

console.log(`Safe — proof: ${result.proof}`);
```

## Drop-in OpenAI proxy

```js
const Kasbah = require('@kasbah/sdk');
const OpenAI = require('openai');

const kasbah = new Kasbah({ apiKey: process.env.KASBAH_API_KEY });
const openai  = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Create a governed agent session
const session = await kasbah.createAgent({
  agentId:   'research-bot',
  passportId: process.env.KASBAH_PASSPORT_ID,
  goal:      'Summarize recent papers on LLM safety',
  manifest:  { allowedTools: ['search', 'read_url'], maxTokens: 50000 },
});

// Wrap OpenAI — every call is auto-governed
const governed = kasbah.wrapOpenAI(openai, session.sessionId);

// This call transparently goes through KasbahOS governance
const completion = await governed.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'Summarize this paper...' }],
});
```

## Drop-in Anthropic proxy

```js
const Kasbah   = require('@kasbah/sdk');
const Anthropic = require('@anthropic-ai/sdk');

const kasbah    = new Kasbah({ apiKey: process.env.KASBAH_API_KEY });
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const session = await kasbah.createAgent({
  agentId:   'claude-agent',
  passportId: process.env.KASBAH_PASSPORT_ID,
  goal:      'Answer customer questions safely',
});

const governed = kasbah.wrapAnthropic(anthropic, session.sessionId);
const message  = await governed.messages.create({ model: 'claude-opus-4-5', ... });
```

## Per-agent passports

```js
// Issue a passport for an agent — limits what it can do
const passport = await k.passport.issue({
  agentId:      'data-pipeline',
  capabilities: ['read_database', 'write_report'],
  trustLevel:   'medium',
  spendPolicy:  { maxTokensPerDay: 100000, hardBlockOnExceed: true },
});

// Every govern() call tracks passport trust score
const result = await k.govern({
  prompt:     userInput,
  passportId: passport.passportId,
});
```

## Scan for secrets and threats

```js
const scan = await k.scan(codeSnippet);
if (!scan.safe) {
  console.log('Threats:', scan.threats);
  // e.g. ['AWS Access Key', 'Hardcoded Password']
}
```

## Verify a governance proof (auditors)

```js
// Zero-trust: verify any governance decision mathematically, no KasbahOS trust needed
const verified = await fetch('https://api.bekasbah.com/v1/zk/verify', {
  method: 'POST',
  body: JSON.stringify({ proof: result.proof, publicInput: { verdict: 'ALLOW' } }),
});
// { valid: true, rulesVerified: ['no_injection', 'no_pii', 'no_secrets'] }
```

## All methods

| Method | Description |
|--------|-------------|
| `govern(opts)` | Govern a prompt/response through all 37 systems |
| `scan(text)` | Lightweight threat scan |
| `explain(prompt)` | Explain why a prompt would be blocked |
| `bells(text)` | Bell's Inequality AI detection (CHSH S-value) |
| `maqasid(text)` | 5-pillar ethics scoring |
| `rtp(text)` | RTP governance pipeline |
| `passport.issue(opts)` | Create agent passport |
| `passport.revoke(id)` | Revoke a passport |
| `delegation.issue(opts)` | Issue delegation token (agent A acts as B) |
| `honeytoken.deploy(service)` | Plant a canary credential |
| `honeytoken.check(text)` | Check text for leaked canaries |
| `createAgent(opts)` | Create governed agent session |
| `governTool(sessionId, tool, args)` | Govern a tool call before executing |
| `scanToolResult(sessionId, tool, output)` | Scan tool output for injections |
| `wrapOpenAI(client, sessionId)` | Auto-govern all OpenAI calls |
| `wrapAnthropic(client, sessionId)` | Auto-govern all Anthropic calls |
| `proxyOpenAI(body, key)` | Proxy an OpenAI completion |
| `proxyAnthropic(body, key)` | Proxy an Anthropic message |
| `getUsage(passportId)` | Token/cost usage for a passport |
| `setBudget(passportId, policy)` | Set hard token/cost limits |
| `health()` | API health check |
| `stats()` | Governance statistics |
| `auditChain()` | Tamper-evident audit ledger |

## TypeScript

Full TypeScript types are included:

```typescript
import Kasbah, { GovernResult, Verdict, Passport, AgentSession } from '@kasbah/sdk';

const k = new Kasbah({ apiKey: process.env.KASBAH_API_KEY! });

const result: GovernResult = await k.govern({ prompt: 'Hello world' });
const verdict: Verdict = result.verdict; // 'ALLOW' | 'WARN' | 'DENY'
```

## Configuration

```js
const k = new Kasbah({
  apiKey:    process.env.KASBAH_API_KEY,    // your API key
  baseUrl:   'http://your-server:8788',     // self-hosted instance
  timeout:   10000,                         // ms (default: 10000)
  autoRetry: true,                          // retry on 5xx (default: true)
  passportId: 'pp_default_agent',           // default passport for all govern() calls
});
```

## Self-hosted

```bash
docker run -p 8788:8788 kasbahguard/kasbah-os:latest
```

Then:
```js
const k = new Kasbah({ baseUrl: 'http://localhost:8788' });
```

---

[bekasbah.com](https://bekasbah.com) &nbsp;|&nbsp; [GitHub](https://github.com/kasbah-guard) &nbsp;|&nbsp; [Docs](https://bekasbah.com/public/glassbox.html)
