# @kasbah/mcp-server

**The trust layer for agentic AI** — drop into Claude Desktop, Claude Code, Cursor, Cline, or any MCP-compatible host. Every tool call your agent makes gets a verdict + an Ed25519-signed receipt that's verifiable offline forever.

[https://bekasbah.com](https://bekasbah.com) · [Receipt Spec v2](https://github.com/Al-Adnane/Kasbah-Core/blob/main/docs/RECEIPT-SPEC.md)

---

## Install

```bash
npx @kasbah/mcp-server
```

That's it. No global install needed.

## Configure your host

Add to `~/.claude/mcp.json` (or `mcp.json` for Cursor / Cline / your host):

```json
{
  "mcpServers": {
    "kasbah": {
      "command": "npx",
      "args": ["@kasbah/mcp-server"],
      "env": {
        "KASBAH_API":   "http://127.0.0.1:8788",
        "KASBAH_AGENT": "my-agent"
      }
    }
  }
}
```

Boot the engine alongside it (one terminal, runs all day):

```bash
git clone https://github.com/Al-Adnane/Kasbah-Core
cd Kasbah-Core
node packages/api-server/server.js
# → engine on http://127.0.0.1:8788, kid 029e59…
```

## What you get

Two tools in your agent's toolbox:

### `kasbah_attest`
Call this **before** any side-effecting action — file write, shell exec, HTTP request, payment, tool call. Returns a verdict and a signed receipt.

```ts
const r = await mcp.call('kasbah_attest', {
  action: 'shell_exec',
  input: 'rm -rf /var/db',
  context: 'cleanup script',
  surface: 'claude-code'
});
// → { verdict: 'DENY', receipt: 'kasbah_receipt:v2:ed25519:…',
//     guidance: 'STOP. Kasbah denied this action. Do not proceed.' }
```

When `verdict === 'DENY'`, **stop**. Kasbah caught something the agent shouldn't do. The receipt is your proof.

### `kasbah_verify`
Verify any Kasbah receipt cryptographically. Works offline — only needs the cached public key.

```ts
const v = await mcp.call('kasbah_verify', { receipt, payload });
// → { verified: true, keyId: '029e59…', decoded: { … } }
```

## Configuration · environment variables

| Var | Default | What it controls |
|---|---|---|
| `KASBAH_API` | `http://127.0.0.1:8788` | Engine endpoint |
| `KASBAH_AGENT` | `mcp-agent` | Identifier in audit receipts |
| `KASBAH_API_KEY` | _(none)_ | Optional bearer token if your engine is behind auth |
| `KASBAH_VERIFY_BASE` | `https://verify.bekasbah.com` | Public verifier URL stamped into receipts |

## Verify it works

```bash
node -e "
const { spawn } = require('child_process');
const p = spawn('npx', ['@kasbah/mcp-server'], { stdio: ['pipe', 'pipe', 'inherit'] });
p.stdin.write(JSON.stringify({ jsonrpc:'2.0', id:1, method:'initialize', params:{} }) + '\n');
p.stdout.on('data', d => { console.log(d.toString()); p.kill(); });
"
# → { jsonrpc:'2.0', id:1, result: { protocolVersion:'2024-11-05',
#     capabilities:{tools:{}}, serverInfo:{name:'kasbah', version:'2.0.0'} } }
```

## The receipt format

Every receipt this server returns is **Ed25519-signed by the engine** following [Receipt Spec v2](https://github.com/Al-Adnane/Kasbah-Core/blob/main/docs/RECEIPT-SPEC.md). Anyone with the engine's public key can verify it offline:

```bash
curl https://bekasbah.com/.well-known/kasbah-keys.json
# → { "keys": [{ "kid": "029e59…", "alg": "EdDSA", "crv": "Ed25519", "x": "…" }] }
```

The format is open, the verifier is open ([standalone WebCrypto, 200 lines](https://github.com/Al-Adnane/Kasbah-Core/blob/main/apps/web/components/VerifierClient.tsx)), and your receipts will verify as long as the spec lives — even if Kasbah ceased to exist tomorrow.

## License

MIT.
