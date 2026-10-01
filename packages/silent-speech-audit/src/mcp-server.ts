// mcp-server.ts — Kasbah Guard
// Silent Speech Detection + Zero-Trust Audit Receipt MCP Server
// ------------------------------------------------------------------
// Exposes two MCP tools:
//   1. silent_speech_detect  — Q.ai-style facial micro-movement intent inference
//   2. zero_trust_audit      — Palantir-compliant verifiable audit receipt
//
// All processing is on-device. No cloud. No surveillance.
// ------------------------------------------------------------------

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import {
  BiometricGuard,
  type SilentSpeechInput,
} from './models/silentSpeech.js';

import {
  generateZeroTrustReceipt,
  type AuditReceiptInput,
} from './audit.js';

// ==================================================================
// MCP Server Setup
// ==================================================================

const server = new Server(
  {
    name: 'kasbah-silent-speech-audit',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Defensive guard instance (no surveillance model).
const guard = new BiometricGuard();

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'silent_speech_detect',
      description:
        'BIOMETRIC_GUARD: refuses biometric/silent-speech intent inference. Submitting ' +
        'video frames returns a BLOCK — Kasbah protects against this surveillance, it does not perform it.',
      inputSchema: {
        type: 'object',
        properties: {
          videoFrames: {
            type: 'array',
            items: { type: 'array', items: { type: 'number' } },
          },
          audioFeatures: { type: 'array', items: { type: 'number' } },
          timestamp: { type: 'number' },
        },
        required: ['videoFrames', 'timestamp'],
      },
    },
    {
      name: 'zero_trust_audit',
      description:
        'Generate a verifiable audit receipt for a DLP decision',
      inputSchema: {
        type: 'object',
        properties: {
          requestId: { type: 'string' },
          policyDecision: {
            type: 'string',
            enum: ['allow', 'block', 'warn'],
          },
          sourceDomain: { type: 'string' },
          riskScore: { type: 'number', minimum: 0, maximum: 100 },
          userId: { type: 'string', optional: true },
        },
        required: ['requestId', 'policyDecision', 'sourceDomain', 'riskScore'],
      },
    },
  ],
}));

// Handle tool calls with input validation
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  // ─── silent_speech_detect ───────────────────────────────────────────
  if (name === 'silent_speech_detect') {
    const raw = args as Record<string, unknown>;
    if (!raw || typeof raw.videoFrames === 'undefined') {
      return {
        content: [{ type: 'text', text: JSON.stringify({
          error: 'invalid_input',
          message: 'videoFrames is required',
        }, null, 2) }],
        isError: true,
      };
    }
    const input: SilentSpeechInput = {
      videoFrames: (raw.videoFrames as number[][]) ?? [],
      timestamp:   (raw.timestamp as number) ?? 0,
    };
    const result = guard.evaluate(input);
    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
    };
  }

  // ─── zero_trust_audit ───────────────────────────────────────────────
  if (name === 'zero_trust_audit') {
    const raw = args as Record<string, unknown>;
    const missing: string[] = [];
    if (typeof raw.requestId !== 'string')       missing.push('requestId');
    if (!['allow','block','warn'].includes(raw.policyDecision as string))
      missing.push('policyDecision (must be allow|block|warn)');
    if (typeof raw.sourceDomain !== 'string')    missing.push('sourceDomain');
    if (typeof raw.riskScore !== 'number')       missing.push('riskScore');

    if (missing.length > 0) {
      return {
        content: [{ type: 'text', text: JSON.stringify({
          error: 'invalid_input',
          message: `Missing or invalid: ${missing.join(', ')}`,
        }, null, 2) }],
        isError: true,
      };
    }

    const input: AuditReceiptInput = {
      requestId:      raw.requestId as string,
      policyDecision: raw.policyDecision as AuditReceiptInput['policyDecision'],
      sourceDomain:   raw.sourceDomain as string,
      riskScore:      raw.riskScore as number,
      userId:         raw.userId as string | undefined,
    };
    const receipt = generateZeroTrustReceipt(input);
    return {
      content: [{ type: 'text', text: JSON.stringify(receipt, null, 2) }],
    };
  }

  // ─── unknown tool ───────────────────────────────────────────────────
  return {
    content: [{ type: 'text', text: JSON.stringify({
      error: 'unknown_tool',
      message: `Tool "${name}" not registered. Available: silent_speech_detect, zero_trust_audit`,
    }, null, 2) }],
    isError: true,
  };
});

// Start MCP server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Kasbah Guard — Silent Speech + Audit MCP server running on stdio');
}

main().catch(console.error);
