// mcp-client.ts — Kasbah Guard
// MCP client helper for extension / desktop integration.
// Connects to the kasbah MCP server via stdio and exposes typed wrappers
// for silent_speech_detect + zero_trust_audit.
// ------------------------------------------------------------------

import { randomUUID } from 'crypto';
import * as path from 'path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

/** Path to the compiled MCP server script — override via KASBAH_MCP_PATH env. */
const MCP_SERVER_PATH =
  process.env.KASBAH_MCP_PATH ?? path.join(__dirname, 'mcp-server.js');

export class KasbahMCPClient {
  private client!: Client;
  private transport!: StdioClientTransport;

  async connect() {
    this.transport = new StdioClientTransport({
      command: 'node',
      args: [MCP_SERVER_PATH],
    });
    this.client = new Client({
      name: 'kasbah-extension',
      version: '1.0.0',
    });
    await this.client.connect(this.transport);
  }

  async detectSilentIntent(videoFrames: number[][], timestamp: number) {
    const result = await this.client.callTool({
      name: 'silent_speech_detect',
      arguments: { videoFrames, timestamp },
    });
    const content = result.content as Array<{ type: string; text: string }>;
    return JSON.parse(content[0].text);
  }

  async createAuditReceipt(
    decision: string,
    domain: string,
    risk: number
  ) {
    const result = await this.client.callTool({
      name: 'zero_trust_audit',
      arguments: {
        requestId: randomUUID(),
        policyDecision: decision,
        sourceDomain: domain,
        riskScore: risk,
      },
    });
    const content = result.content as Array<{ type: string; text: string }>;
    return JSON.parse(content[0].text);
  }
}
