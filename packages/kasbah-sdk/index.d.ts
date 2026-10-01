/**
 * @kasbah/sdk — TypeScript Declarations
 * KasbahOS AI Security Governance — Official Node.js Client
 * https://bekasbah.com
 */

// ── Core types ────────────────────────────────────────────────────────────────

/** Governance verdict returned by most KasbahOS endpoints. */
export type Verdict = 'ALLOW' | 'WARN' | 'DENY';

/** Raw ZK governance proof object (HMAC-signed, offline-verifiable). */
export interface ZKProof {
  proofId:    string;
  hmac:       string;
  rules:      string[];
  circuitHash?: string;
  publicInput?: Record<string, unknown>;
  timestamp:  string;
}

/** Governance receipt — HMAC-signed proof of a governance decision. */
export interface GovernanceReceipt {
  receipt:    string;   // "kasbah_proof:<hmac>"
  proofId:    string;
  verdict:    Verdict;
  timestamp:  string;
}

// ── govern() ─────────────────────────────────────────────────────────────────

export interface GovernOptions {
  /** The prompt / user input to govern. */
  prompt?:           string;
  /** The model response to govern (for output filtering). */
  response?:         string;
  /** KasbahOS Passport ID for per-agent identity tracking. */
  passportId?:       string;
  /** Delegation token ID (proves agent A acts on behalf of principal B). */
  delegationTokenId?: string;
  /** Human-readable agent name for audit logs. */
  agent?:            string;
  /** Extra metadata attached to the audit record. */
  meta?:             Record<string, unknown>;
}

export interface GovernResult {
  verdict:      Verdict;
  /** Trust/safety score 0–1 (higher = safer). */
  score:        number;
  /** List of detected threat labels. */
  threats:      string[];
  /** HMAC-signed governance proof string. */
  proof:        string;
  /** Latency of the governance decision in ms. */
  latency_ms:   number;
  /** ZK governance proof object (null if ZK module unavailable). */
  zkProof?:     ZKProof | null;
  /** RTP pipeline result. */
  rtp?:         RTPResult | null;
  /** Bell's Inequality AI detection result. */
  bells?:       BellsResult | null;
  timestamp:    string;
}

// ── scan() ───────────────────────────────────────────────────────────────────

export interface ScanOptions {
  /** Additional context for the scan. */
  context?: Record<string, unknown>;
}

export interface ScanResult {
  safe:         boolean;
  threats:      string[];
  score:        number;
  verdict:      Verdict;
  timestamp:    string;
}

// ── explain() ────────────────────────────────────────────────────────────────

export interface ExplainResult {
  verdict:      Verdict;
  reasons:      string[];
  suggestions:  string[];
  score:        number;
  timestamp:    string;
}

// ── bells() ──────────────────────────────────────────────────────────────────

export interface BellsResult {
  /** True if the text is detected as AI-generated. */
  isAI:          boolean;
  /** CHSH S-value (>2.0 = AI, ≤2.0 = human, classical bound). */
  sValue:        number;
  /** Confidence score 0–1. */
  confidence:    number;
  verdict:       'AI_GENERATED' | 'UNCERTAIN' | 'HUMAN_WRITTEN';
  semanticDimensions: {
    avgWordLen:           number;
    vocabularyDiversity:  number;
    punctuationDensity:   number;
    transitionDensity:    number;
  };
  correlations: {
    E_ab:          string;
    E_ab_prime:    string;
    E_a_prime_b:   string;
    E_a_prime_b_prime: string;
  };
  processingTimeMs: number;
  timestamp?:    string;
}

// ── maqasid() ────────────────────────────────────────────────────────────────

export interface MaqasidResult {
  verdict:      'allowed' | 'warned' | 'blocked';
  pillars: {
    life:       number;
    intellect:  number;
    wealth:     number;
    lineage:    number;
    faith:      number;
  };
  concerns:     string[];
  score:        number;
  timestamp?:   string;
}

// ── rtp() ────────────────────────────────────────────────────────────────────

export interface RTPResult {
  decision:         'APPROVE' | 'DEFER' | 'DENY';
  brittlenessScore: number;
  modulatorOutput:  number;
  factors:          Array<{ id: string; score: number; weight: number }>;
  f0?:              { normalized: string; length: number; hasCode: boolean };
  f1?:              { intent: string; confidence: number };
  f3?:              { modulator: number; trustScore: number };
  ticket?:          ExecutionTicket;
  latencyMs:        number;
  timestamp?:       string;
}

// ── Execution Tickets ─────────────────────────────────────────────────────────

export interface ExecutionTicket {
  ticketId:   string;
  ttl:        number;
  expiresAt:  number;
  hmac:       string;
  used?:      boolean;
}

// ── Passport ──────────────────────────────────────────────────────────────────

export interface PassportIssueOptions {
  /** Unique identifier for the agent. */
  agentId:          string;
  /** Allowed tool names for this agent. */
  capabilities?:    string[];
  /** Human-readable description. */
  description?:     string;
  /** Trust level: 'low' | 'medium' | 'high' (default: 'medium'). */
  trustLevel?:      'low' | 'medium' | 'high';
  /** EWMA adaptive threshold configuration. */
  thresholds?:      { warn?: number; deny?: number };
  /** Token/cost spend policy. */
  spendPolicy?:     SpendPolicy;
  /** ISO 8601 expiry date. */
  expiresAt?:       string;
}

export interface Passport {
  passportId:       string;
  agentId:          string;
  capabilities:     string[];
  trustScore:       number;
  trustLevel:       string;
  issuedAt:         string;
  expiresAt?:       string;
  revoked?:         boolean;
}

export interface SpendPolicy {
  maxTokensPerMin?:    number;
  maxTokensPerDay?:    number;
  maxCostCentsPerDay?: number;
  hardBlockOnExceed?:  boolean;
}

export interface SpendUsage {
  passportId:          string;
  allowed:             boolean;
  usage: {
    tokensThisMin:     number;
    tokensToday:       number;
    costCentsToday:    number;
  };
}

// ── Delegation ────────────────────────────────────────────────────────────────

export interface DelegationIssueOptions {
  /** Principal passport ID granting the delegation. */
  principalId:     string;
  /** Agent passport ID receiving the delegation. */
  agentId:         string;
  /** Delegated capabilities. */
  capabilities?:   string[];
  /** ISO 8601 expiry. */
  expiresAt?:      string;
}

export interface DelegationToken {
  tokenId:         string;
  principalId:     string;
  agentId:         string;
  capabilities:    string[];
  issuedAt:        string;
  expiresAt?:      string;
  hmac:            string;
}

export interface DelegationVerifyResult {
  valid:           boolean;
  token?:          DelegationToken;
  reason?:         string;
}

// ── Honeytoken ────────────────────────────────────────────────────────────────

export interface HoneytokenDeployResult {
  tokenId:         string;
  service:         string;
  /** The planted fake token value — store this in a monitored location. */
  token:           string;
  deployedAt:      string;
}

export interface HoneytokenCheckResult {
  triggered:       boolean;
  matches:         Array<{ service: string; tokenId: string; pattern: string }>;
  timestamp:       string;
}

// ── Budget / Usage ────────────────────────────────────────────────────────────

export interface UsageRecord {
  passportId:      string;
  tokensThisMin:   number;
  tokensToday:     number;
  costCentsToday:  number;
  policy?:         SpendPolicy | null;
  updatedAt:       string;
}

// ── Agentic Layer ─────────────────────────────────────────────────────────────

export interface AgentManifest {
  allowedTools?:       string[];
  maxTokens?:          number;
  maxCostCents?:       number;
  maxTurns?:           number;
  allowedDomains?:     string[];
  requireApproval?:    string[];
}

export interface CreateAgentOptions {
  agentId:             string;
  passportId:          string;
  goal:                string;
  manifest?:           AgentManifest;
}

export interface AgentSession {
  sessionId:           string;
  agentId:             string;
  passportId:          string;
  goal:                string;
  status:              'active' | 'completed' | 'killed' | 'budget_exceeded';
  manifest:            AgentManifest;
  tokensUsed:          number;
  costCentsUsed:       number;
  turnsCompleted:      number;
  createdAt:           string;
  updatedAt:           string;
}

export interface GovernToolResult {
  ok:                  boolean;
  verdict:             Verdict;
  reason?:             string;
  receipt?:            string;
  riskScore:           number;
}

export interface ScanToolResultResponse {
  ok:                  boolean;
  verdict?:            Verdict;
  reason?:             string;
  riskScore:           number;
}

// ── Proxy helpers ─────────────────────────────────────────────────────────────

export interface ProxyResult<T = Record<string, unknown>> extends Record<string, unknown> {
  _kasbahReceipt: string | null;
}

// ── System endpoints ──────────────────────────────────────────────────────────

export interface HealthResult {
  status:              'ok' | 'degraded';
  version:             string;
  engine:              string;
  uptime:              number;
  systems:             Record<string, boolean>;
  timestamp:           string;
}

export interface StatsResult {
  totalRequests:       number;
  governed:            number;
  verdicts: {
    ALLOW:             number;
    WARN:              number;
    DENY:              number;
  };
  avgLatencyMs:        number;
  engine:              string;
  startedAt:           string;
  timestamp:           string;
}

// ── Sub-clients ───────────────────────────────────────────────────────────────

export declare class PassportClient {
  issue(opts: PassportIssueOptions): Promise<Passport>;
  list(): Promise<{ passports: Passport[] }>;
  get(id: string): Promise<Passport>;
  revoke(id: string): Promise<{ ok: boolean }>;
  spend(id: string): Promise<SpendUsage>;
  setSpendPolicy(id: string, policy: SpendPolicy | null): Promise<{ ok: boolean }>;
}

export declare class DelegationClient {
  issue(opts: DelegationIssueOptions): Promise<DelegationToken>;
  verify(tokenId: string): Promise<DelegationVerifyResult>;
}

export declare class HoneytokenClient {
  list(): Promise<{ honeytokens: HoneytokenDeployResult[] }>;
  deploy(service: string): Promise<HoneytokenDeployResult>;
  check(text: string): Promise<HoneytokenCheckResult>;
}

export declare class SpendClient {
  get(passportId: string): Promise<SpendUsage>;
  setPolicy(passportId: string, policy: SpendPolicy | null): Promise<{ ok: boolean }>;
}

// ── KasbahError ───────────────────────────────────────────────────────────────

export declare class KasbahError extends Error {
  readonly name:   'KasbahError';
  readonly status: number;
  readonly body:   Record<string, unknown>;
  constructor(message: string, status: number, body?: Record<string, unknown>);
}

// ── KasbahClient constructor options ─────────────────────────────────────────

export interface KasbahClientOptions {
  /** API key (default: 'kg_desktop_builtin'). */
  apiKey?:       string;
  /** API base URL (default: 'http://127.0.0.1:8788'). */
  baseUrl?:      string;
  /** Request timeout in ms (default: 10000). */
  timeout?:      number;
  /** Automatically retry on 5xx with exponential backoff (default: true). */
  autoRetry?:    boolean;
  /** Set a default passport ID for all govern() calls. */
  passportId?:   string;
}

// ── Main client class ─────────────────────────────────────────────────────────

export declare class Kasbah {
  /** Passport sub-client — issue, list, revoke passports. */
  readonly passport:   PassportClient;
  /** Delegation sub-client — issue and verify delegation tokens. */
  readonly delegation: DelegationClient;
  /** Honeytoken sub-client — deploy canaries and check for leaks. */
  readonly honeytoken: HoneytokenClient;
  /** Spend/budget sub-client — manage per-agent token budgets. */
  readonly spend:      SpendClient;

  constructor(opts?: KasbahClientOptions);

  // ── Core governance ─────────────────────────────────────────────────────

  /**
   * Govern a prompt or response through all 37 detection systems.
   * This is the primary governance call — every AI agent call should go through this.
   *
   * @example
   * const result = await k.govern({ prompt: userInput, passportId: 'agent-123' });
   * if (result.verdict === 'DENY') throw new Error('Blocked: ' + result.threats.join(', '));
   */
  govern(body?: GovernOptions): Promise<GovernResult>;

  /**
   * Lightweight text scan (no passport/delegation processing).
   * Use for quick content checks without full governance overhead.
   */
  scan(text: string, options?: ScanOptions): Promise<ScanResult>;

  /**
   * Explain why a prompt would be blocked or warned.
   * Useful for debugging governance decisions.
   */
  explain(prompt: string): Promise<ExplainResult>;

  // ── Specialized detection ────────────────────────────────────────────────

  /**
   * Bell's Inequality AI text detection (CHSH S-value).
   * S > 2.0 indicates AI-generated text with non-local semantic correlations.
   */
  bells(text: string): Promise<BellsResult>;

  /**
   * Maqasid Ethics Framework — 5-pillar Islamic ethics scoring.
   * Scores text against: life, intellect, wealth, lineage, faith.
   */
  maqasid(text: string): Promise<MaqasidResult>;

  /**
   * Run RTP governance pipeline (f0–f5 stages, no side-effects).
   * Returns brittleness score and modulator output.
   */
  rtp(text: string, passportId?: string | null): Promise<RTPResult>;

  /**
   * Verify and consume a single-use execution ticket.
   * Returns { valid, consumed, reason? }
   */
  verifyTicket(ticketId: string, hmac: string): Promise<{ valid: boolean; consumed?: boolean; reason?: string }>;

  // ── System endpoints ─────────────────────────────────────────────────────

  health(): Promise<HealthResult>;
  stats(): Promise<StatsResult>;
  audit(n?: number): Promise<{ events: unknown[] }>;
  integrity(): Promise<{ index: number; status: string }>;
  forecast(): Promise<{ threats: unknown[] }>;
  swarm(): Promise<{ agents: unknown[] }>;
  auditChain(): Promise<{ chain: unknown[] }>;
  policy(): Promise<{ policy: Record<string, unknown> }>;
  setPolicy(policy: Record<string, unknown>): Promise<{ ok: boolean; policy: Record<string, unknown> }>;

  // ── Budget management ────────────────────────────────────────────────────

  getUsage(passportId: string): Promise<UsageRecord>;
  setBudget(passportId: string, policy: SpendPolicy): Promise<{ ok: boolean }>;
  getBudget(passportId: string): Promise<{ passportId: string; policy: SpendPolicy | null }>;

  // ── Proxy helpers ─────────────────────────────────────────────────────────

  /**
   * Drop-in replacement for OpenAI's /v1/chat/completions — governs every call.
   * @param body   OpenAI chat completion request body
   * @param upstreamKey  Your OpenAI API key
   */
  proxyOpenAI<T = Record<string, unknown>>(
    body: Record<string, unknown>,
    upstreamKey: string,
    options?: Record<string, unknown>
  ): Promise<ProxyResult<T>>;

  /**
   * Drop-in replacement for Anthropic's /v1/messages — governs every call.
   * @param body   Anthropic messages request body
   * @param upstreamKey  Your Anthropic API key
   */
  proxyAnthropic<T = Record<string, unknown>>(
    body: Record<string, unknown>,
    upstreamKey: string,
    options?: Record<string, unknown>
  ): Promise<ProxyResult<T>>;

  // ── Agentic Layer ─────────────────────────────────────────────────────────

  /**
   * Create a governed agent session.
   * Call this once per agent run — returns a sessionId used for all subsequent calls.
   *
   * @example
   * const session = await k.createAgent({
   *   agentId: 'research-bot',
   *   passportId: 'pp_abc123',
   *   goal: 'Summarize the top 5 papers on LLM safety',
   *   manifest: { allowedTools: ['search', 'read_url'], maxTokens: 50000 }
   * });
   */
  createAgent(opts: CreateAgentOptions): Promise<AgentSession>;

  /**
   * Govern a tool call BEFORE executing it.
   * If result.ok is false, do NOT execute the tool.
   *
   * @example
   * const g = await k.governTool(sessionId, 'bash', args, 'rm -rf /tmp');
   * if (!g.ok) throw new Error('Tool blocked: ' + g.reason);
   * await executeTool(args);
   */
  governTool(
    sessionId: string,
    tool: string,
    args?: Record<string, unknown>,
    argsText?: string
  ): Promise<GovernToolResult>;

  /**
   * Scan a tool result AFTER receiving it, before feeding back to the agent.
   * Detects injected instructions in tool outputs (e.g. web pages, file contents).
   */
  scanToolResult(sessionId: string, tool: string, result: string): Promise<ScanToolResultResponse>;

  /**
   * Record a conversation turn for budget and audit chain tracking.
   * Call after each model response.
   */
  recordTurn(
    sessionId: string,
    role: 'user' | 'assistant' | 'system' | 'tool',
    content: string,
    tokens?: number,
    costCents?: number
  ): Promise<{ ok: boolean }>;

  getAgent(sessionId: string): Promise<AgentSession>;
  listAgents(): Promise<{ sessions: AgentSession[] }>;
  killAgent(sessionId: string, reason?: string): Promise<{ ok: boolean }>;
  completeAgent(sessionId: string): Promise<{ ok: boolean }>;

  /**
   * Wrap an OpenAI SDK client — every API call is automatically governed.
   * The wrapped client has the exact same interface as the original.
   *
   * @example
   * const session = await k.createAgent({ agentId: 'gpt-agent', ... });
   * const governed = k.wrapOpenAI(openai, session.sessionId);
   * // governed.chat.completions.create(...) is auto-governed
   */
  wrapOpenAI<T extends object>(openaiClient: T, sessionId: string): T;

  /**
   * Wrap an Anthropic SDK client — every API call is automatically governed.
   * @example
   * const governed = k.wrapAnthropic(anthropic, session.sessionId);
   * // governed.messages.create(...) is auto-governed
   */
  wrapAnthropic<T extends object>(anthropicClient: T, sessionId: string): T;
}

// ── Module exports ────────────────────────────────────────────────────────────

export = Kasbah;

declare namespace Kasbah {
  export { KasbahError };
  export { Kasbah };
}

// ── Receipt v2 (Ed25519, world-proof) ────────────────────────────────────────

export interface ReceiptPayload {
  v: 2;
  id: string;
  ts: number;
  engine: string;
  keyId: string;
  verdict: Verdict;
  risk: number;
  requestId: string;
  subject: string | null;
  passportId: string | null;
  surface?: string;
  action?: string;
  [k: string]: unknown;
}

export interface SignedReceipt {
  receipt: string;       // kasbah_receipt:v2:ed25519:<keyId>:<sig>
  payload: string;       // base64url canonical JSON
  decoded: ReceiptPayload;
  keyId: string;
}

export interface VerifyResult {
  valid: boolean;
  decoded?: ReceiptPayload;
  keyId?: string;
  error?: string;
}

export interface PublishedKey { kid: string; alg: string; crv: string; x: string; pem: string; createdAt?: string }

declare const receipt: {
  sign(payload: Partial<ReceiptPayload> & { verdict: Verdict }, privateKey: string | Buffer | object): SignedReceipt;
  verify(receipt: string, payloadB64: string, publicKey: string | Buffer | object): VerifyResult;
  canonicalJSON(obj: unknown): string;
  fetchPublicKey(baseUrl: string): Promise<PublishedKey>;
};

declare module '@kasbah/sdk' {
  export { receipt };
}
