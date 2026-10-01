/**
 * KasbahOS SDK — TypeScript definitions
 * @version 6.0.0
 */

export interface GovernOptions {
  agent?: string;
  passportId?: string;
  context?: Record<string, unknown>;
}

export interface GovernResult {
  verdict: 'ALLOW' | 'WARN' | 'DENY';
  score: number;
  threats: string[];
  receipt: string;
  receiptPayload?: string;
  ticket?: { id: string; expiresAt: number; ttlMs: number };
  latency_ms: number;
  timestamp: string;
  requestId: string;
  passport?: Record<string, unknown>;
  pii?: { detected: boolean; count: number; riskScore: number };
  steg?: { detected: boolean; method: string; confidence: number };
  sentinel?: { score: number; threats: string[]; deontic?: string };
  secrets?: { found: boolean; count: number; types: string[] };
  intent?: { intent: string; confidence: number; riskLevel: string };
  manipulation?: { patterns: number; risk: string };
  bells?: { sValue: number; isAI: boolean };
  maqasid?: { compliance: number; concerns: string[] };
  rtp?: { intent: string; modulatorScore: number; obfuscationScore: number };
}

export interface ScanResult {
  verdict: 'ALLOW' | 'WARN' | 'DENY';
  threats: string[];
  risk_score: number;
  safe: boolean;
  latency_ms: number;
  timestamp: string;
}

export interface HealthResult {
  status: string;
  version: string;
  engine: string;
  uptime_s: string;
  persistence: 'redis' | 'memory';
  systems: { active: number; total: number; wasm: boolean };
  timestamp: string;
}

export interface ReceiptVerification {
  valid: boolean;
  verdict?: string;
  requestId?: string;
  timestamp?: number;
  error?: string;
}

export interface PassportResult {
  passportId: string;
  agentId: string;
  publicKey: string;
  privateKey: string;
  issuedAt: string;
  warning: string;
}

export interface StreamHandle {
  close(): void;
  on(event: 'error', handler: (err: Error) => void): StreamHandle;
  on(event: 'open', handler: () => void): StreamHandle;
}

export interface ProxyResult {
  id: string;
  object: string;
  choices: unknown[];
  usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
  _kasbahReceipt?: string;
  _kasbahVerdict?: string;
}

export interface UsageResult {
  passportId: string;
  spendLedger: { tokens1m: number; tokens24h: number; costCents24h: number };
  watcherState: { band: string; brittleness: number; tokensPerHour: number; costPerHour: number };
  timestamp: string;
}

export interface BudgetPolicy {
  maxTokensPerMin?: number;
  maxTokensPerDay?: number;
  maxCostCentsPerDay?: number;
}

export declare class KasbahError extends Error {
  statusCode?: number;
  verdict?: string;
}

export declare class Kasbah {
  constructor(options: { apiKey: string; baseUrl?: string; timeout?: number });

  /** Govern any prompt — returns verdict, receipt, threats */
  govern(prompt: string | { prompt: string; [key: string]: unknown }, options?: GovernOptions): Promise<GovernResult>;

  /** Lightweight text scan without full policy gate */
  scan(text: string): Promise<ScanResult>;

  /** Check API health */
  health(): Promise<HealthResult>;

  /** Verify a governance receipt offline — no API call needed */
  verifyReceipt(receipt: string, payload?: string): ReceiptVerification;

  /** Issue a Governance Passport for an agent */
  issuePassport(agentId: string, capabilities?: string[]): Promise<PassportResult>;

  /** Stream real-time governance events via SSE */
  stream(onEvent: (event: GovernResult) => void): StreamHandle;

  /** Proxy an OpenAI chat completion through Kasbah governance */
  proxyOpenAI(body: Record<string, unknown>, upstreamKey: string, options?: GovernOptions): Promise<ProxyResult>;

  /** Proxy an Anthropic messages call through Kasbah governance */
  proxyAnthropic(body: Record<string, unknown>, upstreamKey: string, options?: GovernOptions): Promise<ProxyResult>;

  /** Get token/cost usage for a passport */
  getUsage(passportId: string): Promise<UsageResult>;

  /** Set token/cost budget policy for a passport */
  setBudget(passportId: string, policy: BudgetPolicy): Promise<{ ok: boolean; passportId: string; policy: BudgetPolicy }>;

  /** Get current budget policy for a passport */
  getBudget(passportId: string): Promise<{ passportId: string; policy: BudgetPolicy; usage: UsageResult }>;

  readonly passport: {
    issue(options: { agentId?: string; capabilities?: string[] }): Promise<PassportResult>;
    get(passportId: string): Promise<Record<string, unknown>>;
    revoke(passportId: string): Promise<{ ok: boolean }>;
    list(): Promise<{ passports: PassportResult[]; total: number }>;
  };
}

export default Kasbah;
