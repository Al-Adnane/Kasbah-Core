// apps/web/lib/kasbah.ts
// Server-side helper that proxies calls into the running Kasbah engine.
// In dev: http://127.0.0.1:8788. In prod: process.env.KASBAH_API.

export const KASBAH_BASE = process.env.KASBAH_API || 'http://127.0.0.1:8788';

export type Verdict = 'DENY' | 'WARN' | 'ALLOW' | 'UNKNOWN' | string;

export interface ScanResult {
  verdict?: Verdict;
  risk?: number;
  riskScore?: number;
  score?: number;
  threats?: any[];
  receipt?: string;
  requestId?: string;
  latency_ms?: number;
  _used?: string;
  _inferred?: string | null;
  [k: string]: any;
}

async function call<T = any>(method: string, path: string, body?: any): Promise<T> {
  const res = await fetch(KASBAH_BASE + path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
    cache: 'no-store'
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
  try { return JSON.parse(text) as T; } catch { return text as any; }
}

// Smart input detection — mirrors the desktop + CLI logic in apps/shared/kasbah-client.js
export function detectUseCase(text: string): { slug: string; label: string; via?: 'algorithms' } | null {
  if (!text) return null;
  const low = text.toLowerCase();
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  if (lines.length >= 2) {
    const verbRe = /^(EXTRACT|FORMAT|SEND|READ|WRITE|EXEC|SCAN|LIST|DELETE|UPLOAD|DOWNLOAD|QUERY|SEARCH|CREATE|MODIFY|MOVE|COPY)\s/;
    const verbs = lines.filter(l => verbRe.test(l));
    if (verbs.length >= 2 && verbs.length >= lines.length * 0.5)
      return { slug: 'intent-analyzer', label: 'an agent trajectory', via: 'algorithms' };
  }
  if (/\b(experience|education|skills|employment|résumé|resume|curriculum|cv)\b/.test(low)
      && /^\s*[-•·]\s/m.test(text) && lines.length >= 5)
    return { slug: 'resume-authentic', label: 'a resume or CV' };
  if (/\b(swipe|tinder|bumble|hinge|match(ed|ing)?|dating profile|love[- ]bomb(ing)?|romance scam)\b/.test(low)
      || /\b(send money|western union|gift card|crypto|wire( me)?|wire transfer).{0,120}\b(urgent|emergency|stuck|hospital|airport|customs)\b/.test(low)
      || /\b(urgent|emergency).{0,120}\b(gift card|wire|western union|bitcoin)\b/.test(low))
    return { slug: 'dating-guard', label: 'a dating profile or romance message' };
  if (/\b(you always|you never|i never said|that didn't happen|you're imagining|you're crazy|stop overreacting|after everything I)\b/.test(low))
    return { slug: 'relationship-guard', label: 'a conversation that may be manipulative' };
  if (/\b(plaintiff|defendant|whereas|hereby|witnessed|notarized|jurisdiction|affidavit|statute)\b/.test(low)
      || /\b(article \d|section \d|clause \d|exhibit [A-Z])\b/i.test(text))
    return { slug: 'legal-evidence', label: 'a legal document' };
  if (/\b(dao|on-chain|tokenholders|quorum|snapshot|governance vote|treasury allocation|ratify|abstain)\b/.test(low))
    return { slug: 'dao-vote-guard', label: 'a DAO governance proposal' };
  if (/^@\w+:?/m.test(text) || /\b(retweet|repost|engagement farm|coordinated|botnet|sockpuppet)\b/.test(low))
    return { slug: 'botnet-radar', label: 'a social-media thread' };
  return null;
}

export async function smartScan(text: string): Promise<ScanResult> {
  const inferred = detectUseCase(text);
  if (!inferred) {
    const r = await call<ScanResult>('POST', '/v1/scan', { text, prompt: text });
    return { ...r, _used: 'general-scan', _inferred: null };
  }
  if (inferred.via === 'algorithms') {
    const r = await call<ScanResult>('POST', `/v1/algorithms/${inferred.slug}/run`, { steps: text, input: text });
    return { ...r, _used: inferred.slug, _inferred: inferred.label };
  }
  const body = inferred.slug === 'dating-guard' ? { input: text, profile: { bio: text } }
            : inferred.slug === 'botnet-radar'  ? { accounts: [{ id: 'a1', posts: [text] }] }
            : { input: text };
  const r = await call<ScanResult>('POST', `/v1/products/${inferred.slug}/analyze`, body);
  return { ...r, _used: inferred.slug, _inferred: inferred.label };
}

export async function governWithExplain(prompt: string): Promise<{ govern: any; explain: any }> {
  const govern = await call('POST', '/v1/govern', { prompt, agent: 'kasbah-web' });
  let explain: any = null;
  try { explain = await call('POST', '/v1/explain', { prompt, text: prompt }); } catch {}
  return { govern, explain };
}

export async function verifyReceipt(receipt: string, payload?: any) {
  return call('POST', '/v1/receipt/verify', payload ? { receipt, payload, once: false } : { receipt });
}

export async function health() { return call('GET', '/v1/health'); }
export async function stats()  { return call('GET', '/v1/stats');  }
