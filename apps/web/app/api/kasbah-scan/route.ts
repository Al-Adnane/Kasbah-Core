// Smart-route the input + sign every verdict with a v2 Ed25519 receipt so the
// user always sees a "verify offline" chip under the result, regardless of
// which product fired.
import { NextResponse } from 'next/server';
import { smartScan, KASBAH_BASE } from '@/lib/kasbah';
import crypto from 'crypto';

export const dynamic = 'force-dynamic';

function toVerdict(result: any): 'ALLOW' | 'WARN' | 'DENY' {
  const raw = String(result?.verdict || '').toUpperCase();
  if (['DENY','SCAM_LIKELY','HIGH_RISK','FAKE','AI_GENERATED','BLOCK','MANIPULATIVE','TOXIC','COORDINATED'].includes(raw)) return 'DENY';
  if (['WARN','MEDIUM_RISK','SUSPICIOUS','LIKELY','UNCERTAIN','MIXED'].includes(raw)) return 'WARN';
  if (['ALLOW','SAFE','LOW_RISK','CLEAN','HUMAN_LIKELY','AUTHENTIC'].includes(raw)) return 'ALLOW';
  const r = typeof result?.score === 'number' ? result.score
         : typeof result?.risk === 'number' ? result.risk
         : typeof result?.riskScore === 'number' ? result.riskScore : 0;
  return r >= 0.7 ? 'DENY' : r >= 0.35 ? 'WARN' : 'ALLOW';
}

export async function POST(req: Request) {
  try {
    const { text } = await req.json();
    if (!text || typeof text !== 'string') return NextResponse.json({ error: 'text required' }, { status: 400 });
    const result: any = await smartScan(text);

    // Sign a v2 receipt so the verdict is provable + the UI shows the chip.
    if (!result.receipt) {
      try {
        const verdict = toVerdict(result);
        const risk = typeof result?.score === 'number' ? result.score
                   : typeof result?.risk === 'number' ? result.risk
                   : typeof result?.riskScore === 'number' ? result.riskScore : 0;
        const subject = crypto.createHash('sha256').update(text).digest('hex');
        const signRes = await fetch(`${KASBAH_BASE}/v1/sign`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            verdict, risk, subject,
            surface: 'web-scanner',
            action: result?._used || result?.product || 'scan'
          }),
          cache: 'no-store'
        });
        if (signRes.ok) {
          const signed = await signRes.json();
          result.receipt = signed.receipt;
          result.receiptPayload = signed.payload;
        }
      } catch (_) { /* receipt is best-effort */ }
    }

    return NextResponse.json(result);
  } catch (e: any) {
    return NextResponse.json({ error: e.message || 'scan failed' }, { status: 502 });
  }
}
