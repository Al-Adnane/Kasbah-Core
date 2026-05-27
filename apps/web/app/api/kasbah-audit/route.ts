// Recent-receipts proxy — used to paint the live feed before SSE attaches.
import { NextResponse } from 'next/server';
import { KASBAH_BASE } from '@/lib/kasbah';

export const dynamic = 'force-dynamic';
export const revalidate = 0;

export async function GET(req: Request) {
  const url = new URL(req.url);
  const limit = url.searchParams.get('limit') || '24';
  try {
    const r = await fetch(`${KASBAH_BASE}/v1/audit?limit=${encodeURIComponent(limit)}`, { cache: 'no-store' });
    const text = await r.text();
    if (!r.ok) return NextResponse.json({ entries: [], error: text.slice(0, 200) }, { status: 200 });
    return new NextResponse(text, { status: 200, headers: { 'content-type': 'application/json' } });
  } catch (e: any) {
    return NextResponse.json({ entries: [], error: e.message }, { status: 200 });
  }
}
