// Fallback for hosts where Next can't serve dot-prefixed paths from /public.
import { NextResponse } from 'next/server';
import { KASBAH_BASE } from '@/lib/kasbah';
import fs from 'fs';
import path from 'path';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const r = await fetch(`${KASBAH_BASE}/.well-known/kasbah-keys.json`, { cache: 'no-store' });
    if (r.ok) {
      const text = await r.text();
      try {
        const dir = path.join(process.cwd(), 'public', '.well-known');
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, 'kasbah-keys.json'), text);
      } catch (_) {}
      return new NextResponse(text, { status: 200, headers: { 'content-type': 'application/json' } });
    }
  } catch (_) {}
  try {
    const p = path.join(process.cwd(), 'public', '.well-known', 'kasbah-keys.json');
    return new NextResponse(fs.readFileSync(p, 'utf8'), { status: 200, headers: { 'content-type': 'application/json' } });
  } catch (_) {
    return NextResponse.json({ error: 'no key available' }, { status: 503 });
  }
}
