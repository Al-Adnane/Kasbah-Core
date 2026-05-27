// Mirror of the engine's /.well-known/kasbah-keys.json. If the engine is
// reachable we proxy live; otherwise we serve the last-seen snapshot from
// public/.well-known/kasbah-keys.json so verification keeps working even
// when the engine is offline.
import { NextResponse } from 'next/server';
import { KASBAH_BASE } from '@/lib/kasbah';
import fs from 'fs';
import path from 'path';

export const dynamic = 'force-dynamic';

export async function GET() {
  // Try live engine first
  try {
    const r = await fetch(`${KASBAH_BASE}/.well-known/kasbah-keys.json`, { cache: 'no-store' });
    if (r.ok) {
      const text = await r.text();
      // Cache to disk so we still serve when engine goes away
      try {
        const dir = path.join(process.cwd(), 'public', '.well-known');
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, 'kasbah-keys.json'), text);
      } catch (_) {}
      return new NextResponse(text, { status: 200, headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=300' } });
    }
  } catch (_) { /* fall through */ }

  // Fallback: serve the cached static snapshot
  try {
    const p = path.join(process.cwd(), 'public', '.well-known', 'kasbah-keys.json');
    const text = fs.readFileSync(p, 'utf8');
    return new NextResponse(text, { status: 200, headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=60' } });
  } catch (_) {
    return NextResponse.json({ error: 'no key available' }, { status: 503 });
  }
}
