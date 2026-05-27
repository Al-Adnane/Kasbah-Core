// Live SSE pipe — streams every governance decision from the engine to the browser.
import { KASBAH_BASE } from '@/lib/kasbah';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export async function GET() {
  const upstream = await fetch(`${KASBAH_BASE}/v1/stream`, {
    headers: { Accept: 'text/event-stream' },
    cache: 'no-store'
  }).catch(() => null);

  if (!upstream || !upstream.ok || !upstream.body) {
    return new Response('event: error\ndata: {"error":"engine unreachable"}\n\n', {
      status: 200,
      headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' }
    });
  }

  return new Response(upstream.body, {
    status: 200,
    headers: {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache, no-transform',
      'connection': 'keep-alive'
    }
  });
}
