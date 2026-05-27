'use client';

// The webapp's defining moment. Not a textarea — a live log of every governed
// AI action streaming from the engine. Each row is a real Ed25519-signed
// receipt, click-through to the offline verifier. Kasbah is ambient; the
// page just shows what it caught while you were working.

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';

type Entry = {
  id?: string;
  ts?: string;
  timestamp?: string;
  type?: string;
  event?: string;
  verdict?: 'ALLOW' | 'WARN' | 'DENY' | string;
  agent?: string;
  source?: string;
  product?: string;
  surface?: string;
  receipt?: string;
  reason?: string;
  latency_ms?: number;
  latencyMs?: number;
  workspaceId?: string;
};

function verdictColor(v?: string) {
  if (v === 'DENY') return '#C1440E';
  if (v === 'WARN') return '#D97706';
  if (v === 'ALLOW') return '#10B981';
  return '#6B7280';
}

function verdictGlyph(v?: string) {
  if (v === 'DENY') return '✗';
  if (v === 'WARN') return '⚠';
  if (v === 'ALLOW') return '✓';
  return '·';
}

function timeAgo(ts?: string) {
  if (!ts) return '';
  const d = new Date(ts).getTime();
  if (!d) return '';
  const s = Math.max(1, Math.floor((Date.now() - d) / 1000));
  if (s < 60) return s + 's ago';
  const m = Math.floor(s / 60); if (m < 60) return m + 'm ago';
  const h = Math.floor(m / 60); if (h < 24) return h + 'h ago';
  return Math.floor(h / 24) + 'd ago';
}

function describe(e: Entry): string {
  if (e.reason) return e.reason;
  const surface = e.surface || e.source || e.agent || 'agent';
  const action = e.event || e.type || 'decision';
  return `${surface} · ${action.replace(/_/g, ' ')}`;
}

function shortReceipt(e: Entry): string {
  const r = e.receipt || e.id || '';
  if (!r) return '';
  if (r.length <= 22) return r;
  return r.slice(0, 10) + '…' + r.slice(-6);
}

export function LiveFeed() {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [online, setOnline] = useState<boolean | null>(null);
  const [paused, setPaused] = useState(false);
  const esRef = useRef<EventSource | null>(null);
  const pausedRef = useRef(false);
  pausedRef.current = paused;

  useEffect(() => {
    let cancelled = false;
    // Initial paint: last ~24 receipts so the feed isn't empty
    fetch('/api/kasbah-audit?limit=24').then(r => r.json()).then(data => {
      if (cancelled) return;
      const seed: Entry[] = data?.entries || data?.audit || [];
      if (seed.length) {
        setEntries(seed.slice(0, 24));
        setOnline(true);
      } else {
        setOnline(false);
      }
    }).catch(() => setOnline(false));

    // Live: SSE pipe
    try {
      const es = new EventSource('/api/kasbah-stream');
      esRef.current = es;
      es.onmessage = (ev) => {
        if (pausedRef.current) return;
        try {
          const parsed = JSON.parse(ev.data);
          if (parsed?.error) return;
          setEntries(prev => [parsed, ...prev].slice(0, 50));
          setOnline(true);
        } catch { /* ignore non-JSON keepalives */ }
      };
      es.onerror = () => { setOnline(false); };
    } catch { setOnline(false); }

    return () => { cancelled = true; esRef.current?.close(); };
  }, []);

  return (
    <div className="feed-wrap">
      <div className="feed-head">
        <div className="feed-status">
          <span className={`live-dot ${online ? '' : 'off'}`} />
          <span>{online === false ? 'engine offline' : online ? 'live · signing decisions now' : 'connecting…'}</span>
          <span className="sep">·</span>
          <code>{entries.length} shown</code>
        </div>
        <div className="feed-actions">
          <button className="feed-btn" onClick={() => setPaused(p => !p)}>{paused ? '▶ resume' : '⏸ pause'}</button>
          <button className="feed-btn" onClick={() => setEntries([])}>clear</button>
        </div>
      </div>

      <div className="feed-list">
        {entries.length === 0 && online !== false && (
          <div className="feed-empty">Waiting for the next decision…</div>
        )}
        {entries.length === 0 && online === false && (
          <div className="feed-empty">
            Engine offline. Boot it: <code>node packages/api-server/server.js</code>
          </div>
        )}
        {entries.map((e, i) => {
          const c = verdictColor(e.verdict);
          const rcpt = shortReceipt(e);
          const lat = e.latency_ms ?? e.latencyMs;
          return (
            <div className="feed-row" key={(e.id || '') + i} style={{ borderLeftColor: c }}>
              <div className="feed-verdict" style={{ color: c }}>
                <span className="feed-glyph">{verdictGlyph(e.verdict)}</span>
                <span className="feed-verdict-word">{e.verdict || 'EVENT'}</span>
              </div>
              <div className="feed-body">
                <div className="feed-desc">{describe(e)}</div>
                <div className="feed-meta">
                  <span>{timeAgo(e.ts || e.timestamp)}</span>
                  {lat != null && <><span className="sep">·</span><span>{lat} ms</span></>}
                  {rcpt && (
                    <>
                      <span className="sep">·</span>
                      <Link href={`/r/${encodeURIComponent(e.receipt || e.id || '')}`} className="feed-receipt">
                        <code>{rcpt}</code> ✓ verifiable
                      </Link>
                    </>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="feed-foot">
        Every row is an Ed25519-signed receipt. Click any receipt to verify it
        cryptographically — no Kasbah login, no round-trip to a vendor cloud.
      </div>
    </div>
  );
}
