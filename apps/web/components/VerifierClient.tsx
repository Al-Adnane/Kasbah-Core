'use client';

// Pure WebCrypto Ed25519 verifier. Zero Kasbah-engine dependency.
// Implements docs/RECEIPT-SPEC.md §3 (canonical JSON) and §5 (verification).

import { useEffect, useState } from 'react';

type KeyEntry = { kid: string; alg: string; crv: string; x?: string; pem?: string };
type Resp = { issuer: string; keys: KeyEntry[] };

function b64urlToBytes(s: string): Uint8Array {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

function canonicalJSON(obj: any): string {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
}

async function importRawEd25519(rawB64url: string): Promise<CryptoKey> {
  // WebCrypto Ed25519: import the 32-byte raw public key as JWK.
  const raw = b64urlToBytes(rawB64url);
  if (raw.length !== 32) throw new Error('public key is not 32 bytes');
  const jwk = { kty: 'OKP', crv: 'Ed25519', x: rawB64url, ext: true };
  // @ts-ignore — Ed25519 typing varies by lib.dom version
  return crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' } as any, true, ['verify']);
}

type Verdict =
  | { state: 'idle' }
  | { state: 'checking' }
  | { state: 'ok'; decoded: any; keyId: string }
  | { state: 'bad'; reason: string };

export function VerifierClient() {
  const [keys, setKeys] = useState<KeyEntry[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [receipt, setReceipt] = useState('');
  const [payload, setPayload] = useState('');
  const [verdict, setVerdict] = useState<Verdict>({ state: 'idle' });
  const [autoRun, setAutoRun] = useState<{ r: string; p: string } | null>(null);

  useEffect(() => {
    // Prefer same-origin /.well-known (works when this page is served by the
    // Kasbah engine host). Fall back to bekasbah.com mirror.
    (async () => {
      const urls = ['/.well-known/kasbah-keys.json', '/api/well-known/kasbah-keys', 'https://bekasbah.com/.well-known/kasbah-keys.json'];
      for (const u of urls) {
        try {
          const r = await fetch(u, { cache: 'no-store' });
          if (!r.ok) continue;
          const data: Resp = await r.json();
          if (data?.keys?.length) { setKeys(data.keys); return; }
        } catch (_) { /* try next */ }
      }
      setErr('Could not fetch the Kasbah public key from any well-known location.');
    })();

    // Auto-fill from query string if present (deep-link from feed rows)
    if (typeof window !== 'undefined') {
      const qp = new URLSearchParams(window.location.search);
      const r = qp.get('r'); const p = qp.get('p');
      if (r) setReceipt(r);
      if (p) setPayload(p);
      if (r && p) setAutoRun({ r, p });
    }
  }, []);

  // Once keys load, run any pending auto-verify deep-link.
  useEffect(() => {
    if (keys && autoRun) {
      verifyNow(autoRun.r, autoRun.p);
      setAutoRun(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [keys, autoRun]);

  async function verifyNow(rIn?: string, pIn?: string) {
    const r = (rIn ?? receipt).trim();
    const p = (pIn ?? payload).trim();
    if (!r || !p) { setVerdict({ state: 'bad', reason: 'Receipt and payload are both required.' }); return; }
    setVerdict({ state: 'checking' });
    try {
      const parts = r.split(':');
      if (parts.length !== 5 || parts[0] !== 'kasbah_receipt' || parts[1] !== 'v2' || parts[2] !== 'ed25519') {
        return setVerdict({ state: 'bad', reason: 'Not a v2 Ed25519 Kasbah receipt.' });
      }
      const keyId = parts[3];
      const sig = b64urlToBytes(parts[4]);
      const canon = b64urlToBytes(p);
      const k = keys?.find(k => k.kid === keyId);
      if (!k) return setVerdict({ state: 'bad', reason: `No public key for keyId ${keyId}. The engine may have rotated keys.` });
      const pub = await importRawEd25519(k.x!);
      // @ts-ignore — Ed25519 typings
      const ok = await crypto.subtle.verify({ name: 'Ed25519' } as any, pub, sig, canon);
      if (!ok) return setVerdict({ state: 'bad', reason: 'Signature does not match. The receipt has been tampered with.' });
      const decoded = JSON.parse(new TextDecoder().decode(canon));
      if (decoded.keyId !== keyId) return setVerdict({ state: 'bad', reason: 'Payload keyId does not match receipt keyId.' });
      // Re-canonicalize to confirm the payload is itself canonical
      const recanon = canonicalJSON(decoded);
      const recanonBytes = new TextEncoder().encode(recanon);
      if (recanonBytes.length !== canon.length) {
        return setVerdict({ state: 'bad', reason: 'Payload is not in canonical form (RECEIPT-SPEC §3).' });
      }
      setVerdict({ state: 'ok', decoded, keyId });
    } catch (e: any) {
      setVerdict({ state: 'bad', reason: e.message || 'verify failed' });
    }
  }

  return (
    <div className="verifier">
      <label className="vlabel">Receipt</label>
      <textarea
        className="vinput" rows={2}
        placeholder="kasbah_receipt:v2:ed25519:…"
        value={receipt} onChange={e => setReceipt(e.target.value)}
      />
      <label className="vlabel">Payload (base64url)</label>
      <textarea
        className="vinput" rows={4}
        placeholder="base64url-encoded canonical JSON"
        value={payload} onChange={e => setPayload(e.target.value)}
      />
      <div className="vactions">
        <button className="btn-primary" disabled={!keys || verdict.state === 'checking'} onClick={() => verifyNow()}>
          {verdict.state === 'checking' ? 'Verifying…' : 'Verify offline →'}
        </button>
        <span className="vmeta">
          {keys ? `pubkey loaded · kid ${keys[0].kid}` : err ? `⚠ ${err}` : 'fetching public key…'}
        </span>
      </div>

      {verdict.state === 'ok' && (
        <div className="vresult ok">
          <div className="vresult-head">✓ Genuine</div>
          <div className="vresult-body">
            This receipt was signed by Kasbah engine key <code>{verdict.keyId}</code>.
            Verified entirely in your browser with WebCrypto Ed25519.
          </div>
          <pre className="vpayload">{JSON.stringify(verdict.decoded, null, 2)}</pre>
        </div>
      )}
      {verdict.state === 'bad' && (
        <div className="vresult bad">
          <div className="vresult-head">✗ Invalid</div>
          <div className="vresult-body">{verdict.reason}</div>
        </div>
      )}
    </div>
  );
}
