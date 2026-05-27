// Static, vendor-independent verifier. Loads the engine public key from
// /.well-known/kasbah-keys.json (mirrored at bekasbah.com), fetches no other
// Kasbah service, runs Ed25519 verification entirely in the browser with
// WebCrypto. Designed to survive Kasbah being offline forever.

export const dynamic = 'force-static';

import { VerifierClient } from '../../components/VerifierClient';

export default function VerifyPage() {
  return (
    <main className="scan-page">
      <div className="container-narrow">
        <span className="eyebrow">Independent receipt verifier</span>
        <h2 style={{ margin: '0 0 12px' }}>Verify a Kasbah receipt <em>offline.</em></h2>
        <p className="lede" style={{ margin: '0 0 28px' }}>
          This page does not call the Kasbah engine. It loads only the published
          public key and runs Ed25519 verification in your browser with WebCrypto.
          The receipt is genuine even if Kasbah, the company, ceased to exist tomorrow.
        </p>
        <VerifierClient />
        <p style={{ marginTop: 28, fontSize: 13, color: 'var(--muted)' }}>
          Implements <a href="https://bekasbah.com/spec/receipt-v2">Receipt Spec v2</a>.
          Source: <code>apps/web/components/VerifierClient.tsx</code>.
        </p>
      </div>
    </main>
  );
}
