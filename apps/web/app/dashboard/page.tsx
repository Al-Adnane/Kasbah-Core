// The live engine dashboard — backstage. Linked from the hero status strip
// for the curious; not on the front page anymore.

import Link from 'next/link';
import { LiveFeed } from '../../components/LiveFeed';

export const dynamic = 'force-dynamic';

export default function Dashboard() {
  return (
    <main className="scan-page">
      <div className="container">
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <span className="eyebrow">Live · streaming from the engine</span>
          <h2 style={{ margin: '0 auto' }}>What Kasbah caught today.</h2>
          <p className="lede" style={{ margin: '14px auto 0', textAlign: 'center' }}>
            Every decision the engine made — for every agent, every editor, every API
            call — flows in here. Each row is signed. Click any receipt to verify it offline.
          </p>
        </div>
        <LiveFeed />
        <div style={{ textAlign: 'center', marginTop: 28 }}>
          <Link href="/">← Back to the scanner</Link>
        </div>
      </div>
    </main>
  );
}
