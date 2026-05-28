import Link from 'next/link';
import { health, stats, KASBAH_BASE } from '@/lib/kasbah';
import { LogoMark } from '../components/Logo';
import { HeroDashboard } from '../components/HeroDashboard';
import {
  AgentRuntimeBand, CostOptimizerBand,
  MaliciousAgentBand, PrivacyBand
} from '../components/CapabilityBands';
import { StickyInstall } from '../components/StickyInstall';

export const revalidate = 30;

async function liveStats() {
  try {
    const [h, s] = await Promise.all([health(), stats()]);
    // Pull real counter from /v1/audit total via stats; fall back to audit endpoint
    let signed = s?.total ?? s?.governed ?? null;
    if (signed == null) {
      try {
        const r = await fetch(`${KASBAH_BASE}/v1/audit?limit=1`, { cache: 'no-store' });
        const j = await r.json();
        signed = j?.total ?? 0;
      } catch { signed = 0; }
    }
    return { online: h?.status === 'ok', version: h?.version, signed };
  } catch { return { online: false, signed: 0 } as any; }
}

async function githubStars(): Promise<number | null> {
  // Try the GitHub API. Returns null on any failure so we hide the chip.
  const repo = process.env.KASBAH_GITHUB_REPO || 'Al-Adnane/Kasbah-Core';
  try {
    const r = await fetch(`https://api.github.com/repos/${repo}`, {
      next: { revalidate: 600 },
      headers: { 'User-Agent': 'kasbah-web' }
    });
    if (!r.ok) return null;
    const j = await r.json();
    return typeof j?.stargazers_count === 'number' ? j.stargazers_count : null;
  } catch { return null; }
}

export default async function Landing() {
  const live = await liveStats();
  const stars = await githubStars();
  return (
    <main>
      <StickyInstall />
      {/* ── HERO · the runtime preview ────────────────────────────── */}
      <section className="hero hero-runtime">
        <div className="container hero-inner">
          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 18 }}>
            <LogoMark size={56} />
          </div>

          <h1 className="hero-h1">
            Your AI does 200 things a day.<br />
            Right now, you can&apos;t see <em>any</em> of them.
          </h1>

          <p className="hero-sub">
            Kasbah is what runs inside your AI stack — saving money, blocking attacks,
            redacting your data, signing every action — so you don&apos;t have to.
          </p>

          <HeroDashboard />
          <div className="dash-disclosure">
            sample preview · your real dashboard lands on{' '}
            <Link href="/dashboard">/dashboard</Link> after install
          </div>

          <div className="hero-installs">
            <div className="hero-installs-label">Install in 60 seconds</div>
            <div className="hero-installs-row">
              <a className="install-btn primary" href="#install-mcp">
                <span className="install-glyph">⌘</span>
                <span><strong>Claude Code / Cursor / Cline</strong><span>one MCP install</span></span>
              </a>
              <a className="install-btn" href="#install-browser">
                <span className="install-glyph">◐</span>
                <span><strong>Browser extension</strong><span>ChatGPT · Claude.ai · Gemini</span></span>
              </a>
              <a className="install-btn" href="#install-mobile">
                <span className="install-glyph">▢</span>
                <span><strong>Mobile</strong><span>iOS · Android share sheet</span></span>
              </a>
              <a className="install-btn" href="#install-selfhost">
                <span className="install-glyph">▦</span>
                <span><strong>Self-host the engine</strong><span>Docker · on-prem · air-gapped</span></span>
              </a>
            </div>
          </div>

          <div className="hero-trust">
            {live.online ? (
              <>
                <span className="live-dot" />
                <span>engine live</span>
                <span className="sep">·</span>
                <code>v{live.version}</code>
                <span className="sep">·</span>
                <Link href="/dashboard" className="hero-trust-link">see receipts streaming →</Link>
              </>
            ) : (
              <>
                <span className="live-dot off" />
                <span>boot the engine</span>
                <span className="sep">·</span>
                <code>node packages/api-server/server.js</code>
              </>
            )}
          </div>
        </div>
      </section>

      {/* ── FOUR CAPABILITY BANDS · the moat made visible ────────── */}
      <AgentRuntimeBand />
      <CostOptimizerBand />
      <MaliciousAgentBand />
      <PrivacyBand />

      {/* ── INSTALL · the four real surfaces, with the actual code ─ */}
      <section className="section section-install">
        <div className="container">
          <div className="install-head">
            <span className="eyebrow">Get protected</span>
            <h2>Pick where you run AI. We&apos;ll meet you there.</h2>
            <p className="lede">
              One engine, four surfaces. Every install lands on your personal
              dashboard — same shape as the preview above, populated with your own agents.
            </p>
          </div>

          <div className="install-grid">
            <div className="install-card" id="install-mcp">
              <div className="install-card-head">⌘  Claude Code · Cursor · Cline</div>
              <p>One MCP server. Every tool call your agent makes gets routed through Kasbah.</p>
              <pre><code>{`# add to ~/.claude/mcp.json
{
  "kasbah": {
    "command": "npx",
    "args": ["@kasbah/mcp-server"]
  }
}`}</code></pre>
              <a className="install-card-cta" href="https://github.com/Al-Adnane/Kasbah-Core" target="_blank" rel="noopener">Install MCP →</a>
            </div>

            <div className="install-card" id="install-browser">
              <div className="install-card-head">◐  Browser extension</div>
              <p>Intercepts every prompt in ChatGPT, Claude.ai, Gemini, Perplexity. PII redacted before egress.</p>
              <div className="install-card-stores">
                <span className="store">Chrome</span>
                <span className="store">Firefox</span>
                <span className="store">Safari</span>
                <span className="store">Edge</span>
              </div>
              <a className="install-card-cta" href="mailto:hello@bekasbah.com?subject=Kasbah%20extension%20beta">Join the beta →</a>
            </div>

            <div className="install-card" id="install-mobile">
              <div className="install-card-head">▢  Mobile</div>
              <p>iOS &amp; Android share-sheet target. Forward any message, screenshot, contract — get a verdict and a saved receipt.</p>
              <div className="install-card-stores">
                <span className="store">App Store</span>
                <span className="store">Google Play</span>
              </div>
              <a className="install-card-cta" href="mailto:hello@bekasbah.com?subject=Kasbah%20mobile%20beta">Join the beta →</a>
            </div>

            <div className="install-card" id="install-selfhost">
              <div className="install-card-head">▦  Self-host the engine</div>
              <p>One container. Your hardware. Air-gapped, SOC 2 ready, EU AI Act Article 14 aligned.</p>
              <pre><code>{`docker run -p 8788:8788 \\
  -v kasbah-data:/data \\
  kasbah/engine:latest`}</code></pre>
              <a className="install-card-cta" href="mailto:hello@bekasbah.com?subject=Kasbah%20enterprise">Talk to us →</a>
            </div>
          </div>
        </div>
      </section>

      {/* ── PROOF · the four reproducible numbers ────────────────── */}
      <section className="section section-proof">
        <div className="container">
          <div className="proof-head">
            <span className="eyebrow">Measured, not claimed</span>
            <h2>Numbers anyone can <em>reproduce.</em></h2>
            <p className="lede">
              Reproducible. <code>node bench/run.js</code> against the committed
              {' '}<code>bench/corpus/v1.json</code> (77 cases) to measure F1/recall on your hardware.
              Catalog and proxy figures readable at <code>/v1/models</code> and <code>/v1/proxy</code>.
            </p>
          </div>
          <div className="proof-grid">
            <div className="proof-num"><div className="n">72</div><div className="l">LLMs recognized · West, China, OSS</div></div>
            <div className="proof-num"><div className="n">18</div><div className="l">providers proxied · drop-in BASE_URL</div></div>
            <div className="proof-num"><div className="n">~40 ms</div><div className="l">p95 verdict latency</div></div>
            <div className="proof-num"><div className="n">Ed25519</div><div className="l">offline-verifiable receipts, forever</div></div>
          </div>
        </div>
      </section>

      {/* ── CLOSING · social proof + CTA ─────────────────────────── */}
      <section className="section section-close">
        <div className="container container-narrow" style={{ textAlign: 'center' }}>
          <span className="eyebrow">Pilot · live engine</span>
          <h2 className="close-h2">
            {live.signed?.toLocaleString() ?? '0'} decisions signed by this engine.<br />
            <em>Yours next.</em>
          </h2>
          <p className="lede" style={{ margin: '14px auto 28px', textAlign: 'center' }}>
            Every action your agents take from the moment you install — provable,
            replayable, verifiable forever. The counter above is live audit data
            from the engine serving this page.
          </p>
          <div className="cta-row" style={{ justifyContent: 'center' }}>
            <a href="#install-mcp"><button className="btn-primary">Install in Claude Code →</button></a>
            <a href="mailto:hello@bekasbah.com?subject=Kasbah%20enterprise"><button className="btn-ghost">Talk to us</button></a>
            {stars != null && (
              <a href="https://github.com/Al-Adnane/Kasbah-Core" target="_blank" rel="noopener" className="stars-chip">
                <span>★</span> <strong>{stars.toLocaleString()}</strong> on GitHub
              </a>
            )}
          </div>
        </div>
      </section>

      {/* ── FOOTER ───────────────────────────────────────────────── */}
      <footer className="footer">
        <div className="footer-inner">
          <div className="footer-brand">
            <LogoMark size={26} />
            <span>Kasbah</span>
          </div>
          <div className="footer-links">
            <Link href="/dashboard">Live dashboard</Link>
            <Link href="/verify">Verify a receipt</Link>
            <Link href="/scan">Playground</Link>
            <a href="https://github.com/Al-Adnane/Kasbah-Core" target="_blank" rel="noopener">GitHub</a>
            <a href="mailto:hello@bekasbah.com">Contact</a>
          </div>
          <p>Kasbah · the runtime for agentic AI · bekasbah.com</p>
        </div>
      </footer>
    </main>
  );
}
