'use client';

// The hero centerpiece — a live-looking command center that previews what
// the user's own dashboard looks like AFTER they install Kasbah. Numbers
// tick up over time; agent rows light; surface badges pulse. Sells the
// install by showing the outcome of having installed.

import { useEffect, useState } from 'react';

const SURFACES = [
  { id: 'mcp',     label: 'MCP',     dot: true },
  { id: 'browser', label: 'Browser', dot: true },
  { id: 'desktop', label: 'Desktop', dot: true },
  { id: 'mobile',  label: 'Mobile',  dot: false },
  { id: 'api',     label: 'API',     dot: true }
];

const AGENTS = [
  { name: 'Claude Code',    status: 'active',   actions: 247 },
  { name: 'Cursor',         status: 'active',   actions: 184 },
  { name: 'Cline',          status: 'active',   actions: 91  },
  { name: 'custom-agent-7', status: 'revoked',  actions: 12  }
];

function useTicker(seed: number, rate: number) {
  const [n, setN] = useState(seed);
  useEffect(() => {
    const i = setInterval(() => setN(prev => prev + (Math.random() < 0.7 ? 1 : 0)), rate);
    return () => clearInterval(i);
  }, [rate]);
  return n;
}

function useDollarTicker(seedCents: number, rate: number) {
  const [c, setC] = useState(seedCents);
  useEffect(() => {
    const i = setInterval(() => setC(prev => prev + Math.floor(Math.random() * 9) + 1), rate);
    return () => clearInterval(i);
  }, [rate]);
  return `$${(c / 100).toLocaleString(undefined, { minimumFractionDigits: 0, maximumFractionDigits: 0 })}`;
}

export function HeroDashboard() {
  const dollars = useDollarTicker(34237, 1600);
  const injections = useTicker(47, 4200);
  const malicious  = useTicker(3, 9000);
  const pii        = useTicker(124, 1100);
  const signed     = useTicker(12482, 320);

  return (
    <div className="dash">
      <div className="dash-head">
        <span className="dash-title">your dashboard · this week</span>
        <span className="dash-live"><span className="live-dot" /> live</span>
      </div>

      <div className="dash-stats">
        <Stat n={dollars}    l="saved in wasted LLM calls"      tone="green" />
        <Stat n={injections} l="prompt injections blocked"      tone="red"   />
        <Stat n={malicious}  l="malicious-agent attempts denied"tone="red"   />
        <Stat n={pii}        l="pieces of PII redacted"         tone="amber" />
        <Stat n={signed.toLocaleString()} l="decisions signed · provable" tone="ink" />
      </div>

      <div className="dash-grid">
        <div className="dash-card">
          <div className="dash-card-title">Agents under governance</div>
          <ul className="dash-agents">
            {AGENTS.map(a => (
              <li key={a.name} className={`dash-agent ${a.status}`}>
                <span className="dash-agent-dot" />
                <span className="dash-agent-name">{a.name}</span>
                <span className="dash-agent-actions">{a.actions} actions</span>
                <span className={`dash-agent-status ${a.status}`}>
                  {a.status === 'active' ? '✓ active' : '✗ revoked'}
                </span>
              </li>
            ))}
          </ul>
        </div>

        <div className="dash-card">
          <div className="dash-card-title">Surfaces protected</div>
          <ul className="dash-surfaces">
            {SURFACES.map(s => (
              <li key={s.id} className={`dash-surface ${s.dot ? 'on' : 'off'}`}>
                <span className="dash-surface-dot" />
                <span>{s.label}</span>
                <span className="dash-surface-state">{s.dot ? 'connected' : 'install'}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="dash-foot">
        <span>engine v2.0 · uptime 14d 9h · p95 38 ms</span>
        <span className="dash-foot-pulse">●</span>
      </div>
    </div>
  );
}

function Stat({ n, l, tone }: { n: string | number; l: string; tone: 'green'|'red'|'amber'|'ink' }) {
  return (
    <div className={`dash-stat tone-${tone}`}>
      <div className="dash-stat-n">{n}</div>
      <div className="dash-stat-l">{l}</div>
    </div>
  );
}
