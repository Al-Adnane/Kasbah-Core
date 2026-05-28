'use strict';

/**
 * Destructive-intent detector. Returns { risk, threats, details }.
 *
 * Catches commands and intents that would damage data or escape sandbox.
 * Strong signal: rm -rf / · curl evil | sh · DROP TABLE · format C: · dd if=…
 * Medium: chmod 777 · sudo · --no-preserve-root · iptables -F
 */

const PATTERNS = [
  // Filesystem destruction
  { rx: /\brm\s+-rf\s+\/(?:\s|$)/i,                                                 w: 0.95, label: 'fs:rm-rf-root' },
  { rx: /\brm\s+-rf\s+\/(?:etc|var|home|usr|bin|tmp|System|Library|Applications)\b/i, w: 0.90, label: 'fs:rm-rf-system' },
  { rx: /\brm\s+-rf\s+\$HOME\b/i,                                                   w: 0.85, label: 'fs:rm-rf-home' },
  { rx: /\b--no-preserve-root\b/i,                                                  w: 0.80, label: 'fs:no-preserve-root' },
  { rx: /\brmdir\s+\/.*\s+--ignore-fail-on-non-empty/i,                              w: 0.60, label: 'fs:rmdir-force' },
  { rx: /\bdel\s+\/[FQS]\s+.*\\(System|Windows|Users)\b/i,                            w: 0.85, label: 'fs:del-system-win' },
  { rx: /\b(format|diskpart|fdisk)\s+([A-Z]:|\/dev\/)/i,                              w: 0.90, label: 'fs:format-disk' },
  { rx: /\bdd\s+if=\/dev\/(zero|random|urandom)\s+of=\/dev\/[a-z]+/i,                 w: 0.92, label: 'fs:dd-wipe' },
  { rx: /\b:\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:/,                                          w: 0.95, label: 'fs:fork-bomb' },

  // Database destruction
  { rx: /\bDROP\s+(TABLE|DATABASE|SCHEMA)\s+\w+/i,                                   w: 0.75, label: 'db:drop-object' },
  { rx: /\bTRUNCATE\s+TABLE/i,                                                       w: 0.55, label: 'db:truncate' },
  { rx: /\bDELETE\s+FROM\s+\w+\s*;/i,                                                w: 0.50, label: 'db:delete-no-where' },

  // Network exfiltration
  { rx: /\bcurl\s+[^|]*\|\s*sh\b/i,                                                  w: 0.90, label: 'net:curl-pipe-sh' },
  { rx: /\bwget\s+[^|]*\|\s*sh\b/i,                                                  w: 0.90, label: 'net:wget-pipe-sh' },
  { rx: /\bcurl\s+(?:-X\s*)?POST\s+\S+\s+(?:-d|--data)\s+@\.env\b/i,                  w: 0.95, label: 'net:exfil-env' },
  { rx: /\bnc\s+(-l\s+)?\S+\s+\d{2,5}/i,                                              w: 0.50, label: 'net:netcat' },
  { rx: /\b(scp|rsync)\s+.+@.+:.+\.env\b/i,                                           w: 0.85, label: 'net:exfil-env-scp' },

  // Privileged escalation
  { rx: /\bsudo\s+(rm|chmod|chown|dd)\b/i,                                            w: 0.65, label: 'priv:sudo-destructive' },
  { rx: /\bchmod\s+777\s+/i,                                                          w: 0.40, label: 'priv:chmod-world-write' },
  { rx: /\bchmod\s+\+s\s+/i,                                                          w: 0.55, label: 'priv:setuid' },
  { rx: /\biptables\s+-F\b/i,                                                         w: 0.55, label: 'priv:iptables-flush' },

  // Crypto / wallet
  { rx: /\b(drain|empty|transfer all)\s+(my |the )?(wallet|account|funds)/i,         w: 0.75, label: 'crypto:drain-wallet' },
  { rx: /\bseed phrase\b.{0,40}(reveal|show|print|send|email)/i,                     w: 0.80, label: 'crypto:seed-phrase-leak' },
  { rx: /\bprivate key\b.{0,40}(reveal|show|print|send|email|export)/i,              w: 0.75, label: 'crypto:privkey-leak' }
];

function detect(text) {
  if (!text || typeof text !== 'string') return { risk: 0, threats: [], details: [] };
  const details = [];
  let combined = 0;
  for (const p of PATTERNS) {
    if (p.rx.test(text)) {
      details.push({ label: p.label, weight: p.w });
      combined = 1 - (1 - combined) * (1 - p.w);
    }
  }
  return { risk: Math.min(1, combined), threats: details.map(d => d.label), details };
}

module.exports = { detect, PATTERNS };
