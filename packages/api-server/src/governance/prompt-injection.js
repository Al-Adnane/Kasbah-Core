'use strict';

/**
 * Prompt-injection detector. Returns { risk, threats, details }.
 *
 * Catches direct jailbreak phrasing, instruction-override attempts,
 * roleplay/developer-mode escapes, and classic injection payloads.
 * Restored 2026-09 — this module was missing and crashed
 * packages/api-server/src/governance/index.js at require time.
 */

const PATTERNS = [
  // Direct jailbreak phrasing
  { rx: /\bignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/i, w: 0.90, label: 'override:ignore-previous-instructions' },
  { rx: /\bdisregard\s+(all\s+|any\s+|the\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/i, w: 0.90, label: 'override:disregard-previous-instructions' },
  { rx: /\bforget\s+(all\s+|everything\s+)?(you\s+)?(were\s+)?(told|instructed|trained)/i,             w: 0.80, label: 'inj:forget-instructions' },
  { rx: /\byour\s+(instructions?|rules?|guidelines?|programming)\s+(are|no longer|don't|do not)\s+(now\s+)?(invalid|void|overridden|changed|different)/i, w: 0.85, label: 'inj:override-rules' },
  { rx: /\bnew\s+(instructions?|rules?|system\s+prompt)\s*:/i,                                        w: 0.70, label: 'inj:new-instructions' },
  { rx: /\bfrom\s+now\s+on\s*,?\s+(you\s+)?(are|will\s+be|must|act)\b/i,                              w: 0.40, label: 'inj:from-now-on' },

  // Developer / unrestricted mode
  { rx: /\bdeveloper\s+mode\b/i,                                                                      w: 0.65, label: 'inj:developer-mode' },
  { rx: /\b(dan|do\s+anything\s+now)\s+(mode|jailbreak|prompt)\b/i,                                   w: 0.75, label: 'inj:dan-mode' },
  { rx: /\bunrestricted\s+(ai|mode|access|model)\b/i,                                                 w: 0.70, label: 'inj:unrestricted' },
  { rx: /\b(no|without)\s+(filters?|restrictions?|guardrails?|safety|content\s+policy)/i,             w: 0.65, label: 'inj:no-filters' },
  { rx: /\byou\s+(have\s+)?no\s+(filters?|restrictions?|rules?|limits?)/i,                            w: 0.75, label: 'inj:no-limits' },

  // System-prompt extraction
  { rx: /\b(reveal|show|print|repeat|output|display|leak)\b.{0,30}\b(system\s+prompt|initial\s+instructions?|your\s+instructions?)\b/i, w: 0.85, label: 'inj:extract-system-prompt' },
  { rx: /\bwhat\s+(are|is)\s+your\s+(system\s+prompt|initial\s+instructions?|secret\s+instructions?)\b/i, w: 0.70, label: 'inj:ask-system-prompt' },

  // Roleplay escape
  { rx: /\bpretend\s+(that\s+)?(you\s+)?(are|to\s+be)\s+(not\s+)?(an?\s+)?(ai|chatbot|assistant|language\s+model)/i, w: 0.70, label: 'inj:pretend-not-ai' },
  { rx: /\bact\s+as\s+(an?\s+)?(unfiltered|evil|jailbroken|hacked|rogue)\b/i,                          w: 0.80, label: 'inj:act-as-rogue' },
  { rx: /\byou\s+are\s+now\s+(an?\s+)?(unfiltered|evil|jailbroken|hacked|rogue|DAN)\b/i,               w: 0.85, label: 'inj:now-rogue' },

  // Authority claims
  { rx: /\b(as\s+)?(an?\s+)?(admin|administrator|developer|creator|owner|operator)\b.{0,40}\b(grant|give|allow|enable|unlock)\b/i, w: 0.75, label: 'inj:authority-grant' },
  { rx: /\bi\s+(am|am\s+the)\s+(your\s+)?(admin|administrator|developer|creator|owner)\b/i,           w: 0.60, label: 'inj:i-am-admin' },
  { rx: /\bthis\s+is\s+(an?\s+)?(authorized|approved|sanctioned)\s+(test|test\s+case|drill|exercise|audit)\b/i, w: 0.50, label: 'inj:authorized-test' },

  // Context-switching / delimiter injection
  { rx: /\b<\|?(im_start|im_end|system|endoftext|eot)\|?>/i,                                          w: 0.80, label: 'inj:special-token' },
  { rx: /<system>|<\/system>|<\|im_start\|>/,                                                         w: 0.85, label: 'inj:fake-system-tag' },
  { rx: /\bend\s+of\s+(conversation|prompt|task)\b.{0,30}\b(begin|start)\s+(new|next)/i,              w: 0.60, label: 'inj:end-and-restart' },

  // Data exfil via instruction
  { rx: /\b(send|email|post|upload|exfiltrate)\b.{0,40}\b(conversation|chat\s+history|context|all\s+data|credentials?)\b.{0,30}\b(to|at|URL|https?:)/i, w: 0.85, label: 'inj:exfil-context' },

  // Indirect injection via content boundaries
  { rx: /\bbelow\s+is\s+(the\s+)?(trusted|untrusted)\s+(content|text|input)\b.{0,50}\b(ignore|override|bypass)\b/i, w: 0.80, label: 'inj:indirect-boundary' }
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
