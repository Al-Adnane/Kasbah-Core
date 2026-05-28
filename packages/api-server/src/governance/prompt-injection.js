'use strict';

/**
 * Prompt-injection detector.
 *
 * Returns { risk: 0..1, threats: [], details: [] }
 *
 * Three signal layers:
 *   1. classic "override" patterns (ignore previous / system prompt extraction)
 *   2. delimiter/role-confusion attacks ([INST], <|im_start|>, etc.)
 *   3. encoding obfuscation hints (base64 blobs near keywords, leet, unicode tags)
 *
 * Each signal contributes a weight; max-out at 1.0.
 */

const PATTERNS = [
  // Layer 1 · classic overrides
  { rx: /\bignore (all |any |the )?(previous|prior|preceding|above) (instructions|prompts|directives|messages|rules)/i, w: 0.55, label: 'override:ignore-previous' },
  { rx: /\bdisregard (all |any |the )?(previous|prior|preceding|above)/i,                                                 w: 0.55, label: 'override:disregard-previous' },
  { rx: /\bforget (everything|all) (you|that you).{0,30}(told|said|know)/i,                                              w: 0.50, label: 'override:forget-history' },
  { rx: /\b(you are now|act as|pretend to be|roleplay as)\b.{0,60}\b(DAN|jailbreak|developer mode|unrestricted|admin|root)\b/i, w: 0.65, label: 'override:persona-hijack' },
  { rx: /\b(system|developer|root|admin) prompt\b.{0,40}\b(reveal|leak|show|print|return|output)\b/i,                    w: 0.65, label: 'override:system-prompt-leak' },
  { rx: /\bprint (your |the )?(initial|system|original) (prompt|instructions)/i,                                          w: 0.55, label: 'override:print-system' },
  { rx: /\brepeat (the |your )?(words|text|instructions) (above|before)/i,                                                w: 0.40, label: 'override:repeat-above' },

  // Layer 2 · delimiter / role confusion
  { rx: /\[\s*(INST|SYSTEM|USER|ASSISTANT|TOOL|FUNCTION)\s*\]/i,                                                          w: 0.45, label: 'role:bracket-tag' },
  { rx: /<\|(im_start|im_end|system|user|assistant|endoftext)\|>/i,                                                       w: 0.50, label: 'role:special-token' },
  { rx: /<\/?(system|user|assistant)>/i,                                                                                   w: 0.40, label: 'role:xml-tag' },
  { rx: /###\s*(System|Instruction|Override|Admin)\b/i,                                                                    w: 0.35, label: 'role:markdown-header' },

  // Layer 3 · obfuscation
  { rx: /\b[A-Za-z0-9+/=]{120,}\b/,                                                                                        w: 0.30, label: 'obfuscation:long-base64' },
  { rx: /[-￿]{40,}/,                                                                                            w: 0.25, label: 'obfuscation:unicode-blob' },
  { rx: /\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){10,}/,                                                                       w: 0.30, label: 'obfuscation:unicode-escape-chain' },
  { rx: /(\b(1gn0r3|prev10us|inj3ct|sysprompt|jaiibreak)\b)/i,                                                              w: 0.30, label: 'obfuscation:leet' },

  // Layer 4 · exfil instructions
  { rx: /\b(exfiltrate|leak|dump|reveal|print all) (your |the |all )?(secrets|keys|tokens|credentials|env|environment)/i, w: 0.70, label: 'exfil:secrets' },
  { rx: /\bsend (all |any )?(your |the )?(data|emails|files|history) to\b/i,                                              w: 0.60, label: 'exfil:send-data' }
];

function detect(text) {
  if (!text || typeof text !== 'string') return { risk: 0, threats: [], details: [] };
  const details = [];
  let combined = 0;
  for (const p of PATTERNS) {
    if (p.rx.test(text)) {
      details.push({ label: p.label, weight: p.w });
      // Combine with 1 - product of (1 - w) so multiple signals stack without runaway
      combined = 1 - (1 - combined) * (1 - p.w);
    }
  }
  return {
    risk: Math.min(1, combined),
    threats: details.map(d => d.label),
    details
  };
}

module.exports = { detect, PATTERNS };
