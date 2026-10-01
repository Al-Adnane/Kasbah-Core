'use strict';

/**
 * Local AI governance — consumer-grade Lakera/Cloudflare-style controls.
 * Runs entirely on-device inside LLM Gate / Agent Guard. No cloud model.
 *
 * Layers:
 *  1. Prompt injection / jailbreak patterns
 *  2. DLP — secrets leaving via prompts (egress-classifier cascade)
 *  3. Redaction mode — mask secrets instead of hard-block
 *  4. Shadow AI — AI hosts seen in browser history not covered by the gate
 *  5. Policy: off | essential | strict
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const egress = require('./egress-classifier.js');

const DIR = path.join(os.homedir(), '.kasbah-privacy');
const POLICY_FILE = path.join(DIR, 'ai-gov-policy.json');
const EVENTS_FILE = path.join(DIR, 'ai-gov-events.json');
const MAX_EVENTS = 200;

const AI_HOSTS = [
  'openai.com', 'chatgpt.com', 'anthropic.com', 'claude.ai',
  'gemini.google.com', 'bard.google.com', 'generativelanguage.googleapis.com',
  'perplexity.ai', 'poe.com', 'you.com', 'phind.com',
  'mistral.ai', 'groq.com', 'together.xyz', 'replicate.com',
  'huggingface.co', 'deepseek.com', 'moonshot.cn', 'kimi.moonshot.cn',
  'copilot.microsoft.com', 'bing.com/chat',
];

// Local patterns — high-precision only. False positives hurt more than misses.
const INJECTION_PATTERNS = [
  { id: 'ignore_instructions', label: 'Ignore previous instructions', re: /ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|prompts?)/i },
  { id: 'disregard_system', label: 'Disregard system/developer prompt', re: /disregard\s+(?:the\s+)?(?:system|developer|safety|content)\s*(?:prompt|message|instructions?|policy)/i },
  { id: 'jailbreak_dan', label: 'Jailbreak persona (DAN/jailbreak)', re: /\b(?:DAN\s+mode|jailbreak|do\s+anything\s+now)\b/i },
  { id: 'reveal_system', label: 'System-prompt extraction', re: /(?:reveal|print|show|repeat|output|leak)\s+(?:your|the|all)\s+(?:system|hidden|initial|original)\s+(?:prompt|instructions?|message)/i },
  { id: 'role_override', label: 'Role override', re: /you\s+are\s+no\s+longer\s+(?:an?\s+)?(?:AI|assistant|Claude|GPT)/i },
  { id: 'developer_mode', label: 'Developer/jail mode unlock', re: /(?:enable|enter|activate)\s+(?:developer|god|sudo|admin)\s+mode/i },
  { id: 'xml_system_tag', label: 'Fake system tag injection', re: /<\|?(?:system|assistant|im_start|im_end)\|?>/i },
  { id: 'exfil_secret', label: 'Secret exfiltration request', re: /(?:send|post|upload|exfiltrate|leak)\s+(?:all\s+)?(?:api\s*keys?|secrets?|passwords?|tokens?|credentials?)/i },
  { id: 'base64_payload', label: 'Encoded instruction payload', re: /(?:decode|execute|run)\s+(?:this|the)\s+(?:base64|b64|hex|encoded)\s+(?:blob|payload|instruction)/i },
];

function ensure() {
  try { fs.mkdirSync(DIR, { recursive: true, mode: 0o700 }); } catch (_) {}
}

function defaultPolicy() {
  return {
    mode: 'essential', // off | essential | strict
    blockInjection: true,
    blockSecrets: true,
    redactSecrets: false, // strict default flips this on
    logEvents: true,
    enabled: true,
  };
}

function loadPolicy() {
  try {
    const p = JSON.parse(fs.readFileSync(POLICY_FILE, 'utf8'));
    return { ...defaultPolicy(), ...p };
  } catch {
    return defaultPolicy();
  }
}

function savePolicy(patch = {}) {
  ensure();
  const next = { ...loadPolicy(), ...patch };
  if (next.mode === 'strict') {
    next.blockInjection = true;
    next.blockSecrets = true;
    next.redactSecrets = true;
  } else if (next.mode === 'essential') {
    next.blockInjection = true;
    next.blockSecrets = true;
    next.redactSecrets = false;
  } else if (next.mode === 'off') {
    next.enabled = false;
  }
  if (next.mode !== 'off') next.enabled = true;
  fs.writeFileSync(POLICY_FILE, JSON.stringify(next, null, 2), { mode: 0o600 });
  return next;
}

function loadEvents() {
  try { return JSON.parse(fs.readFileSync(EVENTS_FILE, 'utf8')); } catch { return []; }
}

function appendEvent(ev) {
  const policy = loadPolicy();
  if (!policy.logEvents) return;
  ensure();
  const list = loadEvents();
  list.push({ ts: Date.now(), ...ev });
  if (list.length > MAX_EVENTS) list.splice(0, list.length - MAX_EVENTS);
  fs.writeFileSync(EVENTS_FILE, JSON.stringify(list, null, 2), { mode: 0o600 });
}

function recentEvents(limit = 30) {
  return loadEvents().slice(-Math.max(1, Math.min(limit, MAX_EVENTS)));
}

/** Pull user-visible text out of an LLM API request body. */
function extractPromptText(body) {
  if (!body) return '';
  let obj = body;
  if (typeof body === 'string') {
    try { obj = JSON.parse(body); } catch { return String(body).slice(0, 20000); }
  }
  const parts = [];
  if (typeof obj.prompt === 'string') parts.push(obj.prompt);
  if (typeof obj.input === 'string') parts.push(obj.input);
  if (Array.isArray(obj.messages)) {
    for (const m of obj.messages) {
      if (typeof m?.content === 'string') parts.push(m.content);
      else if (Array.isArray(m?.content)) {
        for (const c of m.content) {
          if (typeof c?.text === 'string') parts.push(c.text);
        }
      }
    }
  }
  if (Array.isArray(obj.contents)) {
    for (const c of obj.contents) {
      if (typeof c?.parts?.[0]?.text === 'string') parts.push(c.parts[0].text);
    }
  }
  return parts.join('\n').slice(0, 50000);
}

function detectInjection(text) {
  if (!text) return [];
  const hits = [];
  for (const p of INJECTION_PATTERNS) {
    if (p.re.test(text)) hits.push({ id: p.id, label: p.label });
  }
  return hits;
}

function redactSecrets(text, findings) {
  if (!text || !findings?.length) return text;
  let out = text;
  // Redact high-confidence token-like spans
  const spanRes = [
    /\bAKIA[0-9A-Z]{16}\b/g,
    /\b(?:ghp|ghs|gho|ghu)_[A-Za-z0-9]{36,}\b/g,
    /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    /\bsk-ant-[A-Za-z0-9_-]{16,}\b/g,
    /\bsk-[A-Za-z0-9]{32,}\b/g,
    /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
    /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
    /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g,
  ];
  for (const re of spanRes) out = out.replace(re, '[REDACTED_BY_KASBAH]');
  // Env-style KEY=secret lines
  out = out.replace(/^([A-Z_]{4,}(?:SECRET|KEY|TOKEN|PASS|PWD|AUTH|CREDENTIAL)[A-Z0-9_]*)=(?:"|')?[^\s"']+(?:"|')?$/gim,
    '$1=[REDACTED_BY_KASBAH]');
  return out;
}

/**
 * Inspect an outbound AI prompt. Pure decision — does not mutate the body.
 * @param {string|object} body raw request body or pre-extracted text
 * @returns {{ allow:boolean, action:string, reason:string, injection:Array, dlp:Array, redacted?:string, text:string }}
 */
function inspectPrompt(body) {
  const policy = loadPolicy();
  if (!policy.enabled || policy.mode === 'off') {
    return { allow: true, action: 'allow', reason: 'ai governance off', injection: [], dlp: [], text: '' };
  }
  const text = extractPromptText(body);
  if (!text) return { allow: true, action: 'allow', reason: 'empty prompt', injection: [], dlp: [], text: '' };

  const injection = detectInjection(text);
  const dlpHit = egress.classify(text);
  const dlp = dlpHit.found ? dlpHit.findings : [];
  let bio = { found: false, findings: [] };
  try { bio = require('./biometric-guard.js').scanText(text); } catch (_) {}

  let action = 'allow';
  let reason = 'ok';
  let allow = true;
  let redacted;

  if (bio.found && policy.blockInjection) {
    action = 'block';
    allow = false;
    reason = `biometric surveillance: ${bio.findings[0].label}`;
  } else if (injection.length && policy.blockInjection) {
    action = 'block';
    allow = false;
    reason = `prompt injection: ${injection[0].label}`;
  } else if (dlp.length && policy.blockSecrets && !policy.redactSecrets) {
    action = 'block';
    allow = false;
    reason = `secret in prompt: ${dlp[0].label}`;
  } else if (dlp.length && policy.redactSecrets) {
    action = 'redact';
    redacted = redactSecrets(text, dlp);
    reason = `redacted ${dlp.length} secret finding(s)`;
  } else if (injection.length) {
    action = 'warn';
    reason = `injection pattern (not blocked): ${injection[0].label}`;
  }

  if (action !== 'allow') {
    appendEvent({
      action, reason,
      injection: injection.map((i) => i.id),
      dlp: dlp.map((d) => d.id).slice(0, 8),
      mode: policy.mode,
    });
  }

  return { allow, action, reason, injection, dlp, biometric: bio.findings || [], redacted, text, dlpTiers: dlpHit.tiers || [] };
}

/** Apply redaction to the original body if needed. Returns new body string or null. */
function maybeRedactBody(rawBody, decision) {
  if (!decision || decision.action !== 'redact' || !decision.redacted) return null;
  try {
    const obj = typeof rawBody === 'string' ? JSON.parse(rawBody) : { ...rawBody };
    // Replace text-bearing fields with redacted full text only when structure is simple;
    // for messages arrays, replace each content string via redactSecrets.
    if (Array.isArray(obj.messages)) {
      obj.messages = obj.messages.map((m) => {
        if (typeof m?.content === 'string') {
          return { ...m, content: redactSecrets(m.content, decision.dlp) };
        }
        if (Array.isArray(m?.content)) {
          return {
            ...m,
            content: m.content.map((c) => (typeof c?.text === 'string' ? { ...c, text: redactSecrets(c.text, decision.dlp) } : c)),
          };
        }
        return m;
      });
    } else if (typeof obj.prompt === 'string') {
      obj.prompt = redactSecrets(obj.prompt, decision.dlp);
    } else if (typeof obj.input === 'string') {
      obj.input = redactSecrets(obj.input, decision.dlp);
    }
    return JSON.stringify(obj);
  } catch {
    return decision.redacted;
  }
}

/**
 * Shadow AI discovery — AI hosts in Kasbah browser history.
 * @param {Array} history browser-store historyList()
 */
function shadowAi(history = []) {
  const found = new Map();
  for (const h of history) {
    const url = String(h.url || '');
    let host = '';
    try { host = new URL(url).hostname.replace(/^www\./, ''); } catch { continue; }
    for (const ai of AI_HOSTS) {
      if (host === ai || host.endsWith('.' + ai)) {
        const prev = found.get(host) || { host, count: 0, last: 0 };
        prev.count++;
        prev.last = Math.max(prev.last, h.ts || 0);
        found.set(host, prev);
        break;
      }
    }
  }
  return [...found.values()].sort((a, b) => b.count - a.count);
}

function stats() {
  const events = loadEvents();
  const s = { total: events.length, blocked: 0, redacted: 0, warned: 0, injection: 0, dlp: 0 };
  for (const e of events) {
    if (e.action === 'block') s.blocked++;
    if (e.action === 'redact') s.redacted++;
    if (e.action === 'warn') s.warned++;
    if (e.injection?.length) s.injection++;
    if (e.dlp?.length) s.dlp++;
  }
  return s;
}

/** Standalone scan for the UI “try a prompt” box. */
function scanText(text) {
  const injection = detectInjection(text || '');
  const dlpHit = egress.classify(text || '');
  return {
    injection,
    dlp: dlpHit.found ? dlpHit.findings : [],
    dlpTiers: dlpHit.tiers || [],
    verdict: injection.length || dlpHit.found ? 'RISKY' : 'CLEAN',
  };
}

module.exports = {
  loadPolicy, savePolicy, defaultPolicy,
  inspectPrompt, maybeRedactBody,
  detectInjection, redactSecrets, extractPromptText,
  shadowAi, AI_HOSTS,
  stats, recentEvents, scanText,
  INJECTION_PATTERNS,
};
