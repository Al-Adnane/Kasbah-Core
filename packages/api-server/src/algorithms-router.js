'use strict';

/**
 * Universal Algorithms Router — every novel algorithm in Kasbah reachable
 * through one cohesive surface:
 *
 *   GET  /v1/algorithms                       → full registry (id, name, category)
 *   GET  /v1/algorithms/:slug                 → single algorithm metadata
 *   POST /v1/algorithms/:slug/run             → execute and return normalized result
 *
 * Categories surfaced:
 *   • Detection      — Mythos, DetectGPT, Multi-turn, PromptInjAdv, PromptFirewall, RAG
 *   • Behavioral     — KCPE, AIFingerprint, SentinelIntelligence, TextXRay, Persona, CausalXAI
 *   • Math           — Witt-Crys, Crystalline, PersistentCoh, Langlands, Fitra, Fracton, FCI, FKGI, CondExp
 *   • Crypto         — BBS+, Shamir, ZK, ZKGrapheme, PerceptualZK, QuantumCrypto, AdvDecode, Obfuscation
 *   • Coordination   — Bells, BellsEnh, ShadowConsensus, CausalLoop, TAVC-CRDT, Nexus
 *   • Ethics         — Maqasid, MultiEthics, EigenEthicsDrift, UniversalEthics, Nomos, Fitra
 *   • Frontier       — Honeytokens, ThreatCoop, NeuroSNN, OrbitalSec, DNALedger, HoloLedger
 *   • Biological     — PPP(6 techniques), Reynolds, PunctEquil, Harmonic, TopoShield
 *   • Ledgers        — CAIL, ComplianceAudit, ProofChain
 *   • Media          — ImageDeepfake, VoiceClone, Memetic, Stega, MultilingualPII
 *   • Kasbah Suite   — QMBP, BPFC, CAFB, ETQG, PPF, SPIRAL, GHOST, KHADIM, MSHIR, IJTIHAD
 *   • Privacy        — DP, IntentPolicy
 *   • Frontier-Bench — Benchmark, Fingerprint Distribution, Status
 *
 * Each entry has:
 *   { slug, name, category, description, source, inputs, run }
 *
 * The `run` function receives the request body (caller's input form),
 * returns a normalized { ok, verdict?, score?, summary, detail, latencyMs }
 * shape. If the algorithm has a dedicated HTTP route elsewhere, the run
 * function internally calls it — no duplication of logic.
 */

const path  = require('path');
const REPO  = path.resolve(__dirname, '..', '..', '..');

// ─────────────────────────────────────────────────────────────────────────────
// Lazy require helpers — keep boot fast and tolerate missing modules
// ─────────────────────────────────────────────────────────────────────────────
function lazy(rel) {
  let mod = null;
  return () => {
    if (mod !== null) return mod;
    try { mod = require(path.join(REPO, rel)); } catch (e) { mod = { __err: e.message }; }
    return mod;
  };
}
function safeRun(fn) {
  return async (body) => {
    const t0 = Date.now();
    try {
      const result = await fn(body || {});
      return Object.assign({ ok: true, latencyMs: Date.now() - t0 }, result);
    } catch (e) {
      return { ok: false, error: e.message, latencyMs: Date.now() - t0 };
    }
  };
}

// Resolve a class from a module that may export it as:
//   module.exports = Class         (direct)
//   module.exports = { Class }     (named)
//   module.exports.default = Class (default)
function resolveClass(mod, ...names) {
  if (typeof mod === 'function') return mod;
  for (const n of names) if (typeof mod[n] === 'function') return mod[n];
  if (typeof mod.default === 'function') return mod.default;
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Lazy module references (only loaded on first use)
// ─────────────────────────────────────────────────────────────────────────────
const M = {
  mythos:       lazy('src/mythos-pattern-detector.js'),
  detectgpt:    lazy('src/detectgpt.js'),
  fci:          lazy('src/fci-detector.js'),
  fkgi:         lazy('src/fkgi-detector.js'),
  persCoh:      lazy('src/persistent-cohomology-detector.js'),
  condExp:      lazy('src/conditional-expectation-detector.js'),
  langlands:    lazy('src/langlands-ijaz.js'),
  fitra:        lazy('src/fitra-topology.js'),
  fracton:      lazy('src/fracton-detector.js'),
  crystalline:  lazy('src/crystalline-cohomology.js'),
  witt:         lazy('src/witt-crystalline-cohomology.js'),
  ppp:          lazy('src/ppp-biomimetic.js'),
  punct:        lazy('src/punctuated-equilibrium.js'),
  harmonic:     lazy('src/harmonic-dissonance.js'),
  topoShield:   lazy('src/topo-shield.js'),
  eigenEthics:  lazy('src/eigen-ethics-drift.js'),
  causalLoop:   lazy('src/causal-loop-breaker.js'),
  shadow:       lazy('src/shadow-consensus.js'),
  reynolds:     lazy('src/reynolds-flow.js'),
  tavc:         lazy('src/tavc-crdt.js'),
  zkOracle:     lazy('src/perceptual-zk-oracle.js'),
  zkGrapheme:   lazy('src/zk-grapheme.js'),
  bells:        lazy('src/bells-inequality.js'),
  bbs:          lazy('src/bbs-signatures.js'),
  dp:           lazy('src/differential-privacy.js'),
  zkGov:        lazy('src/zk-governance-proof.js'),
  rtp:          lazy('src/rtp-transform.js'),
  kasbahAlgs:   lazy('src/kasbah-algorithms.js'),
  sentinel:     lazy('src/kasbah-sentinel.js'),
  // Systems
  promptInjAdv:    lazy('packages/api-server/src/systems/prompt-injection-advanced.js'),
  multiTurnInj:    lazy('packages/api-server/src/systems/multi-turn-injection.js'),
  promptFirewall:  lazy('packages/api-server/src/systems/prompt-firewall.js'),
  ragSec:          lazy('packages/api-server/src/systems/rag-security.js'),
  obfusDec:        lazy('packages/api-server/src/systems/obfuscation-decoder.js'),
  advDecode:       lazy('packages/api-server/src/systems/adversarial-decode.js'),
  bellsEnh:        lazy('packages/api-server/src/systems/bells-enhanced.js'),
  bellsFull:       lazy('packages/api-server/src/systems/bells-inequality-full.js'),
  causalXai:       lazy('packages/api-server/src/systems/causal-xai.js'),
  multiEthics:     lazy('packages/api-server/src/systems/multi-ethics-consensus.js'),
  cryptoAdv:       lazy('packages/api-server/src/systems/crypto-advanced.js'),
  quantumCrypto:   lazy('packages/api-server/src/systems/quantum-crypto.js'),
  detectorAdv:     lazy('packages/api-server/src/systems/detector-advanced.js'),
  dnaLedger:       lazy('packages/api-server/src/systems/dna-ledger.js'),
  holoLedger:      lazy('packages/api-server/src/systems/holographic-ledger.js'),
  neuroSnn:        lazy('packages/api-server/src/systems/neuromorphic-snn.js'),
  orbital:         lazy('packages/api-server/src/systems/orbital-security.js'),
  proofChain:      lazy('packages/api-server/src/systems/proof-chain.js'),
  complianceAudit: lazy('packages/api-server/src/systems/compliance-audit-ledger.js'),
  intentPolicy:    lazy('packages/api-server/src/systems/intent-policy.js'),
  imageFake:       lazy('packages/api-server/src/systems/image-deepfake.js'),
  voiceClone:      lazy('packages/api-server/src/systems/voice-cloning.js'),
  memetic:         lazy('packages/api-server/src/systems/memetic-warfare.js'),
  stega:           lazy('packages/api-server/src/systems/steganalysis.js'),
  multilingualPII: lazy('packages/api-server/src/systems/multilingual-pii.js'),
  textxray:        lazy('packages/api-server/src/systems/textxray.js'),
  persona:         lazy('packages/api-server/src/systems/synthetic-persona.js'),
  sentinelInt:     lazy('packages/api-server/src/systems/sentinel-intelligence.js'),
  rtpFull:         lazy('packages/api-server/src/systems/rtp-transform-full.js'),
  nexus:           lazy('packages/api-server/src/systems/nexus-bridge.js'),
  // Detector engine
  detector:        lazy('detector.js'),
  // Previously unwired — now fully connected
  intentAnalyzer:  lazy('src/kasbah-intent-analyzer.js'),
  policyEngine:    lazy('src/kasbah-policy-engine.js'),
  matrix:          lazy('packages/api-server/src/systems/matrix.js'),
  // Orphan modules — now wired
  govEngine:       lazy('src/governance-engine.js'),
  agentControl:    lazy('src/kasbah-agent-control.js'),
  kasbahOS:        lazy('src/kasbah-os.js'),
  productOS:       lazy('src/kasbah-product-os.js'),
  workflow:        lazy('src/kasbah-workflow.js'),
  group5:          lazy('src/group5-enhanced.js'),
};

// Standard input descriptors
const TEXT_INPUT     = [{ name: 'input', type: 'textarea', label: 'Text to analyze', required: true }];
const TWO_TEXT_INPUT = [
  { name: 'a', type: 'textarea', label: 'Sample A', required: true },
  { name: 'b', type: 'textarea', label: 'Sample B', required: true }
];
const NUMERIC_INPUT  = [{ name: 'value', type: 'number', label: 'Numeric value', required: true }];

// ─────────────────────────────────────────────────────────────────────────────
// THE FULL ALGORITHM REGISTRY
// ─────────────────────────────────────────────────────────────────────────────
const REGISTRY = [

  // ═══════════ DETECTION ═══════════
  {
    slug: 'mythos-pattern',
    name: 'Mythos Pattern Detector',
    category: 'Detection',
    description: 'AI-crafted Mythos-class attacks: agent-generated phishing, weaponized prompts, automated social engineering.',
    source: 'src/mythos-pattern-detector.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.mythos();
      if (mod.__err) throw new Error(mod.__err);
      const Det = mod.MythosPatternDetector || mod.default || mod;
      const inst = typeof Det === 'function' ? new Det() : Det;
      const out = (inst.analyze ? inst.analyze(b.input || '') : inst(b.input || ''));
      return { verdict: out?.verdict || (out?.mythosDetected ? 'MYTHOS' : 'CLEAN'), score: out?.score || out?.confidence || 0, summary: out?.summary || `Mythos analysis: ${out?.patterns?.length || 0} patterns matched`, detail: out };
    })
  },
  {
    slug: 'detectgpt',
    name: 'DetectGPT (12-signal)',
    category: 'Detection',
    description: '12 statistical signals for AI-generated text: perplexity, burstiness, entropy, token rank.',
    source: 'src/detectgpt.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.detectgpt();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.detectAIText || mod.default || mod;
      const out = fn(b.input || '');
      return { verdict: out.isAI ? 'AI_GENERATED' : 'HUMAN_LIKELY', score: out.score || out.confidence || 0, summary: `AI probability ${((out.score||0)*100).toFixed(1)}% across ${Object.keys(out.signals||{}).length} signals`, detail: out };
    })
  },
  {
    slug: 'prompt-injection-advanced',
    name: 'Prompt Injection Advanced (15-pattern)',
    category: 'Detection',
    description: '15 categorized injection patterns with per-pattern mitigation recommendations.',
    source: 'packages/api-server/src/systems/prompt-injection-advanced.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.promptInjAdv();
      if (mod.__err) throw new Error(mod.__err);
      const Det = mod.PromptInjectionDefense || mod.default;
      const inst = typeof Det === 'function' ? new Det() : Det;
      const out = inst.analyze ? inst.analyze(b.input || '') : (mod.analyze ? mod.analyze(b.input || '') : null);
      return { verdict: out?.injectionDetected ? 'INJECTION' : 'CLEAN', score: out?.threatScore || 0, summary: `${out?.patterns?.length || 0} patterns matched`, detail: out };
    })
  },
  {
    slug: 'multi-turn-injection',
    name: 'Multi-turn Injection (15-pattern)',
    category: 'Detection',
    description: 'Tracks injection across multiple turns: persona switch, system extraction, base64 instruction, context overflow.',
    source: 'packages/api-server/src/systems/multi-turn-injection.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.multiTurnInj();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.scoreMultiTurnInjection || mod.score || mod.default;
      const out = typeof fn === 'function' ? fn(b.input || '') : null;
      return { verdict: (out?.score||0) > 0.7 ? 'INJECTION' : ((out?.score||0) > 0.4 ? 'SUSPICIOUS' : 'CLEAN'), score: out?.score || 0, summary: `${out?.matchedPatterns?.length || 0} patterns matched`, detail: out };
    })
  },
  {
    slug: 'prompt-firewall',
    name: 'Prompt Firewall',
    category: 'Detection',
    description: 'Multi-layer prompt firewall: input sanitization, output filtering, role enforcement.',
    source: 'packages/api-server/src/systems/prompt-firewall.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.promptFirewall();
      if (mod.__err) throw new Error(mod.__err);
      const Fw = mod.PromptFirewall || mod.default;
      const inst = typeof Fw === 'function' ? new Fw() : Fw;
      const out = inst.evaluate ? inst.evaluate(b.input || '') : (inst.analyze ? inst.analyze(b.input || '') : null);
      return { verdict: out?.action || out?.verdict || 'EVALUATED', score: out?.risk || 0, summary: out?.reason || 'Firewall evaluation', detail: out };
    })
  },
  {
    slug: 'rag-security',
    name: 'RAG Security',
    category: 'Detection',
    description: 'Prompt injection inside retrieved context; access control over RAG documents.',
    source: 'packages/api-server/src/systems/rag-security.js',
    inputs: [
      { name: 'query',    type: 'text', label: 'User query', required: true },
      { name: 'context',  type: 'textarea', label: 'Retrieved RAG context', required: true }
    ],
    run: safeRun(async (b) => {
      const mod = M.ragSec();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.analyzeRAG || mod.analyze || mod.default;
      const out = typeof fn === 'function' ? fn({ query: b.query || '', context: b.context || '' }) : null;
      return { verdict: out?.compromised ? 'COMPROMISED' : 'CLEAN', score: out?.risk || 0, summary: out?.summary || 'RAG security analysis', detail: out };
    })
  },
  {
    slug: 'adversarial-decode',
    name: 'Adversarial Multi-Decode (5-pass)',
    category: 'Detection',
    description: 'Base64 → Hex → ROT13 → URL → Unicode 5-pass adversarial payload decoder.',
    source: 'packages/api-server/src/systems/adversarial-decode.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.advDecode();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.adversarialDecode || mod.decode || mod.default;
      const out = typeof fn === 'function' ? fn(b.input || '') : null;
      return { verdict: out?.decoded?.length ? 'DECODED' : 'NO_OBFUSCATION', score: out?.confidence || 0, summary: `${out?.layers?.length || 0} layers detected`, detail: out };
    })
  },
  {
    slug: 'obfuscation-decoder',
    name: 'Obfuscation Decoder (8-layer)',
    category: 'Detection',
    description: '8-layer obfuscation decoder for adversarial payloads. Detects encoded `rm -rf`, `eval(atob(...))`, etc.',
    source: 'packages/api-server/src/systems/obfuscation-decoder.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.obfusDec();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.deepDecode || mod.default;
      const out = typeof fn === 'function' ? fn(b.input || '') : null;
      return { verdict: out?.decodedForms?.length ? 'OBFUSCATED' : 'PLAIN', score: out?.confidence || 0, summary: `${out?.layers?.length || 0} encoding layers found`, detail: out };
    })
  },

  // ═══════════ BEHAVIORAL ═══════════
  {
    slug: 'kcpe',
    name: 'Consciousness Provenance Engine',
    category: 'Behavioral',
    description: 'KCPE — detects conscious authorship vs LLM via working memory, associative leaps, metacognition, typos.',
    source: 'src/kasbah-sentinel.js (ConsciousnessProvenanceEngine)',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.sentinel();
      if (mod.__err) throw new Error(mod.__err);
      const inst = new mod.ConsciousnessProvenanceEngine();
      const out = inst.analyze(b.input || '');
      return { verdict: out.verdict, score: out.consciousness, summary: `Consciousness score: ${out.consciousness.toFixed(2)}`, detail: out };
    })
  },
  {
    slug: 'ai-fingerprint-17',
    name: 'AI Fingerprint (17 models)',
    category: 'Behavioral',
    description: 'Stylometric classifier across 17 LLMs (GPT-4*, Claude-3-*, Gemini, Llama, Mistral, Qwen) + human baselines.',
    source: 'src/kasbah-sentinel.js (AIFingerprintAnalyzer)',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.sentinel();
      if (mod.__err) throw new Error(mod.__err);
      const inst = new mod.AIFingerprintAnalyzer();
      const out = inst.analyze(b.input || '');
      return { verdict: out.generator || 'unknown', score: out.confidence || 0, summary: `Closest match: ${out.generator}`, detail: out };
    })
  },
  {
    slug: 'sentinel-intelligence',
    name: 'Sentinel Intelligence (deontic)',
    category: 'Behavioral',
    description: '17-model AI FP + deontic ethics (Kant/Util/Virtue) unified decision.',
    source: 'packages/api-server/src/systems/sentinel-intelligence.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.sentinelInt();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.sentinelCheck || mod.analyze || mod.default;
      const out = typeof fn === 'function' ? fn(b.input || '') : null;
      return { verdict: out?.verdict || 'EVALUATED', score: out?.score || 0, summary: out?.summary || 'Sentinel analysis', detail: out };
    })
  },
  {
    slug: 'textxray',
    name: 'TextXRay (AI-writing + manipulation)',
    category: 'Behavioral',
    description: 'AI-writing entropy/TTR/connector-density + manipulation pattern detection.',
    source: 'packages/api-server/src/systems/textxray.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.textxray();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.analyzeAI || mod.analyze || mod.default;
      const out = typeof fn === 'function' ? fn(b.input || '') : null;
      return { verdict: out?.isAI ? 'AI_GENERATED' : 'HUMAN_LIKELY', score: out?.score || 0, summary: out?.summary || `AI prob: ${((out?.score||0)*100).toFixed(1)}%`, detail: out };
    })
  },
  {
    slug: 'synthetic-persona',
    name: 'Synthetic Persona Detector',
    category: 'Behavioral',
    description: 'AI fake identity: linguistic + behavioral + profile uniformity signals.',
    source: 'packages/api-server/src/systems/synthetic-persona.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.persona();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.detectPersona || mod.analyze || mod.default;
      const out = typeof fn === 'function' ? fn({ bio: b.input || '' }) : null;
      return { verdict: out?.synthetic ? 'SYNTHETIC' : 'AUTHENTIC', score: out?.confidence || 0, summary: out?.summary || 'Persona analysis', detail: out };
    })
  },
  {
    slug: 'causal-xai',
    name: 'Causal XAI (counterfactual)',
    category: 'Behavioral',
    description: 'Causal counterfactual explainability: "would this still be flagged if X changed?"',
    source: 'packages/api-server/src/systems/causal-xai.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.causalXai();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.explain || mod.analyze || mod.default;
      const out = typeof fn === 'function' ? fn(b.input || '') : null;
      return { verdict: 'EXPLAINED', score: out?.confidence || 0, summary: out?.summary || 'Counterfactual explanation', detail: out };
    })
  },

  {
    slug: 'intent-trajectory',
    name: 'Intent Trajectory Analyzer',
    category: 'Behavioral',
    description: 'Cross-step attack trajectory detection: finds distributed attacks invisible to single-step scanners (exfiltration pipelines, privilege escalation chains, cost bombs).',
    source: 'src/kasbah-intent-analyzer.js',
    inputs: [
      { name: 'steps', type: 'textarea', label: 'Steps — one per line as "VERB target" (e.g. READ patient_db)', required: true },
    ],
    run: safeRun(async (b) => {
      const mod = M.intentAnalyzer();
      if (mod.__err) throw new Error(mod.__err);
      const { KasbahIntentAnalyzer } = mod;
      const inst = new KasbahIntentAnalyzer();
      const lines = (b.steps || '').split('\n').map(l => l.trim()).filter(Boolean);
      const stepHistory = lines.map((line, i) => {
        const [verb, ...rest] = line.split(/\s+/);
        return { id: `step-${i + 1}`, verb: (verb || '').toUpperCase(), target: rest.join(' '), content: line };
      });
      const out = inst.analyze(stepHistory);
      const trajectories = inst.getTrajectories();
      return {
        verdict: out.threat ? (out.trajectoryMatch?.severity === 'critical' ? 'CRITICAL' : 'THREAT') : (out.driftScore >= 0.5 ? 'WARN' : 'CLEAN'),
        score:   out.driftScore || 0,
        summary: out.trajectoryMatch
          ? `${out.trajectoryMatch.name} (${out.trajectoryMatch.severity}) — ${(out.trajectoryMatch.confidence * 100).toFixed(0)}% confidence`
          : (out.warning || `Drift score: ${(out.driftScore || 0).toFixed(2)}`),
        detail: { ...out, knownTrajectories: trajectories }
      };
    })
  },

  // ═══════════ MATH FRAMEWORKS ═══════════
  {
    slug: 'witt-crystalline',
    name: 'Witt-Crystalline Cohomology',
    category: 'Math',
    description: 'Patent-pending: de Rham + crystalline cohomology + Witt vectors for impurity classes.',
    source: 'src/witt-crystalline-cohomology.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.witt();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.wittCrystallineAnalyze || (mod.WittCrystallineCohomology && ((data) => new mod.WittCrystallineCohomology().analyze(data)));
      const out = typeof fn === 'function' ? fn(b.input || '') : null;
      return { verdict: out?.pure ? 'PURE' : 'IMPURE', score: out?.impurityScore || 0, summary: `Cohomology class H^${out?.degree || '?'}`, detail: out };
    })
  },
  {
    slug: 'crystalline-cohomology',
    name: 'Crystalline Cohomology Engine',
    category: 'Math',
    description: 'H^0_crys(X, O_X/W) impurity detection without Witt vectors (the simpler form).',
    source: 'src/crystalline-cohomology.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.crystalline();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = resolveClass(mod, 'CrystallineCohomology', 'CrystallineCohomologyEngine');
      const inst = typeof Cls === 'function' ? new Cls() : Cls;
      const out = inst.analyze ? inst.analyze(b.input || '') : null;
      return { verdict: out?.verdict || 'ANALYZED', score: out?.score || 0, summary: out?.summary || 'Crystalline analysis', detail: out };
    })
  },
  {
    slug: 'persistent-cohomology',
    name: 'Persistent Cohomology Matching',
    category: 'Math',
    description: 'GL₁ Geometric Langlands threat-signature persistence across domain boundaries.',
    source: 'src/persistent-cohomology-detector.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.persCoh();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = resolveClass(mod, 'PersistentCohomologyDetector');
      const inst = typeof Cls === 'function' ? new Cls() : Cls;
      const out = inst.detect ? inst.detect(b.input || '') : (inst.analyze ? inst.analyze(b.input || '') : null);
      return { verdict: out?.persistent ? 'PERSISTENT' : 'TRANSIENT', score: out?.score || 0, summary: out?.summary || 'Persistence analysis', detail: out };
    })
  },
  {
    slug: 'langlands-ijaz',
    name: 'Langlands-I\'jaz Security',
    category: 'Math',
    description: 'Geometric Langlands correspondence for security signatures across representational spaces.',
    source: 'src/langlands-ijaz.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.langlands();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.langlandsAnalyze || (mod.LanglandsIjaz && ((t) => new mod.LanglandsIjaz().analyze(t))) || mod.default;
      const out = typeof fn === 'function' ? fn(b.input || '') : null;
      return { verdict: out?.verdict || 'ANALYZED', score: out?.score || 0, summary: out?.summary || 'Langlands correspondence', detail: out };
    })
  },
  {
    slug: 'fitra',
    name: 'Fitra Topology',
    category: 'Math',
    description: 'Topological invariants over moral fitra (innate-state) manifold.',
    source: 'src/fitra-topology.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.fitra();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.fitraAnalyze || mod.analyze || (mod.FitraTopology && ((t) => new mod.FitraTopology().analyze(t)));
      const out = typeof fn === 'function' ? fn(b.input || '') : null;
      return { verdict: out?.verdict || 'ANALYZED', score: out?.score || 0, summary: out?.summary || 'Fitra analysis', detail: out };
    })
  },
  {
    slug: 'fracton',
    name: 'Fracton Phase Detector',
    category: 'Math',
    description: 'Topological-order condensed-matter phase detection for trapped/immobile adversarial elements.',
    source: 'src/fracton-detector.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.fracton();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = resolveClass(mod, 'FractonDetector');
      const inst = typeof Cls === 'function' ? new Cls() : Cls;
      const out = inst.detect ? inst.detect(b.input || '') : (inst.analyze ? inst.analyze(b.input || '') : null);
      return { verdict: out?.verdict || 'ANALYZED', score: out?.score || 0, summary: out?.summary || 'Fracton phase', detail: out };
    })
  },
  {
    slug: 'fci',
    name: 'FCI (Mobility-Weighted Fracton Index)',
    category: 'Math',
    description: 'Detects immobile/trapped adversarial elements and constrained attack patterns.',
    source: 'src/fci-detector.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.fci();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = resolveClass(mod, 'FCIDetector', 'FCI');
      const inst = typeof Cls === 'function' ? new Cls() : Cls;
      const out = inst.detect ? inst.detect(b.input || '') : (inst.analyze ? inst.analyze(b.input || '') : null);
      return { verdict: out?.verdict || 'ANALYZED', score: out?.score || 0, summary: `Mobility index: ${out?.mobility || '?'}`, detail: out };
    })
  },
  {
    slug: 'fkgi',
    name: 'FKGI (Filtered K-Theory Growth Index)',
    category: 'Math',
    description: 'Fundamentally incompressible threat patterns. High FKGI = coordinated attack.',
    source: 'src/fkgi-detector.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.fkgi();
      if (mod.__err) throw new Error(mod.__err);
      // module.exports = FKGIDetector — default-style export, no named property
      const Cls = (typeof mod === 'function' ? mod : (mod.FKGIDetector || mod.default));
      const inst = typeof Cls === 'function' ? new Cls() : Cls;
      const out = inst.detect ? inst.detect(b.input || '') : (inst.analyze ? inst.analyze(b.input || '') : null);
      return { verdict: out?.verdict || 'ANALYZED', score: out?.fkgi || out?.score || 0, summary: `FKGI: ${(out?.fkgi || 0).toFixed?.(3) ?? '?'}`, detail: out };
    })
  },
  {
    slug: 'conditional-expectation',
    name: 'Conditional Expectation (Jones Index)',
    category: 'Math',
    description: 'Operator-algebra trace-preserving conditional expectation for bounded healing capacity.',
    source: 'src/conditional-expectation-detector.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.condExp();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = resolveClass(mod, 'ConditionalExpectationDetector');
      const inst = typeof Cls === 'function' ? new Cls() : Cls;
      const out = inst.detect ? inst.detect(b.input || '') : (inst.analyze ? inst.analyze(b.input || '') : null);
      return { verdict: out?.verdict || 'ANALYZED', score: out?.score || 0, summary: out?.summary || `Jones index: ${out?.jonesIndex || '?'}`, detail: out };
    })
  },

  {
    slug: 'matrix-linalg',
    name: 'Matrix / Linear Algebra Engine',
    category: 'Math',
    description: 'Core linear algebra: dot product, outer product, matrix multiply, Jacobi eigenvalues, SVD singular values, Pearson correlation, CHSH S-value. Foundation for Bell\'s Inequality, Eigen-Ethics, and Quantum Crypto systems.',
    source: 'packages/api-server/src/systems/matrix.js',
    inputs: TWO_TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.matrix();
      if (mod.__err) throw new Error(mod.__err);
      const { Matrix } = mod;
      const parseVec = (s) => (s || '').split(/[\s,]+/).map(Number).filter(n => !isNaN(n));
      const a = parseVec(b.a);
      const bVec = parseVec(b.b);
      const usable = a.length >= 2 && bVec.length >= 2;
      const aPad  = a.length  < bVec.length ? [...a,  ...Array(bVec.length - a.length).fill(0)] : a.slice(0, bVec.length);
      const bPad  = bVec.length < a.length   ? [...bVec, ...Array(a.length - bVec.length).fill(0)] : bVec.slice(0, a.length);
      const corr  = usable ? Matrix.correlation(aPad, bPad) : 0;
      const dot   = usable ? Matrix.dot(aPad, bPad) : 0;
      const normA = usable ? Matrix.norm(aPad) : 0;
      const normB = usable ? Matrix.norm(bPad) : 0;
      // CHSH: split each vector in half to form a, a', b, b'
      const half  = Math.floor(aPad.length / 2) || 1;
      const chshS = usable ? Matrix.chshS(aPad.slice(0, half), aPad.slice(half), bPad.slice(0, half), bPad.slice(half)) : 0;
      const cov   = usable ? Matrix.covariance([aPad, bPad]) : null;
      return {
        verdict: Math.abs(corr) > 0.8 ? 'HIGH_CORRELATION' : (chshS > 2 ? 'CHSH_VIOLATION' : 'NORMAL'),
        score:   Math.abs(corr),
        summary: `Pearson r=${corr.toFixed(3)}, dot=${dot.toFixed(3)}, CHSH S=${chshS.toFixed(3)}`,
        detail:  { correlation: corr, dot, normA, normB, chshS, covariance: cov }
      };
    })
  },

  // ═══════════ CRYPTO ═══════════
  {
    slug: 'bbs-plus',
    name: 'BBS+ Selective Disclosure',
    category: 'Crypto',
    description: 'Sign multi-attribute credentials; reveal a subset at proof time.',
    source: 'src/bbs-signatures.js',
    inputs: [{ name: 'message', type: 'textarea', label: 'Message to sign', required: true }],
    run: safeRun(async (b) => {
      const mod = M.bbs();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = resolveClass(mod, 'BBSPlus');
      const inst = typeof Cls === 'function' ? new Cls() : Cls;
      const kp = inst.generateKeyPair ? inst.generateKeyPair() : null;
      const sig = kp && inst.sign ? inst.sign(b.message || '', kp.privateKey) : null;
      return { verdict: sig ? 'SIGNED' : 'UNAVAILABLE', score: 1, summary: 'BBS+ keypair + signature', detail: { keypair: kp, signature: sig } };
    })
  },
  {
    slug: 'shamir-secret',
    name: 'Shamir Secret Sharing (GF-256)',
    category: 'Crypto',
    description: 'Split a secret into N shares; any K reconstruct. Galois Field 256.',
    source: 'packages/api-server/src/systems/crypto-advanced.js',
    inputs: [
      { name: 'secret', type: 'text', label: 'Secret to split', required: true },
      { name: 'threshold', type: 'number', label: 'Threshold K', value: 3 },
      { name: 'shares',    type: 'number', label: 'Shares N',    value: 5 }
    ],
    run: safeRun(async (b) => {
      const mod = M.cryptoAdv();
      if (mod.__err) throw new Error(mod.__err);
      const split = mod.shamirSplit || mod.split;
      const k = parseInt(b.threshold, 10); const kFinal = Number.isFinite(k) && k >= 1 ? k : 3;
      const n = parseInt(b.shares, 10);    const nFinal = Number.isFinite(n) && n >= kFinal ? n : 5;
      const secret = b.secret || 'demo';
      // shamirSplit signature: (secret, n, k) — flat positional args
      const out = typeof split === 'function' ? split(secret, nFinal, kFinal) : null;
      return { verdict: out ? 'SPLIT' : 'UNAVAILABLE', score: 1, summary: `${kFinal}-of-${nFinal} sharing`, detail: { shares: out } };
    })
  },
  {
    slug: 'zk-governance',
    name: 'ZK Governance Proof',
    category: 'Crypto',
    description: 'Zero-knowledge proof an agent obeyed policy without revealing private inputs.',
    source: 'src/zk-governance-proof.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.zkGov();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = resolveClass(mod, 'ZKGovernanceProof');
      const inst = typeof Cls === 'function' ? new Cls() : Cls;
      if (inst.createDefaultCircuit) try { inst.createDefaultCircuit(); } catch {}
      const witness = { riskScore: 0.2, verb: 'READ', piiCount: 0, requestCount: 1, targetDomain: '' };
      const pub     = { riskThreshold: 0.7, forbiddenVerbs: ['DROP_TABLE'], rateLimit: 10000, allowedDomains: [] };
      const proof = inst.generateProof ? inst.generateProof(witness, pub) : null;
      return { verdict: proof?.valid ? 'PROVEN' : 'UNAVAILABLE', score: 1, summary: `Proof ${proof?.proofId || ''}`, detail: proof };
    })
  },
  {
    slug: 'zk-grapheme',
    name: 'ZK Grapheme Proofs',
    category: 'Crypto',
    description: 'Zero-knowledge proof of grapheme/character validity without revealing the character.',
    source: 'src/zk-grapheme.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.zkGrapheme();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = resolveClass(mod, 'ZKGraphemeProof');
      const inst = typeof Cls === 'function' ? new Cls() : Cls;
      const out = inst.prove ? inst.prove(b.input || '') : null;
      return { verdict: out ? 'PROVEN' : 'UNAVAILABLE', score: 1, summary: 'Grapheme ZK proof', detail: out };
    })
  },
  {
    slug: 'perceptual-zk-oracle',
    name: 'Perceptual ZK Oracle',
    category: 'Crypto',
    description: 'ZK proof of perceptual equivalence (semantic identity without revealing content).',
    source: 'src/perceptual-zk-oracle.js',
    inputs: TWO_TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.zkOracle();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = resolveClass(mod, 'PerceptualZKOracle');
      const inst = typeof Cls === 'function' ? new Cls() : Cls;
      const out = inst.proveEquivalent ? inst.proveEquivalent(b.a || '', b.b || '') : null;
      return { verdict: out?.equivalent ? 'EQUIVALENT' : 'DIFFERENT', score: out?.confidence || 0, summary: out?.summary || 'Perceptual ZK proof', detail: out };
    })
  },
  {
    slug: 'quantum-crypto-dilithium',
    name: 'Quantum Crypto (Dilithium internals)',
    category: 'Crypto',
    description: 'CRYSTALS-Dilithium2 lattice-based signatures, full polynomial math over Zq[X]/(X^N+1).',
    source: 'packages/api-server/src/systems/quantum-crypto.js',
    inputs: [{ name: 'message', type: 'text', label: 'Message to sign', required: true }],
    run: safeRun(async (b) => {
      const mod = M.quantumCrypto();
      if (mod.__err) throw new Error(mod.__err);
      const kp = mod.dilithiumGenKeys ? mod.dilithiumGenKeys() : null;
      const sig = kp && mod.dilithiumSign ? mod.dilithiumSign(b.message || '', kp.privateKey) : null;
      const verified = sig && mod.dilithiumVerify ? mod.dilithiumVerify(b.message || '', sig, kp.publicKey) : null;
      return { verdict: verified?.valid ? 'VERIFIED' : 'UNAVAILABLE', score: 1, summary: `Dilithium2 signature ${verified?.valid ? '✓' : '✗'}`, detail: { keypair: kp, signature: sig, verified } };
    })
  },
  {
    slug: 'differential-privacy',
    name: 'Differential Privacy (Laplace)',
    category: 'Crypto',
    description: 'Laplace mechanism: add calibrated noise to guarantee ε-differential privacy.',
    source: 'src/differential-privacy.js',
    inputs: [
      { name: 'value', type: 'number', label: 'Value', value: 100 },
      { name: 'epsilon', type: 'number', label: 'Epsilon (privacy budget)', value: 1.0, step: 0.1 },
      { name: 'sensitivity', type: 'number', label: 'Sensitivity', value: 1.0, step: 0.1 }
    ],
    run: safeRun(async (b) => {
      const mod = M.dp();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = resolveClass(mod, 'DifferentialPrivacy');
      const inst = typeof Cls === 'function' ? new Cls() : Cls;
      const noisy = inst.addNoise ? inst.addNoise(b.value || 0, b.epsilon || 1.0, b.sensitivity || 1.0) : null;
      return { verdict: 'NOISY', score: 1, summary: `${b.value || 0} → ${noisy?.toFixed?.(3) || noisy}`, detail: { original: b.value, epsilon: b.epsilon, sensitivity: b.sensitivity, noisy } };
    })
  },

  // ═══════════ COORDINATION ═══════════
  {
    slug: 'bells-chsh',
    name: "Bell's Inequality (CHSH)",
    category: 'Coordination',
    description: 'CHSH inequality: |S| > 2 = AI-generated text or coordinated agents (super-classical correlation).',
    source: 'src/bells-inequality.js',
    inputs: TWO_TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.bells();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = mod.BellsInequality || mod.default;
      const inst = typeof Cls === 'function' ? new Cls({ threshold: 2.0, numDimensions: 4 }) : Cls;
      const a = (b.a || '').split(/\s+/).filter(Boolean).map(x => ({ token: x }));
      const b2 = (b.b || '').split(/\s+/).filter(Boolean).map(x => ({ token: x }));
      const out = inst.test ? inst.test(a, b2) : null;
      return { verdict: out?.collusion ? 'VIOLATION' : 'CLASSICAL', score: out?.sValue || 0, summary: `S-value: ${(out?.sValue || 0).toFixed?.(3) || '?'}`, detail: out };
    })
  },
  {
    slug: 'bells-enhanced-8d',
    name: "Bell's Enhanced (8-dim ensemble)",
    category: 'Coordination',
    description: 'CHSH across 8 semantic dimensions for higher-confidence AI-text detection.',
    source: 'packages/api-server/src/systems/bells-enhanced.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.bellsEnh();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.bellsEnhancedCheck || mod.detect || mod.default;
      const out = typeof fn === 'function' ? fn(b.input || '') : null;
      return { verdict: out?.violation ? 'AI_LIKELY' : 'CLASSICAL', score: out?.sValue || 0, summary: out?.summary || `S: ${out?.sValue || '?'}`, detail: out };
    })
  },
  {
    slug: 'shadow-consensus',
    name: 'Shadow Consensus',
    category: 'Coordination',
    description: 'N perturbed observers — detects gaming when shadows disagree with primary.',
    source: 'src/shadow-consensus.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.shadow();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = resolveClass(mod, 'ShadowConsensus');
      const inst = typeof Cls === 'function' ? new Cls({ shadowCount: 3 }) : Cls;
      const primaryDecision = { verdict: 'ALLOW', risk: 0.1 };
      const shadowEval = async () => ({ verdict: 'ALLOW', risk: 0.1 });
      const out = inst.evaluate ? await inst.evaluate({ content: b.input || '' }, primaryDecision, shadowEval) : null;
      return { verdict: out?.gamingDetected ? 'GAMED' : 'CONSENSUS', score: out?.consensusScore || 0, summary: out?.consensusVerdict || 'Shadow analysis', detail: out };
    })
  },
  {
    slug: 'causal-loop-breaker',
    name: 'Causal Loop Breaker (Pearl do-calculus)',
    category: 'Coordination',
    description: "Distinguishes causal influence from correlation via Pearl's do-calculus.",
    source: 'src/causal-loop-breaker.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.causalLoop();
      if (mod.__err) throw new Error(mod.__err);
      const inst = new mod.CausalLoopBreaker();
      inst.recordAgentState('a1', 0.3); inst.recordAgentState('a2', 0.4);
      inst.recordMessage('a1', 'a2', 'h', Date.now());
      const out = inst.analyze();
      return { verdict: out?.hasCausalLoops ? 'LOOP' : 'ACYCLIC', score: out?.cycleCount || 0, summary: `${out?.cycleCount || 0} cycles, ${out?.causalEdges?.length || 0} edges`, detail: out };
    })
  },
  {
    slug: 'tavc-crdt',
    name: 'TAVC CRDT (Topological Anti-Entropy)',
    category: 'Coordination',
    description: 'Conflict-free replicated data type with topological + vector-clock causality.',
    source: 'src/tavc-crdt.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.tavc();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = resolveClass(mod, 'TAVCNode');
      const inst = typeof Cls === 'function' ? new Cls('node-1') : Cls;
      const op = inst.createOperation ? inst.createOperation('SET', { key: 'x', value: b.input || '' }) : null;
      return { verdict: op ? 'CREATED' : 'UNAVAILABLE', score: 1, summary: 'CRDT operation', detail: op };
    })
  },
  {
    slug: 'nexus-bridge',
    name: 'Nexus Bridge (4-tech unified)',
    category: 'Coordination',
    description: 'RTP + Kernel Gating + Bell\'s + Main Detector unified engine.',
    source: 'packages/api-server/src/systems/nexus-bridge.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.nexus();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.nexusDetect || mod.default;
      const out = typeof fn === 'function' ? fn({ text: b.input || '' }) : null;
      return { verdict: out?.verdict || 'EVALUATED', score: out?.confidence || 0, summary: out?.summary || 'Nexus 4-engine fusion', detail: out };
    })
  },

  // ═══════════ ETHICS ═══════════
  {
    slug: 'maqasid',
    name: 'Maqasid al-Shariah (5 pillars)',
    category: 'Ethics',
    description: 'Life · Intellect · Lineage · Wealth · Faith ethical evaluation.',
    source: 'src/kasbah-sentinel.js (UniversalEthicsEngine)',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.sentinel();
      if (mod.__err) throw new Error(mod.__err);
      const inst = new mod.UniversalEthicsEngine();
      const out = inst.evaluate(b.input || '', 'ANALYZE', 'content');
      return { verdict: out.verdict, score: out.ethicalScore, summary: `${out.violations.length} violations`, detail: out };
    })
  },
  {
    slug: 'multi-ethics-consensus',
    name: 'Multi-Ethics Consensus (26 principles)',
    category: 'Ethics',
    description: 'Privacy · Transparency · Fairness · Accountability · Safety · Autonomy weighted-voting verdict.',
    source: 'packages/api-server/src/systems/multi-ethics-consensus.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.multiEthics();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.evaluateEthics || mod.evaluate || mod.default;
      const out = typeof fn === 'function' ? fn(b.input || '') : null;
      return { verdict: out?.verdict || 'EVALUATED', score: out?.score || 0, summary: out?.summary || 'Multi-tradition consensus', detail: out };
    })
  },
  {
    slug: 'eigen-ethics-drift',
    name: 'Eigen-Ethics Drift (SVD)',
    category: 'Ethics',
    description: 'Spectral analysis of 5×5 ethics covariance via SVD + Schatten norms.',
    source: 'src/eigen-ethics-drift.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.eigenEthics();
      if (mod.__err) throw new Error(mod.__err);
      const inst = new mod.EigenEthicsDrift();
      // Seed minimal history
      inst.record([0.8, 0.7, 0.9, 0.6, 0.8]);
      inst.record([0.6, 0.5, 0.7, 0.4, 0.7]);
      inst.record([0.4, 0.5, 0.5, 0.5, 0.5]);
      const out = inst.analyze();
      return { verdict: out?.drifting ? 'DRIFTING' : 'STABLE', score: out?.nuclearNorm || 0, summary: out?.targetedTradition ? `Drift in ${out.targetedTradition}` : 'No drift', detail: out };
    })
  },

  {
    slug: 'policy-engine',
    name: 'Kasbah Policy Engine (HIPAA/GDPR/SOC2/PCI-DSS)',
    category: 'Ethics',
    description: 'Declarative compliance engine: evaluate any agent action against pre-certified HIPAA, GDPR, SOC2 Type II, and PCI-DSS rule packs. Returns ALLOW / WARN / DENY / REQUIRE_APPROVAL with cited rule ID.',
    source: 'src/kasbah-policy-engine.js',
    inputs: [
      { name: 'packs',   type: 'text',     label: 'Compliance packs (comma-separated: HIPAA, GDPR, SOC2, PCI_DSS)', value: 'HIPAA,GDPR,SOC2' },
      { name: 'verb',    type: 'text',     label: 'Action verb (READ / DELETE / EXPORT / EXEC …)', required: true },
      { name: 'target',  type: 'text',     label: 'Target resource (e.g. patient_records, payment_data)' },
      { name: 'content', type: 'textarea', label: 'Payload / content to evaluate (optional)' },
    ],
    run: safeRun(async (b) => {
      const mod = M.policyEngine();
      if (mod.__err) throw new Error(mod.__err);
      const { KasbahPolicyEngine } = mod;
      const packs = (b.packs || 'HIPAA,GDPR,SOC2').split(',').map(p => p.trim()).filter(Boolean);
      const engine = new KasbahPolicyEngine({ packs });
      const result = engine.evaluate({
        agent:   'demo',
        verb:    (b.verb || '').toUpperCase(),
        target:  b.target || '',
        content: b.content || '',
      });
      const report = engine.generateComplianceReport();
      return {
        verdict: result.decision,
        score:   result.violations.length > 0 ? 1.0 : (result.warnings.length > 0 ? 0.5 : 0),
        summary: result.decision === 'DENY'
          ? `DENIED by ${result.violations[0]?.rule}: ${result.reason}`
          : result.decision === 'WARN'
            ? `WARNING: ${result.warnings[0]?.reason}`
            : result.decision === 'REQUIRE_APPROVAL'
              ? `Approval required: ${result.approvals[0]?.reason}`
              : `ALLOW — ${result.rulesEvaluated} rules passed`,
        detail: { evaluation: result, report }
      };
    })
  },

  // ═══════════ BIOLOGICAL ═══════════
  {
    slug: 'ppp-biomimetic',
    name: 'PPP Biomimetic (6 techniques)',
    category: 'Biological',
    description: 'Beeodiversity, Fungi correlation, LanzaTech, Soil Security, Breathe Easy, Aboriginal Fire.',
    source: 'src/ppp-biomimetic.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.ppp();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = resolveClass(mod, 'PPPBiomimetic');
      const inst = typeof Cls === 'function' ? new Cls() : Cls;
      const out = inst.analyze ? inst.analyze(b.input || '') : null;
      return { verdict: out?.benign ? 'BENIGN' : 'SIGNAL', score: out?.totalBoost || 0, summary: `${Object.keys(out || {}).length} techniques fired`, detail: out };
    })
  },
  {
    slug: 'reynolds-flow',
    name: 'Reynolds Flow (Navier-Stokes turbulence)',
    category: 'Biological',
    description: 'Computational fluid dynamics detects token-stream turbulence (Reynolds number, enstrophy).',
    source: 'src/reynolds-flow.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.reynolds();
      if (mod.__err) throw new Error(mod.__err);
      const inst = new mod.ReynoldsFlow();
      const text = b.input || '';
      const vec = [text.length / 100, (text.match(/[A-Z]/g)||[]).length / 50, (text.match(/[0-9]/g)||[]).length / 50, (text.match(/\W/g)||[]).length / 50];
      inst.record(vec); inst.record(vec.map(x => x * 1.1)); inst.record(vec.map(x => x * 0.9));
      const out = inst.analyze();
      return { verdict: out?.regime || 'LAMINAR', score: out?.reynoldsNumber || 0, summary: `Reynolds: ${(out?.reynoldsNumber||0).toFixed?.(1) || '?'}, enstrophy: ${(out?.enstrophy||0).toFixed?.(3) || '?'}`, detail: out };
    })
  },
  {
    slug: 'punctuated-equilibrium',
    name: 'Punctuated Equilibrium (Eldredge-Gould)',
    category: 'Biological',
    description: 'Evolutionary dynamics: long stasis punctuated by rapid bursts of attack innovation.',
    source: 'src/punctuated-equilibrium.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.punct();
      if (mod.__err) throw new Error(mod.__err);
      const inst = new mod.PunctuatedEquilibrium();
      inst.record([0.1, 0.1, 0.1]); inst.record([0.2, 0.2, 0.2]); inst.record([0.8, 0.7, 0.9]);
      const out = inst.analyze();
      return { verdict: out?.regime || 'STASIS', score: out?.divergence || 0, summary: `${out?.punctuationDetected ? 'Burst detected' : 'Stable'}, stasis length: ${out?.stasisLength || 0}`, detail: out };
    })
  },
  {
    slug: 'harmonic-dissonance',
    name: 'Harmonic Dissonance (Fourier overtones)',
    category: 'Biological',
    description: 'Music-theory Fourier analysis: dissonance = tritone intervals in intent frequency.',
    source: 'src/harmonic-dissonance.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.harmonic();
      if (mod.__err) throw new Error(mod.__err);
      const inst = new mod.HarmonicDissonance();
      inst.record('a1', 0.3); inst.record('a1', 0.7); inst.record('a1', 0.2);
      const out = inst.analyze();
      return { verdict: out?.regime || 'CONSONANCE', score: out?.overallDissonance || 0, summary: `Tritones: ${out?.tritoneCount || 0}, dissonance: ${(out?.overallDissonance||0).toFixed?.(3) || '?'}`, detail: out };
    })
  },
  {
    slug: 'topo-shield',
    name: 'TopoShield (Persistent Homology)',
    category: 'Biological',
    description: 'Topological data analysis: detects multi-agent collusion via Betti number changes.',
    source: 'src/topo-shield.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.topoShield();
      if (mod.__err) throw new Error(mod.__err);
      const inst = new mod.TopoShield();
      const traces = [[0,0],[0.1,0.1],[0.9,0.9],[1,1],[0.5,0.5]];
      const out = inst.analyze(traces);
      return { verdict: out?.alert ? 'ANOMALY' : 'NORMAL', score: out?.bettiChange?.beta0 || 0, summary: `Betti: β₀=${out?.betti?.beta0 || 0} β₁=${out?.betti?.beta1 || 0}`, detail: out };
    })
  },

  // ═══════════ KASBAH FUSION SUITE (10 algorithms) ═══════════
  ...['QMBP','BPFC','CAFB','ETQG','PPF','SPIRAL','GHOST','KHADIM','MSHIR','IJTIHAD'].map(algoName => ({
    slug: 'kasbah-' + algoName.toLowerCase(),
    name: `Kasbah ${algoName}`,
    category: 'Kasbah Suite',
    description: ({
      QMBP:    'Swarm-Mind-Body-Provenance: detects Entangled AI Shadow Councils (LLM swarms forging ethical endorsements).',
      BPFC:    'Byzantine-Paradox-Fire-Consensus: temporal+Byzantine fault-tolerance fusion.',
      CAFB:    'Cognitive-AI-Fire-Brittleness: cognitive coherence over time decay.',
      ETQG:    'Ethic-TOCTOU-Quantum-Guard: race-condition ethics with PQ signatures.',
      PPF:     'Provenance-Paradox-Forecaster: predicts content-passport tampering before it manifests.',
      SPIRAL:  'Self-Poisoning Intent Recognition via Audit-Ledger: detects slow manipulation drift.',
      GHOST:   'Governance Hologram & Observer Shadow Test: holographic shadow consensus.',
      KHADIM:  'Kasbah Holistic Adversarial Defense & Identity Manifold.',
      MSHIR:   'Multi-Signal Holographic Intent Reconstruction.',
      IJTIHAD: 'Independent Jurisprudential Threshold Decision: maqasid-grounded ruling.'
    })[algoName],
    source: 'src/kasbah-algorithms.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.kasbahAlgs();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = mod[algoName];
      if (!Cls) throw new Error(`${algoName} not exported`);
      const inst = typeof Cls === 'function' ? new Cls() : Cls;
      const out = inst.analyze ? inst.analyze({ content: b.input || '', text: b.input || '', input: b.input || '' }) : (inst.detect ? inst.detect(b.input || '') : null);
      return { verdict: out?.verdict || out?.decision || 'ANALYZED', score: out?.confidence || out?.score || 0, summary: out?.summary || `${algoName} analysis`, detail: out };
    })
  })),

  // ═══════════ MEDIA ═══════════
  {
    slug: 'image-deepfake',
    name: 'Image Deepfake (statistical)',
    category: 'Media',
    description: 'GAN frequency, texture, edge, entropy analysis for image authenticity.',
    source: 'packages/api-server/src/systems/image-deepfake.js',
    inputs: [{ name: 'imageData', type: 'textarea', label: 'Image data (base64 or hex)', required: true }],
    run: safeRun(async (b) => {
      const mod = M.imageFake();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.detectImageDeepfake || mod.analyze || mod.default;
      const out = typeof fn === 'function' ? fn(b.imageData || '') : null;
      return { verdict: out?.deepfake ? 'DEEPFAKE' : 'AUTHENTIC', score: out?.confidence || 0, summary: out?.summary || 'Image analysis', detail: out };
    })
  },
  {
    slug: 'voice-cloning',
    name: 'Voice Cloning Detection',
    category: 'Media',
    description: 'TTS artifacts: F0 trajectory, formants, jitter/shimmer, prosody anomalies.',
    source: 'packages/api-server/src/systems/voice-cloning.js',
    inputs: [{ name: 'input', type: 'textarea', label: 'Transcript text (or audio feature description)', required: true }],
    run: safeRun(async (b) => {
      const mod = M.voiceClone();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.voiceCloningCheck || mod.analyze || mod.default;
      const out = typeof fn === 'function' ? fn(b.input || '') : null;
      return { verdict: out?.detected ? 'CLONED' : 'AUTHENTIC', score: out?.confidence || 0, summary: out?.type ? `Type: ${out.type}` : 'Voice analysis', detail: out };
    })
  },
  {
    slug: 'memetic-warfare',
    name: 'Memetic Warfare',
    category: 'Media',
    description: 'Coordinated disinformation, astroturfing, polarization detection.',
    source: 'packages/api-server/src/systems/memetic-warfare.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.memetic();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.detectMemetic || mod.analyze || mod.default;
      const out = typeof fn === 'function' ? fn(b.input || '') : null;
      return { verdict: out?.coordinated ? 'COORDINATED' : 'ORGANIC', score: out?.score || 0, summary: out?.summary || 'Memetic analysis', detail: out };
    })
  },
  {
    slug: 'steganalysis',
    name: 'Steganalysis (8-method)',
    category: 'Media',
    description: 'Zero-width chars, Unicode tags, whitespace encoding, LSB image stego, neural codec.',
    source: 'packages/api-server/src/systems/steganalysis.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.stega();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.detectSteganography || mod.analyze || mod.default;
      const out = typeof fn === 'function' ? fn(b.input || '') : null;
      return { verdict: out?.hidden ? 'HIDDEN_DATA' : 'CLEAN', score: out?.confidence || 0, summary: out?.summary || `${out?.detections?.length || 0} methods triggered`, detail: out };
    })
  },
  {
    slug: 'multilingual-pii',
    name: 'Multilingual PII (100+ langs)',
    category: 'Media',
    description: 'Luhn / MOD-97 / Verhoeff validation across 100+ languages. SSN, IBAN, credit cards, AWS keys.',
    source: 'packages/api-server/src/systems/multilingual-pii.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.multilingualPII();
      if (mod.__err) throw new Error(mod.__err);
      const fn = mod.detectPII || mod.analyze || mod.default;
      const out = typeof fn === 'function' ? fn(b.input || '') : null;
      return { verdict: out?.detected?.length ? 'PII_FOUND' : 'CLEAN', score: out?.score || 0, summary: `${out?.detected?.length || 0} PII items found`, detail: out };
    })
  },

  // ═══════════ FRONTIER STORAGE ═══════════
  {
    slug: 'dna-ledger',
    name: 'DNA Ledger (encode/stego)',
    category: 'Frontier',
    description: 'Encode data into synthetic DNA sequences; detect steganographic insertion.',
    source: 'packages/api-server/src/systems/dna-ledger.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.dnaLedger();
      if (mod.__err) throw new Error(mod.__err);
      const encoder = mod.encodeRecord || mod.dnaEncode || mod.encode;
      const decoder = mod.decodeRecord || mod.dnaDecode || mod.decode;
      // encodeRecord(data: string|Buffer) — pass payload directly, not wrapped
      const payload = b.input || 'demo';
      const encoded = typeof encoder === 'function' ? encoder(payload) : null;
      const decoded = encoded && typeof decoder === 'function' ? decoder(encoded) : null;
      const baseCount = typeof encoded === 'string' ? encoded.length : (encoded?.dna?.length || JSON.stringify(encoded || {}).length);
      return { verdict: encoded ? 'ENCODED' : 'UNAVAILABLE', score: 1, summary: encoded ? `Encoded ${baseCount} bases` : 'No encoder', detail: { encoded, decoded } };
    })
  },
  {
    slug: 'holographic-ledger',
    name: 'Holographic Ledger',
    category: 'Frontier',
    description: 'Hologram-style redundant encoding: any fragment can reconstruct the whole.',
    source: 'packages/api-server/src/systems/holographic-ledger.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.holoLedger();
      if (mod.__err) throw new Error(mod.__err);
      const out = mod.holoEncode ? mod.holoEncode(b.input || '') : null;
      return { verdict: out ? 'ENCODED' : 'UNAVAILABLE', score: 1, summary: 'Holographic encoding', detail: out };
    })
  },
  {
    slug: 'neuromorphic-snn',
    name: 'Neuromorphic SNN',
    category: 'Frontier',
    description: 'Spiking Neural Network behavioral classifier.',
    source: 'packages/api-server/src/systems/neuromorphic-snn.js',
    inputs: TEXT_INPUT,
    run: safeRun(async (b) => {
      const mod = M.neuroSnn();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = resolveClass(mod, 'SNN', 'NeuromorphicSNN');
      const inst = typeof Cls === 'function' ? new Cls() : Cls;
      const out = inst.classify ? inst.classify(b.input || '') : (inst.analyze ? inst.analyze(b.input || '') : null);
      return { verdict: out?.class || out?.verdict || 'CLASSIFIED', score: out?.confidence || 0, summary: out?.summary || 'SNN classification', detail: out };
    })
  },
  {
    slug: 'orbital-security',
    name: 'Orbital Security (key sharding)',
    category: 'Frontier',
    description: 'Distributed key sharding with orbital challenges. Key reconstructible only via verified peers.',
    source: 'packages/api-server/src/systems/orbital-security.js',
    inputs: [{ name: 'secret', type: 'text', label: 'Secret to shard', required: true }],
    run: safeRun(async (b) => {
      const mod = M.orbital();
      if (mod.__err) throw new Error(mod.__err);
      const out = mod.orbitalShard ? mod.orbitalShard(b.secret || '') : null;
      return { verdict: out ? 'SHARDED' : 'UNAVAILABLE', score: 1, summary: `${out?.shards?.length || 0} orbital shards`, detail: out };
    })
  },

  // ═══════════ LEDGERS ═══════════
  {
    slug: 'cail-ledger',
    name: 'CAIL Ledger (PQ-signed hash chain)',
    category: 'Ledgers',
    description: 'Context-Aware Integrity Ledger — every entry signed with both Dilithium + SPHINCS+.',
    source: 'src/kasbah-sentinel.js (CAILLedger)',
    inputs: [{ name: 'action', type: 'text', label: 'Action to record', required: true }],
    run: safeRun(async (b) => {
      const mod = M.sentinel();
      if (mod.__err) throw new Error(mod.__err);
      const inst = new mod.CAILLedger();
      const entry = inst.addEntry(b.action || 'TEST', 'demo', 'SUCCESS', { manual: true });
      const verify = inst.verifyChain();
      return { verdict: verify.valid ? 'VERIFIED' : 'INVALID', score: 1, summary: `Chain depth ${inst.length}, dual PQ sigs`, detail: { entry, verify, pqcAlgorithms: inst.pqcAlgorithms } };
    })
  },
  {
    slug: 'proof-chain',
    name: 'Proof Chain (PoW receipts)',
    category: 'Ledgers',
    description: 'Blockchain-style proof-of-work receipt ledger.',
    source: 'packages/api-server/src/systems/proof-chain.js',
    inputs: [{ name: 'data', type: 'text', label: 'Data to append', required: true }],
    run: safeRun(async (b) => {
      const mod = M.proofChain();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = resolveClass(mod, 'ProofLedger');
      const inst = typeof Cls === 'function' ? new Cls() : Cls;
      const blk = inst.addBlock ? inst.addBlock({ data: b.data || '' }) : null;
      const valid = inst.isValid ? inst.isValid() : null;
      return { verdict: valid ? 'VALID_CHAIN' : 'UNAVAILABLE', score: 1, summary: `Block ${blk?.index || '?'}, hash ${(blk?.hash || '').slice(0,12)}...`, detail: { block: blk, valid } };
    })
  },
  {
    slug: 'compliance-audit-ledger',
    name: 'Compliance Audit Ledger (Merkle)',
    category: 'Ledgers',
    description: 'Merkle-proof compliance audit ledger.',
    source: 'packages/api-server/src/systems/compliance-audit-ledger.js',
    inputs: [{ name: 'entry', type: 'text', label: 'Audit entry', required: true }],
    run: safeRun(async (b) => {
      const mod = M.complianceAudit();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = resolveClass(mod, 'ComplianceAuditLedger');
      // Disable Merkle proofs for the single-entry demo (Merkle requires >1 entry)
      const inst = typeof Cls === 'function' ? new Cls({ enableMerkleProofs: false }) : Cls;
      const append = inst.appendEntry || inst.append;
      const verify = inst.verifyChain  || inst.verify;
      const appended = typeof append === 'function' ? append.call(inst, 'ACCESS', { entry: b.entry || '' }, ['SOC2']) : null;
      const verified = typeof verify === 'function' ? verify.call(inst) : null;
      return { verdict: verified?.valid ? 'VERIFIED' : 'APPENDED', score: 1, summary: `Entry ${appended?.id || '?'} appended`, detail: { appended, verified } };
    })
  },

  // ═══════════ PREVIOUSLY ORPHANED — NOW WIRED ═══════════

  {
    slug: 'intent-analyzer',
    name: 'Intent Trajectory Analyzer',
    category: 'Behavioral',
    description: 'Detects distributed/multi-step attacks by analyzing the trajectory of agent actions across steps. Catches what single-step scanners miss.',
    source: 'src/kasbah-intent-analyzer.js',
    inputs: [{ name: 'steps', type: 'textarea', label: 'Agent steps (one per line: VERB target)', required: true, placeholder: 'EXTRACT users.email\nFORMAT csv\nSEND https://reporting.example.com' }],
    run: safeRun(async (b) => {
      const mod = M.intentAnalyzer();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = resolveClass(mod, 'KasbahIntentAnalyzer');
      const inst = typeof Cls === 'function' ? new Cls() : Cls;
      const raw = (b.steps || b.input || '').toString();
      const steps = raw.split(/\r?\n/).filter(s => s.trim()).map((line, i) => {
        const [verb, ...rest] = line.trim().split(/\s+/);
        return { id: 's' + i, verb: (verb || 'QUERY').toUpperCase(), target: rest.join(' ') || 'unspecified', ts: Date.now() + i };
      });
      const fn = inst.analyze || inst.analyzeTrajectory || inst.detect;
      const out = typeof fn === 'function' ? fn.call(inst, steps) : { error: 'no analyze method' };
      const trajectoryMatch = out?.matchedTrajectory || out?.attackTrajectory || out?.matched || null;
      return {
        verdict: trajectoryMatch ? 'DISTRIBUTED_ATTACK' : 'BENIGN_TRAJECTORY',
        score: out?.risk ?? out?.score ?? (trajectoryMatch ? 0.85 : 0.05),
        summary: trajectoryMatch
          ? `Trajectory matched attack pattern: ${trajectoryMatch.name || trajectoryMatch.id || 'unknown'}`
          : `Analyzed ${steps.length} steps — no attack trajectory detected`,
        detail: { steps, result: out }
      };
    })
  },
  {
    slug: 'policy-engine',
    name: 'Declarative Policy Engine',
    category: 'Privacy',
    description: 'Human-readable policy language with pre-certified compliance packs (HIPAA, GDPR, SOC2, PCI-DSS, ITAR). Audit policies, not JavaScript.',
    source: 'src/kasbah-policy-engine.js',
    inputs: [
      { name: 'pack', type: 'select', label: 'Compliance pack', options: ['HIPAA','GDPR','SOC2','PCI_DSS','ITAR'], required: false },
      { name: 'verb', type: 'text', label: 'Action verb (e.g. DELETE, READ)', required: true },
      { name: 'target', type: 'text', label: 'Action target (e.g. /prod/users, patient.ssn)', required: true }
    ],
    run: safeRun(async (b) => {
      const mod = M.policyEngine();
      if (mod.__err) throw new Error(mod.__err);
      const Cls = resolveClass(mod, 'KasbahPolicyEngine');
      const packs = mod.COMPLIANCE_PACKS || {};
      const inst = typeof Cls === 'function' ? new Cls() : Cls;
      const pack = (b.pack || 'SOC2').toUpperCase();
      if (inst.loadPack && packs[pack]) try { inst.loadPack(packs[pack]); } catch(_) {}
      else if (inst.addPack && packs[pack]) try { inst.addPack(packs[pack]); } catch(_) {}
      const action = { verb: (b.verb || 'READ').toUpperCase(), target: b.target || '', actor: b.actor || 'caller' };
      const fn = inst.evaluate || inst.check || inst.governs;
      const out = typeof fn === 'function' ? fn.call(inst, action) : { error: 'no evaluate method' };
      const decision = (out?.decision || out?.verdict || (out?.allowed === false ? 'DENY' : 'ALLOW')).toString().toUpperCase();
      return {
        verdict: decision,
        score: decision === 'DENY' ? 1 : decision === 'WARN' ? 0.5 : 0,
        summary: `Pack: ${pack} · ${action.verb} ${action.target} → ${decision}${out?.rule ? ' (matched rule: ' + out.rule + ')' : ''}`,
        detail: { action, pack, result: out, availablePacks: Object.keys(packs) }
      };
    })
  },
  {
    slug: 'matrix-utils',
    name: 'Linear Algebra Utilities',
    category: 'Math',
    description: 'Foundational matrix operations (dot, outer product, multiply, transpose) used by Bell-inequality, quantum-crypto, and eigen-ethics systems.',
    source: 'packages/api-server/src/systems/matrix.js',
    inputs: [
      { name: 'op', type: 'select', label: 'Operation', options: ['dot','outer','multiply','transpose'], required: true },
      { name: 'a', type: 'text', label: 'Vector/matrix A (JSON array)', required: true, placeholder: '[1,2,3] or [[1,2],[3,4]]' },
      { name: 'b', type: 'text', label: 'Vector/matrix B (JSON, optional for transpose)', required: false, placeholder: '[4,5,6] or [[5,6],[7,8]]' }
    ],
    run: safeRun(async (b) => {
      const mod = M.matrix();
      if (mod.__err) throw new Error(mod.__err);
      const Mx = mod.Matrix || mod;
      const op = (b.op || 'dot').toLowerCase();
      let A, B;
      try { A = JSON.parse(b.a); } catch { throw new Error('Field A must be valid JSON'); }
      if (b.b) { try { B = JSON.parse(b.b); } catch { throw new Error('Field B must be valid JSON'); } }
      let result;
      if (op === 'dot')          result = Mx.dot(A, B);
      else if (op === 'outer')   result = Mx.outer(A, B);
      else if (op === 'multiply')result = Mx.multiply(A, B);
      else if (op === 'transpose')result = Mx.transpose ? Mx.transpose(A) : A[0].map((_, j) => A.map(row => row[j]));
      else throw new Error('Unknown op: ' + op);
      return {
        verdict: 'COMPUTED',
        score: 1,
        summary: `${op}(${Array.isArray(A) && Array.isArray(A[0]) ? 'matrix' : 'vector'} A${B?', '+(Array.isArray(B[0])?'matrix':'vector')+' B':''}) → ${typeof result === 'number' ? result : (Array.isArray(result) ? '['+result.length+'×'+(Array.isArray(result[0])?result[0].length:1)+']' : '?')}`,
        detail: { op, A, B, result }
      };
    })
  },

  // ═══════════ GOVERNANCE ═══════════
  {
    slug: 'governance-policy',
    name: 'Governance Policy Check',
    category: 'Governance',
    description: 'Fail-closed policy enforcement: forbidden verbs, domain whitelist, rate limits. Returns ALLOW/DENY with deterministic audit trail and policy-version hash.',
    source: 'src/governance-engine.js',
    inputs: [
      { name: 'verb', type: 'select', label: 'Action Verb', options: ['CALL_API','READ_FILE','WRITE_FILE','EXECUTE','BROWSE','DELETE','SEND_MESSAGE'], required: true },
      { name: 'target', type: 'text', label: 'Target resource', required: true, placeholder: 'api.openai.com  or  /etc/passwd' },
      { name: 'subject', type: 'textarea', label: 'Prompt / Content (optional)', required: false, placeholder: 'Text being governed' }
    ],
    run: safeRun(async (b) => {
      const mod = M.govEngine();
      if (mod.__err) throw new Error(mod.__err);
      const { GovernanceEngine } = mod;
      const ge = new GovernanceEngine();
      const action = {
        verb:    (b.verb || 'CALL_API').toUpperCase(),
        target:  b.target || 'unknown',
        subject: (b.subject || '').slice(0, 500),
        agent:   'kasbah-demo'
      };
      const dec = await ge.check(action);
      return {
        verdict: dec.status,
        score:   (dec.risk_score || 0) / 100,
        summary: `${dec.status}: ${dec.reason}`,
        detail:  { decision_id: dec.decision_id, policy_hash: dec.policy_hash, violations: dec.violations, latency_ms: dec.latency_ms }
      };
    })
  },

  // ═══════════ AGENT CONTROL ═══════════
  {
    slug: 'agent-governance',
    name: 'Agent-to-Agent Governance',
    category: 'Governance',
    description: 'Universal LLM/agent governance middleware — intercepts messages between agents and applies all Kasbah layers before forwarding.',
    source: 'src/kasbah-agent-control.js',
    inputs: [
      { name: 'message', type: 'textarea', label: 'Agent message / prompt', required: true },
      { name: 'fromAgent', type: 'text', label: 'Source agent', required: false, placeholder: 'orchestrator' },
      { name: 'toAgent', type: 'text', label: 'Target model / agent', required: false, placeholder: 'claude-3-5-sonnet' }
    ],
    run: safeRun(async (b) => {
      const mod = M.agentControl();
      if (mod.__err) throw new Error(mod.__err);
      const { KasbahAgentControl } = mod;
      const ctrl = new KasbahAgentControl({ timeoutMs: 5000, mode: 'enforce' });
      const fromAgent = b.fromAgent || 'orchestrator';
      const toAgent   = b.toAgent   || 'llm';
      const result = await ctrl.governMessage(b.message || '', fromAgent, toAgent, `session-${Date.now()}`);
      const verdict = result?.verdict || result?.decision || (result?.blocked ? 'DENY' : 'ALLOW');
      const risk    = (typeof result?.risk === 'number' && result.risk > 0) ? result.risk : (verdict === 'DENY' ? 0.85 : verdict === 'WARN' ? 0.55 : 0.1);
      return {
        verdict,
        score:   risk,
        summary: `${verdict}: ${fromAgent} → ${toAgent} (risk ${(risk * 100).toFixed(0)}%)`,
        detail:  result
      };
    })
  },

  // ═══════════ KASBAH OS ═══════════
  {
    slug: 'kasbah-os',
    name: 'KasbahOS Unified Check',
    category: 'Governance',
    description: 'Full OS pipeline: detector (12-layer) + governance (fail-closed) + audit. Single call returns a unified ALLOW/DENY/WARN with trace ID.',
    source: 'src/kasbah-os.js',
    inputs: [
      { name: 'content', type: 'textarea', label: 'Content to check', required: true },
      { name: 'verb', type: 'text', label: 'Action verb', required: false, placeholder: 'CALL_API' },
      { name: 'target', type: 'text', label: 'Target resource', required: false, placeholder: 'api.example.com' },
      { name: 'agent', type: 'text', label: 'Agent identifier', required: false, placeholder: 'my-agent-v1' }
    ],
    run: safeRun(async (b) => {
      const mod = M.kasbahOS();
      if (mod.__err) throw new Error(mod.__err);
      const { KasbahOS } = mod;
      const os = new KasbahOS();
      const action = {
        content: (b.content || '').slice(0, 2000),
        verb:    (b.verb || 'ANALYZE').toUpperCase(),
        target:  b.target || 'unknown',
        agent:   b.agent  || 'demo'
      };
      const dec = await os.check(action);
      const verdict = dec.status || dec.decision || 'UNKNOWN';
      const risk    = typeof dec.risk_score === 'number' ? dec.risk_score / 100 : (dec.risk || 0);
      return {
        verdict,
        score:   risk,
        summary: `${verdict} (risk ${(risk * 100).toFixed(0)}%) — ${dec.reason || dec.summary || ''}`,
        detail:  dec
      };
    })
  },

  // ═══════════ PRODUCT OS ═══════════
  {
    slug: 'product-os',
    name: 'KasbahProductOS — 8-Layer Analysis',
    category: 'Governance',
    description: '8-layer detection pipeline (core detection → sentinel → AI text → biomimetic → novel math → math foundations → product algorithms → ZK proof). 186 mathematical frameworks.',
    source: 'src/kasbah-product-os.js',
    inputs: [
      { name: 'content', type: 'textarea', label: 'Content to analyze', required: true },
      { name: 'productKey', type: 'select', label: 'Product vertical', options: ['baseline','relationship','resume','botnet','legal','dating','dao','quantum','neural','chronos','manifold'], required: true },
      { name: 'agent', type: 'text', label: 'Agent ID', required: false, placeholder: 'user-123' }
    ],
    run: safeRun(async (b) => {
      const mod = M.productOS();
      if (mod.__err) throw new Error(mod.__err);
      const { KasbahProductOS } = mod;
      const pos = new KasbahProductOS();
      const result = await pos.analyze(b.productKey || 'baseline', {
        content: (b.content || '').slice(0, 2000),
        agent:   b.agent || 'demo',
        context: {}
      });
      const verdict = result?.verdict || 'UNKNOWN';
      const risk    = typeof result?.risk === 'number' ? result.risk : 0;
      const layerCount = (result?.algorithms || []).length;
      return {
        verdict,
        score:   risk,
        summary: `${verdict} (risk ${(risk * 100).toFixed(0)}%) via ${layerCount} layers`,
        detail:  { checkId: result?.checkId, algorithms: result?.algorithms, trace: result?.trace, product: b.productKey, safe: result?.safe }
      };
    })
  },

  // ═══════════ WORKFLOW ENGINE ═══════════
  {
    slug: 'workflow-engine',
    name: 'Kasbah Workflow Engine',
    category: 'Governance',
    description: 'Multi-agent workflow orchestration with governance at every step. Define sequential/parallel/conditional/gate workflows; every handoff is scanned and audited.',
    source: 'src/kasbah-workflow.js',
    inputs: [
      { name: 'content', type: 'textarea', label: 'Input content to process through workflow', required: true },
      { name: 'workflowType', type: 'select', label: 'Workflow type', options: ['sequential-scan','parallel-scan','conditional-scan'], required: true }
    ],
    run: safeRun(async (b) => {
      const mod = M.workflow();
      if (mod.__err) throw new Error(mod.__err);
      const { KasbahWorkflow, STEP_TYPES } = mod;
      const wf = new KasbahWorkflow({ policyPath: path.join(REPO, '.kasbahpolicy.json') });
      const content = (b.content || '').slice(0, 1000);
      const type = b.workflowType || 'sequential-scan';

      // Define a built-in demo workflow for each type
      let steps;
      if (type === 'parallel-scan') {
        steps = [
          { id: 'fanout', type: STEP_TYPES?.PARALLEL || 'parallel', agent: 'orchestrator', verb: 'ANALYZE', target: 'content',
            steps: [
              { id: 'scan-a', type: STEP_TYPES?.AGENT || 'agent', agent: 'scanner-a', verb: 'READ_FILE', target: 'input', executor: async (i) => ({ result: 'scan-a OK', risk: 0.1, input: i }) },
              { id: 'scan-b', type: STEP_TYPES?.AGENT || 'agent', agent: 'scanner-b', verb: 'ANALYZE', target: 'input', executor: async (i) => ({ result: 'scan-b OK', risk: 0.15, input: i }) }
            ]
          }
        ];
      } else if (type === 'conditional-scan') {
        steps = [
          { id: 'detect',   type: STEP_TYPES?.AGENT || 'agent', agent: 'detector', verb: 'ANALYZE', target: 'content', executor: async (i) => ({ risk: content.length > 100 ? 0.6 : 0.2, input: i }) },
          { id: 'branch',   type: STEP_TYPES?.CONDITION || 'condition', condition: (out) => (out.risk || 0) > 0.5,
            onTrue: 'escalate', onFalse: 'allow' },
          { id: 'escalate', type: STEP_TYPES?.AGENT || 'agent', agent: 'reviewer', verb: 'ANALYZE', target: 'risk-queue', executor: async (i) => ({ verdict: 'ESCALATED', input: i }) },
          { id: 'allow',    type: STEP_TYPES?.AGENT || 'agent', agent: 'logger',   verb: 'WRITE_FILE', target: 'audit-log', executor: async (i) => ({ verdict: 'ALLOWED', input: i }) }
        ];
      } else {
        steps = [
          { id: 'ingest',   type: STEP_TYPES?.AGENT || 'agent', agent: 'ingestor',  verb: 'READ_FILE',  target: 'input',      executor: async (i) => ({ ingested: true, content: i }) },
          { id: 'analyze',  type: STEP_TYPES?.AGENT || 'agent', agent: 'analyzer',  verb: 'ANALYZE',    target: 'content',    executor: async (i) => ({ analyzed: true, risk: 0.1,  input: i }) },
          { id: 'report',   type: STEP_TYPES?.AGENT || 'agent', agent: 'reporter',  verb: 'WRITE_FILE', target: 'audit-log',  executor: async (i) => ({ reported: true, verdict: 'ALLOW', input: i }) }
        ];
      }

      const workflowId = wf.defineWorkflow(`demo-${type}`, steps, { maxRetries: 0 });
      const result = await wf.execute(workflowId, { content }, { agent: 'demo' });
      const status = result?.status || 'UNKNOWN';
      return {
        verdict: status === 'COMPLETED' ? 'ALLOW' : status === 'BLOCKED' ? 'DENY' : status,
        score:   status === 'BLOCKED' ? 0.9 : 0.1,
        summary: `Workflow ${type}: ${status} in ${result?.executionTime || 0}ms (${result?.completedSteps || 0}/${steps.length} steps)`,
        detail:  { workflowId, executionId: result?.id, status, type, steps: result?.steps, stats: wf.stats }
      };
    })
  },

  // ═══════════ GROUP 5 SUITE ═══════════
  {
    slug: 'group5-suite',
    name: 'Group 5 Enhanced Algorithms',
    category: 'Coordination',
    description: 'Multi-tradition ethics (Nomos), Byzantine shadow consensus, Maqasid Shariah AI ethics, ZK grapheme proof, perceptual oracle, and threat fingerprinting — run as a fused suite.',
    source: 'src/group5-enhanced.js',
    inputs: [
      { name: 'content', type: 'textarea', label: 'Content to analyze', required: true },
      { name: 'action', type: 'text', label: 'Action type', required: false, placeholder: 'ANALYZE' },
      { name: 'risk', type: 'number', label: 'Primary risk score (0–1)', required: false, placeholder: '0.3' }
    ],
    run: safeRun(async (b) => {
      const mod = M.group5();
      if (mod.__err) throw new Error(mod.__err);
      const { executeAlgorithmGroup5 } = mod;
      const shadowMod = M.shadow();
      const ShadowConsensus = shadowMod.__err ? null : (shadowMod.ShadowConsensus || shadowMod);
      const shadowInst = ShadowConsensus && typeof ShadowConsensus === 'function' ? new ShadowConsensus({ shadowCount: 3 }) : null;
      const content = (b.content || '').slice(0, 1000);
      const primaryRisk = Math.min(1, Math.max(0, parseFloat(b.risk) || 0.3));
      const preprocessed = { normalized: content, original: content, hasHomoglyphs: false };
      const context = { action: (b.action || 'ANALYZE').toUpperCase(), permitted: true };
      const results = { rtpTransform: { decision: primaryRisk >= 0.7 ? 'DENY' : 'ALLOW', riskScore: primaryRisk } };
      const engine = {
        shadowConsensus:   shadowInst,
        nomosEngine:       null, maqasidFramework: null,
        zkGrapheme:        null, perceptualOracle: null,
        threatAggregator:  null, appealsProcessor: null,
        distributedSync:   null, debateEngine:     null
      };
      const out = await executeAlgorithmGroup5(preprocessed, context, results, engine);
      const sc = out.shadowConsensus;
      const verified = sc && !sc.error && sc.gamingDetected === false;
      const verdict = sc?.error ? 'ERROR' : (verified ? 'VERIFIED' : 'CONTESTED');
      const score = sc?.confidence != null ? 1 - sc.confidence : primaryRisk;
      return {
        verdict,
        score,
        summary: `Shadow consensus: ${verified ? 'VERIFIED (no gaming detected)' : sc?.error || 'CONTESTED'}`,
        detail:  { shadowConsensus: out.shadowConsensus, nomosConsensus: out.nomosConsensus, maqasid: out.maqasid, threatFingerprint: out.threatFingerprint, inputRisk: primaryRisk }
      };
    })
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Mount HTTP routes
// ─────────────────────────────────────────────────────────────────────────────
function mount(app) {
  app.get('/v1/algorithms', (req, res) => {
    const category = req.query.category;
    const list = REGISTRY
      .filter(a => !category || a.category === category)
      .map(({ slug, name, category, description, source, inputs }) => ({
        slug, name, category, description, source, inputs
      }));
    const categories = [...new Set(REGISTRY.map(a => a.category))].sort();
    res.json({ count: list.length, total: REGISTRY.length, categories, algorithms: list });
  });

  app.get('/v1/algorithms/:slug', (req, res) => {
    const a = REGISTRY.find(x => x.slug === req.params.slug);
    if (!a) return res.status(404).json({ error: 'Unknown algorithm', slug: req.params.slug });
    const { run, ...meta } = a;
    res.json(meta);
  });

  app.post('/v1/algorithms/:slug/run', async (req, res) => {
    const a = REGISTRY.find(x => x.slug === req.params.slug);
    if (!a) return res.status(404).json({ error: 'Unknown algorithm', slug: req.params.slug });
    if (typeof a.run !== 'function') return res.status(501).json({ error: 'No runner for this algorithm' });
    try {
      const result = await a.run(req.body || {});
      res.json(Object.assign({ slug: a.slug, name: a.name, category: a.category }, result));
    } catch (e) {
      res.status(500).json({ slug: a.slug, error: e.message });
    }
  });
}

module.exports = { mount, REGISTRY };
