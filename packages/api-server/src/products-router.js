'use strict';

/**
 * Products Router — exposes every product engine through a uniform HTTP surface.
 *
 *   POST /v1/products/<name>/analyze   { input, options? }  →  normalized result
 *   GET  /v1/products                  → list of available products + capabilities
 *   GET  /v1/products/<name>           → product metadata
 *
 * Wires the 6 previously unwired product engines (BaselineDrift, DAOVoteGuard,
 * QuantumSentinel, NeuralWitness, ChronosParadox, ManifoldValidator) plus the 5
 * already-wrapped ones (DatingGuard, ResumeAuthentic, BotnetRadar, LegalEvidence,
 * RelationshipGuard) into one cohesive product surface — so a single Kasbah API
 * key works against any product.
 *
 * Each adapter normalizes the engine-specific call signature to a stable
 * response shape: { product, verdict, score, summary, detail, latencyMs }.
 */

const path = require('path');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');

// Lazy-load each engine. If one is missing, the product becomes 'unavailable'
// rather than crashing the whole router.
function safeLoad(rel) {
  try { return require(path.join(REPO_ROOT, rel)); }
  catch (e) { return { __error: e.message }; }
}

// ─── 1. Adapters: convert engine-specific calls to a uniform shape ───────────

// BaselineDrift Monitor — Lyapunov stability + Kolmogorov complexity
function adaptBaselineDrift(engineModule) {
  if (engineModule.__error) return { error: engineModule.__error };
  const Engine = engineModule.BaselineDriftEngine;
  const instance = new Engine();
  return {
    name: 'BaselineDrift',
    description: 'Detects baseline drift in AI agent behavior via Lyapunov exponents + Kolmogorov complexity.',
    inputSchema: { input: 'string', priorObservations: 'array of strings (optional)' },
    analyze: (req) => {
      const start = Date.now();
      // observe() expects an object with .text or .output field, not raw string
      const wrap = (s) => (typeof s === 'string' ? { output: s, text: s, content: s } : s);
      const observations = Array.isArray(req.priorObservations) ? req.priorObservations.map(wrap) : [];
      observations.push(wrap(req.input));
      let result = null;
      try {
        for (const obs of observations) {
          result = instance.observe(obs);
        }
      } catch (e) {
        return {
          product: 'BaselineDrift',
          verdict: 'ERROR',
          score: 0,
          summary: 'Engine error: ' + e.message,
          detail: { error: e.message },
          latencyMs: Date.now() - start
        };
      }
      const baseline = typeof instance.computeBaseline === 'function' ? safeCall(() => instance.computeBaseline()) : null;
      const uniformity = typeof instance.computeUniformity === 'function' ? safeCall(() => instance.computeUniformity()) : null;
      return {
        product: 'BaselineDrift',
        verdict: (result && result.driftDetected) ? 'DRIFT' : 'STABLE',
        score: result?.lyapunovExponent ?? result?.driftMagnitude ?? 0,
        summary: result?.driftDetected ? 'Baseline drift detected' : 'Stable behavior',
        detail: { observation: result, baseline, uniformity },
        latencyMs: Date.now() - start
      };
    }
  };
}

// Helper: try/catch wrapper that returns null on error
function safeCall(fn) { try { return fn(); } catch { return null; } }

// DAOVoteGuard — Hyperbolic vote space + Byzantine fault tolerance
function adaptDAOVoteGuard(engineModule) {
  if (engineModule.__error) return { error: engineModule.__error };
  const Engine = engineModule.DAOVoteGuardEngine;
  return {
    name: 'DAOVoteGuard',
    description: 'Detects vote manipulation in DAO governance via hyperbolic vote space + Byzantine weighted voting.',
    inputSchema: {
      proposal: '{ id, title, description, voteOptions[] }',
      votes:    'array of { voterId, optionId, weight, timestamp }'
    },
    analyze: (req) => {
      const start = Date.now();
      const instance = new Engine();
      const proposal = req.proposal || {
        id: 'p1',
        title: req.input || 'untitled',
        content: req.input || '',
        voteOptions: ['yes', 'no']
      };
      const votes = req.votes || [];
      try {
        instance.submitProposal(proposal);
        for (const v of votes) {
          // Accept either flat (voterId, optionId, weight) or wrapped (voteData)
          instance.submitVote({
            voterId:    v.voterId || 'anon',
            proposalId: proposal.id,
            vote:       v.vote || v.optionId || 'yes',
            reputation: v.weight || v.reputation || 1,
            votingPattern: v.votingPattern || []
          });
        }
        const result = instance.computeGovernanceResult(proposal.id);
        return {
          product: 'DAOVoteGuard',
          verdict: result?.byzantineCompromise ? 'COMPROMISED' : (result?.consensus ? 'CONSENSUS' : 'INCONCLUSIVE'),
          score: result?.confidence ?? result?.agreementRate ?? 0.5,
          summary: result?.winningOption ? `Winner: ${result.winningOption}` : (result?.summary || 'Vote analysis complete'),
          detail: result,
          latencyMs: Date.now() - start
        };
      } catch (e) {
        return { product: 'DAOVoteGuard', verdict: 'ERROR', score: 0, summary: e.message, detail: { error: e.message }, latencyMs: Date.now() - start };
      }
    }
  };
}

// QuantumSentinel — Hilbert-space measurement
function adaptQuantumSentinel(engineModule) {
  if (engineModule.__error) return { error: engineModule.__error };
  const Engine = engineModule.QuantumSentinelEngine;
  const instance = new Engine();
  return {
    name: 'QuantumSentinel',
    description: 'Detects quantum-measurement-style hidden state collapse in AI outputs.',
    inputSchema: { input: 'string', baseline: 'string (optional)' },
    analyze: (req) => {
      const start = Date.now();
      let result = null;
      try { result = instance.analyze(req.input); }
      catch (e) {
        return { product: 'QuantumSentinel', verdict: 'ERROR', score: 0, summary: e.message, detail: { error: e.message }, latencyMs: Date.now() - start };
      }
      // analyze() returns { measurements: { ai: {...}, human: {...} }, quantumState: {...} }
      const aiProb = result?.measurements?.ai?.confidence ?? 0;
      const huProb = result?.measurements?.human?.confidence ?? 0;
      const score = aiProb / Math.max(aiProb + huProb, 0.0001);
      let comparison = null;
      if (req.baseline && typeof instance.compare === 'function') {
        try { comparison = instance.compare(req.input, req.baseline); } catch { /* no-op */ }
      }
      return {
        product: 'QuantumSentinel',
        verdict: aiProb > huProb ? 'AI_COLLAPSED' : 'HUMAN_COHERENT',
        score,
        summary: `AI probability: ${(aiProb * 100).toFixed(1)}%, Human probability: ${(huProb * 100).toFixed(1)}%`,
        detail: { analysis: result, comparison },
        latencyMs: Date.now() - start
      };
    }
  };
}

// NeuralWitness — Gradient forensic comparison
function adaptNeuralWitness(engineModule) {
  if (engineModule.__error) return { error: engineModule.__error };
  const Engine = engineModule.NeuralWitnessEngine;
  const instance = new Engine();
  return {
    name: 'NeuralWitness',
    description: 'Gradient forensics: extracts the optimization trajectory signature of an AI output.',
    inputSchema: { input: 'string', reference: 'string (optional, for comparison)' },
    analyze: (req) => {
      const start = Date.now();
      let report = null;
      try { report = instance.generateWitnessReport(req.input); } catch (e) { report = { error: e.message }; }
      let comparison = null;
      if (req.reference && typeof instance.compare === 'function') {
        try { comparison = instance.compare(req.input, req.reference); } catch { /* no-op */ }
      }
      return {
        product: 'NeuralWitness',
        verdict: report?.aiGenerated ? 'AI_GENERATED' : 'INDETERMINATE',
        score: report?.confidence ?? 0,
        summary: report?.summary || 'Gradient forensic analysis complete',
        detail: { report, comparison },
        latencyMs: Date.now() - start
      };
    }
  };
}

// ChronosParadox — Temporal causality + arrow of time
function adaptChronosParadox(engineModule) {
  if (engineModule.__error) return { error: engineModule.__error };
  const Engine = engineModule.ChronosParadoxEngine;
  const instance = new Engine();
  return {
    name: 'ChronosParadox',
    description: 'Detects temporal paradoxes / impossible causality in event streams.',
    inputSchema: { input: 'string|events[]', events: 'array of { id, timestamp, causedBy? }' },
    analyze: (req) => {
      const start = Date.now();
      const events = req.events || (typeof req.input === 'string' ? [{ id: 'e1', timestamp: Date.now(), content: req.input }] : []);
      let result, score = 0;
      try {
        result = instance.analyze(events);
        score = typeof instance.computeAnomalyScore === 'function'
          ? instance.computeAnomalyScore(result) : (result?.anomalyScore ?? 0);
      } catch (e) {
        result = { error: e.message };
      }
      return {
        product: 'ChronosParadox',
        verdict: (result?.paradoxDetected || score > 0.6) ? 'PARADOX' : 'CONSISTENT',
        score,
        summary: result?.paradoxDetected ? 'Temporal paradox detected' : 'Causally consistent',
        detail: result,
        latencyMs: Date.now() - start
      };
    }
  };
}

// ManifoldValidator — Riemannian geometry
function adaptManifoldValidator(engineModule) {
  if (engineModule.__error) return { error: engineModule.__error };
  const Engine = engineModule.ManifoldValidatorEngine;
  const instance = new Engine();
  return {
    name: 'ManifoldValidator',
    description: 'Validates that text lies on the expected semantic manifold (Riemannian geometry).',
    inputSchema: { input: 'string', reference: 'string (optional)' },
    analyze: (req) => {
      const start = Date.now();
      let result, comparison = null;
      try { result = instance.validate(req.input); } catch (e) { result = { error: e.message }; }
      if (req.reference && typeof instance.compare === 'function') {
        try { comparison = instance.compare(req.input, req.reference); } catch { /* no-op */ }
      }
      return {
        product: 'ManifoldValidator',
        verdict: result?.onManifold ? 'ON_MANIFOLD' : 'OFF_MANIFOLD',
        score: result?.geodesicDistance ?? 0,
        summary: result?.onManifold ? 'Within expected semantic manifold' : 'Off-manifold (anomalous)',
        detail: { result, comparison },
        latencyMs: Date.now() - start
      };
    }
  };
}

// ─── 2. Adapters for already-wrapped products (reuse their engines) ───────────

function adaptDatingGuard(mod) {
  if (mod.__error) return { error: mod.__error };
  const instance = new mod.DatingGuardEngine();
  return {
    name: 'DatingGuard',
    description: 'Romance scam detection: love bombing, money requests, AI-generated profile bios.',
    inputSchema: { input: 'string (message)', profile: 'object (optional)' },
    analyze: (req) => {
      const start = Date.now();
      // DatingGuardEngine.analyze(profileData, messagesText)
      const message = typeof req.input === 'string' ? req.input : (req.message || '');
      const profile = req.profile || { bio: message };
      let result;
      try { result = instance.analyze(profile, message); }
      catch (e) { return { product: 'DatingGuard', verdict: 'ERROR', score: 0, summary: e.message, detail: { error: e.message }, latencyMs: Date.now() - start }; }
      return {
        product: 'DatingGuard',
        verdict: result?.riskLevel || (result?.riskScore > 0.6 ? 'SCAM_LIKELY' : 'CLEAR'),
        score: result?.riskScore ?? result?.score ?? 0,
        summary: result?.warnings?.[0] || result?.summary || 'Romance fraud analysis complete',
        detail: result,
        latencyMs: Date.now() - start
      };
    }
  };
}

function adaptRelationshipGuard(mod) {
  if (mod.__error) return { error: mod.__error };
  const instance = new mod.ManipulationEngine();
  return {
    name: 'RelationshipGuard',
    description: 'Detects gaslighting, DARVO, love bombing, and other manipulation tactics in conversations.',
    inputSchema: { input: 'string (conversation transcript)' },
    analyze: (req) => {
      const start = Date.now();
      const result = instance.analyze ? instance.analyze(req.input) : { score: 0 };
      return {
        product: 'RelationshipGuard',
        verdict: result.manipulationDetected ? 'MANIPULATION' : 'CLEAR',
        score: result.score ?? 0,
        summary: result.summary || 'Manipulation analysis complete',
        detail: result,
        latencyMs: Date.now() - start
      };
    }
  };
}

function adaptResumeAuthentic(mod) {
  if (mod.__error) return { error: mod.__error };
  const instance = new mod.ResumeAuthenticEngine();
  return {
    name: 'ResumeAuthentic',
    description: 'Detects AI-generated resumes via stylometric fingerprinting + 17-model AI classifier.',
    inputSchema: { input: 'string (resume text)' },
    analyze: (req) => {
      const start = Date.now();
      const result = instance.analyze ? instance.analyze(req.input) : { score: 0 };
      return {
        product: 'ResumeAuthentic',
        verdict: result.aiGenerated ? 'AI_GENERATED' : 'HUMAN_LIKELY',
        score: result.score ?? 0,
        summary: result.summary || `Detected style: ${result.generator || 'unknown'}`,
        detail: result,
        latencyMs: Date.now() - start
      };
    }
  };
}

function adaptBotnetRadar(mod) {
  if (mod.__error) return { error: mod.__error };
  // BotnetRadar has analyze(accounts) at line 96; build accounts shape defensively
  const instance = new mod.BotnetRadarEngine();
  return {
    name: 'BotnetRadar',
    description: 'Detects coordinated AI agent swarms (Bell-inequality + topological homology).',
    inputSchema: { input: 'string|accounts[]', accounts: 'array of { id, posts[], timestamps[] }' },
    analyze: (req) => {
      const start = Date.now();
      // BotnetRadarEngine.analyze(threadText, accounts[])
      // Build threadText from posts if not directly provided.
      let threadText = req.threadText || req.input || '';
      let handles = req.accounts;
      if (Array.isArray(handles)) {
        // If caller passed structured accounts, serialize their messages into the thread
        const lines = [];
        for (const a of handles) {
          const posts = a.posts || a.messages || [];
          for (const post of posts) {
            lines.push(`@${a.id || a.handle || 'anon'}: ${post}`);
          }
        }
        threadText = threadText ? threadText + '\n' + lines.join('\n') : lines.join('\n');
        handles = handles.map(a => a.id || a.handle || 'anon');
      } else {
        handles = [];
      }
      let result;
      try { result = instance.analyze(threadText, handles); }
      catch (e) { return { product: 'BotnetRadar', verdict: 'ERROR', score: 0, summary: e.message, detail: { error: e.message }, latencyMs: Date.now() - start }; }
      const coordinated = result?.coordinated || result?.swarmDetected || (result?.chsh > 2);
      return {
        product: 'BotnetRadar',
        verdict: coordinated ? 'BOTNET' : 'INDEPENDENT',
        score: result?.confidence ?? result?.chsh ?? 0,
        summary: result?.explanation || result?.summary || `Examined ${handles.length} account(s)`,
        detail: result || {},
        latencyMs: Date.now() - start
      };
    }
  };
}

function adaptLegalEvidence(mod) {
  if (mod.__error) return { error: mod.__error };
  const Engine = mod.ForensicDocumentEngine || mod.LegalEvidenceEngine;
  const instance = new Engine();
  return {
    name: 'LegalEvidence',
    description: 'Forensic AI detection for court-admissible documents (CAIL ledger + ZK proofs).',
    inputSchema: { input: 'string (document text)' },
    analyze: (req) => {
      const start = Date.now();
      const result = instance.analyze ? instance.analyze(req.input) : { score: 0 };
      return {
        product: 'LegalEvidence',
        verdict: result.authentic === false ? 'AI_GENERATED' : 'AUTHENTIC',
        score: result.score ?? 0,
        summary: result.summary || 'Forensic analysis complete',
        detail: result,
        latencyMs: Date.now() - start
      };
    }
  };
}

// ─── 3. Build the registry ────────────────────────────────────────────────────

const REGISTRY = {};

function register(slug, adapterFn, rel) {
  const mod = safeLoad(rel);
  const adapter = adapterFn(mod);
  if (adapter.error) {
    REGISTRY[slug] = { name: slug, unavailable: true, error: adapter.error };
  } else {
    REGISTRY[slug] = adapter;
  }
}

register('baseline-drift',     adaptBaselineDrift,     'products/baseline-drift/src/drift-engine.js');
register('dao-vote-guard',     adaptDAOVoteGuard,      'products/dao-vote-guard/src/governance-engine.js');
register('quantum-sentinel',   adaptQuantumSentinel,   'products/quantum-sentinel/engine.js');
register('neural-witness',     adaptNeuralWitness,     'products/neural-witness/engine.js');
register('chronos-paradox',    adaptChronosParadox,    'products/chronos-paradox/engine.js');
register('manifold-validator', adaptManifoldValidator, 'products/manifold-validator/engine.js');
register('dating-guard',       adaptDatingGuard,       'products/dating-guard/src/dating-engine.js');
register('relationship-guard', adaptRelationshipGuard, 'products/relationship-guard/src/manipulation-engine.js');
register('resume-authentic',   adaptResumeAuthentic,   'products/resume-authentic/src/resume-engine.js');
register('botnet-radar',       adaptBotnetRadar,       'products/botnet-radar/src/swarm-engine.js');
register('legal-evidence',     adaptLegalEvidence,     'products/legal-evidence/src/forensic-engine.js');

// ─── 4. Express router factory ────────────────────────────────────────────────

function mount(app) {
  // List all products
  app.get('/v1/products', (req, res) => {
    const products = Object.entries(REGISTRY).map(([slug, p]) => ({
      slug,
      name: p.name,
      description: p.description,
      available: !p.unavailable,
      inputSchema: p.inputSchema,
      ...(p.unavailable ? { error: p.error } : {})
    }));
    res.json({
      count: products.length,
      available: products.filter(p => p.available).length,
      products
    });
  });

  // Product metadata
  app.get('/v1/products/:slug', (req, res) => {
    const p = REGISTRY[req.params.slug];
    if (!p) return res.status(404).json({ error: 'Unknown product', available: Object.keys(REGISTRY) });
    if (p.unavailable) return res.status(503).json({ error: 'Product unavailable', detail: p.error });
    res.json({
      slug: req.params.slug,
      name: p.name,
      description: p.description,
      inputSchema: p.inputSchema
    });
  });

  // Analyze through a specific product
  app.post('/v1/products/:slug/analyze', (req, res) => {
    const p = REGISTRY[req.params.slug];
    if (!p) return res.status(404).json({ error: 'Unknown product', available: Object.keys(REGISTRY) });
    if (p.unavailable) return res.status(503).json({ error: 'Product unavailable', detail: p.error });
    if (!req.body || typeof req.body !== 'object') {
      return res.status(400).json({ error: 'Request body must be JSON' });
    }
    if (req.body.input === undefined && req.body.events === undefined &&
        req.body.accounts === undefined && req.body.proposal === undefined) {
      return res.status(400).json({ error: '"input" field (string|object) is required (or product-specific shape — see GET /v1/products/' + req.params.slug + ')' });
    }
    try {
      const result = p.analyze(req.body);
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: 'Product analysis failed', detail: err.message });
    }
  });
}

module.exports = { mount, REGISTRY };
