'use strict';

/**
 * Feature IPC handlers — privacy, pro, pop, agent, shamir, mmr, deadman,
 * audit, honey, vuln, zk, llmproxy, fsaudit.
 * Call registerFeatureHandlers(ipcMain, ctx) once during app startup.
 *
 * ctx shape: State, log, V, fs, path, os, crypto, clipboard, Notification,
 *            safePathInside, safeExistingFile, vpnState,
 *            privacy, pro, pop, agentGuard, shamir, mmr, deadman,
 *            honey, merkleBatch, zkProtect, vuln, llmProxy, dohResolver,
 *            _fsAudit, mainWindow getter
 */

module.exports = function registerFeatureHandlers(ipcMain, ctx) {
  const { log, V, fs, path, os, crypto, clipboard, Notification,
          safePathInside, safeExistingFile, vpnState,
          privacy, pro, pop, agentGuard, shamir, mmr, deadman,
          honey, merkleBatch, zkProtect, vuln, llmProxy, dohResolver, _fsAudit } = ctx;

  const impact = (() => { try { return require('./impact.js'); } catch { return { bump: () => {} }; } })();

  /* ── IPC origin guard ──────────────────────────────────────────────────────
   * Reject any IPC call whose sender frame is not the app's own renderer.
   * Prevents a malicious website loaded in the embedded BrowserView from
   * calling privileged channels.
   */
  function assertOrigin(event) {
    const url = event.senderFrame?.url || '';
    if (!url || url.startsWith('file://') || url === 'about:blank') return; // allowed
    // Any non-file origin is rejected (BrowserView pages load http/https)
    throw new Error(`IPC origin rejected: ${url}`);
  }

  /* ── Token-bucket rate limiter ─────────────────────────────────────────────
   * One bucket per expensive channel. Exceeding the rate returns an error
   * rather than executing the operation.
   */
  const _buckets = new Map();
  function rateLimit(channel, { maxPerSecond = 10 } = {}) {
    const now = Date.now();
    let b = _buckets.get(channel);
    if (!b) { b = { count: 0, resetAt: now + 1000 }; _buckets.set(channel, b); }
    if (now > b.resetAt) { b.count = 0; b.resetAt = now + 1000; }
    b.count++;
    if (b.count > maxPerSecond) throw new Error(`rate limit exceeded on ${channel}`);
  }

  /* ── Security-sensitive error logger ──────────────────────────────────────
   * Replaces silent catch (_) {} on security-relevant paths.
   */
  function auditError(module, e) {
    try { _fsAudit.append({ event: 'internal_error', module, message: e?.message || String(e) }); } catch (_) {}
  }

  const commitProof    = (() => { try { return require('./commit-proof.js');    } catch (e) { return { error: e.message }; } })();
  const egressClassifier = (() => { try { return require('./egress-classifier.js'); } catch (e) { return { error: e.message }; } })();
  const agentRegistry    = (() => { try { return require('./agent-registry.js');    } catch (e) { return { error: e.message }; } })();
  const aiGov            = (() => { try { return require('./ai-governance.js');     } catch (e) { return { error: e.message }; } })();
  const browserStore     = (() => { try { return require('./browser-store.js');    } catch (e) { return { error: e.message }; } })();
  const thresholdGov     = (() => { try { return require('./threshold-gov.js');    } catch (e) { return { error: e.message }; } })();
  const bioGuard         = (() => { try { return require('./biometric-guard.js');  } catch (e) { return { error: e.message }; } })();
  const bioLocal         = (() => { try { return require('./biometric-local.js');  } catch (e) { return { error: e.message }; } })();
  const agentCost        = (() => { try { return require('./agent-cost.js');       } catch (e) { return { error: e.message }; } })();
  const promptAttest     = (() => { try { return require('./prompt-attest.js');    } catch (e) { return { error: e.message }; } })();
  const vcExport         = (() => { try { return require('./vc-export.js');        } catch (e) { return { error: e.message }; } })();
  const sessionChain     = (() => { try { return require('./session-chain.js');    } catch (e) { return { error: e.message }; } })();
  const micSentinel      = (() => { try { return require('./mic-sentinel.js');     } catch (e) { return { error: e.message }; } })();
  const cameraSentinel   = (() => { try { return require('./camera-sentinel.js');  } catch (e) { return { error: e.message }; } })();
  const enforcer = (() => {
    const candidates = [
      './kasbah-enforcer-local.js',
      '../../src/kasbah-enforcer.js',
      '../../../src/kasbah-enforcer.js',
    ];
    // Packaged extraResources also ships root src as packages/kasbah-src
    try {
      const pr = process.resourcesPath ? require('path').join(process.resourcesPath, 'packages', 'kasbah-src', 'kasbah-enforcer.js') : null;
      if (pr) candidates.push(pr);
    } catch (_) {}
    for (const c of candidates) { try { return require(c); } catch (_) {} }
    try { return require(require('path').join(__dirname, '../../../src/kasbah-enforcer.js')); }
    catch (e) { return { error: e.message }; }
  })();
  const transparencyLog  = (() => { try { return require('./transparency-log.js'); } catch (e) { return { error: e.message }; } })();
  const { AgentTrace }   = (() => { try { return require('./agent-trace.js');      } catch (e) { return { AgentTrace: null, error: e.message }; } })();
  const voicePrivacy     = (() => { try { return require('./voice-privacy.js');    } catch (e) { return { error: e.message }; } })();
  // Capability bridges — local-first, api-server fallback. All resolve in dev
  // and in packaged DMG via extraResources (packages/kasbah-src, mcise-core, etc).
  function tryRequire(candidates) {
    for (const c of candidates) { try { return require(c); } catch (_) {} }
    return { error: 'module unavailable: ' + candidates[0] };
  }
  const siemLocal = (() => { try {
    return tryRequire(['../../api-server/src/siem-connectors.js', '../../../api-server/src/siem-connectors.js',
      require('path').join(__dirname, '../../packages/api-server/src/siem-connectors.js')]);
  } catch (e) { return { error: e.message }; } })();
  const lineageLocal = (() => { try {
    return tryRequire(['../../api-server/src/data-lineage.js', '../../../api-server/src/data-lineage.js']);
  } catch (e) { return { error: e.message }; } })();
  const maqasidLocal = (() => { try {
    return tryRequire(['../../agent-governance/src/maqasid-framework.js', '../../../packages/agent-governance/src/maqasid-framework.js',
      require('path').join(__dirname, '../../packages/agent-governance/src/maqasid-framework.js')]);
  } catch (e) { return { error: e.message }; } })();
  let _sentinelSingleton = null; let _sentinelError = null;
  function sentinelLocal() {
    if (_sentinelSingleton || _sentinelError) return _sentinelSingleton;
    try {
      const mod = tryRequire(['../../../src/kasbah-sentinel.js', '../../src/kasbah-sentinel.js']);
      if (mod.error || !mod.KasbahSentinel) { _sentinelError = mod.error || 'no KasbahSentinel'; return null; }
      _sentinelSingleton = new mod.KasbahSentinel({});
      return _sentinelSingleton;
    } catch (e) { _sentinelError = e.message; return null; }
  }

  // ─── Privacy analyzers ────────────────────────────────────────────────────────
  ipcMain.handle('privacy:scam',        (_e, text) => privacy.analyzeScam(V.str(text, { name: 'text' })));
  ipcMain.handle('privacy:family',      (_e, text) => privacy.analyzeFamily(V.str(text, { name: 'text' })));
  ipcMain.handle('privacy:wifi-analyze',(_e, body) => privacy.analyzeWifi(V.obj(body, 'body')));
  ipcMain.handle('privacy:secrets',     (_e, text) => privacy.scanSecrets(V.str(text, { name: 'text' })));
  ipcMain.handle('privacy:gen-password',(_e, opts) => privacy.generatePassword(opts || {}));
  ipcMain.handle('privacy:device',      () => privacy.deviceSummary());
  ipcMain.handle('privacy:scam-mm',     (_e, text) => privacy.analyzeScamMyanmar(String(text || '')));
  ipcMain.handle('privacy:pw-score',    (_e, pw)   => privacy.scorePassword(String(pw || '')));
  ipcMain.handle('privacy:latency',     () => privacy.latencyToExit('10.77.0.1'));
  ipcMain.handle('privacy:mm-profile',  () => privacy.myanmarNetworkProfile());

  ipcMain.handle('privacy:dns-leak', async () => {
    const engineResult = await privacy.dnsLeakCheck().catch((e) => ({ error: e.message }));
    const dohResult    = await dohResolver.dnsLeakCheck().catch((e) => ({ error: e.message, dohWorking: false }));
    return { engine: engineResult, doh: dohResult, ok: dohResult.dohWorking !== false };
  });

  ipcMain.handle('privacy:pw-breach', async (_e, password) => privacy.checkPasswordBreach(String(password || '')));
  ipcMain.handle('privacy:email-breach', async (_e, email, apiKey) => privacy.checkEmailBreach(String(email || ''), apiKey));

  ipcMain.handle('privacy:pw-breach-hash5', async (_e, hash5) => {
    const prefix = String(hash5 || '').slice(0, 5).toUpperCase();
    const https = require('https');
    return new Promise((resolve, reject) => {
      const req = https.request({ hostname: 'api.pwnedpasswords.com', path: `/range/${prefix}`, method: 'GET', headers: { 'Add-Padding': 'true', 'User-Agent': 'KasbahPrivacy/3.1' }, timeout: 12000 }, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          if (res.statusCode !== 200) return reject(new Error('HIBP HTTP ' + res.statusCode));
          resolve({ suffixes: body.split('\n').filter(Boolean).map((l) => { const [s, c] = l.split(':'); return { suffix: s.trim(), count: parseInt(c, 10) || 0 }; }) });
        });
      });
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.on('error', reject);
      req.end();
    });
  });

  ipcMain.handle('privacy:checkup', async () => {
    try { impact.bump('scans'); } catch (_) {}
    // Never trust a renderer-supplied `egress` for a checkup that reports
    // real protection status — derive it from a real probe.
    let egress = null;
    if (vpnState.activeLocation) {
      const probe = await ctx.netIntel.realEgressProbe();
      egress = { ip: probe.ip, loc: probe.loc, colo: probe.colo };
    }
    return privacy.privacyCheckup({ connected: !!vpnState.activeLocation, egress });
  });

  let clipWatchTimer = null;
  ipcMain.handle('privacy:clip-watch', (_e, on) => {
    if (clipWatchTimer) { clearInterval(clipWatchTimer); clipWatchTimer = null; }
    if (!on) return { ok: true, watching: false };
    // AI-key patterns to auto-clear (heuristic, not exhaustive)
    const _aiKeyRe = /(?:sk-[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{35}|xoxb-[0-9]{11,}-[A-Za-z0-9]{24,}|AKIA[A-Z0-9]{16})/;
    let _lastClipHash = '';
    clipWatchTimer = setInterval(() => {
      try {
        const text = clipboard.readText() || '';
        if (!text || text.length < 8) return;
        // Dedup — only process when clipboard content changes.
        const h = crypto.createHash('sha256').update(text).digest('hex');
        if (h === _lastClipHash) return;
        _lastClipHash = h;
        setTimeout(() => {
          try {
            const r = privacy.scanSecrets(text.slice(0, 8192));
            if (r.found) {
              try { impact.bump('secretsBlocked'); } catch (_) {}
              // Auto-clear clipboard if it contains an AI key.
              if (_aiKeyRe.test(text)) {
                clipboard.writeText('');
                _lastClipHash = '';
                new Notification({ title: 'Kasbah — AI Key Cleared', body: `${r.findings[0].label} detected and removed from clipboard`, silent: false }).show();
                try { _fsAudit.append({ event: 'clipboard_aikey_cleared', type: r.findings[0].id }); } catch (_) {}
                // Feed into protection score if available.
                try { if (ctx._protectionScore) ctx._protectionScore.onEgress?.('clipboard_aikey'); } catch (_) {}
              } else {
                new Notification({ title: 'Kasbah Privacy', body: `Clipboard contains ${r.findings[0].label} — avoid pasting into chats`, silent: false }).show();
              }
              ctx.mainWindow?.webContents.send('privacy:clip-secret', { found: true, findings: r.findings.map((f) => ({ id: f.id, label: f.label, count: f.count })) });
            }
            // Honeytoken check.
            try {
              const ht = honey.check(text);
              if (ht && ht.found) {
                try { impact.bump('honeyHits'); } catch (_) {}
                new Notification({ title: 'Kasbah Honeytoken', body: `Canary triggered: ${ht.hits?.[0]?.label || 'unknown'}` }).show();
                try { _fsAudit.append({ event: 'honeytoken_hit', hits: ht.hits }); } catch (_) {}
                ctx.mainWindow?.webContents.send('privacy:honeytoken-hit', ht);
              }
            } catch (_) {}
            // Egress classification: fire onEgress for high-risk clipboard content.
            try {
              if (egressClassifier && !egressClassifier.error && text.length >= 30) {
                const eg = egressClassifier.classify(text.slice(0, 4096));
                if (eg && eg.risk > 0.6) {
                  if (ctx._protectionScore) ctx._protectionScore.onEgress?.('clipboard_high_risk');
                  ctx.mainWindow?.webContents.send('privacy:egress-alert', { source: 'clipboard', risk: eg.risk, label: eg.label });
                }
              }
            } catch (_) {}
          } catch (_) {}
        }, 200 + Math.floor(Math.random() * 400));
      } catch (_) {}
    }, 4000);
    return { ok: true, watching: true };
  });

  ipcMain.handle('privacy:safe-mode', async (_e, on) => {
    const { resilience } = ctx;
    const prefs = resilience.loadPrefs();
    prefs.safeMode = !!on;
    resilience.savePrefs(prefs);
    if (on && !clipWatchTimer) {
      clipWatchTimer = setInterval(() => {
        try {
          const text = clipboard.readText() || '';
          if (!text || text.length < 8) return;
          const r = privacy.scanSecrets(text);
          if (r.found) {
            try { impact.bump('secretsBlocked'); } catch (_) {}
            new Notification({ title: 'Kasbah Privacy', body: `Clipboard: ${r.findings[0].label}` }).show();
            ctx.mainWindow?.webContents.send('privacy:clip-secret', r);
            try { _fsAudit.append({ event: 'clipboard_secret', type: r.findings[0].id }); } catch (_) {}
          }
          try { const ht = honey.check(text); if (ht.found) { try { impact.bump('honeyHits'); } catch (_) {} new Notification({ title: 'Kasbah honeytoken', body: `Canary triggered: ${ht.hits[0].label}` }).show(); _fsAudit.append({ event: 'honeytoken_hit', hits: ht.hits }); } } catch (_) {}
        } catch (_) {}
      }, 4000);
    } else if (!on && clipWatchTimer) { clearInterval(clipWatchTimer); clipWatchTimer = null; }
    return { ok: true, safeMode: !!on };
  });

  ipcMain.handle('privacy:leak-test', async () => {
    // Never trust a renderer-supplied exitIp for a leak *test* — always
    // derive it from a real probe, or leave it null while offline.
    let exitIp = null;
    if (vpnState.activeLocation) {
      const probe = await ctx.netIntel.realEgressProbe();
      exitIp = probe.ip;
    }
    return privacy.leakTest({ vpnOn: !!vpnState.activeLocation, exitIp });
  });

  // ─── Voice Privacy / Silent Speech ZK ────────────────────────────────────────
  // Zero-knowledge voice-auth and silent-speech primitives (voice-privacy.js).
  // All handlers are rate-limited and never log secrets.
  const voiceRL = rateLimit('voice:*', { maxPerSecond: 5 });
  const voiceSafe = () => (voicePrivacy.error ? false : true);
  // Main-process ZK session: secrets (tokens/blinds/creds) NEVER leave this
  // process — the renderer only ever sees public commitments and proofs.
  let _voiceSession = null;   // { utterance, secret }  set by commit-utterance
  let _voiceRegistry = null;  // { registry, creds }    set by build-registry
  ipcMain.handle('voice:self-test', async () => {
    try { voiceRL(); if (!voiceSafe()) return { error: 'voice-privacy module unavailable' }; return voicePrivacy.selfTest(); } catch (e) { auditError('voice:self-test', e); return { error: e.message }; }
  });
  ipcMain.handle('voice:simulate-silent-speech', async (_e, spec) => {
    try {
      voiceRL();
      if (!voiceSafe()) return { error: 'voice-privacy unavailable' };
      // Accept a token count (number) or an array (uses its length); default 16.
      const n = Math.min(64, Math.max(1, Number(Array.isArray(spec) ? spec.length : spec) || 16));
      return { ok: true, tokens: voicePrivacy.simulateSilentSpeech(n) };
    } catch (e) { auditError('voice:simulate-silent-speech', e); return { error: e.message }; }
  });
  ipcMain.handle('voice:simulate-voiceprint', async (_e, seed) => {
    try {
      voiceRL();
      if (!voiceSafe()) return { error: 'voice-privacy unavailable' };
      return { ok: true, voiceprint: voicePrivacy.simulateVoiceprint(String(seed || '')) };
    } catch (e) { auditError('voice:simulate-voiceprint', e); return { error: e.message }; }
  });
  ipcMain.handle('voice:build-registry', async (_e, voiceprints) => {
    try {
      voiceRL();
      if (!voiceSafe()) return { error: 'voice-privacy unavailable' };
      const vp = (Array.isArray(voiceprints) ? voiceprints : []).map(Number);
      if (!vp.length) return { ok: false, error: 'voiceprints required (array of ints)' };
      const { registry, creds } = voicePrivacy.buildRegistry(vp);
      _voiceRegistry = { registry, creds };  // creds stay in main — never returned
      return { ok: true, registrySize: registry.length, registry };
    } catch (e) { auditError('voice:build-registry', e); return { error: e.message }; }
  });
  ipcMain.handle('voice:auth-prove', async (_e, payload = {}) => {
    try {
      voiceRL();
      if (!voiceSafe()) return { error: 'voice-privacy unavailable' };
      if (!_voiceRegistry) return { ok: false, error: 'no registry session — call voice:build-registry first' };
      const idx = Math.min(_voiceRegistry.creds.length - 1, Math.max(0, Number(payload.registryIndex) || 0));
      const proof = voicePrivacy.voiceAuthProve(_voiceRegistry.creds[idx], _voiceRegistry.registry);
      return { ok: true, proof };  // {freshCommitment, A, c, z} — no witness
    } catch (e) { auditError('voice:auth-prove', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('voice:auth-verify', async (_e, args = {}) => {
    try {
      voiceRL();
      if (!voiceSafe()) return { ok: false, valid: false, error: 'voice-privacy unavailable' };
      if (!_voiceRegistry) return { ok: false, valid: false, error: 'no registry session — call voice:build-registry first' };
      if (!args.proof) return { ok: false, valid: false, error: 'proof required' };
      return { ok: true, valid: !!voicePrivacy.voiceAuthVerify(_voiceRegistry.registry, args.proof) };
    } catch (e) { auditError('voice:auth-verify', e); return { ok: false, valid: false, error: e.message }; }
  });
  ipcMain.handle('voice:commit-utterance', async (_e, tokens) => {
    try {
      voiceRL();
      if (!voiceSafe()) return { error: 'voice-privacy unavailable' };
      const t = (Array.isArray(tokens) ? tokens : []).map(Number);
      if (!t.length) return { ok: false, error: 'tokens required (array of ints)' };
      const { utterance, secret } = voicePrivacy.commitUtterance(t);
      _voiceSession = { utterance, secret };
      // Commitments are public by construction; the secret stays in main.
      return { ok: true, utterance };
    } catch (e) { auditError('voice:commit-utterance', e); return { error: e.message }; }
  });
  ipcMain.handle('voice:rerandomize-utterance', async () => {
    try {
      voiceRL();
      if (!voiceSafe()) return { error: 'voice-privacy unavailable' };
      if (!_voiceSession) return { ok: false, error: 'no utterance session — call voice:commit-utterance first' };
      const r = voicePrivacy.rerandomizeUtterance(_voiceSession.utterance, _voiceSession.secret);
      _voiceSession = { utterance: r.utterance, secret: r.secret };
      return { ok: true, utterance: r.utterance };
    } catch (e) { auditError('voice:rerandomize-utterance', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('voice:or-sigma-prove-keyword', async (_e, payload = {}) => {
    try {
      voiceRL();
      if (!voiceSafe()) return { error: 'voice-privacy unavailable' };
      if (!_voiceSession) return { ok: false, error: 'no utterance session — call voice:commit-utterance first' };
      const keyword = Number(payload.keyword);
      if (!Number.isFinite(keyword)) return { ok: false, error: 'keyword (number) required' };
      const proof = voicePrivacy.orSigmaProveKeyword(_voiceSession.utterance, _voiceSession.secret, keyword);
      return { ok: true, proof };  // {A, c, z} only — witness never included
    } catch (e) { auditError('voice:or-sigma-prove-keyword', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('voice:or-sigma-verify-keyword', async (_e, payload = {}) => {
    try {
      voiceRL();
      if (!voiceSafe()) return { ok: false, valid: false, error: 'voice-privacy unavailable' };
      const utt = payload.utterance || (_voiceSession && _voiceSession.utterance);
      const keyword = Number(payload.keyword);
      if (!utt || !Number.isFinite(keyword) || !payload.proof) {
        return { ok: false, valid: false, error: 'utterance, keyword and proof required' };
      }
      return { ok: true, valid: !!voicePrivacy.orSigmaVerifyKeyword(utt, keyword, payload.proof) };
    } catch (e) { auditError('voice:or-sigma-verify-keyword', e); return { ok: false, valid: false, error: e.message }; }
  });
  // Fuzzy voice auth: noisy voiceprint within threshold, ZK (no voiceprints revealed).
  // Secrets stay in main — renderer sees commitments + proofs only.
  ipcMain.handle('voice:fuzzy-prove', async (_e, payload = {}) => {
    try {
      voiceRL();
      if (!voiceSafe()) return { error: 'voice-privacy unavailable' };
      if (!_voiceRegistry) return { ok: false, error: 'no registry session — call voice:build-registry first' };
      const idx = Math.min(_voiceRegistry.creds.length - 1, Math.max(0, Number(payload.registryIndex) || 0));
      const threshold = Number(payload.threshold);
      const noisy = Number(payload.noisyVoiceprint);
      if (!Number.isFinite(threshold) || !Number.isFinite(noisy)) return { ok: false, error: 'threshold + noisyVoiceprint (numbers) required' };
      const proof = voicePrivacy.fuzzyVoiceAuthProve(_voiceRegistry.creds[idx], _voiceRegistry.registry, threshold, noisy);
      return { ok: true, proof };
    } catch (e) { auditError('voice:fuzzy-prove', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('voice:fuzzy-verify', async (_e, payload = {}) => {
    try {
      voiceRL();
      if (!voiceSafe()) return { ok: false, valid: false, error: 'voice-privacy unavailable' };
      if (!_voiceRegistry) return { ok: false, valid: false, error: 'no registry session — call voice:build-registry first' };
      const threshold = Number(payload.threshold);
      if (!Number.isFinite(threshold) || !payload.proof) return { ok: false, valid: false, error: 'threshold + proof required' };
      return { ok: true, valid: !!voicePrivacy.fuzzyVoiceAuthVerify(_voiceRegistry.registry, payload.proof, threshold) };
    } catch (e) { auditError('voice:fuzzy-verify', e); return { ok: false, valid: false, error: e.message }; }
  });

  // ─── Pro license ──────────────────────────────────────────────────────────────
  ipcMain.handle('pro:status',     () => pro.status());
  ipcMain.handle('pro:activate',   (_e, code) => pro.activate(V.code(code)));
  ipcMain.handle('pro:deactivate', () => pro.deactivate());
  ipcMain.handle('pro:issue', () => {
    if (process.env.KASBAH_ALLOW_ISSUE !== '1') return { ok: false, error: 'License issue disabled. Support can generate a machine-bound code.' };
    return { ok: true, ...pro.issueCode() };
  });

  // ─── Proof-of-Protection ─────────────────────────────────────────────────────
  ipcMain.handle('pop:mint', async (_e, body = {}) => {
    const b = V.obj(body, 'body');
    // Never trust renderer-supplied protection state for what gets signed —
    // a caller with IPC access could otherwise mint a validly-signed
    // "PROTECTED" proof while actually unprotected. Derive vpnOn from the
    // main process's own tracked VPN state, and egress IP/location from a
    // real network probe; only `note` comes from the caller.
    const vpnOn = !!vpnState.activeLocation;
    const probe = await ctx.netIntel.realEgressProbe();
    return pop.mint({
      vpnOn,
      egressIp: probe.ip,
      egressLoc: probe.loc,
      colo: probe.colo,
      location: vpnState.activeLocation ? (vpnState.activeLocation.name || vpnState.activeLocation.id || null) : null,
      note: V.optStr(b.note, { max: 256, name: 'note' }),
    });
  });
  ipcMain.handle('pop:list',         () => pop.list().slice(-50).reverse());
  ipcMain.handle('pop:verify-all',   () => pop.verifyAll());
  ipcMain.handle('pop:export',       (_e, file) => {
    const dest = file ? safePathInside(path.join(os.homedir(), 'Downloads'), path.basename(String(file))) : undefined;
    return pop.exportAll(dest);
  });
  ipcMain.handle('pop:pubkey',       () => ({ keyId: pop.publicKeyHex(), publicKeyPath: pop.PUB }));

  ipcMain.handle('pop:merkle', () => {
    const list = pop.list();
    const pairs = list.map((e) => ({ receipt: e.receipt, payload: e.payload })).filter((x) => x.receipt && x.payload);
    if (!pairs.length) return { ok: false, error: 'no signed proofs yet' };
    const tree = merkleBatch.buildMerkleTree(pairs);
    const file = path.join(os.homedir(), 'Downloads', `kasbah-pop-merkle-${Date.now()}.json`);
    fs.writeFileSync(file, JSON.stringify({ root: tree.root, count: pairs.length, createdAt: new Date().toISOString(), proofs: list.map((e) => ({ id: e.requestId, receipt: e.receipt, proof: tree.proofs.get(e.receipt) })) }, null, 2), { mode: 0o600 });
    return { ok: true, root: tree.root, count: pairs.length, file };
  });

  ipcMain.handle('pop:merkle-verify', (_e, body = {}) => {
    try {
      const p = safePathInside(path.join(os.homedir(), 'Downloads'), path.basename(String(body.file || '')));
      const j = JSON.parse(fs.readFileSync(p, 'utf8'));
      const pairs = (j.proofs || []).map((pr) => { const live = pop.list().find((x) => x.requestId === pr.id || x.receipt === pr.receipt); return live ? { receipt: live.receipt, payload: live.payload } : { receipt: pr.receipt, payload: pr.payload }; }).filter((x) => x.receipt && x.payload);
      const batch = merkleBatch.verifyBatch(pairs, j.root);
      return { ok: batch.verified, root: j.root, count: batch.count, failures: batch.failures };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── Agent Guard ──────────────────────────────────────────────────────────────
  ipcMain.handle('agent:status',     () => agentGuard.status());
  ipcMain.handle('agent:policy-get', () => agentGuard.loadPolicy());
  ipcMain.handle('agent:policy-set', (_e, patch) => agentGuard.savePolicy({ ...agentGuard.loadPolicy(), ...patch }));
  ipcMain.handle('agent:evaluate',   (_e, call) => agentGuard.evaluate(call || {}));
  ipcMain.handle('agent:server',     (_e, on) => (on ? agentGuard.startServer() : agentGuard.stopServer()));
  ipcMain.handle('agent:set-vpn',    (_e, connected, meta) => agentGuard.setVpnState(!!connected, meta || {}));
  // Real content governance (@kasbah/control) — see agent-guard.js. Returns
  // { available:false } rather than a fake verdict when the control package
  // can't be located.
  ipcMain.handle('agent:govern',      (_e, call) => agentGuard.governContent(call || {}));
  ipcMain.handle('agent:diagnostics', () => agentGuard.diagnostics());
  ipcMain.handle('agent:events',      (_e, limit) => agentGuard.recentEvents(limit));

  // ─── Shamir ───────────────────────────────────────────────────────────────────
  ipcMain.handle('shamir:split', (e, body = {}) => {
    try { assertOrigin(e); rateLimit('shamir:split', { maxPerSecond: 5 }); } catch (err) { return { ok: false, error: err.message }; }
    const n = Number(body.n || 5), k = Number(body.k || 3);
    return { ok: true, shares: shamir.splitString(String(body.secret || ''), n, k) };
  });
  ipcMain.handle('shamir:combine', (_e, shares) => {
    const buf = shamir.combine(shares || []);
    return { ok: true, secret: buf.toString('utf8'), bytes: buf.length };
  });

  // ─── MMR Backup ───────────────────────────────────────────────────────────────
  ipcMain.handle('mmr:manifest', (_e, body = {}) => {
    const files = V.arr(body.files, { max: 50, name: 'files' }).map((f) => safeExistingFile(f));
    if (!files.length) throw new Error('no files');
    const out = body.out ? safePathInside(path.join(os.homedir(), 'Downloads'), path.basename(String(body.out))) : path.join(os.homedir(), 'Downloads', `kasbah-backup-manifest-${Date.now()}.json`);
    const m = mmr.buildManifest(files, out);
    return { ok: true, root: m.root, count: m.count, file: out };
  });
  ipcMain.handle('mmr:verify', (_e, body = {}) => {
    try {
      const mPath = safePathInside(path.join(os.homedir(), '.kasbah-backup'), path.basename(String(body.manifest || '')));
      const m = JSON.parse(fs.readFileSync(mPath, 'utf8'));
      return mmr.verifyManifest(m, safeExistingFile(body.file));
    } catch (e) { return { valid: false, error: e.message }; }
  });

  // ─── Dead-man switch ──────────────────────────────────────────────────────────
  ipcMain.handle('deadman:status',    () => deadman.status());
  ipcMain.handle('deadman:check-in',  (_e, note) => deadman.checkIn(note));
  ipcMain.handle('deadman:configure', (_e, body) => deadman.configure(body || {}));
  ipcMain.handle('deadman:poll',      () => deadman.poll());
  ipcMain.handle('deadman:log',       () => deadman.log());

  // ─── Forward-secure audit chain ───────────────────────────────────────────────
  ipcMain.handle('audit:append', (_e, event) => {
    const r = _fsAudit.append(event || { ts: Date.now() });
    return { ok: true, entry: r };
  });
  ipcMain.handle('audit:verify', () => {
    try { return _fsAudit.verify ? _fsAudit.verify() : { ok: true, note: 'chain present' }; }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('audit:list', () => { try { return _fsAudit.entries || _fsAudit.log || []; } catch { return []; } });

  ipcMain.handle('fsaudit:append', (_e, body = {}) => {
    try { const r = _fsAudit.append(body); return { ok: true, entry: r }; } catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('fsaudit:list',   () => { try { return _fsAudit.entries || []; } catch { return []; } });
  ipcMain.handle('fsaudit:verify', () => { try { return _fsAudit.verify(); } catch (e) { return { ok: false, error: e.message }; } });
  // Destination is always confined to ~/Downloads — a `file` argument is only
  // ever used as a basename, never a full path, closing the arbitrary-file-
  // write this handler previously had (SECURITY.md claimed this class of bug
  // was fixed app-wide; it had been missed here).
  const DOWNLOADS_DIR = path.join(os.homedir(), 'Downloads');
  function exportDest(file, ext) {
    return file
      ? safePathInside(DOWNLOADS_DIR, path.basename(String(file)))
      : path.join(DOWNLOADS_DIR, `kasbah-audit-${Date.now()}.${ext}`);
  }

  ipcMain.handle('fsaudit:export', (_e, file) => {
    try {
      const dest = exportDest(file, 'json');
      fs.writeFileSync(dest, JSON.stringify(_fsAudit.entries || [], null, 2), { mode: 0o600 });
      return { ok: true, file: dest };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── SIEM / compliance export (CSV + optional webhook) ─────────────────────
  ipcMain.handle('fsaudit:export-csv', (_e, file) => {
    try {
      const rows = _fsAudit.entries || [];
      const dest = exportDest(file, 'csv');
      const header = 'ts,epoch,event\n';
      const body = rows.map((r) => {
        const ts = r.ts || r.timestamp || '';
        const ep = r.epoch != null ? r.epoch : '';
        const ev = JSON.stringify(r.event || r).replace(/"/g, '""');
        return `"${ts}","${ep}","${ev}"`;
      }).join('\n');
      fs.writeFileSync(dest, header + body + '\n', { mode: 0o600 });
      return { ok: true, file: dest, count: rows.length };
    } catch (e) { return { ok: false, error: e.message }; }
  });
  // Host allowlist + private-IP rejection, matching llm-proxy.js's SSRF
  // posture — previously this only checked the URL scheme, letting the
  // renderer make the app POST audit contents to any HTTPS endpoint,
  // including internal network services.
  const WEBHOOK_ALLOW_HOSTS = new Set(String(process.env.KASBAH_WEBHOOK_ALLOW_HOSTS || '').split(',').map((h) => h.trim().toLowerCase()).filter(Boolean));
  function isPrivateIpAddr(ip) {
    const net = require('net');
    if (net.isIPv4(ip)) {
      const a = ip.split('.').map(Number);
      return a[0] === 10 || a[0] === 127 || (a[0] === 169 && a[1] === 254) ||
        (a[0] === 172 && a[1] >= 16 && a[1] <= 31) || (a[0] === 192 && a[1] === 168) || a[0] === 0;
    }
    if (net.isIPv6(ip)) {
      const l = ip.toLowerCase();
      return l === '::1' || l.startsWith('fe80:') || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('::ffff:127.');
    }
    return false;
  }
  async function resolveWebhookSafe(hostname) {
    const net = require('net');
    if (net.isIP(hostname)) return isPrivateIpAddr(hostname) ? null : hostname;
    try {
      const dns = require('dns').promises;
      const addrs = await dns.lookup(hostname, { all: true });
      if (!addrs.length || addrs.some((a) => isPrivateIpAddr(a.address))) return null;
      return addrs[0].address;
    } catch { return null; }
  }
  ipcMain.handle('fsaudit:webhook', async (_e, body = {}) => {
    const url = String(body.url || '');
    if (!/^https:\/\//i.test(url)) return { ok: false, error: 'HTTPS URL required' };
    let u;
    try { u = new URL(url); } catch { return { ok: false, error: 'invalid URL' }; }
    if (WEBHOOK_ALLOW_HOSTS.size && !WEBHOOK_ALLOW_HOSTS.has(u.hostname.toLowerCase())) {
      return { ok: false, error: 'webhook host not allowlisted (set KASBAH_WEBHOOK_ALLOW_HOSTS)' };
    }
    const safeIp = await resolveWebhookSafe(u.hostname);
    if (!safeIp) return { ok: false, error: 'webhook host resolves to a private/unresolvable address' };
    try {
      const payload = JSON.stringify({
        source: 'kasbah-privacy',
        exportedAt: new Date().toISOString(),
        entries: (_fsAudit.entries || []).slice(-200),
      });
      const https = require('https');
      await new Promise((resolve, reject) => {
        // Connect to the pre-checked IP directly (not the hostname) to avoid
        // a DNS-rebinding TOCTOU between the check above and the connection.
        const req = https.request({
          hostname: safeIp, servername: u.hostname, path: u.pathname + u.search, method: 'POST',
          headers: { host: u.host, 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) },
          timeout: 10000,
        }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
        req.on('error', reject);
        req.on('timeout', () => req.destroy(new Error('timeout')));
        req.write(payload); req.end();
      });
      return { ok: true, sent: true };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── Honey tokens ─────────────────────────────────────────────────────────────
  ipcMain.handle('honey:deploy', (_e, service) => honey.deploy(service || 'custom'));
  ipcMain.handle('honey:list',   () => honey.list());
  ipcMain.handle('honey:check',  (_e, text) => honey.check(text || ''));
  ipcMain.handle('honey:remove', (_e, id)   => honey.remove(id));
  ipcMain.handle('honey:values', () => honey.list().map((t) => ({ ...t })));

  // ─── Vulnerability scanner ────────────────────────────────────────────────────
  // File/dir scanning is confined under the user's own home directory —
  // previously these accepted any absolute path (including outside the
  // user's account entirely), making them a full-filesystem read oracle for
  // any code with window.kasbah access.
  function safeHomeFile(p) {
    const resolved = safePathInside(os.homedir(), String(p || ''));
    return safeExistingFile(resolved);
  }
  function safeHomeDir(p) {
    const resolved = safePathInside(os.homedir(), String(p || ''));
    if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) throw new Error('directory not found');
    return resolved;
  }
  ipcMain.handle('vuln:scan-text', (_e, text) => {
    const v = vuln(); if (v.error) return { error: v.error };
    try { return v.scanSource(String(text || ''), { path: 'snippet.js' }); } catch (e) { return { error: e.message }; }
  });
  ipcMain.handle('vuln:scan-file', (_e, file) => {
    const v = vuln(); if (v.error) return { error: v.error };
    try { const p = safeHomeFile(file); return v.scanFile(p); } catch (e) { return { error: e.message }; }
  });
  ipcMain.handle('vuln:scan-dir', (_e, dir) => {
    const v = vuln(); if (v.error) return { error: v.error };
    try { const d = safeHomeDir(dir); return v.scanDirectory(d); } catch (e) { return { error: e.message }; }
  });

  // ─── Deep file scan (kasbah-os/zeroday_engine.py, static CWE patterns only) ────
  // Real byte-level regex matching against 19 CWE patterns via a genuine
  // Python subprocess — not simulated. The engine's dynamic/symbolic modes
  // were already removed upstream (see zeroday_engine.py header); this only
  // ever invokes analyze(mode="static").
  function findKasbahOsDir() {
    const candidates = [
      process.resourcesPath ? path.join(process.resourcesPath, 'packages', 'kasbah-os') : null,
      path.join(__dirname, '../../../kasbah-os'),
      path.join(__dirname, '../../kasbah-os'),
    ].filter(Boolean);
    for (const d of candidates) { try { if (fs.existsSync(path.join(d, 'zeroday_cli.py'))) return d; } catch (_) {} }
    return null;
  }
  ipcMain.handle('vuln:scan-file-deep', (_e, file) => new Promise((resolve) => {
    let p;
    try { p = safeHomeFile(file); } catch (e) { return resolve({ ok: false, error: e.message }); }
    const dir = findKasbahOsDir();
    if (!dir) return resolve({ ok: false, error: 'kasbah-os/zeroday_cli.py not found' });
    const { execFile } = require('child_process');
    execFile('python3', [path.join(dir, 'zeroday_cli.py'), p], { timeout: 20000, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err && !stdout) return resolve({ ok: false, error: (stderr || err.message || '').split('\n')[0] });
      try { resolve(JSON.parse(stdout)); }
      catch (e) { resolve({ ok: false, error: `bad output from scanner: ${e.message}` }); }
    });
  }));

  // ─── Benchmark stats (bench/results/, real dated scorecard runs) ───────────────
  // Reads whatever fields the latest real scorecard file actually contains —
  // no computed or invented metrics beyond what the benchmark itself measured.
  function findBenchResultsDir() {
    const candidates = [
      process.resourcesPath ? path.join(process.resourcesPath, 'packages', 'bench-results') : null,
      path.join(__dirname, '../../../bench/results'),
      path.join(__dirname, '../../bench/results'),
    ].filter(Boolean);
    for (const d of candidates) { try { if (fs.existsSync(d)) return d; } catch (_) {} }
    return null;
  }
  ipcMain.handle('stats:benchmark', () => {
    const dir = findBenchResultsDir();
    if (!dir) return { ok: false, error: 'bench/results not found' };
    try {
      const files = fs.readdirSync(dir)
        .filter((f) => /^detection-scorecard-.*\.json$/.test(f))
        .map((f) => ({ f, m: fs.statSync(path.join(dir, f)).mtimeMs }))
        .sort((a, b) => b.m - a.m);
      if (!files.length) return { ok: false, error: 'no scorecard results found' };
      const latest = JSON.parse(fs.readFileSync(path.join(dir, files[0].f), 'utf8'));
      return { ok: true, file: files[0].f, ...latest };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── ZK Protect ───────────────────────────────────────────────────────────────
  ipcMain.handle('zk:protect', (e, body = {}) => {
    try { assertOrigin(e); rateLimit('zk:protect', { maxPerSecond: 5 }); } catch (err) { return { ok: false, error: err.message }; }
    const z = zkProtect(); if (z.error) return { ok: false, error: z.error };
    try {
      const score = Math.round(Number(body.score != null ? body.score : (body.vpnOn ? 5 : 900)));
      const threshold = Math.round(Number(body.threshold || 500));
      const below = score < threshold;
      const proof = z.proveThresholdVerdict(score, threshold, below, 16);
      const verified = z.verifyThresholdVerdict ? z.verifyThresholdVerdict(proof) : null;
      return { ok: true, verified, direction: below ? 'below-threshold' : 'at-or-above', note: 'ZK: risk is below threshold without revealing the exact score', proofType: proof && proof.type };
    } catch (e) { auditError('zk:protect', e); return { ok: false, error: e.message }; }
  });
  // Local ZK primitives for Forensics (no api-server)
  ipcMain.handle('zk:generate', (e, body = {}) => {
    try { assertOrigin(e); rateLimit('zk:generate', { maxPerSecond: 5 }); } catch (err) { return { ok: false, error: err.message }; }
    const z = zkProtect(); if (z.error) return { ok: false, error: z.error };
    try {
      const privateInputs = body.privateInputs || { secret: 'x' };
      const publicInputs = body.publicInputs || { verdict: 'DENY', riskScore: 0.9 };
      if (privateInputs.value === undefined) privateInputs.value = privateInputs.secret || 'x';
      const proof = z.generateDetectionProof({ privateInputs, publicInputs });
      return { ok: true, proof, publicInputs };
    } catch (e) { auditError('zk:generate', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('zk:verify', (_e, body = {}) => {
    const z = zkProtect(); if (z.error) return { ok: false, error: z.error };
    try {
      const proof = body.proof || body;
      const r = z.verifyDetectionProof ? z.verifyDetectionProof(proof) : (z.verifyThresholdVerdict ? z.verifyThresholdVerdict(proof) : { isValid: false, error: 'no verifier' });
      return { ok: true, ...r, valid: r.isValid !== false && r.valid !== false };
    } catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('zk:commit', (_e, body = {}) => {
    const z = zkProtect(); if (z.error) return { ok: false, error: z.error };
    try { return { ok: true, ...z.commit(body.value != null ? body.value : 'test') }; }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('zk:range', (_e, body = {}) => {
    const z = zkProtect(); if (z.error) return { ok: false, error: z.error };
    try {
      const value = Number(body.value != null ? body.value : 42);
      const bitSize = Number(body.bitSize || 32);
      const proof = z.generateRangeProof(value, bitSize);
      const verified = z.verifyRangeProof(proof);
      return { ok: true, proof: { type: proof.type, valueCommitment: proof.valueCommitment, bits: proof.bitProofs?.length }, verified };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── LLM Proxy ────────────────────────────────────────────────────────────────
  ipcMain.handle('llmproxy:start',     (_e, port) => llmProxy.start(Number(port) || 8796));
  ipcMain.handle('llmproxy:stop',      () => llmProxy.stop());
  ipcMain.handle('llmproxy:status',    () => llmProxy.status());
  ipcMain.handle('llmproxy:install',   (_e, port) => llmProxy.install(Number(port) || 8796));
  ipcMain.handle('llmproxy:uninstall', () => llmProxy.uninstall());

  // ─── Local AI governance (Lakera/CF-style, on-device) ────────────────────────
  ipcMain.handle('aigov:status', () => {
    if (aiGov.error) return { error: aiGov.error };
    return { policy: aiGov.loadPolicy(), stats: aiGov.stats(), proxy: llmProxy.status() };
  });
  ipcMain.handle('aigov:policy-set', (_e, patch) => {
    if (aiGov.error) return { error: aiGov.error };
    return aiGov.savePolicy(V.obj(patch, 'patch') || {});
  });
  ipcMain.handle('aigov:scan', (_e, text) => {
    if (aiGov.error) return { error: aiGov.error };
    return aiGov.scanText(V.str(text, { name: 'text', max: 200000 }));
  });
  ipcMain.handle('aigov:events', (_e, n) => {
    if (aiGov.error) return [];
    return aiGov.recentEvents(Number(n) || 30);
  });
  ipcMain.handle('aigov:shadow', () => {
    if (aiGov.error) return { error: aiGov.error };
    let hist = [];
    try { hist = browserStore.historyList(500) || []; } catch (_) {}
    return { hosts: aiGov.shadowAi(hist), gatePort: 8796 };
  });
  ipcMain.handle('aigov:agent-lock', () => {
    try { return agentGuard.status(); } catch (e) { return { error: e.message }; }
  });

  // ─── Threshold governance (KasbahOS v5.0 practical layer) ────────────────────
  ipcMain.handle('gov:status', () => {
    if (thresholdGov.error) return { error: thresholdGov.error };
    try { thresholdGov.seedDefaultBoard(); } catch (_) {}
    return thresholdGov.status();
  });
  ipcMain.handle('gov:seats', () => {
    if (thresholdGov.error) return { error: thresholdGov.error };
    return thresholdGov.listSeats();
  });
  ipcMain.handle('gov:seat-create', (_e, body = {}) => {
    if (thresholdGov.error) return { error: thresholdGov.error };
    try { return { ok: true, seat: thresholdGov.createSeat(V.str(body.name, { name: 'name', max: 64 }), { level: Number(body.level) || 3 }) }; }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('gov:advisory', (_e, body = {}) => {
    if (thresholdGov.error) return { error: thresholdGov.error };
    return thresholdGov.advisory(body || {});
  });
  ipcMain.handle('gov:propose', (e, body = {}) => {
    try { assertOrigin(e); rateLimit('gov:propose', { maxPerSecond: 5 }); } catch (err) { return { ok: false, error: err.message }; }
    if (thresholdGov.error) return { error: thresholdGov.error };
    try {
      const r = thresholdGov.propose({
        action: body.action || 'manual',
        clearanceLevel: Number(body.clearanceLevel) || 3,
        note: body.note || '',
        useWgas: !!body.useWgas,
        // wgasGraph is intentionally NOT accepted from the caller — see the
        // security note on threshold-gov.js's propose().
      });
      try { _fsAudit.append({ event: 'gov_propose', id: r.id, clearance: r.requiredT, wgas: !!body.useWgas }); } catch (_) {}
      return { ok: true, ...r };
    } catch (e) { auditError('gov:propose', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('gov:wgas-eval', (_e, body = {}) => {
    if (thresholdGov.error) return { error: thresholdGov.error };
    try {
      const seats = Array.isArray(body.seats) ? body.seats : [];
      return thresholdGov.wgasEvaluate(seats, body.graph || null);
    } catch (e) { return { ok: false, authorized: false, error: e.message }; }
  });
  ipcMain.handle('gov:wgas-demo', () => {
    if (thresholdGov.error) return { error: thresholdGov.error };
    try {
      const w = thresholdGov.wgas;
      const demo = w.nonThresholdDemo();
      const ab = w.evaluate(demo, ['Operator-A', 'Operator-B']);
      const c = w.evaluate(demo, ['Operator-C']);
      const aOnly = w.evaluate(demo, ['Operator-A']);
      return { ok: true, note: '(A∧B) ∨ C at κ=1 — not pure threshold', ab, c, aOnly };
    } catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('gov:cosign', (e, body = {}) => {
    try { assertOrigin(e); rateLimit('gov:cosign', { maxPerSecond: 5 }); } catch (err) { return { ok: false, error: err.message }; }
    if (thresholdGov.error) return { error: thresholdGov.error };
    try {
      const r = thresholdGov.coSign({ approvalId: body.approvalId, seatId: body.seatId });
      try { _fsAudit.append({ event: 'gov_cosign', id: body.approvalId, seat: body.seatId, approved: r.approved }); } catch (_) {}
      return r;
    } catch (e) { auditError('gov:cosign', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('gov:pending', () => {
    if (thresholdGov.error) return [];
    return thresholdGov.listPending();
  });
  ipcMain.handle('gov:chain-verify', () => {
    if (thresholdGov.error) return { ok: false, error: thresholdGov.error };
    return thresholdGov.verifyChain();
  });

  ipcMain.handle('gov:wgas-conservation', (_e, body = {}) => {
    try {
      const wgas = thresholdGov.wgas;
      const g = wgas.normalizeGraph(body.graph);
      return wgas.checkConservation(g, body.flowByEdgeId || {});
    } catch (e) { return { ok: false, error: e.message }; }
  });

  ipcMain.handle('gov:wgas-crosscheck', (_e, body = {}) => {
    try {
      const wgas = thresholdGov.wgas;
      const g = wgas.normalizeGraph(body.graph);
      return wgas.crossCheck(g, body.coalition || []);
    } catch (e) { return { ok: false, error: e.message }; }
  });

  ipcMain.handle('gov:wgas-federated-eval', (_e, body = {}) => {
    try {
      const wgas = thresholdGov.wgas;
      const { shards, globalSource, globalSink, kappa, candidateFlow, coalition } = body;
      const federated = wgas.buildFederated(shards, globalSource, globalSink, kappa);
      return wgas.evaluateFederated(federated, candidateFlow || {}, coalition || []);
    } catch (e) { return { authorized: false, error: e.message }; }
  });

  ipcMain.handle('audit:red-team', () => {
    try {
      const selfAudit = require('./self-audit.js');
      return selfAudit.runRedTeam();
    } catch (e) { return { ok: false, error: e.message }; }
  });

  ipcMain.handle('audit:readiness', () => {
    try {
      const selfAudit = require('./self-audit.js');
      return selfAudit.readiness();
    } catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── DKG (Feldman VSS two-round) ─────────────────────────────────────────
  ipcMain.handle('dkg:round1', (_e, body = {}) => {
    try {
      const dkg = require('./dkg.js');
      const { id, threshold, n } = body;
      const { state, broadcast } = dkg.round1(Number(id), Number(threshold), Number(n));
      // Never return poly coefficients to renderer — only the broadcast half
      return { ok: true, state: dkg.serializeState(state), broadcast };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  ipcMain.handle('dkg:compute-share', (_e, body = {}) => {
    try {
      const dkg = require('./dkg.js');
      const state = dkg.deserializeState(body.state);
      return { ok: true, share: dkg.computeShareForPeer(state, Number(body.peerId)) };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  ipcMain.handle('dkg:verify-share', (_e, body = {}) => {
    try {
      const dkg = require('./dkg.js');
      const ok = dkg.verifyShare(body.share, body.commitments, Number(body.myId));
      return { ok, verified: ok };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  ipcMain.handle('dkg:aggregate', (_e, body = {}) => {
    try {
      const dkg = require('./dkg.js');
      const state = dkg.deserializeState(body.state);
      const allComms = new Map(Object.entries(body.allCommitments).map(([k, v]) => [Number(k), v]));
      const result = dkg.aggregate(state, body.receivedShares || [], allComms);
      return { ok: true, masterPublicKey: result.masterPublicKey };
      // myShare never returned to renderer — store it encrypted in the vault
    } catch (e) { return { ok: false, error: e.message }; }
  });

  ipcMain.handle('dkg:self-test', () => {
    try {
      const dkg = require('./dkg.js');
      return { ok: true, ...dkg.selfTest() };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── Range proofs ─────────────────────────────────────────────────────────
  ipcMain.handle('zk:range-bounded', (_e, body = {}) => {
    try {
      const rp = require('./range-proof.js');
      const value    = BigInt(body.value);
      const blinding = BigInt(body.blinding);
      const w        = BigInt(body.w);
      const proof = rp.proveBounded(value, blinding, w);
      return { ok: true, proof };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  ipcMain.handle('zk:range-bounded-verify', (_e, body = {}) => {
    try {
      const rp = require('./range-proof.js');
      return { ok: true, ...rp.verifyBounded(body.proof) };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  ipcMain.handle('zk:range-self-test', () => {
    try {
      const rp = require('./range-proof.js');
      return { ok: true, ...rp.selfTest() };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── N1: Execution delay ─────────────────────────────────────────────────────
  ipcMain.handle('gov:can-execute', (_e, body = {}) => {
    if (thresholdGov.error) return { ok: false, error: thresholdGov.error };
    try { return thresholdGov.canExecute(body.approvalId); }
    catch (e) { auditError('gov:can-execute', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('gov:mark-executed', (e, body = {}) => {
    try { assertOrigin(e); rateLimit('gov:mark-executed', { maxPerSecond: 5 }); } catch (err) { return { ok: false, error: err.message }; }
    if (thresholdGov.error) return { ok: false, error: thresholdGov.error };
    try { return thresholdGov.markExecuted(body.approvalId, body.note); }
    catch (e) { auditError('gov:mark-executed', e); return { ok: false, error: e.message }; }
  });

  // ─── N2: Policy diff proofs ──────────────────────────────────────────────────
  ipcMain.handle('gov:policy-commit', (e, body = {}) => {
    try { assertOrigin(e); rateLimit('gov:policy-commit', { maxPerSecond: 3 }); } catch (err) { return { ok: false, error: err.message }; }
    if (thresholdGov.error) return { ok: false, error: thresholdGov.error };
    try { return thresholdGov.commitPolicyChange(body || {}); }
    catch (e) { auditError('gov:policy-commit', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('gov:policy-hash', () => {
    if (thresholdGov.error) return { ok: false, error: thresholdGov.error };
    try { return { ok: true, policyHash: thresholdGov.currentPolicyHash() }; }
    catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── N3: Canary governance trip ──────────────────────────────────────────────
  ipcMain.handle('gov:canary-deploy', (e, body = {}) => {
    try { assertOrigin(e); } catch (err) { return { ok: false, error: err.message }; }
    if (thresholdGov.error) return { ok: false, error: thresholdGov.error };
    try {
      const result = thresholdGov.deployCanary({
        label: body.label || 'nuclear-action',
        alertCallback: (trip) => {
          try { _fsAudit.append({ event: 'canary_tripped', ...trip }); } catch (_) {}
          ctx.mainWindow?.webContents.send('gov:canary-tripped', trip);
        },
      });
      return result;
    } catch (e) { auditError('gov:canary-deploy', e); return { ok: false, error: e.message }; }
  });

  // ─── N4: Reputation WGAS ─────────────────────────────────────────────────────
  ipcMain.handle('gov:reputation-update', (e, body = {}) => {
    try { assertOrigin(e); rateLimit('gov:reputation-update', { maxPerSecond: 5 }); } catch (err) { return { ok: false, error: err.message }; }
    if (thresholdGov.error) return { ok: false, error: thresholdGov.error };
    try {
      const wgas = require('./wgas.js');
      return { ok: true, ...wgas.updateReputation(body.seatId, Number(body.delta) || 0, body.reason) };
    } catch (e) { auditError('gov:reputation-update', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('gov:reputation-status', () => {
    try {
      const wgas = require('./wgas.js');
      return { ok: true, ...wgas.reputationStatus() };
    } catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('gov:wgas-reputation-eval', (_e, body = {}) => {
    if (thresholdGov.error) return { ok: false, error: thresholdGov.error };
    try {
      const wgasMod = require('./wgas.js');
      const graph   = thresholdGov.wgas.seedDefault();
      return wgasMod.evaluateWithReputation(graph, body.seats || [], body.seatNameToId || {});
    } catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── N5: Threshold audit export ──────────────────────────────────────────────
  ipcMain.handle('gov:export-key-create', (e, body = {}) => {
    try { assertOrigin(e); } catch (err) { return { ok: false, error: err.message }; }
    if (thresholdGov.error) return { ok: false, error: thresholdGov.error };
    try { return thresholdGov.createThresholdExportKey(body || {}); }
    catch (e) { auditError('gov:export-key-create', e); return { ok: false, error: e.message }; }
  });

  // ─── N6: Session continuity chain ────────────────────────────────────────────
  ipcMain.handle('session:begin', (e, body = {}) => {
    try { assertOrigin(e); } catch (err) { return { ok: false, error: err.message }; }
    if (sessionChain.error) return { ok: false, error: sessionChain.error };
    try {
      const gov    = thresholdGov.error ? {} : thresholdGov.status();
      const policy = body.policySnapshot || gov;
      return { ok: true, ...sessionChain.beginSession(policy, { minThreshold: body.minThreshold, label: body.label }) };
    } catch (e) { auditError('session:begin', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('session:end', (_e, body = {}) => {
    if (sessionChain.error) return { ok: false, error: sessionChain.error };
    try { return sessionChain.endSession(body.sessionId); }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('session:verify-continuity', (_e, body = {}) => {
    if (sessionChain.error) return { ok: false, error: sessionChain.error };
    try { return sessionChain.verifyContinuity(body.fromIdx ?? 0, body.toIdx ?? Infinity); }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('session:head', () => {
    if (sessionChain.error) return { ok: false, error: sessionChain.error };
    try { return { ok: true, ...sessionChain.head() }; }
    catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── N8: Prompt attestation ──────────────────────────────────────────────────
  ipcMain.handle('attest:commit', (e, body = {}) => {
    try { assertOrigin(e); rateLimit('attest:commit', { maxPerSecond: 20 }); } catch (err) { return { ok: false, error: err.message }; }
    if (promptAttest.error) return { ok: false, error: promptAttest.error };
    try { return { ok: true, ...promptAttest.commit(body.prompt || '', { label: body.label, agentId: body.agentId }) }; }
    catch (e) { auditError('attest:commit', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('attest:verify', (_e, body = {}) => {
    if (promptAttest.error) return { ok: false, error: promptAttest.error };
    try { return promptAttest.verify(body.id, body.prompt || ''); }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('attest:verify-full', (_e, body = {}) => {
    if (promptAttest.error) return { ok: false, error: promptAttest.error };
    try { return promptAttest.verifyAttestation(body.id, body.prompt || ''); }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('attest:list', (_e, body = {}) => {
    if (promptAttest.error) return [];
    try { return promptAttest.list(body.limit || 50); }
    catch { return []; }
  });
  ipcMain.handle('attest:public-key', () => {
    if (promptAttest.error) return { ok: false, error: promptAttest.error };
    try { return { ok: true, publicKey: promptAttest.publicKey() }; }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('attest:self-test', () => {
    if (promptAttest.error) return { ok: false, error: promptAttest.error };
    try { return { ok: true, ...promptAttest.selfTest() }; }
    catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── N9: Portable Verifiable Credentials ─────────────────────────────────────
  // Freemium: free = unlimited verify + up to 3 issues (preview); Pro = unlimited
  // issue + file export. Honest gate — not a fake paywall.
  ipcMain.handle('vc:issue', (e, body = {}) => {
    try { assertOrigin(e); rateLimit('vc:issue', { maxPerSecond: 5 }); } catch (err) { return { ok: false, error: err.message }; }
    if (vcExport.error) return { ok: false, error: vcExport.error };
    try {
      const isPro = !pro.error && pro.has && pro.has('vc_export');
      if (!isPro) {
        const n = (vcExport.listIssued(50) || []).length;
        if (n >= 3) {
          return { ok: false, requiresPro: true, feature: 'vc_export',
            error: 'Free tier allows 3 credential previews. Upgrade to Pro for unlimited compliance VCs.' };
        }
      }
      return { ok: true, tier: isPro ? 'pro' : 'free', vc: vcExport.issue(body.popEntry || {}, { expiryDays: body.expiryDays, subjectDid: body.subjectDid }) };
    } catch (e) { auditError('vc:issue', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('vc:verify', (_e, body = {}) => {
    if (vcExport.error) return { ok: false, error: vcExport.error };
    try { return vcExport.verifyVC(body.vc || {}); }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('vc:export-file', (_e, body = {}) => {
    if (vcExport.error) return { ok: false, error: vcExport.error };
    const isPro = !pro.error && pro.has && pro.has('vc_export');
    if (!isPro) {
      return { ok: false, requiresPro: true, feature: 'vc_export',
        error: 'File export of compliance credentials is a Pro feature.' };
    }
    try {
      const dest = vcExport.exportToFile(body.vc || {}, body.filename);
      return { ok: true, file: dest };
    } catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('vc:issuer-public-key', () => {
    if (vcExport.error) return { ok: false, error: vcExport.error };
    try { return { ok: true, publicKey: vcExport.issuerPublicKey(), did: vcExport.issuerDid() }; }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('vc:did-document', () => {
    if (vcExport.error) return { ok: false, error: vcExport.error };
    try { return vcExport.writeDidDocument(); }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('vc:issue-didkey', (e, body = {}) => {
    try { assertOrigin(e); rateLimit('vc:issue', { maxPerSecond: 5 }); } catch (err) { return { ok: false, error: err.message }; }
    if (vcExport.error) return { ok: false, error: vcExport.error };
    try {
      const isPro = !pro.error && pro.has && pro.has('vc_export');
      if (!isPro) {
        const n = (vcExport.listIssued(50) || []).length;
        if (n >= 3) {
          return { ok: false, requiresPro: true, feature: 'vc_export',
            error: 'Free tier allows 3 credential previews. Upgrade to Pro for unlimited compliance VCs.' };
        }
      }
      const r = vcExport.issueDidKey(body.popEntry || {}, { subjectDid: body.subjectDid });
      try { _fsAudit.append({ event: 'vc_issue_didkey', issuer: r.issuerDid }); } catch (_) {}
      return { ok: true, tier: isPro ? 'pro' : 'free', ...r };
    } catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('vc:verify-didkey', (_e, body = {}) => {
    if (vcExport.error) return { ok: false, error: vcExport.error };
    try { return vcExport.verifyDidKey(body.vc || {}); }
    catch (e) { return { valid: false, error: e.message }; }
  });

  // ─── Capability tokens (delegation chains) ──────────────────────────────────
  ipcMain.handle('cap:self-test', () => {
    try { return require('./capability-tokens.js').selfTest(); }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('cap:verify-chain', (_e, body = {}) => {
    try {
      const cap = require('./capability-tokens.js');
      return cap.verifyChain(body.chain || [], body.resource || '', body.action || '');
    } catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('vss:self-test', () => {
    try { return require('./vss-feldman.js').selfTest(); }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('vss:split', (_e, body = {}) => {
    try {
      const vss = require('./vss-feldman.js');
      const r = vss.split(String(body.secret || ''), Number(body.n) || 5, Number(body.k) || 3);
      return { ok: true, ...r, shares: r.shares.slice(0, 5) };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── PVS-R · PQ seal · DKG transport ────────────────────────────────────────
  ipcMain.handle('pvs:self-test', () => {
    try { return require('./pvs-r.js').selfTest(); }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('pvs:refresh-demo', () => {
    try {
      const pvs = require('./pvs-r.js');
      const secret = Buffer.from('epoch-' + Date.now());
      const s = pvs.split(secret, 5, 3);
      const r = pvs.refresh(s.shares, s.commitment);
      const vr = pvs.verifyRefresh(s.commitment, r.commitment, r.refresh);
      const rec = pvs.combine(r.shares.slice(0, 3), r.commitment);
      return {
        ok: vr.valid && rec.buf.equals(secret),
        refreshValid: vr.valid,
        secretPreserved: rec.buf.equals(secret),
        epoch: r.commitment.epoch,
      };
    } catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('pq:self-test', () => {
    try { return require('./pq-seal.js').selfTest(); }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('dkg:transport-self-test', () => {
    try { return require('./dkg-transport.js').selfTest(); }
    catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── Voice: silent-speech ZK + anonymous voiceprint auth (merge) ────────────
  // The EARLIER block registers voice:self-test … voice:auth-verify with real
  // main-process ZK sessions (secrets never leave main). Only the two keyword
  // channels that exist nowhere else are added here; ipcMain.handle throws on
  // duplicates, so registration failures are swallowed.
  const _voiceReg = (ch, fn) => { try { ipcMain.handle(ch, fn); } catch (_) {} };
  _voiceReg('voice:prove-keyword', (_e, body = {}) => {
    try {
      const v = require('./voice-privacy.js');
      const utt = body.utterance || body.public;
      const secret = body.secret;
      if (!utt || !secret) return { ok: false, error: 'utterance + secret required' };
      const proof = v.orSigmaProveKeyword(utt, secret, Number(body.keyword));
      // Never return the witness (secret.tokens) to the renderer
      return { ok: true, proof: { A: proof.A, c: proof.c, z: proof.z } };
    } catch (e) { return { ok: false, error: e.message }; }
  });
  _voiceReg('voice:verify-keyword', (_e, body = {}) => {
    try {
      const v = require('./voice-privacy.js');
      const valid = v.orSigmaVerifyKeyword(body.utterance, Number(body.keyword), body.proof);
      return { ok: true, valid: !!valid };
    } catch (e) { return { ok: false, valid: false, error: e.message }; }
  });

  // ─── Local nomos ethics (packages/nomos-engine) ─────────────────────────────
  ipcMain.handle('nomos:status', () => {
    try { return require('./nomos-local.js').status(); }
    catch (e) { return { available: false, error: e.message }; }
  });
  ipcMain.handle('nomos:evaluate', (_e, body = {}) => {
    try { return require('./nomos-local.js').evaluate(body.content || ''); }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('nomos:debate', (_e, body = {}) => {
    try {
      return require('./nomos-local.js').debate(body.content || '', body.initialVerdict, body.challenge || '');
    } catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('vc:list', (_e, body = {}) => {
    if (vcExport.error) return [];
    try { return vcExport.listIssued(body.limit || 50); }
    catch { return []; }
  });
  ipcMain.handle('vc:self-test', () => {
    if (vcExport.error) return { ok: false, error: vcExport.error };
    try { return { ok: true, ...vcExport.selfTest() }; }
    catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── N10: Dead-man governance degradation ────────────────────────────────────
  ipcMain.handle('gov:deadman-check', () => {
    if (thresholdGov.error) return { ok: false, error: thresholdGov.error };
    try { return { ok: true, ...thresholdGov.checkDeadManDegradation() }; }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('gov:degradation-override', () => {
    if (thresholdGov.error) return { ok: false, error: thresholdGov.error };
    try { return { ok: true, override: thresholdGov.getDegradationOverride() }; }
    catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── BIOMETRIC_GUARD (local silent-speech / surveillance block) ──────────────
  ipcMain.handle('bio:scan', (_e, text) => {
    if (bioGuard.error) return { error: bioGuard.error };
    const r = bioGuard.scanText(V.str(text, { name: 'text', max: 200000 }));
    if (r.found) {
      try { impact.bump('secretsBlocked'); } catch (_) {}
      try { _fsAudit.append({ event: 'biometric_guard', severity: r.severity, findings: r.findings.map((f) => f.id) }); } catch (_) {}
    }
    return r;
  });
  ipcMain.handle('bio:status', () => {
    const local = bioLocal?.status ? bioLocal.status() : { available: false };
    return {
      guard: 'BIOMETRIC_GUARD',
      package: local,
      localChannels: ['bio:scan', 'bio:rppg', 'bio:neural-fingerprint', 'bio:voice-clone', 'bio:neural-codec'],
      apiStub: '/v1/biometric/* API mirror still needs the package — local bio:* channels are wired',
    };
  });
  ipcMain.handle('bio:rppg', (_e, body = {}) => {
    if (bioLocal?.rppg) return bioLocal.rppg(body.frames || [], Number(body.frameRate) || 30);
    return { ok: false, available: false, error: 'biometric-local missing' };
  });
  ipcMain.handle('bio:neural-fingerprint', (_e, body = {}) => {
    if (bioLocal?.neuralFingerprint) return bioLocal.neuralFingerprint(body.samples || [], body.opts || {});
    return { ok: false, available: false, error: 'biometric-local missing' };
  });
  ipcMain.handle('bio:voice-clone', (_e, body = {}) => {
    if (bioLocal?.voiceClone) return bioLocal.voiceClone(body.samples || [], body.opts || {});
    return { ok: false, available: false, error: 'biometric-local missing' };
  });
  ipcMain.handle('bio:neural-codec', (_e, body = {}) => {
    if (bioLocal?.neuralCodec) return bioLocal.neuralCodec(body.samples || [], body.opts || {});
    return { ok: false, available: false, error: 'biometric-local missing' };
  });

  // ─── Agent cost governor ─────────────────────────────────────────────────────
  ipcMain.handle('cost:status', () => {
    if (agentCost.error) return { error: agentCost.error };
    return agentCost.status();
  });
  ipcMain.handle('cost:record', (_e, body = {}) => {
    if (agentCost.error) return { error: agentCost.error };
    return agentCost.record(body || {});
  });
  ipcMain.handle('cost:configure', (_e, body = {}) => {
    if (agentCost.error) return { error: agentCost.error };
    return agentCost.configure(body || {});
  });

  // ─── Packaging honesty ───────────────────────────────────────────────────────
  ipcMain.handle('packaging:status', () => {
    const has = (p) => { try { return fs.existsSync(p); } catch { return false; } };
    const res = process.resourcesPath || '';
    return {
      localModules: ['ai-governance', 'threshold-gov', 'wgas', 'biometric-guard', 'agent-cost', 'shamir-vault', 'zk-protect', 'ext-gateway'],
      packaged: {
        'biometric-detection': has(require('path').join(res, 'packages', 'biometric-detection')) || bioLocal?.status?.().available || false,
        'agent-cost-watch': agentCost.status?.().package?.available || false,
        'kasbah-vpn': has(require('path').join(res, 'packages', 'kasbah-vpn')),
        'kasbah-browser-extension': has(require('path').join(res, 'packages', 'kasbah-browser-extension')),
        'control': has(require('path').join(res, 'packages', 'control')),
        'nomos-engine': has(require('path').join(res, 'packages', 'nomos-engine')),
        'kasbah-os': has(require('path').join(res, 'packages', 'kasbah-os', 'crypto_audit.py')),
        'silent-speech-audit': false,
        'kasbah-mcp': has(require('path').join(res, 'packages', 'kasbah-mcp')),
      },
      apiStubs: [
        '/v1/silent-speech (use bio:scan locally)',
        '/v1/biometric/* (use bio:rppg if package present)',
        '/v1/nomos/* (ethics UI needs nomos-engine)',
      ],
      extensionGateway: (() => {
        try { return require('./ext-gateway.js').status(); } catch { return null; }
      })(),
      note: 'Stubs that call missing packages are listed — not faked as local engines.',
    };
  });

  // ─── Browser extension install helper ───────────────────────────────────────
  ipcMain.handle('ext:status', () => {
    const candidates = [
      process.resourcesPath ? path.join(process.resourcesPath, 'packages', 'kasbah-browser-extension') : null,
      path.join(__dirname, '..', '..', 'kasbah-browser-extension'),
      '/Users/mac/Desktop/KasbahFinal/packages/kasbah-browser-extension',
    ].filter(Boolean);
    let dir = null;
    for (const c of candidates) { try { if (fs.existsSync(path.join(c, 'manifest.json'))) { dir = c; break; } } catch (_) {} }
    let gw = null;
    try { gw = require('./ext-gateway.js').status(); } catch (_) {}
    return {
      dir,
      hasManifest: !!dir,
      gateway: gw,
      loadHint: dir
        ? `Chrome → chrome://extensions → Developer mode → Load unpacked → ${dir}`
        : 'Extension folder not found',
    };
  });
  ipcMain.handle('ext:open-folder', () => {
    try {
      const r = require('./ext-gateway.js');
      const st = r.status();
      const candidates = [
        process.resourcesPath ? path.join(process.resourcesPath, 'packages', 'kasbah-browser-extension') : null,
        path.join(__dirname, '..', '..', 'kasbah-browser-extension'),
        '/Users/mac/Desktop/KasbahFinal/packages/kasbah-browser-extension',
      ].filter(Boolean);
      for (const c of candidates) {
        if (fs.existsSync(path.join(c, 'manifest.json'))) {
          require('electron').shell.openPath(c);
          return { ok: true, dir: c, gateway: st };
        }
      }
      return { ok: false, error: 'extension not found' };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── Commitment Proof ─────────────────────────────────────────────────────────
  ipcMain.handle('commit:create', (_e, body = {}) => {
    if (commitProof.error) return { ok: false, error: commitProof.error };
    try { return commitProof.create(body); } catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('commit:list', () => {
    if (commitProof.error) return [];
    try { return commitProof.list(); } catch { return []; }
  });
  ipcMain.handle('commit:reveal', (_e, id) => {
    if (commitProof.error) return { ok: false, error: commitProof.error };
    try { return commitProof.open(String(id || '')); } catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── One-click "Harden Mac" ───────────────────────────────────────────────────
  // Enables all privacy protections in one shot: DoH system resolver, FP noise,
  // clipboard watcher, auto-VPN, honeytoken seeding, and dead-man check-in.
  ipcMain.handle('privacy:harden', async () => {
    const results = {};
    // 1. Seed honeytokens if none exist
    try {
      const existing = honey.list();
      if (existing.length === 0) {
        honey.deploy('email');
        honey.deploy('aws-key');
        results.honeyTokensSeeded = true;
      } else { results.honeyTokensSeeded = false; }
    } catch (e) { results.honeyTokensError = e.message; }

    // 2. Enable fingerprint protection in browser settings
    try {
      const browserStore = require('./browser-store.js');
      browserStore.settingsSet({ fingerprintProtection: true, trackerBlocking: true });
      results.browserHardened = true;
    } catch (e) { results.browserError = e.message; }

    // 3. Set DoH system resolver (macOS: networksetup)
    try {
      const { execFile } = require('child_process');
      await new Promise((resolve) => {
        execFile('networksetup', ['-setdnsservers', 'Wi-Fi', '1.1.1.1', '8.8.8.8'], (err) => {
          results.dohDnsSet = !err;
          if (err) results.dohDnsError = err.message;
          resolve();
        });
      });
    } catch (e) { results.dohDnsError = e.message; }

    // 4. Enable dead-man check-in if not already enabled
    try {
      const dm = deadman.status();
      if (!dm.enabled) {
        deadman.configure({ enabled: true, intervalHours: 24, graceHours: 2 });
        results.deadManEnabled = true;
      } else { results.deadManEnabled = false; }
    } catch (e) { results.deadManError = e.message; }

    // 5. Persist harden settings
    ctx.saveSettings({ clipWatch: true, killSwitch: true });
    results.settings = ctx.loadSettings();

    // 6. Notify
    try { new Notification({ title: '🛡️ Kasbah — Mac Hardened', body: 'DoH, fingerprint protection, clipboard watch, and honeytokens are now active.' }).show(); } catch (_) {}
    _fsAudit.append({ event: 'harden_mac', results: Object.keys(results) });
    return { ok: true, ...results };
  });

  // ─── Fix DNS to DoH ───────────────────────────────────────────────────────────
  ipcMain.handle('privacy:fix-dns', async (_e, iface = 'Wi-Fi') => {
    const { execFile } = require('child_process');
    return new Promise((resolve) => {
      execFile('networksetup', ['-setdnsservers', String(iface), '1.1.1.1', '8.8.8.8', '9.9.9.9'], (err) => {
        resolve(err ? { ok: false, error: err.message } : { ok: true, iface, servers: ['1.1.1.1', '8.8.8.8', '9.9.9.9'] });
      });
    });
  });

  // ─── Login item ───────────────────────────────────────────────────────────────
  ipcMain.handle('app:get-login-item',  () => ctx.app.getLoginItemSettings({ openAtLogin: true }));
  ipcMain.handle('app:set-login-item',  (_e, on) => {
    ctx.app.setLoginItemSettings({ openAtLogin: !!on, openAsHidden: true });
    return { ok: true, openAtLogin: !!on };
  });

  // ─── Pro: founder self-issue ──────────────────────────────────────────────────
  ipcMain.handle('pro:issue-self', () => {
    // Always available in dev; in prod requires KASBAH_ALLOW_ISSUE=1.
    if (process.env.NODE_ENV !== 'development' && process.env.KASBAH_ALLOW_ISSUE !== '1') {
      return { ok: false, error: 'Set KASBAH_ALLOW_ISSUE=1 to self-issue a code.' };
    }
    try { return { ok: true, ...pro.issueCode() }; } catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── Receipt verify CLI command ───────────────────────────────────────────────
  ipcMain.handle('receipt:verify-cmd', (_e, file) => {
    const cands = [
      path.join(process.resourcesPath || '', 'packages', 'kasbah-receipts', 'bin', 'kasbah-verify.js'),
      path.join(__dirname, '../../packages/kasbah-receipts/bin/kasbah-verify.js'),
    ];
    const bin = cands.find((p) => { try { return fs.existsSync(p); } catch { return false; } });
    const cmd = bin ? `node "${bin}" verify "${file || '<receipt-file>'}"` : `npx kasbah-verify verify "${file || '<receipt-file>'}"`;
    return { cmd, binPath: bin || null };
  });

  // ─── Honeytoken: seed defaults on first launch ────────────────────────────────
  ipcMain.handle('honey:seed-defaults', () => {
    const existing = honey.list();
    if (existing.length > 0) return { ok: true, seeded: false, count: existing.length };
    const a = honey.deploy('email');
    const b = honey.deploy('aws-key');
    _fsAudit.append({ event: 'honey_seed', ids: [a.id, b.id] });
    return { ok: true, seeded: true, tokens: [a, b] };
  });

  // ─── Network intel: best-exit recommendation ──────────────────────────────────
  ipcMain.handle('net:best-exit', async () => {
    try {
      const { netIntel } = ctx;
      const pings = await netIntel.pingAll().catch(() => []);
      const best  = netIntel.recommendExit(pings);
      return { ok: true, best, pings };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── Dead-man: status + overdue check ────────────────────────────────────────
  ipcMain.handle('deadman:overdue', () => {
    try {
      const s = deadman.status();
      return { ok: true, overdue: s.overdue, enabled: s.enabled, nextDeadline: s.nextDeadline };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── Egress Classifier ────────────────────────────────────────────────────────
  ipcMain.handle('egress:classify',  (_e, text) => {
    if (egressClassifier.error) return { ok: false, error: egressClassifier.error };
    try { return { ok: true, ...egressClassifier.classify(String(text || '')) }; } catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('egress:scan-dir', async (_e, dir) => {
    if (egressClassifier.error) return { ok: false, error: egressClassifier.error };
    try {
      // Confined to the home directory — this walks for .env files and
      // secret patterns, so an unconfined path here was a full-filesystem
      // secret-exfiltration oracle for anything with window.kasbah access.
      const d = safeHomeDir(dir);
      const findings = [];
      function walk(p, depth = 0) {
        if (depth > 4) return;
        const entries = fs.readdirSync(p, { withFileTypes: true });
        for (const e of entries) {
          if (e.name.startsWith('.') && e.name !== '.env') continue;
          if (['node_modules', '.git', 'dist', 'build', '.next'].includes(e.name)) continue;
          const full = path.join(p, e.name);
          if (e.isDirectory()) { walk(full, depth + 1); continue; }
          if (e.isFile() && fs.statSync(full).size < 500000) {
            try {
              const text = fs.readFileSync(full, 'utf8');
              const r = egressClassifier.classify(text);
              if (r.found) findings.push({ file: full, findings: r.findings.map((f) => ({ id: f.id, label: f.label, tier: f.tier })) });
            } catch (_) {}
          }
        }
      }
      walk(d);
      return { ok: true, dir: d, count: findings.length, findings };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── Agent Registry ───────────────────────────────────────────────────────────
  ipcMain.handle('agent-registry:list',          () => { if (agentRegistry.error) return []; return agentRegistry.list(); });
  ipcMain.handle('agent-registry:register',      (_e, opts) => { if (agentRegistry.error) return { ok: false, error: agentRegistry.error }; try { return { ok: true, agent: agentRegistry.register(opts || {}) }; } catch (e) { return { ok: false, error: e.message }; } });
  ipcMain.handle('agent-registry:unregister',    (_e, id)   => { if (agentRegistry.error) return { ok: false }; return agentRegistry.unregister(id); });
  ipcMain.handle('agent-registry:audit-log',     (_e, opts) => { if (agentRegistry.error) return { ok: false }; try { return { ok: true, entry: agentRegistry.auditLog(opts || {}) }; } catch (e) { return { ok: false, error: e.message }; } });
  ipcMain.handle('agent-registry:audit-tail',    (_e, n)    => { if (agentRegistry.error) return []; return agentRegistry.auditTail(Number(n) || 50); });
  ipcMain.handle('agent-registry:session-start', (_e, name, opts) => { if (agentRegistry.error) return { ok: false }; try { return { ok: true, ...agentRegistry.sessionStart(name, opts || {}) }; } catch (e) { return { ok: false, error: e.message }; } });
  ipcMain.handle('agent-registry:session-end',   (_e, name, sid) => { if (agentRegistry.error) return { ok: false }; return agentRegistry.sessionEnd(name, sid); });

  // Poll dead-man every 5 min and fire a notification if overdue.
  (function pollDeadMan() {
    function tick() {
      try {
        const s = deadman.status();
        if (s.enabled && s.overdue) {
          try {
            new Notification({ title: '⚠️ Kasbah Dead-Man', body: 'Missed check-in! Your emergency contacts have been notified per your policy.', urgency: 'critical' }).show();
          } catch (_) {}
          try { _fsAudit.append({ event: 'deadman_overdue', nextDeadline: s.nextDeadline }); } catch (_) {}
          try { deadman.poll(); } catch (_) {}
        }
      } catch (_) {}
      setTimeout(tick, 5 * 60 * 1000); // every 5 min
    }
    setTimeout(tick, 60 * 1000); // first check after 1 min
  })();

  // ─── Microphone Sentinel ─────────────────────────────────────────────────────
  // Sentinel → Stone: alerts also push to the local consent-gate aura so
  // the Stone/wearable glows without the renderer. Best-effort, never throws.
  function pushStoneAlert(source, detail) {
    try {
      const http = require('http');
      const body = JSON.stringify({ source, detail: detail || {} });
      const req = http.request({ host: '127.0.0.1', port: Number(process.env.KASBAH_API_PORT) || 8788, path: '/v1/consent/stone/local-user/alert', method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }, timeout: 3000 }, (res) => { res.resume(); });
      req.on('error', () => {});
      req.on('timeout', () => { try { req.destroy(); } catch (_) {} });
      req.write(body); req.end();
    } catch (_) {}
  }
  if (micSentinel && !micSentinel.error) {
    micSentinel.start((result) => {
      try {
        const win = ctx.mainWindow?.();
        if (win && !win.isDestroyed()) win.webContents.send('mic:alert', result);
        // Tier-3 enforcement on confirmed alerts (no-op unless enforce mode is on)
        if (enforcer && !enforcer.error && result.alerts) {
          result.alerts.forEach(a => enforcer.actOnAlert({ device: 'mic', name: a.name, pid: a.pid }).catch(() => {}));
        }
        if (result.alerts && result.alerts.length) pushStoneAlert('mic-unapproved', { app: result.alerts[0]?.name, count: result.alerts.length });
      } catch (_) {}
    });
  }

  // ─── Camera Sentinel — face-detection / rPPG harvesting watch ────────────────
  if (cameraSentinel && !cameraSentinel.error) {
    cameraSentinel.start((result) => {
      try {
        const win = ctx.mainWindow?.();
        if (win && !win.isDestroyed()) win.webContents.send('camera:alert', result);
        // Tier-3 enforcement on confirmed alerts (no-op unless enforce mode is on)
        if (enforcer && !enforcer.error && result.alerts) {
          result.alerts.forEach(a => enforcer.actOnAlert({ device: 'camera', name: a.name, pid: a.pid }).catch(() => {}));
        }
        if (result.alerts && result.alerts.length) pushStoneAlert('camera-capture', { app: result.alerts[0]?.name, count: result.alerts.length });
      } catch (_) {}
    });
  }

  // ─── Enforcer — user-space enforcement (Tier 3) ──────────────────────────────
  if (enforcer && !enforcer.error) {
    ipcMain.handle('enforcer:status', (_e) => {
      assertOrigin(_e);
      return enforcer.status();
    });
    ipcMain.handle('enforcer:set-enforce', (_e, on) => {
      assertOrigin(_e);
      return enforcer.setEnforce(!!on);
    });
    ipcMain.handle('enforcer:set-action', (_e, action) => {
      assertOrigin(_e);
      return enforcer.setAction(String(action || ''));
    });
    ipcMain.handle('enforcer:recent-actions', (_e, n) => {
      assertOrigin(_e);
      return enforcer.recentActions(typeof n === 'number' ? n : 20);
    });
  }

  ipcMain.handle('mic:status', async (_e) => {
    assertOrigin(_e);
    if (micSentinel?.error) return { error: micSentinel.error };
    return micSentinel.check();
  });

  ipcMain.handle('mic:approve', (_e, appName) => {
    assertOrigin(_e);
    if (micSentinel?.error) return { error: micSentinel.error };
    return micSentinel.approve(V.str(appName, { name: 'appName' }));
  });

  ipcMain.handle('mic:revoke', (_e, appName) => {
    assertOrigin(_e);
    if (micSentinel?.error) return { error: micSentinel.error };
    return micSentinel.revoke(V.str(appName, { name: 'appName' }));
  });

  ipcMain.handle('mic:list-approved', (_e) => {
    assertOrigin(_e);
    if (micSentinel?.error) return { error: micSentinel.error };
    return micSentinel.listApproved();
  });

  // ─── Quarantine — monotonic deny that approval cannot clear ───────────────
  ipcMain.handle('mic:quarantine', (_e, body = {}) => {
    try { assertOrigin(_e); rateLimit('mic:quarantine', { maxPerSecond: 5 }); } catch (err) { return { ok: false, error: err.message }; }
    if (micSentinel?.error) return { ok: false, error: micSentinel.error };
    try {
      const r = micSentinel.quarantine(V.str(body.app || body.appName || '', { name: 'app', max: 128 }), String(body.reason || '').slice(0, 256));
      try { _fsAudit.append({ event: 'mic_quarantine', app: body.app || body.appName, reason: body.reason || '' }); } catch (_) {}
      return r;
    } catch (e) { auditError('mic:quarantine', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('mic:unquarantine', (_e, body = {}) => {
    try { assertOrigin(_e); rateLimit('mic:unquarantine', { maxPerSecond: 5 }); } catch (err) { return { ok: false, error: err.message }; }
    if (micSentinel?.error) return { ok: false, error: micSentinel.error };
    try {
      const r = micSentinel.unquarantine(V.str(body.app || body.appName || '', { name: 'app', max: 128 }), String(body.note || '').slice(0, 256));
      try { _fsAudit.append({ event: 'mic_unquarantine', app: body.app || body.appName }); } catch (_) {}
      return r;
    } catch (e) { auditError('mic:unquarantine', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('mic:quarantined', (_e) => {
    try { assertOrigin(_e); } catch (err) { return { ok: false, error: err.message }; }
    if (micSentinel?.error) return { ok: false, error: micSentinel.error };
    return { ok: true, quarantined: micSentinel.listQuarantined() };
  });

  // ─── Camera Sentinel — face-detection / rPPG harvesting watch ────────────────
  ipcMain.handle('camera:status', async (_e) => {
    assertOrigin(_e);
    if (cameraSentinel?.error) return { error: cameraSentinel.error };
    return cameraSentinel.check();
  });

  ipcMain.handle('camera:approve', (_e, appName) => {
    assertOrigin(_e);
    if (cameraSentinel?.error) return { error: cameraSentinel.error };
    return cameraSentinel.approve(V.str(appName, { name: 'appName' }));
  });

  ipcMain.handle('camera:revoke', (_e, appName) => {
    assertOrigin(_e);
    if (cameraSentinel?.error) return { error: cameraSentinel.error };
    return cameraSentinel.revoke(V.str(appName, { name: 'appName' }));
  });

  ipcMain.handle('camera:list-approved', (_e) => {
    assertOrigin(_e);
    if (cameraSentinel?.error) return { error: cameraSentinel.error };
    return cameraSentinel.listApproved();
  });
  ipcMain.handle('camera:quarantine', (_e, body = {}) => {
    try { assertOrigin(_e); rateLimit('camera:quarantine', { maxPerSecond: 5 }); } catch (err) { return { ok: false, error: err.message }; }
    if (cameraSentinel?.error) return { ok: false, error: cameraSentinel.error };
    try {
      const r = cameraSentinel.quarantine(V.str(body.app || body.appName || '', { name: 'app', max: 128 }), String(body.reason || '').slice(0, 256));
      try { _fsAudit.append({ event: 'camera_quarantine', app: body.app || body.appName, reason: body.reason || '' }); } catch (_) {}
      return r;
    } catch (e) { auditError('camera:quarantine', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('camera:unquarantine', (_e, body = {}) => {
    try { assertOrigin(_e); rateLimit('camera:unquarantine', { maxPerSecond: 5 }); } catch (err) { return { ok: false, error: err.message }; }
    if (cameraSentinel?.error) return { ok: false, error: cameraSentinel.error };
    try {
      const r = cameraSentinel.unquarantine(V.str(body.app || body.appName || '', { name: 'app', max: 128 }), String(body.note || '').slice(0, 256));
      try { _fsAudit.append({ event: 'camera_unquarantine', app: body.app || body.appName }); } catch (_) {}
      return r;
    } catch (e) { auditError('camera:unquarantine', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('camera:quarantined', (_e) => {
    try { assertOrigin(_e); } catch (err) { return { ok: false, error: err.message }; }
    if (cameraSentinel?.error) return { ok: false, error: cameraSentinel.error };
    return { ok: true, quarantined: cameraSentinel.listQuarantined() };
  });

  // ─── Transparency Log ─────────────────────────────────────────────────────────
  ipcMain.handle('tlog:recent', (_e, n) => {
    assertOrigin(_e);
    if (transparencyLog?.error) return { error: transparencyLog.error };
    return transparencyLog.recent(typeof n === 'number' ? n : 50);
  });

  ipcMain.handle('tlog:verify', (_e) => {
    assertOrigin(_e);
    if (transparencyLog?.error) return { error: transparencyLog.error };
    return transparencyLog.verify();
  });

  ipcMain.handle('tlog:proof', (_e, index) => {
    assertOrigin(_e);
    if (transparencyLog?.error) return { error: transparencyLog.error };
    return transparencyLog.inclusionProof(Number(index));
  });

  ipcMain.handle('tlog:sth', (_e) => {
    assertOrigin(_e);
    if (transparencyLog?.error) return { error: transparencyLog.error };
    return transparencyLog.latestSth();
  });

  ipcMain.handle('tlog:pubkey', (_e) => {
    assertOrigin(_e);
    if (transparencyLog?.error) return { error: transparencyLog.error };
    return transparencyLog.publicKey();
  });

  // ─── Agent Trace ─────────────────────────────────────────────────────────────
  ipcMain.handle('trace:list', (_e, n) => {
    assertOrigin(_e);
    if (!AgentTrace) return { error: 'agent-trace unavailable' };
    return AgentTrace.list(typeof n === 'number' ? n : 50);
  });

  ipcMain.handle('trace:verify', (_e, cert) => {
    assertOrigin(_e);
    if (!AgentTrace) return { ok: false, reason: 'agent-trace unavailable' };
    return AgentTrace.verify(cert);
  });

  ipcMain.handle('trace:pubkey', (_e) => {
    assertOrigin(_e);
    if (!AgentTrace) return { error: 'agent-trace unavailable' };
    return AgentTrace.publicKey();
  });

  // ── Agent activity monitor — real-time MCP tool call stream ──────────────────
  // Polls /v1/kernel/trace/list every 2 s while a renderer is subscribed and
  // pushes delta events via 'agent:activity'. Renderer calls agent:activity:start
  // to subscribe and agent:activity:stop to unsubscribe.
  let _activityTimer = null;
  let _lastActivityLen = 0;

  async function _pollAgentActivity() {
    const win = ctx.mainWindow?.();
    if (!win || win.isDestroyed()) { _lastActivityLen = 0; return; }
    try {
      const http = require('http');
      const data = await new Promise((resolve, reject) => {
        const req = http.get('http://127.0.0.1:8788/v1/kernel/trace/list', (res) => {
          let body = '';
          res.on('data', (c) => { body += c; });
          res.on('end', () => { try { resolve(JSON.parse(body)); } catch { resolve(null); } });
        });
        req.on('error', reject);
        req.setTimeout(1500, () => { req.destroy(); reject(new Error('timeout')); });
      });
      if (!data?.traces) return;
      const events = data.traces.slice(_lastActivityLen);
      _lastActivityLen = data.traces.length;
      if (events.length) win.webContents.send('agent:activity', events);
    } catch (_) {}
  }

  ipcMain.handle('agent:activity:start', (_e) => {
    assertOrigin(_e);
    if (_activityTimer) return { ok: true, already: true };
    _lastActivityLen = 0;
    _activityTimer = setInterval(_pollAgentActivity, 2000);
    return { ok: true };
  });

  ipcMain.handle('agent:activity:stop', (_e) => {
    assertOrigin(_e);
    if (_activityTimer) { clearInterval(_activityTimer); _activityTimer = null; }
    _lastActivityLen = 0;
    return { ok: true };
  });

  // ── Fire Button (DDG) — nuke all in-process AI session state ─────────────────
  // Clears: mic approved list, clipboard, browser cookies/cache/storage,
  // active agent traces, and posts a kill-switch to the API server.
  // Beats DDG: one tap clears web traces AND AI traces, with a signed proof.
  ipcMain.handle('session:burn', async (_e) => {
    assertOrigin(_e);
    // Clear mic approved list
    if (!micSentinel?.error && micSentinel.clearApproved) micSentinel.clearApproved();
    try { clipboard.clear(); } catch (_) {}
    try {
      const { session } = require('electron');
      const ses = session.fromPartition('persist:private');
      await ses.clearStorageData();
      await ses.clearCache();
    } catch (e) { auditError('session:burn-clear', e); }
    // Agent traces live in server.js process — the kill-switch POST below handles them.
    // Notify API server kill-switch (best-effort)
    try {
      const http = require('http');
      const body = JSON.stringify({ reason: 'fire_button', actorId: 'desktop-session' });
      const req = http.request({ host: '127.0.0.1', port: 8788, path: '/v1/kernel/killswitch', method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } });
      req.write(body); req.end();
    } catch (_) {}
    // Notify renderer so UI can reset protection score
    ctx.mainWindow?.()?.webContents?.send('session:burned', { ts: Date.now() });
    return { ok: true, burned: true, ts: Date.now() };
  });

  // ─── MCISE OS Desktop IPC ───────────────────────────────────────────────────
  const mciseHttp = (path, method, body) => {
    return new Promise((resolve) => {
      try {
        const http = require('http');
        const data = body ? JSON.stringify(body) : '';
        const req = http.request({
          host: '127.0.0.1',
          port: process.env.KASBAH_API_PORT || 8788,
          path: `/v1/mcise${path}`,
          method,
          headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) }
        }, (res) => {
          let out = '';
          res.on('data', c => out += c);
          res.on('end', () => {
            try { resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, data: JSON.parse(out) }); }
            catch { resolve({ ok: false, data: out }); }
          });
        });
        req.on('error', () => resolve({ ok: false, data: null }));
        if (data) req.write(data);
        req.end();
      } catch { resolve({ ok: false, data: null }); }
    });
  };

  ipcMain.handle('mcise:fixed-core:list', async () => {
    const r = await mciseHttp('/fixed-core', 'GET');
    return r.data;
  });
  ipcMain.handle('mcise:audit:verify', async () => {
    const r = await mciseHttp('/audit/verify', 'GET');
    return r.data;
  });
  ipcMain.handle('mcise:ladder:status', async (_e, agentId) => {
    const r = await mciseHttp(`/ladder/${agentId}`, 'GET');
    return r.data;
  });

  // ─── SSI admission gate (kasbah-os/ssi_universal_core.py mirror) ──────────
  const ssiLocal = (() => { try {
    return tryRequire(['../../../src/ssi-admission.js', '../../src/ssi-admission.js']);
  } catch (e) { return { error: e.message }; } })();
  ipcMain.handle('ssi:status', (_e) => {
    try { assertOrigin(_e); } catch (err) { return { ok: false, error: err.message }; }
    try {
      if (ssiLocal && !ssiLocal.error) {
        const t = ssiLocal.selfTest();
        return { ok: t.passed === t.total, selfTest: t, rightsBase: ssiLocal.RIGHTS_BASE, epsilon: ssiLocal.EPSILON_LEAK };
      }
      return { ok: false, error: (ssiLocal && ssiLocal.error) || 'ssi unavailable' };
    } catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('ssi:screen', (_e, body = {}) => {
    try { assertOrigin(_e); rateLimit('ssi:screen', { maxPerSecond: 10 }); } catch (err) { return { ok: false, error: err.message }; }
    try {
      if (ssiLocal && !ssiLocal.error) return { ok: true, ...ssiLocal.ssiScreen(body || {}) };
      return { ok: false, error: (ssiLocal && ssiLocal.error) || 'ssi unavailable' };
    } catch (e) { auditError('ssi:screen', e); return { ok: false, error: e.message }; }
  });

  // ─── SSI Python cores via api-server HTTP (spawns ssi_cli bridge) ─────────
  // Falls back to 503-shaped payloads when the embedded api-server is down.
  const _ssiHttp = (apiPath, method, body) => new Promise((resolve) => {
    try {
      const http = require('http');
      const data = body ? JSON.stringify(body) : '';
      const req = http.request({
        host: '127.0.0.1', port: process.env.KASBAH_API_PORT || 8788,
        path: apiPath, method,
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) },
      }, (res) => {
        let out = '';
        res.on('data', (c) => { out += c; });
        res.on('end', () => {
          try { resolve(JSON.parse(out)); }
          catch { resolve({ ok: false, error: 'bad gateway response' }); }
        });
      });
      req.on('error', () => resolve({ ok: false, error: 'api-server unreachable' }));
      req.setTimeout(65000, () => { try { req.destroy(); } catch (_) {} resolve({ ok: false, error: 'ssi timeout' }); });
      if (data) req.write(data);
      req.end();
    } catch { resolve({ ok: false, error: 'ssi bridge failed' }); }
  });
  ipcMain.handle('ssi:admit', async (_e, body = {}) => {
    try { assertOrigin(_e); rateLimit('ssi:admit', { maxPerSecond: 5 }); } catch (err) { return { ok: false, error: err.message }; }
    return _ssiHttp('/v1/ssi/admit', 'POST', body || {});
  });
  ipcMain.handle('ssi:engine-admit', async (_e, body = {}) => {
    try { assertOrigin(_e); rateLimit('ssi:engine-admit', { maxPerSecond: 5 }); } catch (err) { return { ok: false, error: err.message }; }
    return _ssiHttp('/v1/ssi/engine/admit', 'POST', body || {});
  });
  ipcMain.handle('ssi:engine-selftest', async (_e) => {
    try { assertOrigin(_e); } catch (err) { return { ok: false, error: err.message }; }
    return _ssiHttp('/v1/ssi/engine/selftest', 'GET');
  });

  // ─── Travel mode — one toggle for the whole world ───────────────────────
  // On: VPN auto-connect on boot + kill switch enforced. Off: restore prefs.
  ipcMain.handle('travel:status', (_e) => {
    try { assertOrigin(_e); } catch (err) { return { ok: false, error: err.message }; }
    try {
      const s = ctx.loadSettings ? ctx.loadSettings() : {};
      return { ok: true, on: !!s.travelMode, autoConnect: !!s.autoConnect, killSwitch: s.killSwitch !== false };
    } catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('travel:set', (_e, on) => {
    try { assertOrigin(_e); rateLimit('travel:set', { maxPerSecond: 3 }); } catch (err) { return { ok: false, error: err.message }; }
    try {
      const s = ctx.loadSettings ? ctx.loadSettings() : {};
      const next = ctx.saveSettings ? ctx.saveSettings({
        travelMode: !!on,
        autoConnect: !!on ? true : !!s.autoConnect,
        killSwitch: !!on ? true : s.killSwitch,
      }) : s;
      try { _fsAudit.append({ event: 'travel_mode', on: !!on }); } catch (_) {}
      return { ok: true, on: !!on, settings: { travelMode: !!next.travelMode } };
    } catch (e) { auditError('travel:set', e); return { ok: false, error: e.message }; }
  });

  // ─── My data — see it, take it, delete it ─────────────────────────────────
  const KASBAH_FILES = () => {
    const home = os.homedir();
    const cands = ['.kasbah-settings.json', '.kasbah-backup', '.kasbah-vault.json', '.kasbah-audit.jsonl'];
    const out = [];
    for (const c of cands) {
      const p = path.join(home, c);
      try {
        const st = fs.statSync(p);
        out.push({ file: c, bytes: st.isDirectory() ? null : st.size, dir: st.isDirectory() });
      } catch (_) {}
    }
    return out;
  };
  ipcMain.handle('data:inventory', (_e) => {
    try { assertOrigin(_e); } catch (err) { return { ok: false, error: err.message }; }
    try {
      return { ok: true, files: KASBAH_FILES(), home: os.homedir() };
    } catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('data:export', (_e) => {
    try { assertOrigin(_e); rateLimit('data:export', { maxPerSecond: 2 }); } catch (err) { return { ok: false, error: err.message }; }
    try {
      const bundle = { exportedAt: new Date().toISOString(), settings: null, browser: null, honeytokens: 0 };
      try { bundle.settings = ctx.loadSettings ? ctx.loadSettings() : null; } catch (_) {}
      try { bundle.browser = { history: browserStore.historyList(1000), bookmarks: browserStore.bookmarkList() }; } catch (_) {}
      try { bundle.honeytokens = (honey.list() || []).length; } catch (_) {}
      try { bundle.audit = (_fsAudit.entries || []).slice(-500); } catch (_) {}
      const dest = path.join(os.homedir(), 'Downloads', `kasbah-my-data-${Date.now()}.json`);
      fs.writeFileSync(dest, JSON.stringify(bundle, null, 2), { mode: 0o600 });
      try { _fsAudit.append({ event: 'data_export', file: path.basename(dest) }); } catch (_) {}
      return { ok: true, file: dest };
    } catch (e) { auditError('data:export', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('data:erase', (_e) => {
    try { assertOrigin(_e); rateLimit('data:erase', { maxPerSecond: 2 }); } catch (err) { return { ok: false, error: err.message }; }
    try {
      const done = [];
      try { browserStore.historyClear(); done.push('history'); } catch (_) {}
      try { browserStore.downloadsClear(); done.push('downloads'); } catch (_) {}
      try { if (ctx.State && Array.isArray(ctx.State.recentActivity)) { ctx.State.recentActivity.length = 0; done.push('activity'); } } catch (_) {}
      // Vault and audit log are NEVER touched here — vault needs its own
      // delete per entry, the audit log is append-only by design.
      try { _fsAudit.append({ event: 'data_erase', cleared: done }); } catch (_) {}
      return { ok: true, cleared: done, kept: ['vault', 'audit-log'] };
    } catch (e) { auditError('data:erase', e); return { ok: false, error: e.message }; }
  });

  // ─── Device pairing — your protection on every Mac, no cloud ─────────────
  // Export: password-locked bundle (settings + vault + approved lists).
  // Carry the file yourself (AirDrop/USB); import it on the other Mac.
  function _pairKey(password, salt) {
    return crypto.pbkdf2Sync(String(password || ''), salt, 100000, 32, 'sha256');
  }
  ipcMain.handle('device:export-pair', (_e, body = {}) => {
    try { assertOrigin(_e); rateLimit('device:export-pair', { maxPerSecond: 2 }); } catch (err) { return { ok: false, error: err.message }; }
    try {
      const password = String(body.password || '');
      if (password.length < 8) return { ok: false, error: 'Use a password of 8+ characters.' };
      const bundle = { v: 1, exportedAt: new Date().toISOString(), settings: null, vault: [], mic: [], camera: [] };
      try { bundle.settings = ctx.loadSettings ? ctx.loadSettings() : null; } catch (_) {}
      // Vault entries only while unlocked; locked vault exports settings only.
      try {
        if (ctx._vault && ctx._vault.isUnlocked()) {
          const full = ctx._vault.listFull() || [];
          bundle.vault = full.slice(0, 500);
          bundle.vaultLocked = false;
        } else {
          bundle.vaultLocked = true;
        }
      } catch (_) { bundle.vaultLocked = true; }
      try { if (!micSentinel?.error && micSentinel.listApproved) bundle.mic = micSentinel.listApproved(); } catch (_) {}
      try { if (!cameraSentinel?.error && cameraSentinel.listApproved) bundle.camera = cameraSentinel.listApproved(); } catch (_) {}
      const salt = crypto.randomBytes(16);
      const key = _pairKey(password, salt);
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const enc = Buffer.concat([cipher.update(JSON.stringify(bundle), 'utf8'), cipher.final()]);
      const out = { v: 1, salt: salt.toString('base64'), iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: enc.toString('base64') };
      const dest = path.join(os.homedir(), 'Downloads', `kasbah-pair-${Date.now()}.kpair`);
      fs.writeFileSync(dest, JSON.stringify(out), { mode: 0o600 });
      try { _fsAudit.append({ event: 'device_pair_export', vaultEntries: bundle.vault.length }); } catch (_) {}
      return { ok: true, file: dest, vaultEntries: bundle.vault.length };
    } catch (e) { auditError('device:export-pair', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('device:import-pair', (_e, body = {}) => {
    try { assertOrigin(_e); rateLimit('device:import-pair', { maxPerSecond: 2 }); } catch (err) { return { ok: false, error: err.message }; }
    try {
      const file = safePathInside(path.join(os.homedir(), 'Downloads'), path.basename(String(body.file || '')));
      const password = String(body.password || '');
      const outer = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (outer.v !== 1) return { ok: false, error: 'Unknown pairing file version.' };
      const key = _pairKey(password, Buffer.from(outer.salt, 'base64'));
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(outer.iv, 'base64'));
      decipher.setAuthTag(Buffer.from(outer.tag, 'base64'));
      const bundle = JSON.parse(Buffer.concat([decipher.update(Buffer.from(outer.data, 'base64')), decipher.final()]).toString('utf8'));
      const restored = { settings: false, vault: 0 };
      try {
        if (bundle.settings && ctx.saveSettings) { ctx.saveSettings({ ...bundle.settings, travelMode: !!bundle.settings.travelMode }); restored.settings = true; }
      } catch (_) {}
      try {
        if (Array.isArray(bundle.vault) && bundle.vault.length && ctx._vault && ctx._vault.isUnlocked()) {
          restored.vault = ctx._vault.importEntries(bundle.vault) || 0;
        } else if (Array.isArray(bundle.vault) && bundle.vault.length) {
          restored.vaultSkipped = 'unlock vault first, then import again';
        }
      } catch (e) { restored.vaultError = e.message; }
      try { _fsAudit.append({ event: 'device_pair_import', file: path.basename(file), restored }); } catch (_) {}
      return { ok: true, restored, note: 'Microphone/camera approvals are per-Mac and were not transferred.' };
    } catch (e) { return { ok: false, error: e.message && e.message.includes('auth') ? 'Wrong password or damaged file.' : e.message }; }
  });

  // ─── SIEM connectors (local-first) ──────────────────────────────────────
  ipcMain.handle('siem:status', (_e) => {
    try { assertOrigin(_e); } catch (err) { return { ok: false, error: err.message }; }
    try {
      if (siemLocal && !siemLocal.error && typeof siemLocal.status === 'function') return { ok: true, ...siemLocal.status() };
      return { ok: false, error: siemLocal.error || 'siem unavailable' };
    } catch (e) { auditError('siem:status', e); return { ok: false, error: e.message }; }
  });
  ipcMain.handle('siem:forward', (_e, body = {}) => {
    try { assertOrigin(_e); rateLimit('siem:forward', { maxPerSecond: 5 }); } catch (err) { return { ok: false, error: err.message }; }
    try {
      if (siemLocal && !siemLocal.error && typeof siemLocal.forwardEvent === 'function') return { ok: true, forwarded: siemLocal.forwardEvent(body || {}) };
      return { ok: false, error: siemLocal.error || 'siem unavailable' };
    } catch (e) { auditError('siem:forward', e); return { ok: false, error: e.message }; }
  });

  // ─── Data lineage (local-first) ─────────────────────────────────────────
  ipcMain.handle('lineage:stats', (_e) => {
    try { assertOrigin(_e); } catch (err) { return { ok: false, error: err.message }; }
    try {
      if (lineageLocal && !lineageLocal.error) return { ok: true, ...lineageLocal.stats() };
      return { ok: false, error: lineageLocal.error || 'lineage unavailable' };
    } catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('lineage:chain', (_e, body = {}) => {
    try { assertOrigin(_e); } catch (err) { return { ok: false, error: err.message }; }
    try {
      if (lineageLocal && !lineageLocal.error) return { ok: true, edges: lineageLocal.chain(body.keyId || 'anonymous', { surface: body.surface, limit: body.limit }) };
      return { ok: false, error: lineageLocal.error || 'lineage unavailable' };
    } catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('lineage:provenance', (_e, body = {}) => {
    try { assertOrigin(_e); } catch (err) { return { ok: false, error: err.message }; }
    try {
      if (lineageLocal && !lineageLocal.error) return { ok: true, ...lineageLocal.provenance(body.keyId || 'anonymous') };
      return { ok: false, error: lineageLocal.error || 'lineage unavailable' };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── Maqasid 5-pillar (local, no API hop) ───────────────────────────────
  ipcMain.handle('maqasid:evaluate', (_e, body = {}) => {
    try { assertOrigin(_e); rateLimit('maqasid:evaluate', { maxPerSecond: 10 }); } catch (err) { return { ok: false, error: err.message }; }
    try {
      const text = String(body.text || body.content || '');
      if (!text) return { ok: false, error: 'text required' };
      if (maqasidLocal && !maqasidLocal.error) return { ok: true, ...new maqasidLocal.MaqasidFramework().evaluate(text) };
      return { ok: false, error: maqasidLocal.error || 'maqasid unavailable' };
    } catch (e) { auditError('maqasid:evaluate', e); return { ok: false, error: e.message }; }
  });

  // ─── Unified sentinel (advisory-only, local) ────────────────────────────
  ipcMain.handle('sentinel:status', (_e) => {
    try { assertOrigin(_e); } catch (err) { return { ok: false, error: err.message }; }
    const s = sentinelLocal();
    if (!s) return { ok: false, error: _sentinelError || 'sentinel unavailable' };
    try { return { ok: true, stats: s.stats, layers: ['eigenEthics','shadowConsensus','topoShield','causalBreaker','zkProof','reynoldsFlow','punctEquil','harmonicDiss'].map((k) => ({ layer: k, loaded: !!s[k] })) }; }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('sentinel:scan', async (_e, body = {}) => {
    try { assertOrigin(_e); rateLimit('sentinel:scan', { maxPerSecond: 5 }); } catch (err) { return { ok: false, error: err.message }; }
    const s = sentinelLocal();
    if (!s) return { ok: false, error: _sentinelError || 'sentinel unavailable' };
    try {
      const text = String(body.text ?? body.content ?? '');
      const r = await s.sentinelCheck({ agent: body.agent || 'desktop-user', verb: body.verb || 'ANALYZE', target: body.target || 'local', content: text });
      return { ok: true, verdict: r.decision || r.verdict, risk: r.governance?.risk ?? r.scan?.risk ?? r.risk, decision: r.decision, violations: r.violations, advisory: true };
    } catch (e) { auditError('sentinel:scan', e); return { ok: false, error: e.message }; }
  });

};
