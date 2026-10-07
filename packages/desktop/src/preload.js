'use strict';

/**
 * Kasbah Guard Desktop — Preload (Secure IPC Bridge)
 * Exposes a typed API to the renderer process via contextBridge.
 * Never leaks Node.js APIs into the renderer.
 */

const { contextBridge, ipcRenderer } = require('electron');

// Test that preload runs
try {
  ipcRenderer.send('preload-test', 'preload loaded');
  console.log('[Kasbah] preload loaded');
} catch (e) {
  ipcRenderer.send('preload-error', e.message);
}

// Forward renderer console logs to main process for debugging
const originalConsoleLog = console.log;
const originalConsoleError = console.error;
const originalConsoleWarn = console.warn;

console.log = (...args) => {
  originalConsoleLog.apply(console, args);
  try {
    ipcRenderer.send('renderer-log', { level: 'log', args: args.map(String) });
  } catch (e) {}
};

console.error = (...args) => {
  originalConsoleError.apply(console, args);
  try {
    ipcRenderer.send('renderer-log', { level: 'error', args: args.map(String) });
  } catch (e) {}
};

console.warn = (...args) => {
  originalConsoleWarn.apply(console, args);
  try {
    ipcRenderer.send('renderer-log', { level: 'warn', args: args.map(String) });
  } catch (e) {}
};

contextBridge.exposeInMainWorld('kasbah', {
  // ── State ──────────────────────────────────────────────────────────────────
  getState:           ()           => ipcRenderer.invoke('get-state'),
  toggleProtection:   ()           => ipcRenderer.invoke('toggle-protection'),
  scanClipboard:      ()           => ipcRenderer.invoke('scan-clipboard'),

  // ── Event push from main (protection:score etc.) ───────────────────────────
  on: (channel, fn) => {
    const allowed = ['protection:score', 'egress-threat', 'bwr:download-progress', 'bwr:download-done', 'bwr:download-start', 'sitrep', 'mic:alert', 'camera:alert', 'bwr:paste-scan'];
    if (!allowed.includes(channel)) return () => {};
    const handler = (_e, data) => { try { fn(data); } catch (_) {} };
    ipcRenderer.on(channel, handler);
    return () => ipcRenderer.removeListener(channel, handler);
  },

  // ── API Proxy ──────────────────────────────────────────────────────────────
  // opts.params (4th arg) is serialized into the query string — the main
  // handler only understands (method, endpoint, body).
  api:     (method, endpoint, body, opts) => {
    if (opts && opts.params && typeof endpoint === 'string') {
      try {
        const qs = new URLSearchParams(
          Object.entries(opts.params).filter(([, v]) => v !== undefined && v !== null)
        ).toString();
        if (qs) endpoint += (endpoint.includes('?') ? '&' : '?') + qs;
      } catch (_) {}
    }
    return ipcRenderer.invoke('api', method, endpoint, body);
  },
  // Generic request helper used by premium feature controllers
  request: (method, endpoint, body) => ipcRenderer.invoke('api', method, endpoint, body),
  // Base URL for direct browser navigation (compliance PDF)
  get apiBase() { return `http://127.0.0.1:8788`; },

  // ── Convenience wrappers ───────────────────────────────────────────────────
  govern:   (body)        => ipcRenderer.invoke('api', 'POST', '/v1/govern', body),
  scan:     (text)        => ipcRenderer.invoke('api', 'POST', '/v1/scan', { prompt: text }),
  health:   ()            => ipcRenderer.invoke('api', 'GET',  '/v1/health'),
  stats:    ()            => ipcRenderer.invoke('api', 'GET',  '/v1/stats'),
  // Ground-breaking feature surfaces
  viralCoefficient: ()    => ipcRenderer.invoke('api', 'GET',  '/v1/viral/coefficient'),
  viralShare:   (body)    => ipcRenderer.invoke('api', 'POST', '/v1/receipt/share', body),
  viralShareCard: (body)  => ipcRenderer.invoke('api', 'POST', '/v1/viral/share-card', body),
  viralSlack:   (body)    => ipcRenderer.invoke('api', 'POST', '/v1/viral/slack', body),
  moats:        ()        => ipcRenderer.invoke('api', 'GET',  '/v1/moats'),
  cryptoGenesis:()        => ipcRenderer.invoke('api', 'GET',  '/v1/crypto/genesis'),
  cryptoPedersenVss:(body)=> ipcRenderer.invoke('api', 'POST', '/v1/crypto/pedersen-vss', body),
  cryptoMerkleShares:(body)=> ipcRenderer.invoke('api', 'POST', '/v1/crypto/merkle-shares', body),
  cryptoBerlekampWelch:(body)=> ipcRenderer.invoke('api', 'POST', '/v1/crypto/berlekamp-welch', body),
  piiOnDevice:  (text)    => ipcRenderer.invoke('api', 'POST', '/v1/pii/ondevice', { text }),
  // Real dated benchmark scorecard (bench/results/) — the actual measured
  // precision/recall/f1/accuracy from the latest run, not a display number.
  benchmarkStats: ()      => ipcRenderer.invoke('stats:benchmark'),
  integrity:()            => ipcRenderer.invoke('api', 'GET',  '/v1/integrity'),
  forecast: (passportId)  => ipcRenderer.invoke('api', 'GET',
    passportId ? `/v1/forecast?passportId=${passportId}` : '/v1/forecast'),

  // Passports
  passportIssue:  (body)  => ipcRenderer.invoke('api', 'POST',   '/v1/passport/issue', body),
  passportList:   ()      => ipcRenderer.invoke('api', 'GET',    '/v1/passport/list'),
  passports:      ()      => ipcRenderer.invoke('api', 'GET',    '/v1/passports'),
  passportGet:    (id)    => ipcRenderer.invoke('api', 'GET',    `/v1/passport/${id}`),
  passportRevoke: (id)    => ipcRenderer.invoke('api', 'DELETE', `/v1/passport/${id}`),

  // Receipts (v2 + v3)
  receiptSign:   (body)   => ipcRenderer.invoke('api', 'POST', '/v1/sign', body),
  receiptSignV3: (body)   => ipcRenderer.invoke('api', 'POST', '/v1/sign?v=3', body),
  receiptVerify: (body)   => ipcRenderer.invoke('api', 'POST', '/v1/receipt/verify', body),
  receiptVerifyBatch: (b) => ipcRenderer.invoke('api', 'POST', '/v1/receipt/verify-batch', b),

  // Silent speech + Zero-trust audit
  silentSpeech:  (body)   => ipcRenderer.invoke('api', 'POST', '/v1/silent-speech', body),
  auditReceipt:  (body)   => ipcRenderer.invoke('api', 'POST', '/v1/audit/receipt', body),

  // KasbahOS Python core bridge
  kasbahOSIngest:  (body) => ipcRenderer.invoke('api', 'POST', '/v1/kasbah-os/ingest', body),
  kasbahOSHealth:  ()     => ipcRenderer.invoke('api', 'GET',  '/v1/kasbah-os/health'),
  kasbahOSRetrieve:(body) => ipcRenderer.invoke('api', 'POST', '/v1/kasbah-os/retrieve', body),

  // Delegation
  delegationIssue:  (b)   => ipcRenderer.invoke('api', 'POST', '/v1/delegation/issue', b),
  delegationVerify: (id)  => ipcRenderer.invoke('api', 'POST', '/v1/delegation/verify', { tokenId: id }),

  // Spend
  spendUsage:     (id)    => ipcRenderer.invoke('api', 'GET',  `/v1/passport/${id}/spend`),
  spendPolicy:    (id, p) => ipcRenderer.invoke('api', 'POST', `/v1/passport/${id}/spend/policy`, p),

  // Keys + specs
  keys:         ()        => ipcRenderer.invoke('api', 'GET', '/v1/keys'),
  wellKnownKeys:()        => ipcRenderer.invoke('api', 'GET', '/.well-known/kasbah-keys.json'),

  // Audit chain
  auditChain: ()          => ipcRenderer.invoke('api', 'GET', '/v1/audit/chain'),

  // Models
  models:       ()        => ipcRenderer.invoke('api', 'GET', '/v1/models'),

  // ── Products (all 16 engines) ──────────────────────────────────────────────
  productsStatus:    ()   => ipcRenderer.invoke('api', 'GET',  '/v1/products/status'),
  productScan:    (p, t)  => ipcRenderer.invoke('api', 'POST', `/v1/products/${p}`, { text: t }),

  // Crypto
  shamirSplit:    (s,n,k) => ipcRenderer.invoke('api', 'POST', '/v1/crypto/shamir/split', { secret: s, n, k }),
  shamirCombine:  (shares)=>ipcRenderer.invoke('api', 'POST', '/v1/crypto/shamir/combine', { shares }),
  mmrAppend:      (data)  => ipcRenderer.invoke('api', 'POST', '/v1/crypto/mmr/append', { data }),
  vdfEval:        (inp,it)=>ipcRenderer.invoke('api', 'POST', '/v1/crypto/vdf/eval', { input: inp, iterations: it }),

  // Multi-MCP Governance
  mcpServers:     ()      => ipcRenderer.invoke('api', 'GET',  '/v1/mcp/servers'),
  mcpPolicies:    ()      => ipcRenderer.invoke('api', 'GET',  '/v1/mcp/policies'),

  // ── Events from Main ───────────────────────────────────────────────────────
  onActivity:    (fn) => { ipcRenderer.on('activity-update', (_e, d) => fn(d)); },
  onStateChange: (fn) => { ipcRenderer.on('state-change',   (_e, d) => fn(d)); },

  // ── Kasbah Browser — real sub-resource ad/tracker blocking ─────────────────
  // Enforced in main (session.webRequest on each webview's own session, see
  // main.js did-attach-webview) — never in the renderer, which can't see
  // sub-resource loads at all.
  trackerBlocklist:  ()   => ipcRenderer.invoke('browser:tracker-blocklist'),
  onTrackerBlocked:  (fn) => { ipcRenderer.on('bwr:blocked', (_e, d) => fn(d)); },

  // ── Kasbah Browser — history, bookmarks, downloads, settings ───────────────
  browserHistory: {
    list:   (limit)   => ipcRenderer.invoke('browser:history-list', limit),
    search: (query)   => ipcRenderer.invoke('browser:history-search', query),
    delete: (id)      => ipcRenderer.invoke('browser:history-delete', id),
    clear:  ()        => ipcRenderer.invoke('browser:history-clear'),
    onAdded:(fn)      => { ipcRenderer.on('bwr:history-added', (_e, d) => fn(d)); },
  },
  browserBookmarks: {
    list:    ()           => ipcRenderer.invoke('browser:bookmark-list'),
    add:     (entry)      => ipcRenderer.invoke('browser:bookmark-add', entry),
    remove:  (urlOrId)    => ipcRenderer.invoke('browser:bookmark-remove', urlOrId),
    isSaved: (url)        => ipcRenderer.invoke('browser:bookmark-is-saved', url),
  },
  browserDownloads: {
    list:   ()            => ipcRenderer.invoke('browser:downloads-list'),
    clear:  ()            => ipcRenderer.invoke('browser:downloads-clear'),
    open:   (savePath)    => ipcRenderer.invoke('browser:download-open', savePath),
    reveal: (savePath)    => ipcRenderer.invoke('browser:download-reveal', savePath),
    onUpdate: (fn)        => { ipcRenderer.on('bwr:download-update', (_e, d) => fn(d)); },
  },
  browserSettings: {
    get: ()      => ipcRenderer.invoke('browser:settings-get'),
    set: (patch) => ipcRenderer.invoke('browser:settings-set', patch),
  },
  browserPrivacy: {
    clearData: () => ipcRenderer.invoke('browser:clear-data'),
    vpnStatus: () => ipcRenderer.invoke('browser:vpn-status'),
  },

  // ── Utility ────────────────────────────────────────────────────────────────
  openUrl: (url) => ipcRenderer.invoke('open-url', url),
  version: () => process.versions,

  // ── Kasbah VPN (Labs) — local WireGuard orchestration, no HTTP hop ──────────
  vpn: {
    state:          ()        => ipcRenderer.invoke('vpn:state'),
    init:           (body)    => ipcRenderer.invoke('vpn:init', body),
    serverInit:     (body)    => ipcRenderer.invoke('vpn:server-init', body),
    join:           (body)    => ipcRenderer.invoke('vpn:join', body),
    peerAdd:        (body)    => ipcRenderer.invoke('vpn:peer-add', body),
    config:         (kind, split) => ipcRenderer.invoke('vpn:config', kind, split),
    mesh:           (body)    => ipcRenderer.invoke('vpn:mesh', body),
    aiLaneStart:    (body)    => ipcRenderer.invoke('vpn:ai-lane-start', body),
    aiLaneStop:     ()        => ipcRenderer.invoke('vpn:ai-lane-stop'),
    receiptsVerify: ()        => ipcRenderer.invoke('vpn:receipts-verify'),
    locations:      ()        => ipcRenderer.invoke('vpn:locations'),
    connect:        (locationId) => ipcRenderer.invoke('vpn:connect', { locationId }),
    disconnect:     ()        => ipcRenderer.invoke('vpn:disconnect'),
    checkEgress:    ()        => ipcRenderer.invoke('vpn:check-egress'),
    wssCheck:       ()        => ipcRenderer.invoke('vpn:wss-check'),
    quickTestPing:  ()        => ipcRenderer.invoke('vpn:quick-test-ping'),
    onAutoDisconnected: (fn) => { ipcRenderer.on('vpn:auto-disconnected', (_e, d) => fn(d)); },
    onAutoReconnected: (fn) => { ipcRenderer.on('vpn:auto-reconnected', (_e, d) => fn(d)); },
    helperStatus: () => ipcRenderer.invoke('vpn:helper-status'),
    helperInstall: () => ipcRenderer.invoke('vpn:helper-install'),
    helperRemove: () => ipcRenderer.invoke('vpn:helper-remove'),
    exportReceipts: () => ipcRenderer.invoke('vpn:export-receipts'),
  },

  settings: {
    get: () => ipcRenderer.invoke('settings:get'),
    set: (patch) => ipcRenderer.invoke('settings:set', patch),
  },

  // ── Privacy Pro ────────────────────────────────────────────────────────────
  pro: {
    status:    ()       => ipcRenderer.invoke('pro:status'),
    activate:  (code)   => ipcRenderer.invoke('pro:activate', code),
    deactivate:()       => ipcRenderer.invoke('pro:deactivate'),
    issue:     ()       => ipcRenderer.invoke('pro:issue'),
  },

  // ── Network intelligence (unique) ─────────────────────────────────────────
  net: {
    snapshot:  ()        => ipcRenderer.invoke('net:snapshot'),
    dpiProbe:  (body)    => ipcRenderer.invoke('net:dpi-probe', body || {}),
    bestExit:  ()        => ipcRenderer.invoke('net:best-exit'),
  },
  vpnExtra: {
    autoReconnectStart:  (body) => ipcRenderer.invoke('vpn:auto-reconnect-start', body || {}),
    autoReconnectStop:   ()     => ipcRenderer.invoke('vpn:auto-reconnect-stop'),
    autoReconnectStatus: ()     => ipcRenderer.invoke('vpn:auto-reconnect-status'),
    exportReceipts:      ()     => ipcRenderer.invoke('vpn:export-receipts'),
    onAutoReconnect:     (fn)   => { ipcRenderer.on('vpn:auto-reconnect', (_e, d) => fn(d)); },
  },
  privacyExtra: {
    safeMode: (on) => ipcRenderer.invoke('privacy:safe-mode', !!on),
  },

  // ─── Unique agentic / future-proof ─────────────────────────────────────────
  pop: {
    mint:      (body) => ipcRenderer.invoke('pop:mint', body || {}),
    list:      ()     => ipcRenderer.invoke('pop:list'),
    verifyAll: ()     => ipcRenderer.invoke('pop:verify-all'),
    export:    (file) => ipcRenderer.invoke('pop:export', file),
    pubkey:    ()     => ipcRenderer.invoke('pop:pubkey'),
  },
  agentGuard: {
    status:     ()      => ipcRenderer.invoke('agent:status'),
    policyGet:  ()      => ipcRenderer.invoke('agent:policy-get'),
    policySet:  (p)     => ipcRenderer.invoke('agent:policy-set', p),
    evaluate:   (c)     => ipcRenderer.invoke('agent:evaluate', c),
    server:     (on)    => ipcRenderer.invoke('agent:server', !!on),
    setVpn:     (on,m)  => ipcRenderer.invoke('agent:set-vpn', !!on, m||{}),
    // Real content governance + cross-call diagnostics (@kasbah/control) —
    // see packages/desktop/src/agent-guard.js. Returns { available:false }
    // rather than a fake result if the control package isn't present.
    govern:      (call)  => ipcRenderer.invoke('agent:govern', call || {}),
    diagnostics: ()      => ipcRenderer.invoke('agent:diagnostics'),
    events:      (limit) => ipcRenderer.invoke('agent:events', limit),
  },
  shamir: {
    split:   (body) => ipcRenderer.invoke('shamir:split', body),
    combine: (shares) => ipcRenderer.invoke('shamir:combine', shares),
  },
  mmr: {
    manifest: (body) => ipcRenderer.invoke('mmr:manifest', body),
    verify:   (body) => ipcRenderer.invoke('mmr:verify', body),
  },
  deadman: {
    status:    ()     => ipcRenderer.invoke('deadman:status'),
    checkIn:   (n)    => ipcRenderer.invoke('deadman:check-in', n),
    configure: (b)    => ipcRenderer.invoke('deadman:configure', b),
    poll:      ()     => ipcRenderer.invoke('deadman:poll'),
    log:       ()     => ipcRenderer.invoke('deadman:log'),
    overdue:   ()     => ipcRenderer.invoke('deadman:overdue'),
  },
  auditFs: {
    append: (e) => ipcRenderer.invoke('audit:append', e),
    verify: ()  => ipcRenderer.invoke('audit:verify'),
    list:   ()  => ipcRenderer.invoke('audit:list'),
  },
  popExtra: {
    merkle:        ()     => ipcRenderer.invoke('pop:merkle'),
    merkleVerify:  (file) => ipcRenderer.invoke('pop:merkle-verify', { file }),
  },
  zk: {
    protect:            (body) => ipcRenderer.invoke('zk:protect', body || {}),
    generate:           (body) => ipcRenderer.invoke('zk:generate', body || {}),
    verify:             (body) => ipcRenderer.invoke('zk:verify', body || {}),
    commit:             (body) => ipcRenderer.invoke('zk:commit', body || {}),
    range:              (body) => ipcRenderer.invoke('zk:range', body || {}),
    rangeBounded:       (body) => ipcRenderer.invoke('zk:range-bounded', body || {}),
    rangeBoundedVerify: (body) => ipcRenderer.invoke('zk:range-bounded-verify', body || {}),
    rangeSelfTest:      ()     => ipcRenderer.invoke('zk:range-self-test'),
  },
  honey: {
    deploy:       (s)  => ipcRenderer.invoke('honey:deploy', s),
    list:         ()   => ipcRenderer.invoke('honey:list'),
    check:        (t)  => ipcRenderer.invoke('honey:check', t),
    remove:       (id) => ipcRenderer.invoke('honey:remove', id),
    seedDefaults: ()   => ipcRenderer.invoke('honey:seed-defaults'),
  },
  vuln: {
    scanText: (t)   => ipcRenderer.invoke('vuln:scan-text', t),
    scanFile: (f)   => ipcRenderer.invoke('vuln:scan-file', f),
    scanDir:  (d)   => ipcRenderer.invoke('vuln:scan-dir', d),
    // Real static CWE pattern scan (kasbah-os/zeroday_engine.py) — byte-level
    // regex matching, not simulated. See main-features.js.
    scanFileDeep: (f) => ipcRenderer.invoke('vuln:scan-file-deep', f),
  },
  llmproxy: {
    start:     (p) => ipcRenderer.invoke('llmproxy:start', p),
    stop:      ()  => ipcRenderer.invoke('llmproxy:stop'),
    status:    ()  => ipcRenderer.invoke('llmproxy:status'),
    install:   (p) => ipcRenderer.invoke('llmproxy:install', p),
    uninstall: ()  => ipcRenderer.invoke('llmproxy:uninstall'),
  },
  aigov: {
    status:    ()      => ipcRenderer.invoke('aigov:status'),
    policySet: (patch) => ipcRenderer.invoke('aigov:policy-set', patch || {}),
    scan:      (text)  => ipcRenderer.invoke('aigov:scan', text),
    events:    (n)     => ipcRenderer.invoke('aigov:events', n),
    shadow:    ()      => ipcRenderer.invoke('aigov:shadow'),
    agentLock: ()      => ipcRenderer.invoke('aigov:agent-lock'),
  },
  gov: {
    status:     ()      => ipcRenderer.invoke('gov:status'),
    seats:      ()      => ipcRenderer.invoke('gov:seats'),
    seatCreate: (body)  => ipcRenderer.invoke('gov:seat-create', body || {}),
    advisory:   (body)  => ipcRenderer.invoke('gov:advisory', body || {}),
    propose:    (body)  => ipcRenderer.invoke('gov:propose', body || {}),
    cosign:     (body)  => ipcRenderer.invoke('gov:cosign', body || {}),
    pending:    ()      => ipcRenderer.invoke('gov:pending'),
    chainVerify:        ()     => ipcRenderer.invoke('gov:chain-verify'),
    wgasEval:           (body) => ipcRenderer.invoke('gov:wgas-eval', body || {}),
    wgasDemo:           ()     => ipcRenderer.invoke('gov:wgas-demo'),
    wgasConservation:   (body) => ipcRenderer.invoke('gov:wgas-conservation', body || {}),
    wgasCrosscheck:     (body) => ipcRenderer.invoke('gov:wgas-crosscheck', body || {}),
    wgasFederatedEval:  (body) => ipcRenderer.invoke('gov:wgas-federated-eval', body || {}),
  },
  dkg: {
    round1:       (body) => ipcRenderer.invoke('dkg:round1', body || {}),
    computeShare: (body) => ipcRenderer.invoke('dkg:compute-share', body || {}),
    verifyShare:  (body) => ipcRenderer.invoke('dkg:verify-share', body || {}),
    aggregate:    (body) => ipcRenderer.invoke('dkg:aggregate', body || {}),
    selfTest:     ()     => ipcRenderer.invoke('dkg:self-test'),
  },
  audit: {
    redTeam:   () => ipcRenderer.invoke('audit:red-team'),
    readiness: () => ipcRenderer.invoke('audit:readiness'),
  },
  bio: {
    scan:   (text)  => ipcRenderer.invoke('bio:scan', text),
    status: ()      => ipcRenderer.invoke('bio:status'),
    rppg:   (body)  => ipcRenderer.invoke('bio:rppg', body || {}),
    neuralFingerprint: (body) => ipcRenderer.invoke('bio:neural-fingerprint', body || {}),
    voiceClone: (body) => ipcRenderer.invoke('bio:voice-clone', body || {}),
    neuralCodec: (body) => ipcRenderer.invoke('bio:neural-codec', body || {}),
  },
  cost: {
    status:    ()     => ipcRenderer.invoke('cost:status'),
    record:    (body) => ipcRenderer.invoke('cost:record', body || {}),
    configure: (body) => ipcRenderer.invoke('cost:configure', body || {}),
  },
  packaging: {
    status: () => ipcRenderer.invoke('packaging:status'),
  },
  ext: {
    status:      () => ipcRenderer.invoke('ext:status'),
    openFolder:  () => ipcRenderer.invoke('ext:open-folder'),
  },

  // ─── Unique outlier product ────────────────────────────────────────────────
  sitrep: {
    get:     (body) => ipcRenderer.invoke('sitrep:get', body || {}),
    crisis:  (on)   => ipcRenderer.invoke('sitrep:crisis', !!on),
    history: ()     => ipcRenderer.invoke('sitrep:history'),
  },
  exitMarket: {
    list: () => ipcRenderer.invoke('exit-market:list'),
  },
  claims: {
    list:  ()     => ipcRenderer.invoke('claims:list'),
    check: (id)   => ipcRenderer.invoke('claims:check', id),
  },
  impactCard: {
    snapshot: ()     => ipcRenderer.invoke('impact:snapshot'),
    bump:     (k, n) => ipcRenderer.invoke('impact:bump', k, n),
  },
  harden: {
    status:   ()   => ipcRenderer.invoke('harden:status'),
    start:    ()   => ipcRenderer.invoke('harden:start'),
    step:     (id) => ipcRenderer.invoke('harden:step', id),
    commit:   (n)  => ipcRenderer.invoke('harden:commit', n),
    reset:    ()   => ipcRenderer.invoke('harden:reset'),
  },
  commitHide: {
    create: (body) => ipcRenderer.invoke('commit:create-hidden', body || {}),
    list:   ()     => ipcRenderer.invoke('commit:list-hidden'),
    open:   (id)   => ipcRenderer.invoke('commit:open-hidden', id),
  },
  merkleBatch: {
    batchProofs: () => ipcRenderer.invoke('merkle:batch-proofs'),
  },
  fsaudit: {
    exportCsv: (f) => ipcRenderer.invoke('fsaudit:export-csv', f),
    webhook:   (b) => ipcRenderer.invoke('fsaudit:webhook', b),
    append: (body) => ipcRenderer.invoke('fsaudit:append', body),
    list:   (n)    => ipcRenderer.invoke('fsaudit:list', n),
    verify: ()     => ipcRenderer.invoke('fsaudit:verify'),
    export: (f)    => ipcRenderer.invoke('fsaudit:export', f),
  },
  commit: {
    create: (body) => ipcRenderer.invoke('commit:create', body),
    list:   ()     => ipcRenderer.invoke('commit:list'),
    reveal: (id)   => ipcRenderer.invoke('commit:reveal', id),
  },
  appSettings: {
    getLoginItem: () => ipcRenderer.invoke('app:get-login-item'),
    setLoginItem: (on) => ipcRenderer.invoke('app:set-login-item', on),
  },
  receipt: {
    verifyCmd: (file) => ipcRenderer.invoke('receipt:verify-cmd', file),
  },
  egress: {
    classify: (text) => ipcRenderer.invoke('egress:classify', text),
    scanDir:  (dir)  => ipcRenderer.invoke('egress:scan-dir', dir),
  },
  agentRegistry: {
    list:         ()           => ipcRenderer.invoke('agent-registry:list'),
    register:     (opts)       => ipcRenderer.invoke('agent-registry:register', opts),
    unregister:   (id)         => ipcRenderer.invoke('agent-registry:unregister', id),
    auditLog:     (opts)       => ipcRenderer.invoke('agent-registry:audit-log', opts),
    auditTail:    (n)          => ipcRenderer.invoke('agent-registry:audit-tail', n),
    sessionStart: (name, opts) => ipcRenderer.invoke('agent-registry:session-start', name, opts),
    sessionEnd:   (name, sid)  => ipcRenderer.invoke('agent-registry:session-end', name, sid),
  },

  // ── Password Vault ─────────────────────────────────────────────────────────
  vault: {
    list:     ()       => ipcRenderer.invoke('vault:list'),
    add:      (entry)  => ipcRenderer.invoke('vault:add', entry),
    delete:   (id)     => ipcRenderer.invoke('vault:delete', id),
    get:      (id)     => ipcRenderer.invoke('vault:get', id),
    generate: ()       => ipcRenderer.invoke('vault:generate'),
  },

  // ── Local privacy analyzers (no API server) ────────────────────────────────
  privacy: {
    scam:          (text)       => ipcRenderer.invoke('privacy:scam', text),
    scamMM:        (text)       => ipcRenderer.invoke('privacy:scam-mm', text),
    family:        (text)       => ipcRenderer.invoke('privacy:family', text),
    wifiAnalyze:   (body)       => ipcRenderer.invoke('privacy:wifi-analyze', body),
    secrets:       (text)       => ipcRenderer.invoke('privacy:secrets', text),
    genPassword:   (opts)       => ipcRenderer.invoke('privacy:gen-password', opts),
    pwScore:       (pw)         => ipcRenderer.invoke('privacy:pw-score', pw),
    checkup:       (body)       => ipcRenderer.invoke('privacy:checkup', body || {}),
    clipWatch:     (on)         => ipcRenderer.invoke('privacy:clip-watch', !!on),
    dnsLeak:       ()           => ipcRenderer.invoke('privacy:dns-leak'),
    device:        ()           => ipcRenderer.invoke('privacy:device'),
    pwBreach:      (password)   => ipcRenderer.invoke('privacy:pw-breach', password),
    emailBreach:   (email, key) => ipcRenderer.invoke('privacy:email-breach', email, key),
    pwBreachHash5: (hash5)      => ipcRenderer.invoke('privacy:pw-breach-hash5', hash5),
    onClipSecret:      (fn) => { ipcRenderer.on('privacy:clip-secret',    (_e, d) => fn(d)); },
    onEgressAlert:     (fn) => { ipcRenderer.on('privacy:egress-alert',  (_e, d) => fn(d)); },
    onHoneytokenHit:   (fn) => { ipcRenderer.on('privacy:honeytoken-hit',(_e, d) => fn(d)); },
    onMicAlert:        (fn) => { ipcRenderer.on('mic:alert',             (_e, d) => fn(d)); },
    onSessionBurned:   (fn) => { ipcRenderer.on('session:burned',        (_e, d) => fn(d)); },
    leakTest:      (body)       => ipcRenderer.invoke('privacy:leak-test', body || {}),
    latency:       ()           => ipcRenderer.invoke('privacy:latency'),
    mmProfile:     ()           => ipcRenderer.invoke('privacy:mm-profile'),
    harden:        ()           => ipcRenderer.invoke('privacy:harden'),
    fixDns:        (iface)      => ipcRenderer.invoke('privacy:fix-dns', iface),
  },

  // ── Wi-Fi Guard ────────────────────────────────────────────────────────────
  wifi: {
    getNetwork: () => ipcRenderer.invoke('wifi:get-network'),
  },

  // ── Secure Backup ──────────────────────────────────────────────────────────
  backup: {
    chooseFile: ()          => ipcRenderer.invoke('backup:choose-file'),
    encrypt:    (filePath)  => ipcRenderer.invoke('backup:encrypt', filePath),
    list:       ()          => ipcRenderer.invoke('backup:list'),
    delete:     (file)      => ipcRenderer.invoke('backup:delete', file),
    decrypt:    (file)      => ipcRenderer.invoke('backup:decrypt', file),
  },

  // ── N1: Execution delay ───────────────────────────────────────────────────
  // N2: Policy diff proofs
  // N3: Canary governance
  // N5: Threshold export key
  // N10: Dead-man degradation
  // (all wired into the gov namespace below)
  govEx: {
    canExecute:          (approvalId) => ipcRenderer.invoke('gov:can-execute',        { approvalId }),
    markExecuted:        (approvalId, note) => ipcRenderer.invoke('gov:mark-executed', { approvalId, note }),
    policyCommit:        (body)       => ipcRenderer.invoke('gov:policy-commit',       body || {}),
    policyHash:          ()           => ipcRenderer.invoke('gov:policy-hash'),
    canaryDeploy:        (body)       => ipcRenderer.invoke('gov:canary-deploy',       body || {}),
    onCanaryTripped:     (fn)         => { ipcRenderer.on('gov:canary-tripped', (_e, d) => fn(d)); },
    reputationUpdate:    (body)       => ipcRenderer.invoke('gov:reputation-update',   body || {}),
    reputationStatus:    ()           => ipcRenderer.invoke('gov:reputation-status'),
    wgasReputationEval:  (body)       => ipcRenderer.invoke('gov:wgas-reputation-eval', body || {}),
    exportKeyCreate:     (body)       => ipcRenderer.invoke('gov:export-key-create',   body || {}),
    deadmanCheck:        ()           => ipcRenderer.invoke('gov:deadman-check'),
    degradationOverride: ()           => ipcRenderer.invoke('gov:degradation-override'),
  },

  // ── N6: Session continuity chain + Fire Button (merged — was duplicated) ───
  session: {
    begin:             (body)          => ipcRenderer.invoke('session:begin',              body || {}),
    end:               (sessionId)     => ipcRenderer.invoke('session:end',                { sessionId }),
    verifyContinuity:  (from, to)      => ipcRenderer.invoke('session:verify-continuity',  { fromIdx: from, toIdx: to }),
    head:              ()              => ipcRenderer.invoke('session:head'),
    burn:              ()              => ipcRenderer.invoke('session:burn'),
  },

  // ── N8: Prompt attestation ────────────────────────────────────────────────
  attest: {
    commit:        (prompt, label, agentId) => ipcRenderer.invoke('attest:commit', { prompt, label, agentId }),
    verify:        (id, prompt)             => ipcRenderer.invoke('attest:verify',      { id, prompt }),
    verifyFull:    (id, prompt)             => ipcRenderer.invoke('attest:verify-full', { id, prompt }),
    list:          (limit)                  => ipcRenderer.invoke('attest:list',        { limit }),
    publicKey:     ()                       => ipcRenderer.invoke('attest:public-key'),
    selfTest:      ()                       => ipcRenderer.invoke('attest:self-test'),
  },

  // ── N9: Portable Verifiable Credentials ──────────────────────────────────
  vc: {
    issue:          (popEntry, expiryDays, subjectDid) => ipcRenderer.invoke('vc:issue', { popEntry, expiryDays, subjectDid }),
    issueDidKey:    (popEntry, subjectDid)             => ipcRenderer.invoke('vc:issue-didkey', { popEntry, subjectDid }),
    verify:         (vc)                               => ipcRenderer.invoke('vc:verify', { vc }),
    verifyDidKey:   (vc)                               => ipcRenderer.invoke('vc:verify-didkey', { vc }),
    exportFile:     (vc, filename)                     => ipcRenderer.invoke('vc:export-file', { vc, filename }),
    issuerPublicKey:()                                 => ipcRenderer.invoke('vc:issuer-public-key'),
    didDocument:    ()                                 => ipcRenderer.invoke('vc:did-document'),
    list:           (limit)                            => ipcRenderer.invoke('vc:list', { limit }),
    selfTest:       ()                                 => ipcRenderer.invoke('vc:self-test'),
  },
  cap: {
    selfTest:    ()     => ipcRenderer.invoke('cap:self-test'),
    verifyChain: (body) => ipcRenderer.invoke('cap:verify-chain', body || {}),
  },
  vss: {
    selfTest: ()     => ipcRenderer.invoke('vss:self-test'),
    split:    (body) => ipcRenderer.invoke('vss:split', body || {}),
  },
  pvs: {
    selfTest:     () => ipcRenderer.invoke('pvs:self-test'),
    refreshDemo:  () => ipcRenderer.invoke('pvs:refresh-demo'),
  },
  pq: {
    selfTest: () => ipcRenderer.invoke('pq:self-test'),
  },
  dkgTransport: {
    selfTest: () => ipcRenderer.invoke('dkg:transport-self-test'),
  },
  voice: {
    selfTest:               () => ipcRenderer.invoke('voice:self-test'),
    simulateSilentSpeech:  (body) => ipcRenderer.invoke('voice:simulate-silent-speech', body || []),
    simulateVoiceprint:    (seed) => ipcRenderer.invoke('voice:simulate-voiceprint', seed || ''),
    buildRegistry:         (body) => ipcRenderer.invoke('voice:build-registry', body || []),
    authProve:             (body) => ipcRenderer.invoke('voice:auth-prove', body || {}),
    authVerify:            (body) => ipcRenderer.invoke('voice:auth-verify', body || {}),
    commitUtterance:       (body) => ipcRenderer.invoke('voice:commit-utterance', body || []),
    rerandomizeUtterance:  (body) => ipcRenderer.invoke('voice:rerandomize-utterance', body || {}),
    orSigmaProveKeyword:   (body) => ipcRenderer.invoke('voice:or-sigma-prove-keyword', body || {}),
    orSigmaVerifyKeyword:  (body) => ipcRenderer.invoke('voice:or-sigma-verify-keyword', body || {}),
    fuzzyProve:            (body) => ipcRenderer.invoke('voice:fuzzy-prove', body || {}),
    fuzzyVerify:           (body) => ipcRenderer.invoke('voice:fuzzy-verify', body || {}),
  },
  nomos: {
    status:   ()     => ipcRenderer.invoke('nomos:status'),
    evaluate: (body) => ipcRenderer.invoke('nomos:evaluate', body || {}),
    debate:   (body) => ipcRenderer.invoke('nomos:debate', body || {}),
  },
  mic: {
    status:       ()        => ipcRenderer.invoke('mic:status'),
    approve:      (appName) => ipcRenderer.invoke('mic:approve', appName),
    revoke:       (appName) => ipcRenderer.invoke('mic:revoke', appName),
    listApproved: ()        => ipcRenderer.invoke('mic:list-approved'),
    quarantine:   (app, reason) => ipcRenderer.invoke('mic:quarantine', { app, reason }),
    unquarantine: (app, note)   => ipcRenderer.invoke('mic:unquarantine', { app, note }),
    quarantined:  ()        => ipcRenderer.invoke('mic:quarantined'),
  },
  camera: {
    status:       ()        => ipcRenderer.invoke('camera:status'),
    approve:      (appName) => ipcRenderer.invoke('camera:approve', appName),
    revoke:       (appName) => ipcRenderer.invoke('camera:revoke', appName),
    listApproved: ()        => ipcRenderer.invoke('camera:list-approved'),
    quarantine:   (app, reason) => ipcRenderer.invoke('camera:quarantine', { app, reason }),
    unquarantine: (app, note)   => ipcRenderer.invoke('camera:unquarantine', { app, note }),
    quarantined:  ()        => ipcRenderer.invoke('camera:quarantined'),
  },
  enforcer: {
    status:       ()        => ipcRenderer.invoke('enforcer:status'),
    setEnforce:   (on)      => ipcRenderer.invoke('enforcer:set-enforce', on),
    setAction:    (action)  => ipcRenderer.invoke('enforcer:set-action', action),
    recentActions:(n)       => ipcRenderer.invoke('enforcer:recent-actions', n),
  },
  tlog: {
    recent:  (n)     => ipcRenderer.invoke('tlog:recent', n),
    verify:  ()      => ipcRenderer.invoke('tlog:verify'),
    proof:   (index) => ipcRenderer.invoke('tlog:proof', index),
    sth:     ()      => ipcRenderer.invoke('tlog:sth'),
    pubkey:  ()      => ipcRenderer.invoke('tlog:pubkey'),
  },
  trace: {
    list:    (n)    => ipcRenderer.invoke('trace:list', n),
    verify:  (cert) => ipcRenderer.invoke('trace:verify', cert),
    pubkey:  ()     => ipcRenderer.invoke('trace:pubkey'),
  },
  travel: {
    status: ()   => ipcRenderer.invoke('travel:status'),
    set:    (on) => ipcRenderer.invoke('travel:set', !!on),
  },
  data: {
    inventory: () => ipcRenderer.invoke('data:inventory'),
    export:    () => ipcRenderer.invoke('data:export'),
    erase:     () => ipcRenderer.invoke('data:erase'),
  },
  device: {
    exportPair: (password)       => ipcRenderer.invoke('device:export-pair', { password }),
    importPair: (file, password) => ipcRenderer.invoke('device:import-pair', { file, password }),
  },
  // ── Agent activity real-time stream ────────────────────────────────────────
  agentActivity: {
    start:  ()   => ipcRenderer.invoke('agent:activity:start'),
    stop:   ()   => ipcRenderer.invoke('agent:activity:stop'),
    onEvent: (fn) => { ipcRenderer.on('agent:activity', (_e, events) => fn(events)); },
  },
  // ── Competitor USP bridges ──────────────────────────────────────────────────
  browser: {
    resizeWebview: (webContentsId, width, height) =>
      ipcRenderer.invoke('browser:resize-webview', { webContentsId, width, height }),
  },
  bv: {
    create:        ()              => ipcRenderer.invoke('bv:create'),
    destroy:       (id)            => ipcRenderer.invoke('bv:destroy', id),
    navigate:      (id, url)       => ipcRenderer.invoke('bv:navigate', { id, url }),
    setBounds:     (id, x, y, w, h) => ipcRenderer.invoke('bv:set-bounds', { id, x, y, w, h }),
    goBack:        (id)            => ipcRenderer.invoke('bv:go-back', id),
    goForward:     (id)            => ipcRenderer.invoke('bv:go-forward', id),
    reload:        (id)            => ipcRenderer.invoke('bv:reload', id),
    canGoBack:     (id)            => ipcRenderer.invoke('bv:can-go-back', id),
    canGoForward:  (id)            => ipcRenderer.invoke('bv:can-go-forward', id),
    execJS:        (id, code)      => ipcRenderer.invoke('bv:exec-js', { id, code }),
    hide:          (id)            => ipcRenderer.invoke('bv:hide', id),
    onEvent:       (fn)            => ipcRenderer.on('bv:event', (_e, ev) => fn(ev)),
  },
  // ── New capability bridges (local-first IPC) ──────────────────────────
  mcise: {
    fixedCore:   ()          => ipcRenderer.invoke('mcise:fixed-core:list'),
    auditVerify: ()          => ipcRenderer.invoke('mcise:audit:verify'),
    ladder:      (agentId)   => ipcRenderer.invoke('mcise:ladder:status', agentId),
  },
  siem: {
    status:  ()     => ipcRenderer.invoke('siem:status'),
    forward: (body)  => ipcRenderer.invoke('siem:forward', body || {}),
  },
  lineage: {
    stats:      ()     => ipcRenderer.invoke('lineage:stats'),
    chain:      (body) => ipcRenderer.invoke('lineage:chain', body || {}),
    provenance: (body) => ipcRenderer.invoke('lineage:provenance', body || {}),
  },
  maqasid: {
    evaluate: (text) => ipcRenderer.invoke('maqasid:evaluate', { text }),
  },
  sentinel: {
    status: ()     => ipcRenderer.invoke('sentinel:status'),
    scan:   (body) => ipcRenderer.invoke('sentinel:scan', body || {}),
  },
  ssi: {
    status: ()     => ipcRenderer.invoke('ssi:status'),
    screen: (body) => ipcRenderer.invoke('ssi:screen', body || {}),
    admit:  (body) => ipcRenderer.invoke('ssi:admit', body || {}),
    engineAdmit: (body) => ipcRenderer.invoke('ssi:engine-admit', body || {}),
    engineSelftest: () => ipcRenderer.invoke('ssi:engine-selftest'),
  },
});
