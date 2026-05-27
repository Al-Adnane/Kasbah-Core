'use strict';

/**
 * Users, Workspaces, and RBAC for Kasbah Guard.
 *
 * Identity model layered on top of the existing API-key system. Adds:
 *   - User (email + name + auth providers + workspaces)
 *   - Workspace (org/team — owns API keys, passports, audit log, billing)
 *   - Membership (user → workspace with role: owner | admin | analyst | viewer)
 *   - RBAC: route-level role enforcement helpers
 *
 * Persistence model:
 *   - In-memory Maps mirrored to disk JSONL at .kasbah/users.jsonl + workspaces.jsonl
 *   - On boot, load files into memory. On every write, append a line.
 *   - For production: swap _appendJSONL() for a Redis hash / Postgres insert.
 *
 * The existing _apiKeys.jsonl integration:
 *   - Each API key gets a workspaceId field
 *   - On /v1/keys/issue, we auto-create-or-attach the email to a workspace
 *   - Tier enforcement happens at workspace level (not per-key)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');

const DATA_DIR = path.resolve(__dirname, '..', '..', '..', '.kasbah');
const USERS_FILE      = path.join(DATA_DIR, 'users.jsonl');
const WORKSPACES_FILE = path.join(DATA_DIR, 'workspaces.jsonl');
const MEMBERS_FILE    = path.join(DATA_DIR, 'workspace_members.jsonl');

// Ensure data dir exists
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch {}

const _users      = new Map(); // userId  → user record
const _usersByEmail = new Map(); // email   → user record (lookup index)
const _workspaces = new Map(); // wsId    → workspace record
const _members    = new Map(); // userId  → [{ workspaceId, role }]

const ROLES = ['owner', 'admin', 'analyst', 'viewer'];
const ROLE_PRIORITY = { owner: 4, admin: 3, analyst: 2, viewer: 1 };

// ── Persistence ───────────────────────────────────────────────────────────────

function _appendJSONL(file, record) {
  try { fs.appendFileSync(file, JSON.stringify(record) + '\n'); } catch {}
}

function _loadJSONL(file) {
  if (!fs.existsSync(file)) return [];
  try {
    return fs.readFileSync(file, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map(l => { try { return JSON.parse(l); } catch { return null; } })
      .filter(Boolean);
  } catch { return []; }
}

function _hydrate() {
  for (const u of _loadJSONL(USERS_FILE)) {
    if (u && u.id && !u._deleted) {
      _users.set(u.id, u);
      _usersByEmail.set(u.email.toLowerCase(), u);
    } else if (u && u.id && u._deleted) {
      _users.delete(u.id);
      _usersByEmail.delete(u.email?.toLowerCase());
    }
  }
  for (const w of _loadJSONL(WORKSPACES_FILE)) {
    if (w && w.id) _workspaces.set(w.id, w);
  }
  for (const m of _loadJSONL(MEMBERS_FILE)) {
    if (m && m.userId && m.workspaceId) {
      const list = _members.get(m.userId) || [];
      list.push({ workspaceId: m.workspaceId, role: m.role, addedAt: m.addedAt });
      _members.set(m.userId, list);
    }
  }
}
_hydrate();

// ── Users ─────────────────────────────────────────────────────────────────────

function getOrCreateUser({ email, name, provider }) {
  if (!email || !email.includes('@')) throw new Error('Valid email required');
  const lower = email.toLowerCase();
  let user = _usersByEmail.get(lower);
  if (user) {
    // Update last-seen, merge provider if new
    user.lastSeenAt = new Date().toISOString();
    if (provider && !user.providers.includes(provider)) {
      user.providers.push(provider);
    }
    _appendJSONL(USERS_FILE, user);
    return user;
  }
  user = {
    id: 'usr_' + crypto.randomBytes(8).toString('hex'),
    email: lower,
    name: name || email.split('@')[0],
    providers: provider ? [provider] : ['email'],
    createdAt: new Date().toISOString(),
    lastSeenAt: new Date().toISOString()
  };
  _users.set(user.id, user);
  _usersByEmail.set(lower, user);
  _appendJSONL(USERS_FILE, user);
  return user;
}

function getUserById(id) { return _users.get(id) || null; }
function getUserByEmail(email) { return _usersByEmail.get((email || '').toLowerCase()) || null; }

// ── Workspaces ────────────────────────────────────────────────────────────────

function createWorkspace({ name, ownerId, tier = 'free' }) {
  if (!ownerId || !_users.get(ownerId)) throw new Error('Valid ownerId required');
  const ws = {
    id: 'ws_' + crypto.randomBytes(8).toString('hex'),
    name: name || 'Personal',
    tier,
    ownerId,
    createdAt: new Date().toISOString(),
    // Billing fields populated by Stripe webhook later
    stripeCustomerId: null,
    stripeSubscriptionId: null,
    planActivatedAt: null
  };
  _workspaces.set(ws.id, ws);
  _appendJSONL(WORKSPACES_FILE, ws);
  addMember({ userId: ownerId, workspaceId: ws.id, role: 'owner' });
  return ws;
}

function getWorkspace(id) { return _workspaces.get(id) || null; }

function updateWorkspace(id, patch) {
  const ws = _workspaces.get(id);
  if (!ws) return null;
  Object.assign(ws, patch);
  _appendJSONL(WORKSPACES_FILE, ws);
  return ws;
}

// ── Membership ────────────────────────────────────────────────────────────────

function addMember({ userId, workspaceId, role }) {
  if (!ROLES.includes(role)) throw new Error('Invalid role: ' + role);
  if (!_users.get(userId)) throw new Error('User not found');
  if (!_workspaces.get(workspaceId)) throw new Error('Workspace not found');
  const list = _members.get(userId) || [];
  const existing = list.find(m => m.workspaceId === workspaceId);
  if (existing) {
    existing.role = role;
  } else {
    list.push({ workspaceId, role, addedAt: new Date().toISOString() });
    _members.set(userId, list);
  }
  _appendJSONL(MEMBERS_FILE, { userId, workspaceId, role, addedAt: new Date().toISOString() });
  return list;
}

function getMemberships(userId) { return _members.get(userId) || []; }

function getRole(userId, workspaceId) {
  const list = _members.get(userId) || [];
  const m = list.find(x => x.workspaceId === workspaceId);
  return m ? m.role : null;
}

function getMembers(workspaceId) {
  const members = [];
  for (const [userId, list] of _members) {
    const m = list.find(x => x.workspaceId === workspaceId);
    if (m) members.push({ userId, role: m.role, addedAt: m.addedAt });
  }
  return members;
}

function hasRole(userId, workspaceId, minRole) {
  const role = getRole(userId, workspaceId);
  if (!role) return false;
  return ROLE_PRIORITY[role] >= ROLE_PRIORITY[minRole];
}

// ── Single helper: provision an account on first API-key issuance ────────────

function provisionFromKeyIssuance({ email, name, tier }) {
  const user = getOrCreateUser({ email, name, provider: 'email' });
  const existing = (getMemberships(user.id))[0];
  let workspace = existing ? _workspaces.get(existing.workspaceId) : null;
  if (!workspace) {
    workspace = createWorkspace({
      name: (name || email.split('@')[0]) + "'s Workspace",
      ownerId: user.id,
      tier: tier || 'free'
    });
  } else if (tier && tier !== workspace.tier) {
    workspace = updateWorkspace(workspace.id, { tier });
  }
  return { user, workspace };
}

// ── Express middleware ────────────────────────────────────────────────────────

/** Express middleware: attaches req.workspace from the API key's workspaceId. */
function attachWorkspace(_apiKeys) {
  return (req, res, next) => {
    const key = req.headers['x-api-key'];
    if (!key) return next();
    const entry = _apiKeys.get(key);
    if (entry?.workspaceId) {
      req.workspace = _workspaces.get(entry.workspaceId);
    }
    next();
  };
}

/** Express middleware: require minimum role on a workspace.
 *  Use as: app.post('/v1/admin/...', requireRole('admin'), handler)
 *  Workspace identified by req.workspace (set by attachWorkspace).
 *  User identified by x-user-id header (placeholder — replace with real session).
 */
function requireRole(minRole) {
  return (req, res, next) => {
    const userId = req.headers['x-user-id'];
    if (!userId) return res.status(401).json({ error: 'x-user-id required' });
    if (!req.workspace) return res.status(403).json({ error: 'No workspace context' });
    if (!hasRole(userId, req.workspace.id, minRole)) {
      return res.status(403).json({ error: `Requires role: ${minRole}`, yourRole: getRole(userId, req.workspace.id) });
    }
    req.userId = userId;
    next();
  };
}

// ── OAuth helpers ─────────────────────────────────────────────────────────────

// In-memory CSRF state store with 5-minute TTL
const _oauthStates = new Map(); // state → { provider, createdAt }
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of _oauthStates) {
    if (now - v.createdAt > 5 * 60 * 1000) _oauthStates.delete(k);
  }
}, 60 * 1000).unref();

function _generateOAuthState(provider) {
  const state = crypto.randomBytes(16).toString('hex');
  _oauthStates.set(state, { provider, createdAt: Date.now() });
  return state;
}

function _consumeOAuthState(state, provider) {
  const entry = _oauthStates.get(state);
  if (!entry) return false;
  _oauthStates.delete(state);
  if (Date.now() - entry.createdAt > 5 * 60 * 1000) return false;
  if (entry.provider !== provider) return false;
  return true;
}

function _httpsGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const req = https.request({
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: { 'User-Agent': 'KasbahGuard/1.0', ...headers }
    }, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch { resolve(data); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

function _httpsPost(url, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const bodyStr = typeof body === 'string' ? body : new URLSearchParams(body).toString();
    const req = https.request({
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(bodyStr),
        'Accept': 'application/json',
        'User-Agent': 'KasbahGuard/1.0',
        ...headers
      }
    }, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch { resolve(data); }
      });
    });
    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

function _issueApiKey(_apiKeys, user, workspace) {
  const key = 'ksk_' + crypto.randomBytes(24).toString('hex');
  const entry = {
    key, keyId: 'kid_' + crypto.randomBytes(8).toString('hex'),
    email: user.email, userId: user.id, workspaceId: workspace.id, tier: workspace.tier,
    createdAt: new Date().toISOString(), lastUsedAt: null, requestCount: 0
  };
  _apiKeys.set(key, entry);
  try { fs.appendFileSync(path.join(DATA_DIR, 'api-keys.jsonl'), JSON.stringify(entry) + '\n'); } catch {}
  return entry;
}

// ── HTTP routes ───────────────────────────────────────────────────────────────

function mount(app, _apiKeys) {
  // POST /v1/auth/signup — create user + workspace + API key
  app.post('/v1/auth/signup', (req, res) => {
    const { email, name } = req.body || {};
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }
    try {
      const { user, workspace } = provisionFromKeyIssuance({ email, name, tier: 'free' });
      const key = 'ksk_' + crypto.randomBytes(24).toString('hex');
      const entry = {
        key,
        keyId: 'kid_' + crypto.randomBytes(8).toString('hex'),
        email: user.email,
        userId: user.id,
        workspaceId: workspace.id,
        tier: workspace.tier,
        createdAt: new Date().toISOString(),
        lastUsedAt: null,
        requestCount: 0
      };
      _apiKeys.set(key, entry);
      // Persist key
      try {
        fs.appendFileSync(
          path.join(DATA_DIR, 'api-keys.jsonl'),
          JSON.stringify(entry) + '\n'
        );
      } catch {}
      return res.json({
        user: { id: user.id, email: user.email, name: user.name },
        workspace: { id: workspace.id, name: workspace.name, tier: workspace.tier },
        apiKey: key,
        keyId: entry.keyId,
        message: 'Save this API key — it will not be shown again.'
      });
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  });

  // GET /v1/me — returns current user (from x-user-id header) and their workspaces
  app.get('/v1/me', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
      // Try resolving via api key
      const key = req.headers['x-api-key'];
      const entry = key ? _apiKeys.get(key) : null;
      if (!entry?.userId) {
        // Return anonymous profile for local / Electron desktop use (no auth configured)
        return res.json({
          user: { id: 'anon', name: 'Local User', email: null, tier: 'free', credits: 0, isAnonymous: true },
          workspaces: [],
          tier: 'free',
          quotaUsed: 0,
          quotaMonthly: 500,
          isAnonymous: true,
          serverVersion: '9.1.0',
        });
      }
      const user = _users.get(entry.userId);
      const workspaces = (_members.get(entry.userId) || []).map(m => ({
        ..._workspaces.get(m.workspaceId),
        role: m.role
      })).filter(Boolean);
      return res.json({ user, workspaces });
    }
    const user = _users.get(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const workspaces = (_members.get(userId) || []).map(m => ({
      ..._workspaces.get(m.workspaceId),
      role: m.role
    })).filter(Boolean);
    return res.json({ user, workspaces });
  });

  // GET /v1/workspaces/:id — workspace details (must be member)
  app.get('/v1/workspaces/:id', (req, res) => {
    const userId = req.headers['x-user-id'];
    const ws = _workspaces.get(req.params.id);
    if (!ws) return res.status(404).json({ error: 'Workspace not found' });
    if (!userId || !getRole(userId, ws.id)) {
      return res.status(403).json({ error: 'Not a member of this workspace' });
    }
    return res.json({
      ...ws,
      members: getMembers(ws.id),
      yourRole: getRole(userId, ws.id)
    });
  });

  // POST /v1/workspaces/:id/members — add member (admin+ only)
  app.post('/v1/workspaces/:id/members', (req, res) => {
    const userId = req.headers['x-user-id'];
    const ws = _workspaces.get(req.params.id);
    if (!ws) return res.status(404).json({ error: 'Workspace not found' });
    if (!hasRole(userId, ws.id, 'admin')) {
      return res.status(403).json({ error: 'Requires admin or owner role' });
    }
    const { email, role } = req.body || {};
    if (!ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role; must be one of: ' + ROLES.join(',') });
    const target = getOrCreateUser({ email, name: email });
    addMember({ userId: target.id, workspaceId: ws.id, role });
    return res.json({ userId: target.id, email: target.email, role });
  });

  // POST /v1/workspaces — create new workspace (any signed-in user can create)
  app.post('/v1/workspaces', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId || !_users.get(userId)) return res.status(401).json({ error: 'Authentication required' });
    const { name } = req.body || {};
    if (!name) return res.status(400).json({ error: 'Workspace name required' });
    const ws = createWorkspace({ name, ownerId: userId, tier: 'free' });
    return res.json(ws);
  });

  // POST /v1/workspaces/:id/invite — invite by email, magic-link token
  // Tier limits enforce team-member caps (Starter=1, Pro=5, Business=25, Enterprise=∞)
  const TEAM_LIMITS = { free: 1, starter: 1, pro: 5, business: 25, enterprise: Infinity };
  const _invites = new Map(); // token → { email, workspaceId, role, expiresAt }
  app.post('/v1/workspaces/:id/invite', (req, res) => {
    const userId = req.headers['x-user-id'];
    const ws = _workspaces.get(req.params.id);
    if (!ws) return res.status(404).json({ error: 'Workspace not found' });
    if (!hasRole(userId, ws.id, 'admin')) {
      return res.status(403).json({ error: 'Requires admin or owner role' });
    }
    const { email, role = 'analyst' } = req.body || {};
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required' });
    if (!ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role; must be one of: ' + ROLES.join(',') });

    // Enforce team-member cap by tier
    const cap = TEAM_LIMITS[ws.tier] ?? TEAM_LIMITS.free;
    const currentMembers = getMembers(ws.id).length;
    if (currentMembers >= cap) {
      return res.status(402).json({
        error: 'Team member limit reached for current plan',
        currentMembers,
        limit: cap,
        tier: ws.tier,
        upgrade: 'https://bekasbah.com/pricing'
      });
    }

    const token = crypto.randomBytes(24).toString('base64url');
    const expiresAt = Date.now() + 7 * 86400000; // 7 days
    _invites.set(token, { email: email.toLowerCase(), workspaceId: ws.id, role, expiresAt, invitedBy: userId });
    const inviteUrl = `https://bekasbah.com/invite?token=${token}`;
    // In production: send email here. For now return the URL so SDK/app can.
    return res.json({
      inviteToken: token,
      inviteUrl,
      expiresAt: new Date(expiresAt).toISOString(),
      email,
      role,
      workspace: { id: ws.id, name: ws.name }
    });
  });

  // POST /v1/invites/accept — exchange invite token for membership + API key
  app.post('/v1/invites/accept', (req, res) => {
    const { token, name } = req.body || {};
    if (!token) return res.status(400).json({ error: 'token required' });
    const invite = _invites.get(token);
    if (!invite) return res.status(404).json({ error: 'Invite not found or already used' });
    if (Date.now() > invite.expiresAt) { _invites.delete(token); return res.status(410).json({ error: 'Invite expired' }); }
    const user = getOrCreateUser({ email: invite.email, name: name || invite.email });
    addMember({ userId: user.id, workspaceId: invite.workspaceId, role: invite.role });
    _invites.delete(token);
    const ws = _workspaces.get(invite.workspaceId);
    // Issue an API key for the new member
    const key = 'ksk_' + crypto.randomBytes(24).toString('hex');
    const entry = {
      key, keyId: 'kid_' + crypto.randomBytes(8).toString('hex'),
      email: user.email, userId: user.id, workspaceId: ws.id, tier: ws.tier,
      createdAt: new Date().toISOString(), lastUsedAt: null, requestCount: 0
    };
    _apiKeys.set(key, entry);
    try { fs.appendFileSync(path.join(DATA_DIR, 'api-keys.jsonl'), JSON.stringify(entry) + '\n'); } catch {}
    return res.json({
      user: { id: user.id, email: user.email, name: user.name },
      workspace: { id: ws.id, name: ws.name, tier: ws.tier },
      role: invite.role,
      apiKey: key,
      keyId: entry.keyId,
      message: 'Welcome! Save your API key — it will not be shown again.'
    });
  });

  // GET /v1/workspaces/:id/invites — list pending invites (admin+)
  app.get('/v1/workspaces/:id/invites', (req, res) => {
    const userId = req.headers['x-user-id'];
    const ws = _workspaces.get(req.params.id);
    if (!ws) return res.status(404).json({ error: 'Workspace not found' });
    if (!hasRole(userId, ws.id, 'admin')) return res.status(403).json({ error: 'Requires admin or owner role' });
    const list = [];
    for (const [token, inv] of _invites.entries()) {
      if (inv.workspaceId === ws.id) list.push({ token, ...inv });
    }
    return res.json({ invites: list });
  });

  // DELETE /v1/invites/:token — revoke pending invite (admin+)
  app.delete('/v1/invites/:token', (req, res) => {
    const userId = req.headers['x-user-id'];
    const invite = _invites.get(req.params.token);
    if (!invite) return res.status(404).json({ error: 'Invite not found' });
    if (!hasRole(userId, invite.workspaceId, 'admin')) {
      return res.status(403).json({ error: 'Requires admin or owner role' });
    }
    _invites.delete(req.params.token);
    return res.json({ revoked: true });
  });

  // ── GitHub OAuth ─────────────────────────────────────────────────────────
  app.get('/v1/auth/github', (req, res) => {
    const { GITHUB_CLIENT_ID } = process.env;
    if (!GITHUB_CLIENT_ID) {
      return res.status(501).json({ error: 'OAuth not configured', setup: 'Set GITHUB_CLIENT_ID + GITHUB_CLIENT_SECRET env vars' });
    }
    const state = _generateOAuthState('github');
    const url = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&scope=user:email&state=${state}`;
    return res.redirect(url);
  });

  app.get('/v1/auth/github/callback', async (req, res) => {
    const { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, OAUTH_REDIRECT_BASE } = process.env;
    if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
      return res.status(501).json({ error: 'OAuth not configured', setup: 'Set GITHUB_CLIENT_ID + GITHUB_CLIENT_SECRET env vars' });
    }
    const { code, state } = req.query;
    if (!code || !state || !_consumeOAuthState(state, 'github')) {
      return res.status(400).json({ error: 'Invalid or expired OAuth state' });
    }
    try {
      const tokenData = await _httpsPost('https://github.com/login/oauth/access_token', {
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code
      }, { Accept: 'application/json' });
      if (!tokenData.access_token) return res.status(401).json({ error: 'GitHub token exchange failed', detail: tokenData });

      const ghUser = await _httpsGet('https://api.github.com/user', { Authorization: `Bearer ${tokenData.access_token}` });
      let email = ghUser.email;
      if (!email) {
        // Fetch primary email from /user/emails
        const emails = await _httpsGet('https://api.github.com/user/emails', { Authorization: `Bearer ${tokenData.access_token}` });
        if (Array.isArray(emails)) {
          const primary = emails.find(e => e.primary && e.verified);
          email = primary ? primary.email : (emails[0] && emails[0].email);
        }
      }
      if (!email) return res.status(400).json({ error: 'Could not retrieve email from GitHub' });

      const user = getOrCreateUser({ email, name: ghUser.name || ghUser.login, provider: 'github' });
      const memberships = getMemberships(user.id);
      let workspace = memberships[0] ? _workspaces.get(memberships[0].workspaceId) : null;
      if (!workspace) {
        workspace = createWorkspace({ name: (ghUser.login || email.split('@')[0]) + "'s Workspace", ownerId: user.id, tier: 'free' });
      }
      const entry = _issueApiKey(_apiKeys, user, workspace);
      return res.json({
        user: { id: user.id, email: user.email, name: user.name },
        workspace: { id: workspace.id, name: workspace.name, tier: workspace.tier },
        apiKey: entry.key,
        keyId: entry.keyId,
        provider: 'github',
        message: 'Save this API key — it will not be shown again.'
      });
    } catch (e) {
      return res.status(500).json({ error: 'GitHub OAuth failed', detail: e.message });
    }
  });

  // ── Google OAuth ─────────────────────────────────────────────────────────
  app.get('/v1/auth/google', (req, res) => {
    const { GOOGLE_CLIENT_ID, OAUTH_REDIRECT_BASE } = process.env;
    if (!GOOGLE_CLIENT_ID) {
      return res.status(501).json({ error: 'OAuth not configured', setup: 'Set GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET env vars' });
    }
    const state = _generateOAuthState('google');
    const redirectUri = encodeURIComponent((OAUTH_REDIRECT_BASE || 'http://127.0.0.1:8788') + '/v1/auth/google/callback');
    const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${GOOGLE_CLIENT_ID}&redirect_uri=${redirectUri}&response_type=code&scope=openid+email+profile&state=${state}`;
    return res.redirect(url);
  });

  app.get('/v1/auth/google/callback', async (req, res) => {
    const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, OAUTH_REDIRECT_BASE } = process.env;
    if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
      return res.status(501).json({ error: 'OAuth not configured', setup: 'Set GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET env vars' });
    }
    const { code, state } = req.query;
    if (!code || !state || !_consumeOAuthState(state, 'google')) {
      return res.status(400).json({ error: 'Invalid or expired OAuth state' });
    }
    try {
      const redirectUri = (OAUTH_REDIRECT_BASE || 'http://127.0.0.1:8788') + '/v1/auth/google/callback';
      const tokenData = await _httpsPost('https://oauth2.googleapis.com/token', {
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        code,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code'
      });
      if (!tokenData.access_token) return res.status(401).json({ error: 'Google token exchange failed', detail: tokenData });

      const gUser = await _httpsGet('https://www.googleapis.com/oauth2/v3/userinfo', { Authorization: `Bearer ${tokenData.access_token}` });
      if (!gUser.email) return res.status(400).json({ error: 'Could not retrieve email from Google' });

      const user = getOrCreateUser({ email: gUser.email, name: gUser.name, provider: 'google' });
      const memberships = getMemberships(user.id);
      let workspace = memberships[0] ? _workspaces.get(memberships[0].workspaceId) : null;
      if (!workspace) {
        workspace = createWorkspace({ name: (gUser.name || gUser.email.split('@')[0]) + "'s Workspace", ownerId: user.id, tier: 'free' });
      }
      const entry = _issueApiKey(_apiKeys, user, workspace);
      return res.json({
        user: { id: user.id, email: user.email, name: user.name },
        workspace: { id: workspace.id, name: workspace.name, tier: workspace.tier },
        apiKey: entry.key,
        keyId: entry.keyId,
        provider: 'google',
        message: 'Save this API key — it will not be shown again.'
      });
    } catch (e) {
      return res.status(500).json({ error: 'Google OAuth failed', detail: e.message });
    }
  });
}

module.exports = {
  mount,
  attachWorkspace,
  requireRole,
  getOrCreateUser,
  getUserById,
  getUserByEmail,
  createWorkspace,
  getWorkspace,
  updateWorkspace,
  addMember,
  getMemberships,
  getRole,
  hasRole,
  getMembers,
  provisionFromKeyIssuance,
  ROLES
};
