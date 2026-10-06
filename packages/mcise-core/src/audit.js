// Chained HMAC audit log – Node.js port
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SECRET = process.env.KASBAH_RECEIPT_SECRET || 'dev-secret-change';
const LOG_PATH = process.env.KASBAH_AUDIT_PATH || path.join(__dirname, '../../data/audit-chain.jsonl');

function hmac(data) {
  return crypto.createHmac('sha256', SECRET).update(JSON.stringify(data)).digest('hex');
}

class AuditChain {
  constructor() {
    this.chain = [];
    this._load();
  }

  _load() {
    try {
      if (!fs.existsSync(LOG_PATH)) return;
      const lines = fs.readFileSync(LOG_PATH, 'utf8').trim().split('\n');
      this.chain = lines.map(l => JSON.parse(l));
    } catch {}
  }

  _persist() {
    fs.mkdirSync(path.dirname(LOG_PATH), { recursive: true });
    fs.writeFileSync(LOG_PATH, this.chain.map(e => JSON.stringify(e)).join('\n') + '\n');
  }

  async append({ actorType, actorId, action, entityType, entityId, payload = {}, traceId }) {
    const prev = this.chain[this.chain.length - 1];
    const sequence = (prev?.sequence || 0) + 1;
    const occurredAt = new Date().toISOString();
    const previousHash = prev?.entryHash || null;
    const canonical = { sequence, occurredAt, actorType, actorId, action, entityType, entityId, payload, previousHash };
    const entryHash = hmac(canonical);
    const entry = { id: crypto.randomUUID(), ...canonical, entryHash };
    this.chain.push(entry);
    this._persist();
    return entry;
  }

  verify() {
    let prevHash = null;
    for (let i = 0; i < this.chain.length; i++) {
      const e = this.chain[i];
      if (e.previousHash !== prevHash) return { valid: false, brokenAt: e.sequence, reason: 'chain_break' };
      const canonical = { sequence: e.sequence, occurredAt: e.occurredAt, actorType: e.actorType, actorId: e.actorId, action: e.action, entityType: e.entityType, entityId: e.entityId, payload: e.payload, previousHash: e.previousHash };
      if (hmac(canonical) !== e.entryHash) return { valid: false, brokenAt: e.sequence, reason: 'hash_mismatch' };
      prevHash = e.entryHash;
    }
    return { valid: true, entriesVerified: this.chain.length };
  }

  list(limit = 100) {
    return this.chain.slice(-limit).reverse();
  }
}

module.exports = { AuditChain };
