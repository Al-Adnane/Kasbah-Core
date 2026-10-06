// HMAC-signed Fixed Core service – Node.js port of MCISE OS
const crypto = require('crypto');

const SECRET = process.env.KASBAH_RECEIPT_SECRET || 'dev-secret-change';

function hmac(data) {
  return crypto.createHmac('sha256', SECRET).update(JSON.stringify(data)).digest('hex');
}

class FixedCore {
  constructor() {
    this.store = new Map();
  }

  list() {
    return Array.from(this.store.values());
  }

  get(key) {
    const rec = this.store.get(key);
    if (!rec) return null;
    if (hmac({ ...rec, signature: undefined }) !== rec.signature) {
      throw new Error('Fixed Core signature invalid');
    }
    return rec;
  }

  update(key, value, actor, boardToken) {
    if (!boardToken || boardToken !== process.env.KASBAH_BOARD_TOKEN) {
      throw new Error('board token required');
    }
    const rec = {
      key,
      value,
      modifiedBy: actor,
      modifiedAt: new Date().toISOString(),
      version: (this.store.get(key)?.version || 0) + 1,
    };
    rec.signature = hmac(rec);
    this.store.set(key, { ...rec });
    return rec;
  }

  seedDefaults() {
    const defaults = [
      { key: 'vision', value: 'Sovereign governance through adversarial agents' },
      { key: 'mission', value: 'Protect truth with cryptographic receipts' },
      { key: 'refusals', value: ['refusal1','refusal2','refusal3'] },
      { key: 'evidence_hierarchy', value: {} },
      { key: 'paradox_watch', value: [] },
    ];
    defaults.forEach(d => {
      if (!this.store.has(d.key)) this.update(d.key, d.value, 'system', process.env.KASBAH_BOARD_TOKEN);
    });
  }
}

module.exports = { FixedCore };
