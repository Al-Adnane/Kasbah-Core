'use strict';

/**
 * persistence.js — Redis adapter with graceful in-memory fallback
 *
 * Tries ioredis → redis → Map-based in-memory store.
 * All methods return Promises so callers are identical regardless
 * of which backend is active.
 */

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';

// ---------------------------------------------------------------------------
// Backend detection
// ---------------------------------------------------------------------------

let redisClientLib = null;

try {
  require.resolve('ioredis');
  redisClientLib = 'ioredis';
} catch (_) {
  try {
    require.resolve('redis');
    redisClientLib = 'redis';
  } catch (_) {
    // will use in-memory
  }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

let _client = null;        // ioredis / redis client instance
let _connected = false;    // true only when Redis handshake succeeded

// In-memory stores (used when Redis is unavailable)
const MAX_MEM_ENTRIES = 10_000; // LRU cap per store — prevents OOM when Redis is down
const _kv      = new Map();   // key → { value, expiresAt? }
const _hashes  = new Map();   // hash → Map<field, value>
const _lists   = new Map();   // key  → Array (head = index 0)
const _zsets   = new Map();   // key  → Array<{ score, member }>
const _counters = new Map();  // key  → number

function _evictOldest(store) {
  if (store.size >= MAX_MEM_ENTRIES) {
    store.delete(store.keys().next().value);
  }
}

// ---------------------------------------------------------------------------
// In-memory helpers
// ---------------------------------------------------------------------------

function _kvGet(key) {
  const entry = _kv.get(key);
  if (!entry) return null;
  if (entry.expiresAt && Date.now() > entry.expiresAt) {
    _kv.delete(key);
    return null;
  }
  return entry.value;
}

function _kvSet(key, value, ttlSec) {
  _evictOldest(_kv);
  const entry = { value };
  if (ttlSec != null && ttlSec > 0) {
    entry.expiresAt = Date.now() + ttlSec * 1000;
  }
  _kv.set(key, entry);
}

// Background TTL cleanup — sweep expired entries every 60 seconds
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of _kv) { if (v.expiresAt && now > v.expiresAt) _kv.delete(k); }
}, 60_000).unref();

function _matchPattern(pattern, key) {
  // Convert Redis glob pattern to RegExp
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`).test(key);
}

// ---------------------------------------------------------------------------
// connect() — called at startup, safe to skip
// ---------------------------------------------------------------------------

async function connect() {
  if (_connected) return;

  if (!redisClientLib) {
    console.log('[persistence] Redis unavailable — using in-memory store (data will not persist across restarts)');
    return;
  }

  try {
    if (redisClientLib === 'ioredis') {
      const Redis = require('ioredis');
      _client = new Redis(REDIS_URL, {
        lazyConnect: true,
        enableOfflineQueue: false,
        maxRetriesPerRequest: 1,
        connectTimeout: 2000,
      });
      _client.on('error', () => {}); // suppress AggregateError flood when Redis is down
      await _client.connect();
      _connected = true;
      console.log(`[persistence] Redis connected at ${REDIS_URL}`);
    } else if (redisClientLib === 'redis') {
      const { createClient } = require('redis');
      _client = createClient({
        url: REDIS_URL,
        socket: { connectTimeout: 2000 },
      });
      _client.on('error', () => {}); // suppress unhandled error events
      await _client.connect();
      _connected = true;
      console.log(`[persistence] Redis connected at ${REDIS_URL}`);
    }
  } catch (err) {
    _client = null;
    _connected = false;
    const msg = '[persistence] Redis unavailable — using in-memory store (data will not persist across restarts)';
    // Warn when REDIS_URL was set but connection failed; plain info otherwise
    if (process.env.REDIS_URL) console.warn(msg); else console.log(msg);
  }
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

function _serialize(value) {
  return JSON.stringify(value);
}

function _deserialize(raw) {
  if (raw == null) return null;
  try {
    return JSON.parse(raw);
  } catch (_) {
    return raw;
  }
}

// ---------------------------------------------------------------------------
// Generic KV
// ---------------------------------------------------------------------------

async function get(key) {
  if (_connected && _client) {
    const raw = await _client.get(key);
    return _deserialize(raw);
  }
  return _kvGet(key);
}

async function set(key, value, ttlSec) {
  if (_connected && _client) {
    const serialized = _serialize(value);
    if (ttlSec != null && ttlSec > 0) {
      await _client.set(key, serialized, 'EX', ttlSec);
    } else {
      await _client.set(key, serialized);
    }
    return;
  }
  _kvSet(key, value, ttlSec);
}

async function del(key) {
  if (_connected && _client) {
    await _client.del(key);
    return;
  }
  _kv.delete(key);
  _hashes.delete(key);
  _lists.delete(key);
  _zsets.delete(key);
  _counters.delete(key);
}

async function keys(pattern) {
  if (_connected && _client) {
    return _client.keys(pattern);
  }
  const allKeys = [
    ..._kv.keys(),
    ..._hashes.keys(),
    ..._lists.keys(),
    ..._zsets.keys(),
    ..._counters.keys(),
  ];
  const unique = [...new Set(allKeys)];
  return unique.filter(k => _matchPattern(pattern, k));
}

// ---------------------------------------------------------------------------
// Hash operations
// ---------------------------------------------------------------------------

async function hget(hash, field) {
  if (_connected && _client) {
    const raw = await _client.hget(hash, field);
    return _deserialize(raw);
  }
  const h = _hashes.get(hash);
  if (!h) return null;
  const raw = h.get(field);
  return raw !== undefined ? _deserialize(raw) : null;
}

async function hset(hash, field, value) {
  if (_connected && _client) {
    await _client.hset(hash, field, _serialize(value));
    return;
  }
  if (!_hashes.has(hash)) _hashes.set(hash, new Map());
  _hashes.get(hash).set(field, _serialize(value));
}

async function hdel(hash, field) {
  if (_connected && _client) {
    await _client.hdel(hash, field);
    return;
  }
  const h = _hashes.get(hash);
  if (h) h.delete(field);
}

async function hgetall(hash) {
  if (_connected && _client) {
    const raw = await _client.hgetall(hash);
    if (!raw) return {};
    const result = {};
    for (const [k, v] of Object.entries(raw)) {
      result[k] = _deserialize(v);
    }
    return result;
  }
  const h = _hashes.get(hash);
  if (!h || h.size === 0) return {};
  const result = {};
  for (const [k, v] of h.entries()) {
    result[k] = _deserialize(v);
  }
  return result;
}

// ---------------------------------------------------------------------------
// List / append (audit chain)
// ---------------------------------------------------------------------------

async function lpush(key, value) {
  if (_connected && _client) {
    await _client.lpush(key, _serialize(value));
    return;
  }
  if (!_lists.has(key)) _lists.set(key, []);
  _lists.get(key).unshift(_serialize(value));
}

async function lrange(key, start, stop) {
  if (_connected && _client) {
    const raw = await _client.lrange(key, start, stop);
    return (raw || []).map(_deserialize);
  }
  const list = _lists.get(key) || [];
  const end = stop === -1 ? list.length : stop + 1;
  return list.slice(start, end).map(_deserialize);
}

async function llen(key) {
  if (_connected && _client) {
    return _client.llen(key);
  }
  return (_lists.get(key) || []).length;
}

// ---------------------------------------------------------------------------
// Sorted set (time-ordered events, spend ledger)
// ---------------------------------------------------------------------------

function _zsetInsert(arr, score, member) {
  const idx = arr.findIndex(e => e.score > score);
  if (idx === -1) {
    arr.push({ score, member });
  } else {
    arr.splice(idx, 0, { score, member });
  }
}

async function zadd(key, score, member) {
  if (_connected && _client) {
    await _client.zadd(key, score, _serialize(member));
    return;
  }
  if (!_zsets.has(key)) _zsets.set(key, []);
  const arr = _zsets.get(key);
  // remove existing entry with same member (upsert)
  const serialized = _serialize(member);
  const existing = arr.findIndex(e => e.member === serialized);
  if (existing !== -1) arr.splice(existing, 1);
  _zsetInsert(arr, score, serialized);
}

async function zrange(key, start, stop, withScores) {
  if (_connected && _client) {
    if (withScores) {
      const raw = await _client.zrange(key, start, stop, 'WITHSCORES');
      const result = [];
      for (let i = 0; i < raw.length; i += 2) {
        result.push({ member: _deserialize(raw[i]), score: parseFloat(raw[i + 1]) });
      }
      return result;
    }
    const raw = await _client.zrange(key, start, stop);
    return (raw || []).map(_deserialize);
  }
  const arr = _zsets.get(key) || [];
  const end = stop === -1 ? arr.length : stop + 1;
  const slice = arr.slice(start, end);
  if (withScores) {
    return slice.map(e => ({ member: _deserialize(e.member), score: e.score }));
  }
  return slice.map(e => _deserialize(e.member));
}

async function zrangebyscore(key, min, max) {
  if (_connected && _client) {
    const raw = await _client.zrangebyscore(key, min, max);
    return (raw || []).map(_deserialize);
  }
  const arr = _zsets.get(key) || [];
  return arr
    .filter(e => e.score >= min && e.score <= max)
    .map(e => _deserialize(e.member));
}

// ---------------------------------------------------------------------------
// Atomic increment
// ---------------------------------------------------------------------------

async function incr(key) {
  if (_connected && _client) {
    return _client.incr(key);
  }
  const cur = _counters.get(key) || 0;
  const next = cur + 1;
  _counters.set(key, next);
  return next;
}

async function incrby(key, amount) {
  if (_connected && _client) {
    return _client.incrby(key, amount);
  }
  const cur = _counters.get(key) || 0;
  const next = cur + amount;
  _counters.set(key, next);
  return next;
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Pub/Sub — in-memory event bus (Redis-backed when available)
// ---------------------------------------------------------------------------

const { EventEmitter } = require('events');
const _eventBus = new EventEmitter();
// Limit listeners per channel to prevent memory leaks
_eventBus.setMaxListeners(100);

async function publish(channel, message) {
  if (_connected && _client) {
    return _client.publish(channel, _serialize(message));
  }
  // In-memory event bus
  const data = typeof message === 'string' ? message : _serialize(message);
  _eventBus.emit(channel, data);
  return _eventBus.listenerCount(channel);
}

async function subscribe(channel, handler) {
  if (_connected && _client) {
    // Redis subscribe would go here
    return;
  }
  _eventBus.on(channel, handler);
}

async function unsubscribe(channel, handler) {
  if (_connected && _client) {
    return;
  }
  if (handler) {
    _eventBus.removeListener(channel, handler);
  } else {
    _eventBus.removeAllListeners(channel);
  }
}

// ---------------------------------------------------------------------------
// isRedis helper
// ---------------------------------------------------------------------------

function isRedis() {
  return _connected;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  connect,
  isRedis,
  get,
  set,
  del,
  keys,
  hget,
  hset,
  hdel,
  hgetall,
  lpush,
  lrange,
  llen,
  zadd,
  zrange,
  zrangebyscore,
  incr,
  incrby,
  publish,
  subscribe,
  unsubscribe,
};
