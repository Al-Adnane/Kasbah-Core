'use strict';

/**
 * IPC input validation — reject oversized / wrong-typed payloads
 * before they hit handlers.
 */

const MAX_STR = 200_000; // ~200KB text
const MAX_ARR = 1000;

function isObj(v) { return v && typeof v === 'object' && !Array.isArray(v); }

function str(v, { max = MAX_STR, name = 'string' } = {}) {
  if (v == null) return '';
  if (typeof v !== 'string') throw new Error(name + ' must be a string');
  if (v.length > max) throw new Error(name + ' too long');
  return v;
}

function optStr(v, opts) {
  if (v == null || v === '') return null;
  return str(v, opts);
}

function num(v, { min = -Infinity, max = Infinity, name = 'number' } = {}) {
  const n = Number(v);
  if (!Number.isFinite(n)) throw new Error(name + ' must be a number');
  if (n < min || n > max) throw new Error(name + ' out of range');
  return n;
}

function bool(v, dflt = false) {
  if (v == null) return dflt;
  return !!v;
}

function arr(v, { max = MAX_ARR, name = 'array' } = {}) {
  if (v == null) return [];
  if (!Array.isArray(v)) throw new Error(name + ' must be an array');
  if (v.length > max) throw new Error(name + ' too long');
  return v;
}

function obj(v, name = 'object') {
  if (v == null) return {};
  if (!isObj(v)) throw new Error(name + ' must be an object');
  return v;
}

function locationId(v) {
  const s = str(v, { max: 32, name: 'locationId' });
  if (!/^[a-z0-9_-]{1,32}$/i.test(s)) throw new Error('invalid locationId');
  return s;
}

function code(v) {
  const s = str(v, { max: 40, name: 'code' });
  if (!/^KASBAH-PRO-[A-Z0-9-]{4,20}$/i.test(s.trim())) throw new Error('invalid license code format');
  return s.trim().toUpperCase();
}

module.exports = { str, optStr, num, bool, arr, obj, locationId, code, MAX_STR };
