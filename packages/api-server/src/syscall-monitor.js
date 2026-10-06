'use strict';

/**
 * syscall-monitor — sandbox policy primitives ported from
 * kasbah-os/kernel_fuzzer.py (models only; no simulated execution).
 *
 * validateArgs(def, args): typed argument checks per syscall definition.
 * anomalyScore(seq): mean(1-p) over adjacent transition pairs; unknown
 *   edge scores 1.0; sequences shorter than 2 score 0.
 * nextState(current, rand): weighted pick from TRANSITIONS.
 */

const SYSCALLS = {
  open:    { number: 2,   category: 'file',    dangerous: false, args: [{ name: 'path', type: 'path' }, { name: 'flags', type: 'flags' }] },
  read:    { number: 0,   category: 'file',    dangerous: false, args: [{ name: 'fd', type: 'fd' }, { name: 'buf', type: 'ptr' }, { name: 'count', type: 'len' }] },
  write:   { number: 1,   category: 'file',    dangerous: false, args: [{ name: 'fd', type: 'fd' }, { name: 'buf', type: 'ptr' }, { name: 'count', type: 'len' }] },
  close:   { number: 3,   category: 'file',    dangerous: false, args: [{ name: 'fd', type: 'fd' }] },
  mmap:    { number: 9,   category: 'memory',  dangerous: true,  args: [{ name: 'addr', type: 'addr' }, { name: 'len', type: 'len' }] },
  munmap:  { number: 11,  category: 'memory',  dangerous: false, args: [{ name: 'addr', type: 'addr' }, { name: 'len', type: 'len' }] },
  mprotect:{ number: 10,  category: 'memory',  dangerous: true,  args: [{ name: 'addr', type: 'addr' }, { name: 'len', type: 'len' }] },
  ioctl:   { number: 16,  category: 'file',    dangerous: true,  args: [{ name: 'fd', type: 'fd' }] },
  ptrace:  { number: 101, category: 'process', dangerous: true,  args: [{ name: 'pid', type: 'pid' }] },
  execve:  { number: 59,  category: 'process', dangerous: true,  args: [{ name: 'path', type: 'path' }] },
  fork:    { number: 57,  category: 'process', dangerous: true,  args: [] },
  clone:   { number: 56,  category: 'process', dangerous: true,  args: [{ name: 'flags', type: 'flags' }] },
  socket:  { number: 41,  category: 'net',     dangerous: false, args: [] },
  connect: { number: 42,  category: 'net',     dangerous: false, args: [{ name: 'fd', type: 'fd' }] },
  bind:    { number: 49,  category: 'net',     dangerous: false, args: [{ name: 'fd', type: 'fd' }] },
  sendmsg: { number: 46,  category: 'net',     dangerous: false, args: [{ name: 'fd', type: 'fd' }] },
  recvmsg: { number: 47,  category: 'net',     dangerous: false, args: [{ name: 'fd', type: 'fd' }] },
  kill:    { number: 62,  category: 'signal',  dangerous: true,  args: [{ name: 'pid', type: 'pid' }, { name: 'sig', type: 'signal' }] },
};

const TRANSITIONS = {
  open: { read: 0.4, write: 0.3, close: 0.2, ioctl: 0.1 },
  read: { read: 0.3, write: 0.3, close: 0.4 },
  write: { write: 0.3, close: 0.5, read: 0.2 },
  close: { open: 0.5, execve: 0.3, mmap: 0.2 },
  mmap: { mprotect: 0.3, munmap: 0.5, write: 0.2 },
  mprotect: { munmap: 0.5, write: 0.3, mmap: 0.2 },
  munmap: { mmap: 0.4, open: 0.3, execve: 0.3 },
  fork: { execve: 0.5, clone: 0.3, kill: 0.2 },
  clone: { execve: 0.4, ptrace: 0.3, kill: 0.3 },
  execve: { read: 0.3, write: 0.3, mmap: 0.2, open: 0.2 },
  ptrace: { kill: 0.4, write: 0.3, ptrace: 0.3 },
  socket: { bind: 0.3, connect: 0.3, close: 0.4 },
  bind: { sendmsg: 0.3, recvmsg: 0.3, close: 0.4 },
  connect: { sendmsg: 0.3, recvmsg: 0.3, close: 0.4 },
  sendmsg: { recvmsg: 0.5, close: 0.5 },
  recvmsg: { sendmsg: 0.5, close: 0.5 },
  kill: { kill: 0.1, read: 0.2, write: 0.2, close: 0.5 },
};

const TOTAL_EDGES = Object.values(TRANSITIONS).reduce((n, outs) => n + Object.keys(outs).length, 0);

function validateArgs(name, args = {}) {
  const def = SYSCALLS[name];
  if (!def) return { ok: false, error: `unknown syscall: ${name}` };
  const violations = [];
  for (const a of def.args) {
    const v = args[a.name];
    if (v === undefined) { violations.push(`missing ${a.name}`); continue; }
    switch (a.type) {
      case 'fd': if (!Number.isInteger(v) || v < 0) violations.push(`bad fd ${a.name}=${v}`); break;
      case 'pid': if (!Number.isInteger(v) || v < -1) violations.push(`bad pid ${a.name}=${v}`); break;
      case 'signal': if (!Number.isInteger(v) || v < 0 || v > 64) violations.push(`bad signal ${a.name}=${v}`); break;
      case 'path': if (typeof v !== 'string' || !v.length) violations.push(`bad path ${a.name}`); break;
      case 'ptr': case 'addr': if (typeof v === 'number' && v < 0) violations.push(`bad pointer ${a.name}=${v}`); break;
      case 'len': if (!Number.isInteger(v) || v < 0) violations.push(`bad length ${a.name}=${v}`); break;
      default: break;
    }
  }
  return { ok: violations.length === 0, violations, dangerous: def.dangerous, category: def.category };
}

function anomalyScore(seq) {
  if (!Array.isArray(seq) || seq.length < 2) return { score: 0, pairs: 0 };
  let sum = 0;
  const details = [];
  for (let i = 0; i < seq.length - 1; i++) {
    const outs = TRANSITIONS[seq[i]];
    const p = outs ? outs[seq[i + 1]] : undefined;
    const s = p === undefined ? 1.0 : 1 - p;
    sum += s;
    details.push({ from: seq[i], to: seq[i + 1], p: p === undefined ? 0 : p, anomaly: +s.toFixed(3) });
  }
  return { score: +(sum / (seq.length - 1)).toFixed(4), pairs: seq.length - 1, details };
}

function nextState(current, rand = Math.random) {
  const outs = TRANSITIONS[current];
  if (!outs) return { next: null, reason: 'no out-edges' };
  let r = rand();
  for (const [to, p] of Object.entries(outs)) {
    r -= p;
    if (r <= 0) return { next: to, p };
  }
  const keys = Object.keys(outs);
  return { next: keys[keys.length - 1], p: outs[keys[keys.length - 1]] };
}

module.exports = { SYSCALLS, TRANSITIONS, TOTAL_EDGES, validateArgs, anomalyScore, nextState };
