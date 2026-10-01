'use strict';

// Singleton entry for the kernel gating capability. `available` is true only
// when this host could actually load an eBPF program (Linux + bpffs + root) —
// everywhere else callers must treat gating as userspace policy evaluation,
// which is what KernelGatingEngine reports via its `mode` field.

const { KernelGatingEngine, DEFAULT_POLICY, detectMode } = require('./src/kernel-gating-engine.js');

const engine = new KernelGatingEngine();

module.exports = {
  available: detectMode() === 'ebpf-capable',
  mode: engine.mode,
  blockedSyscalls: DEFAULT_POLICY.deniedOperations,
  engine,
  KernelGatingEngine,
};
