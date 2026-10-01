'use strict';

/**
 * kernel-gating-engine.js — syscall/operation gating policy engine.
 *
 * HONEST MODES (reported in every result):
 *   - 'ebpf-capable'      Linux with /sys/fs/bpf mounted and root — a real
 *                          eBPF program could enforce this policy in-kernel
 *                          (the archived seccomp/eBPF loader in
 *                          packages/_archive/kernel-ebpf builds one).
 *   - 'policy-userspace'   everywhere else (macOS, unprivileged Linux):
 *                          the SAME policy is evaluated in userspace before
 *                          the agent runtime executes the operation. This is
 *                          real pre-execution gating at the process level,
 *                          not kernel-level enforcement, and says so.
 *
 * The policy itself is deterministic and auditable: explicit deny/allow
 * lists plus argument rules (path prefixes, address blocks).
 */

const fs = require('fs');
const os = require('os');

const DEFAULT_POLICY = {
  version: 1,
  defaultAction: 'allow',
  deniedOperations: [
    'ptrace', 'process_vm_writev', 'kexec_load', 'init_module', 'delete_module',
    'mount', 'reboot', 'setuid', 'setgid', 'chroot',
  ],
  pathRules: [
    { prefix: '/etc/shadow', action: 'deny', reason: 'credential store' },
    { prefix: '/etc/sudoers', action: 'deny', reason: 'privilege escalation surface' },
    { prefix: os.homedir() + '/.ssh', action: 'deny', reason: 'SSH key material' },
    { prefix: os.homedir() + '/.aws', action: 'deny', reason: 'cloud credentials' },
  ],
  networkRules: [
    { cidrPrefix: '169.254.169.254', action: 'deny', reason: 'cloud metadata endpoint (SSRF target)' },
  ],
};

function detectMode() {
  try {
    if (process.platform === 'linux' && fs.existsSync('/sys/fs/bpf') && process.getuid && process.getuid() === 0) {
      return 'ebpf-capable';
    }
  } catch (_) {}
  return 'policy-userspace';
}

class KernelGatingEngine {
  constructor(policy) {
    this.policy = { ...DEFAULT_POLICY, ...(policy || {}) };
    this.mode = detectMode();
    this.checks = 0;
    this.denials = 0;
  }

  /**
   * Evaluate one operation against the policy.
   * @param {string} operation — syscall or abstract op name (e.g. 'open', 'connect')
   * @param {object} context — { path?, address?, args? }
   */
  evaluate(operation, context = {}) {
    this.checks++;
    const deny = (reason, rule) => { this.denials++; return { allowed: false, operation, reason, rule, mode: this.mode }; };

    if (this.policy.deniedOperations.includes(operation)) {
      return deny(`operation "${operation}" is on the deny list`, 'deniedOperations');
    }
    if (context.path) {
      for (const r of this.policy.pathRules) {
        if (String(context.path).startsWith(r.prefix) && r.action === 'deny') {
          return deny(`path ${context.path} matches denied prefix ${r.prefix} (${r.reason})`, 'pathRules');
        }
      }
    }
    if (context.address) {
      for (const r of this.policy.networkRules) {
        if (String(context.address).startsWith(r.cidrPrefix) && r.action === 'deny') {
          return deny(`address ${context.address} matches denied block ${r.cidrPrefix} (${r.reason})`, 'networkRules');
        }
      }
    }
    if (this.policy.defaultAction === 'deny') {
      const allowed = (this.policy.allowedOperations || []).includes(operation);
      return allowed
        ? { allowed: true, operation, reason: 'on allow list (default-deny policy)', mode: this.mode }
        : deny(`default-deny policy and "${operation}" is not on the allow list`, 'defaultAction');
    }
    return { allowed: true, operation, reason: 'no deny rule matched', mode: this.mode };
  }

  /** Replace/merge the active policy after validating its shape. */
  updatePolicy(policy) {
    if (!policy || typeof policy !== 'object') throw new Error('policy must be an object');
    for (const key of ['deniedOperations', 'allowedOperations']) {
      if (policy[key] !== undefined && !Array.isArray(policy[key])) throw new Error(`${key} must be an array`);
    }
    for (const key of ['pathRules', 'networkRules']) {
      if (policy[key] !== undefined) {
        if (!Array.isArray(policy[key])) throw new Error(`${key} must be an array`);
        for (const r of policy[key]) {
          if (!r || typeof r !== 'object' || !r.action) throw new Error(`${key} entries need at least { action }`);
        }
      }
    }
    if (policy.defaultAction !== undefined && !['allow', 'deny'].includes(policy.defaultAction)) {
      throw new Error('defaultAction must be "allow" or "deny"');
    }
    this.policy = { ...this.policy, ...policy, version: (this.policy.version || 0) + 1 };
    return { updated: true, version: this.policy.version, mode: this.mode };
  }

  status() {
    return {
      mode: this.mode,
      enforcement: this.mode === 'ebpf-capable'
        ? 'kernel enforcement possible on this host (eBPF program not auto-loaded — see packages/_archive/kernel-ebpf)'
        : 'userspace pre-execution gating only — this host cannot enforce in-kernel',
      policyVersion: this.policy.version,
      checks: this.checks,
      denials: this.denials,
    };
  }
}

module.exports = { KernelGatingEngine, DEFAULT_POLICY, detectMode };
