// ssi-gate.ts — Sovereign SSI Admission Gate (v14.1 risk-proportional escalation)
//
// Integration:
//   Claude Code / Cursor / Windsurf → MCP server → Consent Stone → real shell
//
// When an agent wants to run a dangerous command (shell, file write, network POST),
// the MCP server:
//   1. Computes the action hash
//   2. Sends a request to the Stone over BLE
//   3. Stone lights up, user taps
//   4. Stone signs the action hash with the SE key
//   5. MCP server verifies the signature
//   6. MCP server forwards the call to the real tool
//
// v14.1 RISK-PROPORTIONAL ESCALATION:
// Eliminates prompt fatigue by classifying every tool call into one of
// three risk tiers. The Stone only ignites for the top tier.
//
// ZERO-TOUCH (90% of calls): read_file, grep, format, test
//   → MCP passes through silently. Stone stays dark.
//
// SOFT-GATE (9% of calls): write_file to non-sensitive paths, local builds
//   → MCP logs the action. Stone stays dark but audit trail records it.
//
// PHYSICAL TOUCH (1% of calls): destructive shell, production DB, secrets
//   → Stone lights up. User MUST tap. SE signs the action hash.
//
// This is the patent's ignition threshold in practice:
//   s(c*) > θ_ign  →  zero-touch passthrough
//   θ_del < s(c*) ≤ θ_ign  →  soft-gate (log only)
//   s(c*) ≤ θ_del  →  physical touch required
//
import { NextRequest, NextResponse } from 'next/server'

// ── Risk tier classification ──────────────────────────────────────────────

// ZERO-TOUCH: safe, read-only operations — Stone stays dark
const ZERO_TOUCH_TOOLS = {
  "read_file", "grep", "find", "ls", "cat", "head", "tail",
  "wc", "diff", "git_status", "git_log", "git_diff",
  "format", "lint", "type_check", "test", "pytest",
  "cargo_check", "npm_test", "bun_test",
}

// SOFT-GATE: moderate risk — logged but no Stone tap required
const SOFT_GATE_TOOLS = {
  "write_file", "move_file", "mkdir", "touch",
  "git_add", "git_commit", "git_push",
  "pip_install", "npm_install", "cargo_build",
  "http_get",
}

// PHYSICAL TOUCH: high-consequence — Stone MUST be tapped
const PHYSICAL_TOUCH_TOOLS = {
  "shell", "exec", "bash", "zsh", "sh",
  "delete_file", "rm", "rmdir", "chmod", "chown",
  "http_post", "http_put", "http_delete",
  "sudo", "dd", "mkfs", "fdisk",
  "pip_install", "npm_install", "cargo_run",  // when executing untrusted code
  "db_migrate", "db_drop", "db_schema_change",
  "git_force_push", "git_reset_hard",
}

// Sensitive path patterns — any tool touching these requires physical touch
const SENSITIVE_PATH_PATTERNS = [
  b".ssh/", b".env", b"credentials", b".aws/",
  b".gnupg/", b"id_rsa", b"id_ed25519",
  b"~/.config/gcloud", b"service_account.json",
  b".npmrc", b".pypirc", b".docker/config",
]

/** Classify a tool call into a risk tier. */
function classifyRisk(toolName: string, args: Uint8Array = new Uint8Array()): 'ZERO_TOUCH' | 'SOFT_GATE' | 'PHYSICAL_TOUCH' {
  const tool = toolName.toLowerCase()

  // Check for sensitive path patterns in args first
  for (const pattern of SENSITIVE_PATH_PATTERNS) {
    if (pattern.some(p => args.includes(p))) {
      return 'PHYSICAL_TOUCH'
    }
  }

  if (ZERO_TOUCH_TOOLS.includes(tool)) {
    return 'ZERO_TOUCH'
  }
  if (SOFT_GATE_TOOLS.includes(tool)) {
    return 'SOFT_GATE'
  }
  if (PHYSICAL_TOUCH_TOOLS.includes(tool)) {
    return 'PHYSICAL_TOUCH'
  }
  // Unknown tools default to physical touch (fail-safe)
  return 'PHYSICAL_TOUCH'
}

// ── MCP Server ──────────────────────────────────────────────────────────────

/** Risk-proportional escalation middleware. */
export function* withRiskProportionalGate(
  toolName: string,
  args: Uint8Array,
  stone: { allowsExecution: () => { allowed: boolean; reason?: string } },
  handler: (allowed: boolean, signature?: Uint8Array, reason?: string) => NextResponse
): NextResponse {
  const risk = classifyRisk(toolName, args)

  if (risk === 'ZERO_TOUCH') {
    // Silent passthrough — Stone stays dark
    return handler(true, undefined, undefined)
  }

  if (risk === 'SOFT_GATE') {
    // Logged action — Stone stays dark, audit trail records it
    return handler(true, undefined, 'soft-gate-logged')
  }

  // PHYSICAL TOUCH — Stone MUST be tapped
  // Compute action hash for signing
  const actionHash = computeActionHash(toolName, args)

  // Check Stone state
  const allowed = stone.allowsExecution()
  if (!allowed.allowed) {
    return handler(false, undefined, allowed.reason)
  }

  // Stone is connected and tapped — sign the action
  const signature = signAction(actionHash)
  if (signature === undefined) {
    return handler(false, undefined, 'stone-failed-to-sign')
  }

  // Verify the signature (defense in depth)
  if (!verifySignature(actionHash, signature)) {
    return handler(false, undefined, 'signature-verification-failed')
  }

  // Elevate epistemic tier: tap transforms MODEL → RULE
  return handler(true, signature, 'tap-elevated-model-to-rule')
}

/** Compute action hash for signing. */
function computeActionHash(toolName: string, args: Uint8Array): Uint8Array {
  const parts: Uint8Array[] = [new TextEncoder().encode(toolName), args, new TextEncoder().encode(Date.now().toString())]
  return sha256Concat(...parts)
}

/** SHA-256 concat hash. */
function sha256Concat(...parts: Uint8Array[]): Uint8Array {
  const h = createHash('sha256')
  for (const p of parts) h.update(p)
  return h.digest()
}

/** Sign action hash with Stone key. */
function signAction(actionHash: Uint8Array): Uint8Array | undefined {
  // In production: OPTIGA Trust M signs with ECDSA P-256, key never leaves chip
  // Here: HMAC-based simulation
  return createHmac('sha256', 'stone-secret-key').update(actionHash).digest()
}

/** Verify Stone signature independently. */
function verifySignature(actionHash: Uint8Array, signature: Uint8Array): boolean {
  const expected = createHmac('sha256', 'stone-secret-key').update(actionHash).digest()
  return expected.equals(signature)
}

// Export types and constants for use in the MCP server
export type { classifyRisk }
export { ZERO_TOUCH_TOOLS, SOFT_GATE_TOOLS, PHYSICAL_TOUCH_TOOLS, SENSITIVE_PATH_PATTERNS }

// ── Export ─────────────────────────────────────────────────────────────────
export type { classifyRisk }
export {
  withRiskProportionalGate,
  classifyRisk,
  computeActionHash,
  sha256Concat,
  signAction,
  verifySignature,
}
