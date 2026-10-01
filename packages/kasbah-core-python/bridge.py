#!/usr/bin/env python3
"""
Kasbah Core Bridge — JSON IPC interface between Node.js and Python.
Protocol: one JSON object per line on stdin/stdout.

KasbahOS v4.0 — Mythos-Class Frontier System
Integrates original kasbah_os (v2.0) + kasbah-os engines (v4.0).
"""

import sys
import json
import os
import hashlib
import traceback

# ---------------------------------------------------------------
# Path setup: kasbah-os engines live at project root
# ---------------------------------------------------------------
_KASBAH_OS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "kasbah-os")
)
if os.path.isdir(_KASBAH_OS_DIR):
    sys.path.insert(0, _KASBAH_OS_DIR)

# ---------------------------------------------------------------
# Original kasbah_os v2.0 (always available)
# ---------------------------------------------------------------
try:
    from kasbah_os import KasbahOS, KasbahConfig as OriginalConfig
    _HAS_ORIGINAL = True
except ImportError:
    _HAS_ORIGINAL = False
    KasbahOS = None

# ---------------------------------------------------------------
# kasbah-os v4.0 engines (optional, graceful fallback)
# ---------------------------------------------------------------

_HAS_MYTHOS = False
_HAS_CRYPTO = False
_HAS_BINARY = False
_HAS_GOVERNANCE = False

try:
    from kasbah_types import SecurityClearance, ThreatClass, AuditEntry
    _HAS_TYPES = True
except ImportError:
    _HAS_TYPES = False
    SecurityClearance = ThreatClass = AuditEntry = None

try:
    from crypto_audit import Ed25519Signer, AuditChain, ZeroTrustAudit, MerkleTree
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False
    Ed25519Signer = AuditChain = ZeroTrustAudit = MerkleTree = None

try:
    from binary_engine import BinaryAnalysisEngine
    _HAS_BINARY = True
except ImportError:
    _HAS_BINARY = False
    BinaryAnalysisEngine = None

try:
    from kasbah_mythos import KasbahMythos, ThreatOrchestrator, ResearchPipeline
    _HAS_MYTHOS = True
except ImportError:
    _HAS_MYTHOS = False
    KasbahMythos = ThreatOrchestrator = ResearchPipeline = None

try:
    from governance_proxy import get_governance, KasbahGovernanceProxy, ClearanceLevel
    _HAS_GOVERNANCE = True
except ImportError:
    _HAS_GOVERNANCE = False
    get_governance = KasbahGovernanceProxy = ClearanceLevel = None

# ---------------------------------------------------------------
# P³SG engine (Public-Planet Persistent Sheaf Governance)
# ---------------------------------------------------------------
_HAS_P3SG = False
p3sg_engine = None
p3sg_config = None
try:
    from kasbah_p3sg import PublicPlanetSheafEWA, KasbahConfig as P3SGConfig, ClearanceLevel as P3SGClearance
    p3sg_config = P3SGConfig()
    p3sg_engine = PublicPlanetSheafEWA(p3sg_config)
    _HAS_P3SG = True
except ImportError:
    pass

# ---------------------------------------------------------------
# Engine instances
# ---------------------------------------------------------------

kos = None          # v2.0 KasbahOS
mythos = None       # v4.0 KasbahMythos
audit = None        # v4.0 ZeroTrustAudit
binary_eng = None   # v4.0 BinaryAnalysisEngine

# Init original engine
if _HAS_ORIGINAL and KasbahOS:
    try:
        kos = KasbahOS()
    except Exception:
        kos = None

# Init mythos engines
if _HAS_MYTHOS and KasbahMythos:
    try:
        mythos = KasbahMythos(clearance=(
            SecurityClearance.ADMIN if _HAS_TYPES else None
        ))
    except Exception:
        mythos = None

if _HAS_CRYPTO and ZeroTrustAudit:
    try:
        audit = ZeroTrustAudit(
            clearance=(SecurityClearance.ADMIN if _HAS_TYPES else None)
        )
    except Exception:
        audit = None

if _HAS_BINARY and BinaryAnalysisEngine:
    try:
        binary_eng = BinaryAnalysisEngine()
    except Exception:
        binary_eng = None

if _HAS_GOVERNANCE and get_governance:
    try:
        governance = get_governance()
    except Exception:
        governance = None
else:
    governance = None

# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------

def _ok(data: dict = None, req_id=None) -> dict:
    resp = {"ok": True}
    if req_id is not None:
        resp["id"] = req_id
    if data:
        resp.update(data)
    return resp

def _err(message: str, req_id=None) -> dict:
    resp = {"ok": False, "error": message}
    if req_id is not None:
        resp["id"] = req_id
    return resp

def _extract_params(msg: dict):
    """Extract params from message, handling both protocols:
    - {method, params: {...}}   (original protocol)
    - {id, method, ...params}   (JS bridge protocol)
    """
    if "params" in msg and isinstance(msg["params"], dict):
        return msg["params"]
    # JS bridge: rest of message minus id and method
    return {k: v for k, v in msg.items() if k not in ("id", "method")}

# ---------------------------------------------------------------
# Bridge method table
# ---------------------------------------------------------------

# ═══════════════════════════════════════════════════════════════
# Original v2.0 methods
# ═══════════════════════════════════════════════════════════════

def handle_ingest(params: dict, req_id=None):
    """Ingest a secret for processing."""
    if not kos:
        return _err("KasbahOS v2.0 not loaded", req_id)
    try:
        import asyncio
        secret_text = params.get("secret_text", "")
        source = params.get("source", "api")
        result = asyncio.run(kos.ingest_secret(secret_text, source=source))
        return _ok({
            "result": result,
            "decision": result.get("decision"),
            "category": result.get("category"),
        }, req_id)
    except Exception as e:
        return _err(f"ingest failed: {e}", req_id)

def handle_health(params: dict, req_id=None):
    """System health check (v2 + v4 engines)."""
    modules = {}

    # v2 health
    if kos:
        try:
            modules["kasbah_os_v2"] = kos.health_check()
        except Exception:
            modules["kasbah_os_v2"] = {"status": "error", "error": "health check failed"}

    # v4 modules
    if mythos:
        try:
            engines = mythos.registry.list_engines()
            modules["kasbah_os_v4"] = {
                "status": "online",
                "version": getattr(mythos, "VERSION", "4.0"),
                "engines": engines,
                "clearance": mythos.clearance.name if hasattr(mythos.clearance, 'name') else str(mythos.clearance),
            }
        except Exception as e:
            modules["kasbah_os_v4"] = {"status": "error", "error": str(e)}

    if audit:
        modules["audit"] = {"status": "online", "events": audit.total_events}

    if binary_eng:
        modules["binary"] = {"status": "online"}

    return _ok({"modules": modules, "timestamp": __import__("time").time()}, req_id)

def handle_retrieve(params: dict, req_id=None):
    """Retrieve a previously ingested secret."""
    if not kos:
        return _err("KasbahOS v2.0 not loaded", req_id)
    secret_id = params.get("secret_id", "")
    result = kos.retrieve_secret(secret_id)
    return _ok({"result": result}, req_id)

def handle_shutdown(params: dict, req_id=None):
    """Graceful shutdown."""
    return _ok({"message": "Shutdown signal received"}, req_id)

# ═══════════════════════════════════════════════════════════════
# v4.0 Mythos methods — Crypto / Audit
# ═══════════════════════════════════════════════════════════════

def handle_ping(params: dict, req_id=None):
    """Readiness check for JS bridge startup."""
    ready = {
        "kasbah_os_v2": _HAS_ORIGINAL and kos is not None,
        "mythos": _HAS_MYTHOS and mythos is not None,
        "crypto": _HAS_CRYPTO and audit is not None,
        "binary": _HAS_BINARY and binary_eng is not None,
    }
    return _ok({"pong": True, "ready": ready, "version": "4.0"}, req_id)

def handle_keygen(params: dict, req_id=None):
    """Generate an Ed25519 keypair. Returns seed_hex and public_key_hex."""
    if not _HAS_CRYPTO:
        return _err("crypto_audit module not loaded", req_id)
    try:
        seed, pubkey = Ed25519Signer.keygen()
        return _ok({
            "seed_hex": seed.hex(),
            "public_key_hex": pubkey.hex(),
        }, req_id)
    except Exception as e:
        return _err(f"keygen failed: {e}", req_id)

def handle_pubkey(params: dict, req_id=None):
    """Derive Ed25519 public key from seed."""
    if not _HAS_CRYPTO:
        return _err("crypto_audit module not loaded", req_id)
    try:
        seed_hex = params.get("seed_hex", "")
        seed = bytes.fromhex(seed_hex)
        # Derive using same logic as keygen
        h = hashlib.sha512(seed).digest()
        a = int.from_bytes(h[:32], "little")
        a &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8
        a &= ~(1 << 255)
        # Import the helper from crypto_audit
        from crypto_audit import _montgomery_u_from_edwards_scalar
        A = _montgomery_u_from_edwards_scalar(a).to_bytes(32, "little")
        return _ok({"public_key_hex": A.hex()}, req_id)
    except Exception as e:
        return _err(f"pubkey derivation failed: {e}", req_id)

def handle_sign(params: dict, req_id=None):
    """Sign a message with Ed25519."""
    if not _HAS_CRYPTO:
        return _err("crypto_audit module not loaded", req_id)
    try:
        message_hex = params.get("message_hex", "")
        seed_hex = params.get("seed_hex", "")
        message = bytes.fromhex(message_hex)
        seed = bytes.fromhex(seed_hex)
        sig = Ed25519Signer.sign(message, seed)
        # Get pubkey too
        h = hashlib.sha512(seed).digest()
        a = int.from_bytes(h[:32], "little")
        a &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8
        a &= ~(1 << 255)
        from crypto_audit import _montgomery_u_from_edwards_scalar
        pubkey = _montgomery_u_from_edwards_scalar(a).to_bytes(32, "little")
        return _ok({
            "signature_hex": sig.hex(),
            "public_key_hex": pubkey.hex(),
        }, req_id)
    except Exception as e:
        return _err(f"sign failed: {e}", req_id)

def handle_verify(params: dict, req_id=None):
    """Verify an Ed25519 signature."""
    if not _HAS_CRYPTO:
        return _err("crypto_audit module not loaded", req_id)
    try:
        message_hex = params.get("message_hex", "")
        signature_hex = params.get("signature_hex", "")
        public_key_hex = params.get("public_key_hex", "")
        message = bytes.fromhex(message_hex)
        signature = bytes.fromhex(signature_hex)
        public_key = bytes.fromhex(public_key_hex)
        valid = Ed25519Signer.verify(message, signature, public_key)
        return _ok({"valid": valid}, req_id)
    except Exception as e:
        return _err(f"verify failed: {e}", req_id)

def handle_record_event(params: dict, req_id=None):
    """Record an event to the ZeroTrust audit chain."""
    if not audit:
        return _err("ZeroTrustAudit not loaded", req_id)
    try:
        engine = params.get("engine", "bridge")
        event_type = params.get("event_type", "event")
        data = params.get("data", {})
        entry_id = audit.record_event(engine, event_type, data)
        return _ok({
            "entry_id": entry_id,
            "total_events": audit.total_events,
        }, req_id)
    except Exception as e:
        return _err(f"record_event failed: {e}", req_id)

def handle_audit_report(params: dict, req_id=None):
    """Generate a full audit report."""
    if not audit:
        return _err("ZeroTrustAudit not loaded", req_id)
    try:
        report = audit.generate_audit_report()
        return _ok({"report": report}, req_id)
    except Exception as e:
        return _err(f"audit_report failed: {e}", req_id)

def handle_audit_chain_export(params: dict, req_id=None):
    """Export the raw audit chain entries."""
    if not audit:
        return _err("ZeroTrustAudit not loaded", req_id)
    try:
        chain_data = audit.chain.export_chain()
        return _ok({
            "chain": chain_data,
            "entries": len(chain_data),
            "verified": audit.chain.verify_chain(),
        }, req_id)
    except Exception as e:
        return _err(f"chain_export failed: {e}", req_id)

def handle_audit_chain_import(params: dict, req_id=None):
    """Import and verify a chain export."""
    if not audit:
        return _err("ZeroTrustAudit not loaded", req_id)
    try:
        chain_data = params.get("chain", [])
        verified = audit.chain.import_chain(chain_data)
        return _ok({"verified": verified, "entries": len(audit.chain.entries)}, req_id)
    except Exception as e:
        return _err(f"chain_import failed: {e}", req_id)

def handle_merkle_build(params: dict, req_id=None):
    """Build a Merkle tree from entries and return root."""
    if not _HAS_CRYPTO:
        return _err("crypto_audit module not loaded", req_id)
    try:
        entries = params.get("entries", [])
        if isinstance(entries, list):
            entry_bytes = [
                e.encode() if isinstance(e, str)
                else json.dumps(e, sort_keys=True).encode()
                for e in entries
            ]
        else:
            entry_bytes = params.get("entries_bytes", [])
        tree = MerkleTree(leaves=entry_bytes if entry_bytes else entries)
        root = tree.root_hash()
        return _ok({
            "root_hex": root.hex(),
            "leaf_count": len(tree.leaves),
            "depth": tree.depth if hasattr(tree, 'depth') else None,
        }, req_id)
    except Exception as e:
        return _err(f"merkle_build failed: {e}", req_id)

def handle_merkle_verify(params: dict, req_id=None):
    """Verify a Merkle inclusion proof."""
    if not _HAS_CRYPTO:
        return _err("crypto_audit module not loaded", req_id)
    try:
        root_hex = params.get("root_hex", "")
        leaf_hex = params.get("leaf_hex", "")
        proof_hex = params.get("proof_hex", [])
        root = bytes.fromhex(root_hex)
        leaf = bytes.fromhex(leaf_hex)
        proof = [bytes.fromhex(p) for p in proof_hex]
        valid = MerkleTree.verify_proof(root, proof, leaf)
        return _ok({"valid": valid}, req_id)
    except Exception as e:
        return _err(f"merkle_verify failed: {e}", req_id)

def handle_trust_evaluate(params: dict, req_id=None):
    """Evaluate trust score for an engine."""
    if not audit:
        return _err("ZeroTrustAudit not loaded", req_id)
    try:
        engine_name = params.get("engine", "bridge")
        trust = audit.compute_trust_score(engine_name)
        return _ok({"engine": engine_name, "trust": trust}, req_id)
    except Exception as e:
        return _err(f"trust_evaluate failed: {e}", req_id)

# ═══════════════════════════════════════════════════════════════
# v4.0 Mythos methods — Binary / Pipeline
# ═══════════════════════════════════════════════════════════════

def handle_analyze_binary(params: dict, req_id=None):
    """Analyze binary hex data for vulnerabilities."""
    if not binary_eng:
        return _err("BinaryAnalysisEngine not loaded", req_id)
    try:
        binary_hex = params.get("binary_hex", "")
        sample_id = params.get("sample_id", "unknown")
        raw = bytes.fromhex(binary_hex)

        # Auto-detect architecture from binary header
        try:
            from binary_engine import Arch
            arch = _detect_arch(raw)
            if arch is None:
                arch = Arch.X64  # default fallback
        except ImportError:
            return _err("binary_engine module not importable", req_id)

        analysis = binary_eng.analyze(raw, arch=arch)
        vulns = binary_eng.detect_vulnerabilities(analysis)
        return _ok({
            "architecture": arch.name,
            "analysis": {k: v for k, v in analysis.items()
                         if k not in ("instructions", "cfg", "gadgets")},
            "vulnerabilities": [
                {"type": v.pattern_id if hasattr(v, 'pattern_id') else str(v),
                 "severity": getattr(v, 'severity', 'INFO'),
                 "detail": getattr(v, 'description', str(v))}
                for v in vulns
            ],
            "sample_id": sample_id,
        }, req_id)
    except Exception as e:
        return _err(f"analyze_binary failed: {e}", req_id)


def _detect_arch(data: bytes):
    """Detect architecture from binary magic bytes."""
    try:
        from binary_engine import Arch
    except ImportError:
        return None

    if len(data) < 4:
        return None

    # ELF header: 0x7f 'E' 'L' 'F'
    if data[:4] == b'\x7fELF':
        # ELF class at offset 4: 1=32-bit, 2=64-bit
        if len(data) > 18:
            elf_class = data[4]
            elf_machine = data[18]
            if elf_class == 2:  # 64-bit
                EM_MAP = {0x3E: Arch.X64, 0xB7: Arch.ARM64, 0xF3: Arch.RISC_V64, 8: Arch.MIPS64}
                return EM_MAP.get(elf_machine, Arch.X64)
            else:  # 32-bit
                EM_MAP = {0x03: Arch.X86, 0x28: Arch.ARM, 0xF3: Arch.RISC_V32, 8: Arch.MIPS}
                return EM_MAP.get(elf_machine, Arch.X86)
        return Arch.X64

    # Mach-O magic
    elif data[:4] in (b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
        return Arch.X64  # x86_64 Mach-O (little-endian)
    elif data[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf'):
        # Big-endian Mach-O could be ARM64 or X64
        return Arch.ARM64

    # PE magic: 'MZ'
    elif data[:2] == b'MZ':
        # PE32+ (64-bit) has Magic 0x20b in optional header
        if len(data) > 0x40:
            pe_offset = int.from_bytes(data[0x3C:0x40], 'little')
            if pe_offset + 24 < len(data):
                magic = int.from_bytes(data[pe_offset + 24:pe_offset + 26], 'little')
                if magic == 0x20b:  # PE32+
                    return Arch.X64
        return Arch.X86

    return Arch.X64  # default

def handle_run_pipeline(params: dict, req_id=None):
    """Run a full research pipeline on binary data."""
    if not mythos:
        return _err("KasbahMythos not loaded", req_id)
    try:
        binary_hex = params.get("binary_hex", "")
        target_info = params.get("target_info", {})
        if binary_hex:
            target_info["binary_data"] = bytes.fromhex(binary_hex)
        results = mythos.run_research_cycle(target_info)
        return _ok({"cycle": results}, req_id)
    except Exception as e:
        return _err(f"run_pipeline failed: {e}", req_id)

def handle_module_list(params: dict, req_id=None):
    """List all available engines and their status."""
    modules = {
        "original": {
            "kasbah_os_v2": _HAS_ORIGINAL and kos is not None,
        },
        "mythos": {
            "types": _HAS_TYPES,
            "crypto": _HAS_CRYPTO and audit is not None,
            "binary": _HAS_BINARY and binary_eng is not None,
            "mythos": _HAS_MYTHOS and mythos is not None,
        },
    }
    if mythos:
        modules["mythos"]["engines"] = mythos.registry.list_engines()
    return _ok({"modules": modules}, req_id)

# ═══════════════════════════════════════════════════════════════
# v4.0 Governance Proxy methods
# ═══════════════════════════════════════════════════════════════

def handle_governance_process(params: dict, req_id=None):
    """Run the governance proxy on a conversation turn."""
    if not governance:
        return _err("Governance proxy not loaded", req_id)
    try:
        messages = params.get("messages", [])
        tools = params.get("tools", [])
        clearance_raw = params.get("clearance", 2)
        clearance = None
        if _HAS_GOVERNANCE and ClearanceLevel:
            try:
                clearance = ClearanceLevel(clearance_raw)
            except (ValueError, TypeError):
                clearance = ClearanceLevel.RESEARCHER
        result = governance.process_turn_sync(messages, tools, clearance)
        return _ok(result, req_id)
    except Exception as e:
        return _err(f"governance_process failed: {e}", req_id)


def handle_governance_approve(params: dict, req_id=None):
    """Approve a queued governance action."""
    if not governance:
        return _err("Governance proxy not loaded", req_id)
    try:
        action_id = params.get("action_id", "")
        result = governance.approve_action(action_id)
        return _ok(result, req_id)
    except Exception as e:
        return _err(f"governance_approve failed: {e}", req_id)


def handle_governance_health(params: dict, req_id=None):
    """Governance proxy health check."""
    if not governance:
        return _err("Governance proxy not loaded", req_id)
    try:
        result = governance.health()
        return _ok(result, req_id)
    except Exception as e:
        return _err(f"governance_health failed: {e}", req_id)


# ---------------------------------------------------------------
# P³SG handlers (Public-Planet Persistent Sheaf Governance)
# ---------------------------------------------------------------

def handle_p3sg_advise(params: dict, req_id=None):
    """Run P³SG advisory on an observation window."""
    if not _HAS_P3SG or p3sg_engine is None:
        return _err("P³SG engine not loaded", req_id)
    try:
        import numpy as np
        import asyncio
        obs = np.array(params.get("observation", np.random.randn(32, 8)), dtype=float)
        planet = np.array(params.get("planet_signal", np.zeros(obs.shape[1])), dtype=float)
        clearance_val = params.get("clearance", 2)
        clearance = P3SGClearance(clearance_val) if clearance_val in [0,1,2,3,4] else P3SGClearance.TWO
        result = asyncio.run(p3sg_engine.process(obs, planet, clearance))
        return _ok({
            "prediction_set": list(result.prediction_set),
            "ensemble_score": result.ensemble_score,
            "num_flags": result.num_flags,
            "persistent_sheaf_drift": result.persistent_sheaf_drift,
            "regenerative_score": result.regenerative_score,
            "conformal_coverage": result.conformal_coverage,
            "islamic_compliance": result.islamic_compliance,
            "chain_verified": result.chain_verified,
            "audit_receipt_id": result.audit_receipt.get("id")
        }, req_id)
    except Exception as e:
        return _err(f"p3sg_advise failed: {e}", req_id)


def handle_p3sg_audit_verify(params: dict, req_id=None):
    """Verify P³SG audit chain integrity."""
    if not _HAS_P3SG or p3sg_engine is None:
        return _err("P³SG engine not loaded", req_id)
    try:
        return _ok({
            "chain_valid": p3sg_engine.audit.verify_chain(),
            "total_receipts": len(p3sg_engine.audit.receipts),
            "merkle_root": p3sg_engine.audit.merkle.root().hex() if p3sg_engine.audit.merkle.root() else None
        }, req_id)
    except Exception as e:
        return _err(f"p3sg_audit_verify failed: {e}", req_id)


def handle_p3sg_mathematical_core(params: dict, req_id=None):
    """Return P³SG theoretical foundations documentation."""
    if not _HAS_P3SG or p3sg_config is None:
        return _err("P³SG engine not loaded", req_id)
    return _ok({
        "title": "Public-Planet Persistent Sheaf Governance (P³SG)",
        "origin": "Synthesis of 8-module RKHS specification + EWA martingale + conformal prediction + persistent sheaf cohomology",
        "guarantees": [
            "Lipschitz modules (Lemma 2.1)",
            "Sublinear regret (EWA Shūrā)",
            "Anytime-valid coverage (Conformal Martingale)",
            "Tamper-evidence with forward security (Theorem 5.1)"
        ],
        "advisory_levels": ["CLEAR", "WARN", "REQUIRE_APPROVAL", "REGENERATIVE"],
        "planetary_weight": p3sg_config.planetary_weight,
        "status": "Production-ready. No simulation theater."
    }, req_id)


def handle_p3sg_health(params: dict, req_id=None):
    """P³SG engine health check."""
    if not _HAS_P3SG or p3sg_engine is None:
        return _err("P³SG engine not loaded", req_id)
    return _ok({
        "status": "operational",
        "modules": 8,
        "audit_chain_length": len(p3sg_engine.audit.receipts),
        "planetary_weight": p3sg_config.planetary_weight if p3sg_config else 0.4
    }, req_id)


# ---------------------------------------------------------------
# Method dispatch table
# ---------------------------------------------------------------

METHODS = {
    # v2.0 original
    "ingest": handle_ingest,
    "health": handle_health,
    "retrieve": handle_retrieve,
    "shutdown": handle_shutdown,

    # v4.0 crypto / audit
    "ping": handle_ping,
    "keygen": handle_keygen,
    "pubkey": handle_pubkey,
    "sign": handle_sign,
    "verify": handle_verify,
    "record_event": handle_record_event,
    "audit_report": handle_audit_report,
    "audit_chain_export": handle_audit_chain_export,
    "audit_chain_import": handle_audit_chain_import,
    "merkle_build": handle_merkle_build,
    "merkle_verify": handle_merkle_verify,
    "trust_evaluate": handle_trust_evaluate,

    # v4.0 binary / pipeline
    "analyze_binary": handle_analyze_binary,
    "binary_analyze": handle_analyze_binary,  # alias
    "run_pipeline": handle_run_pipeline,
    "module_list": handle_module_list,

    # v4.0 governance proxy
    "governance_process": handle_governance_process,
    "governance_approve": handle_governance_approve,
    "governance_health": handle_governance_health,

    # P³SG (Public-Planet Persistent Sheaf Governance)
    "p3sg_advise": handle_p3sg_advise,
    "p3sg_audit_verify": handle_p3sg_audit_verify,
    "p3sg_mathematical_core": handle_p3sg_mathematical_core,
    "p3sg_health": handle_p3sg_health,
}

# ---------------------------------------------------------------
# Main event loop
# ---------------------------------------------------------------

def main():
    """Read JSON lines from stdin, dispatch, write JSON lines to stdout."""
    # Signal readiness
    startup = _ok({
        "status": "ready",
        "version": "4.0",
        "modules": {
            "original": _HAS_ORIGINAL and kos is not None,
            "mythos": _HAS_MYTHOS and mythos is not None,
            "crypto": _HAS_CRYPTO and audit is not None,
            "binary": _HAS_BINARY and binary_eng is not None,
            "p3sg": _HAS_P3SG and p3sg_engine is not None,
        }
    })
    sys.stdout.write(json.dumps(startup) + "\n")
    sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            sys.stdout.write(json.dumps(_err(f"Invalid JSON: {e}")) + "\n")
            sys.stdout.flush()
            continue

        method = msg.get("method", "")
        request_id = msg.get("id", None)
        params = _extract_params(msg)

        handler = METHODS.get(method)
        if handler is None:
            sys.stdout.write(
                json.dumps(_err(f"Unknown method: {method}", request_id)) + "\n"
            )
            sys.stdout.flush()
            continue

        try:
            response = handler(params, request_id)
        except Exception as e:
            response = _err(f"{method}: {e}\n{traceback.format_exc()}", request_id)

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()

        # Shutdown signal
        if method == "shutdown":
            break

if __name__ == "__main__":
    main()
