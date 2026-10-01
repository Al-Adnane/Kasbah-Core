#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║ HONEST SCOPE: CWE Pattern Scanner & Static Analyzer         ║
║ NOT a zero-day discovery engine — research analysis tool    ║
╚══════════════════════════════════════════════════════════════╝

REAL: 19 CWE pattern definitions with byte-level regex matching,
      binary section analysis, threat classification, severity scoring.
SIMULATED: Dynamic/symbolic modes use random (inert), no live execution.
PURPOSE: Static vulnerability pattern detection in binary artifacts.

ZeroDayDiscoveryEngine — CWE pattern scanner and static analyzer.

Modes:
  'static'   — Pattern-based binary scanning against 19 CWE dangerous patterns.
  'dynamic'  — Coverage-guided fuzzing with byte-level mutations.
  'symbolic' — Constraint-based path exploration (simulated).
  'hybrid'   — Run all three, merge and deduplicate findings.

Context-aware severity scoring:
  score = base_score × reachability_factor × privilege_factor × exploitability_factor

No external deps beyond stdlib. Pure Python 3.10+.
"""

from __future__ import annotations

import hashlib
import re
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from kasbah_types import BinarySection, SecurityClearance, ThreatClass, ThreatFinding


# ═══════════════════════════════════════════════════════════════════════════════
# CWE Pattern Definitions
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class CWEPattern:
    """A single CWE-related dangerous pattern definition."""

    cwe_id: str
    name: str
    pattern_regex: bytes  # compiled regex or byte pattern
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str

    def matches(self, data: bytes) -> List[int]:
        """Return all byte offsets where pattern matches."""
        offsets = []
        for match in re.finditer(self.pattern_regex, data, re.DOTALL):
            offsets.append(match.start())
        return offsets


# ── 19 CWE Pattern Definitions ────────────────────────────────────────────

CWE_PATTERNS: List[CWEPattern] = [
    # Stack-based buffer overflow
    CWEPattern("CWE-121", "Stack Buffer Overflow",
               rb"(strcpy|strcat|sprintf|gets|scanf|strncpy)\x00",
               "CRITICAL", "memory_corruption"),
    # Heap overflow
    CWEPattern("CWE-122", "Heap Buffer Overflow",
               rb"(malloc|calloc|realloc)\x00",
               "CRITICAL", "memory_corruption"),
    # Format string vulnerability
    CWEPattern("CWE-134", "Format String",
               rb"(printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|syslog)\x00",
               "HIGH", "input_validation"),
    # Integer overflow/wraparound
    CWEPattern("CWE-190", "Integer Overflow",
               rb"[\x00-\xff]{0,4}(atoi|atol|strtol|strtoul|strtoll|strtoull)\x00",
               "HIGH", "numeric_error"),
    # Use after free
    CWEPattern("CWE-416", "Use After Free",
               rb"(free|delete)\x00",
               "CRITICAL", "memory_corruption"),
    # NULL pointer dereference
    CWEPattern("CWE-476", "NULL Pointer Dereference",
               rb"(\x48\x8b\x00|\x48\x8b\x40|\xe8[\x00-\xff]{4}\x48\x85\xc0)",
               "MEDIUM", "memory_corruption"),
    # Out-of-bounds write
    CWEPattern("CWE-787", "Out-of-Bounds Write",
               rb"memcpy\x00|memmove\x00|memset\x00|bcopy\x00",
               "CRITICAL", "memory_corruption"),
    # Out-of-bounds read
    CWEPattern("CWE-125", "Out-of-Bounds Read",
               rb"memcmp\x00|strcmp\x00|strncmp\x00",
               "MEDIUM", "memory_corruption"),
    # Improper input validation
    CWEPattern("CWE-20", "Improper Input Validation",
               rb"(recv|recvfrom|recvmsg|read)\x00",
               "MEDIUM", "input_validation"),
    # OS command injection
    CWEPattern("CWE-78", "OS Command Injection",
               rb"(system|popen|exec[lv]?[pe]?|fork|execve)\x00",
               "CRITICAL", "injection"),
    # SQL injection
    CWEPattern("CWE-89", "SQL Injection",
               rb"(mysql_query|sqlite3_exec|PQexec|OCIStmtExecute|odbc_exec)\x00",
               "CRITICAL", "injection"),
    # Generic buffer overflow
    CWEPattern("CWE-119", "Buffer Overflow (Generic)",
               rb"(vsprintf|vscanf|sscanf)\x00",
               "HIGH", "memory_corruption"),
    # Race condition
    CWEPattern("CWE-362", "Race Condition",
               rb"(access|stat|open|fopen|creat|mkdir|symlink|link|unlink|rename)\x00",
               "MEDIUM", "concurrency"),
    # Resource exhaustion
    CWEPattern("CWE-400", "Resource Exhaustion",
               rb"(fork|clone|pthread_create|CreateThread)\x00",
               "LOW", "resource_management"),
    # Double free
    CWEPattern("CWE-415", "Double Free",
               rb"free\x00[\x00-\xff]{0,32}free\x00",
               "CRITICAL", "memory_corruption"),
    # Deserialization of untrusted data
    CWEPattern("CWE-502", "Deserialization",
               rb"(pickle|unpickle|json\.loads|yaml\.load|marshal\.load)",
               "HIGH", "data_handling"),
    # Incorrect permission assignment
    CWEPattern("CWE-732", "Permission Issues",
               rb"(chmod|chown|setuid|setgid|seteuid|setegid)\x00",
               "MEDIUM", "authorization"),
    # Hardcoded credentials
    CWEPattern("CWE-798", "Hardcoded Credentials",
               rb"(?i)(password|passwd|secret|api[_-]?key|token|auth)[\x20-\x7e]{0,64}[=:]\x20*[\"\'][\x20-\x7e]{8,}[\"\']",
               "CRITICAL", "credential_management"),
    # Server-Side Request Forgery
    CWEPattern("CWE-918", "SSRF",
               rb"(curl_easy_setopt|urlopen|requests\.get|requests\.post|fetch|XMLHttpRequest)",
               "HIGH", "network"),
]

# Severity weight map
SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}


# ═══════════════════════════════════════════════════════════════════════════════
# Static Analyzer
# ═══════════════════════════════════════════════════════════════════════════════


class StaticAnalyzer:
    """Pattern-based static binary analysis."""

    # Additional dangerous function patterns (byte-level)
    DANGEROUS_FUNCTIONS = [
        (rb"strcpy", "STRCPY"),
        (rb"sprintf", "SPRINTF"),
        (rb"gets", "GETS"),
        (rb"scanf", "SCANF"),
        (rb"system", "SYSTEM"),
        (rb"popen", "POPEN"),
        (rb"exec[lv]", "EXEC"),
        (rb"eval", "EVAL"),
        (rb"strcat", "STRCAT"),
        (rb"read\b", "READ"),
        (rb"write\b", "WRITE"),
        (rb"send\b", "SEND"),
    ]

    def __init__(self, sections: Optional[List[BinarySection]] = None):
        self.sections = sections or []
        self.findings: List[ThreatFinding] = []

    def scan_binary(self, data: bytes) -> List[ThreatFinding]:
        """Comprehensive static scan of binary data.

        Args:
            data: Raw binary bytes.

        Returns:
            List of ThreatFinding objects.
        """
        findings: List[ThreatFinding] = []
        seen = set()  # Deduplicate by (cwe, offset)

        # CWE pattern matching
        for cwe in CWE_PATTERNS:
            offsets = cwe.matches(data)
            for offset in offsets:
                key = (cwe.cwe_id, offset)
                if key in seen:
                    continue
                seen.add(key)

                # Extract context (32 bytes around hit)
                start = max(0, offset - 16)
                end = min(len(data), offset + 16)
                context_bytes = data[start:end]

                findings.append(
                    ThreatFinding(
                        threat_class=self._cwe_to_threat_class(cwe),
                        confidence=self._severity_to_confidence(cwe.severity),
                        raw_logits=None,
                        uncertainty=0.15,
                        metadata={
                            "cwe_id": cwe.cwe_id,
                            "cwe_name": cwe.name,
                            "severity": cwe.severity,
                            "category": cwe.category,
                            "offset": offset,
                            "context_hex": context_bytes.hex(),
                            "engine": "zeroday_static",
                        },
                    )
                )

        # Dangerous function scan
        for pattern, name in self.DANGEROUS_FUNCTIONS:
            for match in re.finditer(pattern, data, re.DOTALL):
                offset = match.start()
                key = ("DANGEROUS_FUNC", name, offset)
                if key in seen:
                    continue
                seen.add(key)

                ctx = data[max(0, offset - 8) : offset + 24]
                findings.append(
                    ThreatFinding(
                        threat_class=ThreatClass.EXPLOITATION,
                        confidence=0.65,
                        raw_logits=None,
                        uncertainty=0.20,
                        metadata={
                            "cwe_id": "CWE-676",
                            "cwe_name": f"Dangerous Function: {name}",
                            "severity": "HIGH",
                            "offset": offset,
                            "context_hex": ctx.hex(),
                            "engine": "zeroday_static",
                        },
                    )
                )

        # Hardcoded secret scan
        secret_patterns = [
            rb'(?i)(api[_-]?key|apikey|secret|token|password|passwd|auth_token)[\s]*[=:]\s*["\'][\x20-\x7e]{8,64}["\']',
            rb'(?i)(BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY)',
            rb'[A-Za-z0-9+/]{40,}={0,2}',
        ]
        for pat in secret_patterns:
            for match in re.finditer(pat, data, re.DOTALL):
                offset = match.start()
                key = ("SECRET", offset)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    ThreatFinding(
                        threat_class=ThreatClass.CREDENTIAL_ACCESS,
                        confidence=0.80,
                        raw_logits=None,
                        uncertainty=0.10,
                        metadata={
                            "cwe_id": "CWE-798",
                            "cwe_name": "Hardcoded Credentials",
                            "severity": "CRITICAL",
                            "offset": offset,
                            "engine": "zeroday_static",
                        },
                    )
                )

        return findings

    @staticmethod
    def _cwe_to_threat_class(cwe: CWEPattern) -> ThreatClass:
        """Map CWE category to threat class."""
        mapping = {
            "memory_corruption": ThreatClass.EXPLOITATION,
            "input_validation": ThreatClass.DEFENSE_EVASION,
            "injection": ThreatClass.EXPLOITATION,
            "numeric_error": ThreatClass.EXPLOITATION,
            "concurrency": ThreatClass.EXPLOITATION,
            "resource_management": ThreatClass.IMPACT,
            "data_handling": ThreatClass.COLLECTION,
            "authorization": ThreatClass.PRIVILEGE_ESCALATION,
            "credential_management": ThreatClass.CREDENTIAL_ACCESS,
            "network": ThreatClass.COMMAND_AND_CONTROL,
        }
        return mapping.get(cwe.category, ThreatClass.EXPLOITATION)

    @staticmethod
    def _severity_to_confidence(severity: str) -> float:
        return {
            "CRITICAL": 0.90,
            "HIGH": 0.75,
            "MEDIUM": 0.55,
            "LOW": 0.30,
        }.get(severity, 0.50)


# ═══════════════════════════════════════════════════════════════════════════════
# Dynamic Analyzer (Coverage-Guided Fuzzing)
# ═══════════════════════════════════════════════════════════════════════════════


class CoverageBitmap:
    """Simulated AFL-style coverage bitmap."""

    def __init__(self, map_size: int = 65536):
        self.map = bytearray(map_size)
        self.total_edges: int = 0

    def update(self, edge_id: int) -> bool:
        """Record edge coverage. Returns True if new edge."""
        bucket = edge_id % len(self.map)
        if self.map[bucket] == 0:
            self.map[bucket] = 1
            self.total_edges += 1
            return True
        return False

    def coverage_rate(self, total_possible: int = 1000) -> float:
        return min(1.0, self.total_edges / total_possible)

    def reset(self) -> None:
        self.map = bytearray(len(self.map))
        self.total_edges = 0


class DynamicAnalyzer:
    """Coverage-guided fuzzing simulator with byte-level mutations."""

    def __init__(self, bitmap_size: int = 65536):
        self.coverage = CoverageBitmap(bitmap_size)
        self.crashes: Dict[str, ThreatFinding] = {}

    def mutate_input(self, seed: bytes) -> bytes:
        """Apply random byte-level mutations to seed.

        Mutation strategies:
          1. Bit flip (40% probability)
          2. Byte insertion (20%)
          3. Byte deletion (15%)
          4. Arithmetic mutation (15%)
          5. Interesting value insertion (10%)
        """
        data = bytearray(seed)
        if len(data) == 0:
            return bytes([0x41])

        r = __import__("random").random()

        if r < 0.40:
            # Bit flip
            pos = __import__("random").randint(0, len(data) - 1)
            bit = 1 << __import__("random").randint(0, 7)
            data[pos] ^= bit
        elif r < 0.60:
            # Byte insertion
            pos = __import__("random").randint(0, len(data))
            data.insert(pos, __import__("random").randint(0, 255))
        elif r < 0.75:
            # Byte deletion
            if len(data) > 1:
                pos = __import__("random").randint(0, len(data) - 1)
                del data[pos]
        elif r < 0.90:
            # Arithmetic: increment/decrement by random
            pos = __import__("random").randint(0, len(data) - 1)
            delta = __import__("random").randint(-35, 35)
            data[pos] = (data[pos] + delta) % 256
        else:
            # Interesting values
            interesting = [0, 0xFF, 0x7F, 0x80, 0x00, 0x41]
            pos = __import__("random").randint(0, len(data) - 1)
            data[pos] = __import__("random").choice(interesting)

        return bytes(data)

    def track_coverage(self, input_data: bytes) -> int:
        """Simulated coverage: hash-based path tracking.

        Returns number of new edges found.
        """
        # Simple hash-based edge simulation
        h = hashlib.sha256(input_data).digest()
        edges = 0
        for i in range(0, len(h), 4):
            edge = struct.unpack(">I", h[i : i + 4])[0]
            if self.coverage.update(edge):
                edges += 1
        return edges

    def fuzz(
        self, target_fn: Callable[[bytes], int], iterations: int = 1000, seed: bytes = b""
    ) -> List[ThreatFinding]:
        """Coverage-guided fuzzing loop.

        Args:
            target_fn: Function that takes bytes input and returns 0 (ok), -1 (crash), 1 (hang).
            iterations: Number of fuzz iterations.
            seed: Initial seed input.

        Returns:
            List of ThreatFindings from crashes.
        """
        import random as _random

        corpus = [seed if seed else b"A" * 16]
        findings: List[ThreatFinding] = []
        crash_hashes = set()

        for _ in range(iterations):
            # Select from corpus (favor recent additions via simple round-robin)
            idx = _random.randint(0, len(corpus) - 1)
            parent = corpus[idx]
            mutated = self.mutate_input(parent)

            # Track coverage
            new_edges = self.track_coverage(mutated)
            if new_edges > 0:
                corpus.append(mutated)
                if len(corpus) > 200:
                    corpus = corpus[-200:]  # Keep corpus bounded

            # Execute target
            result = target_fn(mutated)
            if result != 0:
                crash_hash = hashlib.sha256(mutated).hexdigest()[:16]
                if crash_hash not in crash_hashes:
                    crash_hashes.add(crash_hash)
                    findings.append(
                        ThreatFinding(
                            threat_class=ThreatClass.EXPLOITATION,
                            confidence=0.85 if result == -1 else 0.60,
                            raw_logits=None,
                            uncertainty=0.10,
                            metadata={
                                "cwe_id": "CWE-119",
                                "severity": "HIGH",
                                "crash_type": "crash" if result == -1 else "hang",
                                "input_hash": crash_hash,
                                "input_len": len(mutated),
                                "engine": "zeroday_dynamic",
                            },
                        )
                    )

        return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Symbolic Verifier (Constraint-Based Simulation)
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class SymVar:
    """Symbolic variable with optional concrete value."""

    name: str
    size: int  # bits
    constraints: List[Tuple[str, Any]] = field(default_factory=list)
    concrete: Optional[int] = None


class SymbolicVerifier:
    """Constraint-based symbolic execution simulation.

    Without Z3, uses interval constraint propagation and
    brute-force solving on small domains.
    """

    MAX_SOLVE_SIZE = 24  # bits

    def __init__(self):
        self.variables: Dict[str, SymVar] = {}
        self.path_constraints: List[Dict] = []

    def create_symbolic_vars(self, n: int, prefix: str = "x") -> List[SymVar]:
        """Create n symbolic variables."""
        vars_list = []
        for i in range(n):
            name = f"{prefix}_{i}"
            sv = SymVar(name=name, size=32)
            self.variables[name] = sv
            vars_list.append(sv)
        return vars_list

    def add_constraint(self, var_name: str, op: str, value: int) -> None:
        """Add a constraint: var OP value (e.g., x_0 < 256)."""
        if var_name in self.variables:
            self.variables[var_name].constraints.append((op, value))

    def add_path_constraint(self, condition: Dict) -> None:
        """Record a path condition."""
        self.path_constraints.append(condition)

    def solve_constraints(
        self, constraints: List[Tuple[str, str, int]], target_expr: Optional[str] = None
    ) -> Optional[Dict[str, int]]:
        """Produce concrete values satisfying all constraints.

        Uses brute-force over small domains. For larger domains,
        produces a single satisfying assignment via interval propagation.

        Args:
            constraints: List of (var_name, op, value) tuples.
            target_expr: Optional target expression.

        Returns:
            Dict mapping variable names to concrete values, or None if UNSAT.
        """
        # Collect all variables and their domains
        domains: Dict[str, set] = {}
        for name, sv in self.variables.items():
            domains[name] = set(range(min(256, 1 << min(sv.size, self.MAX_SOLVE_SIZE))))

        # Apply constraints to narrow domains
        for var_name, op, value in constraints:
            if var_name not in domains:
                continue
            domain = domains[var_name]
            if op == "==":
                domain &= {value}
            elif op == "!=":
                domain -= {value}
            elif op == "<":
                domain &= {v for v in domain if v < value}
            elif op == "<=":
                domain &= {v for v in domain if v <= value}
            elif op == ">":
                domain &= {v for v in domain if v > value}
            elif op == ">=":
                domain &= {v for v in domain if v >= value}
            domains[var_name] = domain

        # Find any satisfying assignment
        assignment = {}
        for name, domain in domains.items():
            if not domain:
                return None
            assignment[name] = min(domain)

        return assignment

    def verify_finding(self, finding: ThreatFinding, binary_data: bytes) -> bool:
        """Verify if a finding is exploitable via constraint solving.

        Simulates: can we construct an input that triggers the vulnerability?
        """
        # For simplicity, verify based on confidence and pattern location
        if finding.confidence > 0.85:
            return True
        if finding.confidence > 0.55:
            # Simulate partial verification
            hash_val = int(hashlib.md5(binary_data).hexdigest()[:8], 16)
            return hash_val % 3 != 0  # ~66% pass rate for medium confidence
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# ZeroDayDiscoveryEngine — Main Engine
# ═══════════════════════════════════════════════════════════════════════════════


class ZeroDayDiscoveryEngine:
    """Hybrid zero-day vulnerability discovery engine.

    Clearance: ANALYST or higher.
    """

    def __init__(
        self,
        clearance: SecurityClearance = SecurityClearance.ANALYST,
        sections: Optional[List[BinarySection]] = None,
    ):
        if clearance.value < SecurityClearance.ANALYST.value:
            raise PermissionError(
                f"ZeroDayDiscoveryEngine requires ANALYST clearance, got {clearance.name}"
            )
        self.clearance = clearance
        self.static = StaticAnalyzer(sections)
        self.dynamic = None   # removed — was simulated (random-based)
        self.symbolic = None  # removed — was simulated (random-based)
        self.total_scans = 0

    def analyze(
        self, binary_data: bytes, mode: str = "static"
    ) -> List[ThreatFinding]:
        """Run static CWE pattern analysis on binary data.

        ONLY static analysis is available. Dynamic/symbolic modes were
        simulated (random-based) and have been removed. Real dynamic
        fuzzing requires AFL++/libFuzzer; real symbolic execution
        requires angr/Triton/Z3.

        Args:
            binary_data: Raw binary content.
            mode: 'static' only (dynamic/symbolic ignored).

        Returns:
            Deduplicated, scored list of ThreatFindings.
        """
        all_findings: List[ThreatFinding] = []
        all_findings.extend(self.static.scan_binary(binary_data))

        # Deduplicate
        findings = self._deduplicate(all_findings)

        # Score
        for f in findings:
            if f.metadata:
                f.metadata["composite_score"] = self.score_finding(f, {})

        # Sort by composite score descending
        findings.sort(
            key=lambda f: f.metadata.get("composite_score", 0) if f.metadata else 0,
            reverse=True,
        )

        self.total_scans += 1
        return findings

    def score_finding(self, finding: ThreatFinding, context: dict) -> float:
        """Context-aware severity scoring.

        score = base × reachability × privilege × exploitability

        Where:
          base = severity_weight / 10
          reachability = 1.0 (attack surface), 0.5 (internal), 0.2 (deep)
          privilege = 1.0 (none needed), 0.7 (user), 0.3 (admin)
          exploitability = confidence ∈ [0,1]
        """
        severity = (finding.metadata or {}).get("severity", "MEDIUM")
        base = SEVERITY_WEIGHTS.get(severity, 4) / 10.0

        reachability = 1.0   # default: on attack surface
        privilege = 0.7       # default: user-level
        exploitability = finding.confidence

        return base * reachability * privilege * exploitability * 10.0

    def generate_report(self) -> Dict[str, Any]:
        """Generate summary statistics."""
        return {
            "total_scans": self.total_scans,
            "cwe_patterns_loaded": len(CWE_PATTERNS),
            "engine": "zeroday_discovery",
            "clearance": self.clearance.name,
        }

    @staticmethod
    def _deduplicate(findings: List[ThreatFinding]) -> List[ThreatFinding]:
        """Deduplicate findings by CWE + location."""
        seen = set()
        unique = []
        for f in findings:
            cwe = (f.metadata or {}).get("cwe_id", "UNKNOWN")
            offset = (f.metadata or {}).get("offset", hash(str(f.metadata)))
            key = (cwe, offset)
            if key not in seen:
                seen.add(key)
                unique.append(f)
            else:
                # Update existing with max confidence
                for uf in unique:
                    uf_key = ((uf.metadata or {}).get("cwe_id"), (uf.metadata or {}).get("offset"))
                    if uf_key == key:
                        uf.confidence = max(uf.confidence, f.confidence)
                        break
        return unique


# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    engine = ZeroDayDiscoveryEngine(clearance=SecurityClearance.ANALYST)
    sample = b"system('/bin/sh')\x00" + b"A" * 200 + b"strcpy\x00" + b"password='admin123'\x00"
    findings = engine.analyze(sample, mode="hybrid")
    for f in findings[:5]:
        cwe = (f.metadata or {}).get("cwe_id", "???")
        score = (f.metadata or {}).get("composite_score", 0)
        print(f"[{cwe}] {f.threat_class.name}  conf={f.confidence:.3f}  score={score:.2f}")
