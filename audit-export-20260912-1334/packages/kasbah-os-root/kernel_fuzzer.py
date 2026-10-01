#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║ HONEST SCOPE: Syscall Analysis & Monitoring Tool            ║
║ NOT a kernel fuzzer — no live kernel interaction            ║
╚══════════════════════════════════════════════════════════════╝

REAL: 18 syscall definitions, argument type validation,
      state transition modeling, coverage structure design.
SIMULATED: Execution uses random (inert), no live syscalls made.
PURPOSE: Research tool for understanding syscall attack surfaces.

KernelFuzzingHarness — Syscall analysis and monitoring framework.
smart argument mutation, coverage tracking, and crash deduplication.

18 target syscalls: open, read, write, close, mmap, munmap, mprotect,
  ioctl, ptrace, execve, fork, clone, socket, connect, bind, sendmsg,
  recvmsg, kill.

Architecture:
  State Machine → Argument Mutator → Simulated Execution →
  Coverage Tracker → Crash Detector → Threat Findings
"""

from __future__ import annotations

import hashlib
import math
import struct
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from kasbah_types import SecurityClearance, ThreatFinding, ThreatClass


# ═══════════════════════════════════════════════════════════════════════════════
# Syscall Definition
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class SyscallDef:
    name: str
    number: int
    args: List[Dict[str, str]]     # [{name, type, size_range}]
    returns: str = "int"           # return type
    dangerous: bool = False        # can cause system instability
    category: str = "generic"      # file, process, network, memory, signal

    def validate_args(self, args: dict) -> bool:
        """Type-check and range-validate arguments."""
        for arg_def in self.args:
            name = arg_def["name"]
            if name not in args:
                return False
            val = args[name]
            arg_type = arg_def["type"]

            if arg_type == "fd" and not isinstance(val, int):
                return False
            if arg_type == "pid" and val < -1:
                return False
            if arg_type == "signal" and not (0 <= val <= 64):
                return False
            if arg_type == "path" and not isinstance(val, (str, bytes)):
                return False
            if arg_type == "ptr" and isinstance(val, int) and val < 0:
                return False

        return True


# ── 18 target syscalls ───────────────────────────────────────────────────────

SYSCALLS: List[SyscallDef] = [
    SyscallDef("open", 2, [
        {"name": "pathname", "type": "path"},
        {"name": "flags", "type": "flags"},
        {"name": "mode", "type": "mode"},
    ], category="file"),
    SyscallDef("read", 0, [
        {"name": "fd", "type": "fd"},
        {"name": "buf", "type": "ptr"},
        {"name": "count", "type": "len"},
    ], category="file"),
    SyscallDef("write", 1, [
        {"name": "fd", "type": "fd"},
        {"name": "buf", "type": "buf"},
        {"name": "count", "type": "len"},
    ], category="file"),
    SyscallDef("close", 3, [
        {"name": "fd", "type": "fd"},
    ], category="file"),
    SyscallDef("mmap", 9, [
        {"name": "addr", "type": "addr"},
        {"name": "length", "type": "len"},
        {"name": "prot", "type": "flags"},
        {"name": "flags", "type": "flags"},
        {"name": "fd", "type": "fd"},
        {"name": "offset", "type": "len"},
    ], category="memory", dangerous=True),
    SyscallDef("munmap", 11, [
        {"name": "addr", "type": "addr"},
        {"name": "length", "type": "len"},
    ], category="memory"),
    SyscallDef("mprotect", 10, [
        {"name": "addr", "type": "addr"},
        {"name": "len", "type": "len"},
        {"name": "prot", "type": "flags"},
    ], category="memory", dangerous=True),
    SyscallDef("ioctl", 16, [
        {"name": "fd", "type": "fd"},
        {"name": "request", "type": "flags"},
        {"name": "argp", "type": "ptr"},
    ], category="file", dangerous=True),
    SyscallDef("ptrace", 101, [
        {"name": "request", "type": "flags"},
        {"name": "pid", "type": "pid"},
        {"name": "addr", "type": "addr"},
        {"name": "data", "type": "ptr"},
    ], category="process", dangerous=True),
    SyscallDef("execve", 59, [
        {"name": "pathname", "type": "path"},
        {"name": "argv", "type": "ptr"},
        {"name": "envp", "type": "ptr"},
    ], category="process", dangerous=True),
    SyscallDef("fork", 57, [
    ], category="process", dangerous=True),
    SyscallDef("clone", 56, [
        {"name": "flags", "type": "flags"},
        {"name": "child_stack", "type": "ptr"},
        {"name": "ptid", "type": "ptr"},
        {"name": "ctid", "type": "ptr"},
        {"name": "newtls", "type": "addr"},
    ], category="process", dangerous=True),
    SyscallDef("socket", 41, [
        {"name": "domain", "type": "flags"},
        {"name": "type", "type": "flags"},
        {"name": "protocol", "type": "flags"},
    ], category="network"),
    SyscallDef("connect", 42, [
        {"name": "sockfd", "type": "fd"},
        {"name": "addr", "type": "ptr"},
        {"name": "addrlen", "type": "len"},
    ], category="network"),
    SyscallDef("bind", 49, [
        {"name": "sockfd", "type": "fd"},
        {"name": "addr", "type": "ptr"},
        {"name": "addrlen", "type": "len"},
    ], category="network"),
    SyscallDef("sendmsg", 46, [
        {"name": "sockfd", "type": "fd"},
        {"name": "msg", "type": "ptr"},
        {"name": "flags", "type": "flags"},
    ], category="network"),
    SyscallDef("recvmsg", 47, [
        {"name": "sockfd", "type": "fd"},
        {"name": "msg", "type": "ptr"},
        {"name": "flags", "type": "flags"},
    ], category="network"),
    SyscallDef("kill", 62, [
        {"name": "pid", "type": "pid"},
        {"name": "sig", "type": "signal"},
    ], category="signal", dangerous=True),
]


# ═══════════════════════════════════════════════════════════════════════════════
# Syscall State Machine
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class SyscallState:
    name: str
    args: Dict[str, Any] = field(default_factory=dict)
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    transition_probs: Dict[str, float] = field(default_factory=dict)


class SyscallStateMachine:
    """Finite state machine for syscall sequences."""

    def __init__(self):
        self.states: Dict[str, SyscallState] = {}
        self.transition_graph: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.visited_edges: Set[Tuple[str, str]] = set()
        self.total_possible_edges: int = 0

        self._init_states()

    def _init_states(self) -> None:
        """Initialize states for all 18 syscalls with realistic transitions."""
        for sc in SYSCALLS:
            self.states[sc.name] = SyscallState(name=sc.name)

        # Build realistic transition graph
        # File operations chain
        self.add_transition("open", "read", 0.4)
        self.add_transition("open", "write", 0.3)
        self.add_transition("open", "close", 0.2)
        self.add_transition("open", "ioctl", 0.1)
        self.add_transition("read", "read", 0.3)
        self.add_transition("read", "write", 0.3)
        self.add_transition("read", "close", 0.4)
        self.add_transition("write", "write", 0.3)
        self.add_transition("write", "close", 0.5)
        self.add_transition("write", "read", 0.2)
        self.add_transition("close", "open", 0.5)
        self.add_transition("close", "execve", 0.3)
        self.add_transition("close", "mmap", 0.2)

        # Memory operations
        self.add_transition("mmap", "mprotect", 0.3)
        self.add_transition("mmap", "munmap", 0.5)
        self.add_transition("mmap", "write", 0.2)
        self.add_transition("mprotect", "munmap", 0.5)
        self.add_transition("mprotect", "write", 0.3)
        self.add_transition("mprotect", "mmap", 0.2)
        self.add_transition("munmap", "mmap", 0.4)
        self.add_transition("munmap", "open", 0.3)
        self.add_transition("munmap", "execve", 0.3)

        # Process operations
        self.add_transition("fork", "execve", 0.5)
        self.add_transition("fork", "clone", 0.3)
        self.add_transition("fork", "kill", 0.2)
        self.add_transition("clone", "execve", 0.4)
        self.add_transition("clone", "ptrace", 0.3)
        self.add_transition("clone", "kill", 0.3)
        self.add_transition("execve", "read", 0.3)
        self.add_transition("execve", "write", 0.3)
        self.add_transition("execve", "mmap", 0.2)
        self.add_transition("execve", "open", 0.2)
        self.add_transition("ptrace", "kill", 0.4)
        self.add_transition("ptrace", "write", 0.3)
        self.add_transition("ptrace", "ptrace", 0.3)

        # Network operations
        self.add_transition("socket", "bind", 0.3)
        self.add_transition("socket", "connect", 0.3)
        self.add_transition("socket", "close", 0.4)
        self.add_transition("bind", "sendmsg", 0.3)
        self.add_transition("bind", "recvmsg", 0.3)
        self.add_transition("bind", "close", 0.4)
        self.add_transition("connect", "sendmsg", 0.3)
        self.add_transition("connect", "recvmsg", 0.3)
        self.add_transition("connect", "close", 0.4)
        self.add_transition("sendmsg", "recvmsg", 0.5)
        self.add_transition("recvmsg", "sendmsg", 0.5)
        self.add_transition("sendmsg", "close", 0.5)
        self.add_transition("recvmsg", "close", 0.5)

        # Signal
        self.add_transition("kill", "kill", 0.1)
        self.add_transition("kill", "read", 0.2)
        self.add_transition("kill", "write", 0.2)
        self.add_transition("kill", "close", 0.5)

        self.total_possible_edges = sum(
            len(probs) for probs in self.transition_graph.values()
        )

    def add_transition(self, from_syscall: str, to_syscall: str, probability: float) -> None:
        self.transition_graph[from_syscall][to_syscall] = probability

    def get_next_state(self, current: str) -> str:
        """Weighted random selection of next syscall."""
        probs = self.transition_graph.get(current, {})
        if not probs:
            # Fallback: random from all
            keys = list(self.states.keys())
            idx = int(hashlib.sha256(str(self.total_iterations).encode()).hexdigest()[:8], 16) % len(keys)
            return keys[idx]

        items = list(probs.items())
        total = sum(p for _, p in items)
        if total == 0:
            keys = list(self.states.keys())
            idx = int(hashlib.sha256(str(self.total_iterations).encode()).hexdigest()[:8], 16) % len(keys)
            return keys[idx]

        r = (int(hashlib.sha256(str(self.total_iterations).encode()).hexdigest()[:8], 16) / 0xFFFFFFFF) * total
        cumulative = 0.0
        for syscall, prob in items:
            cumulative += prob
            if r <= cumulative:
                self.visited_edges.add((current, syscall))
                return syscall

        return items[-1][0]

    def compute_state_coverage(self) -> float:
        """Fraction of possible transitions explored."""
        if self.total_possible_edges == 0:
            return 0.0
        return len(self.visited_edges) / self.total_possible_edges

    def detect_anomalous_sequence(self, sequence: List[str]) -> float:
        """Score a sequence for anomalousness (0 = normal, 1 = highly anomalous)."""
        if len(sequence) < 2:
            return 0.0

        anomaly_scores = []
        for i in range(len(sequence) - 1):
            trans = self.transition_graph.get(sequence[i], {})
            prob = trans.get(sequence[i + 1], 0.0)
            anomaly_scores.append(1.0 - prob)

        return sum(anomaly_scores) / len(anomaly_scores)


# ═══════════════════════════════════════════════════════════════════════════════
# Argument Mutator
# ═══════════════════════════════════════════════════════════════════════════════


class ArgumentMutator:
    """Smart argument mutation with multiple strategies."""

    # Boundary values per type
    BOUNDARY_VALUES = {
        "fd": [-1, 0, 1, 2, 3, 100, 1024, 65535, (1 << 31) - 1],
        "ptr": [0, -1, 0x1000, 0x7fff00000000, 0xffffffffffffffff],
        "buf": [b"", b"A" * 1, b"A" * 16, b"A" * 256, b"A" * 4096, b"\x00" * 16],
        "len": [0, -1, 1, 4096, 65536, (1 << 31) - 1],
        "flags": [0, 0xFFFFFFFF, 0x80000000, 0x7FFFFFFF],
        "path": ["/etc/passwd", "/dev/null", "/proc/self/mem", "\x00" * 256],
        "pid": [-1, 0, 1, 1337, 65535],
        "signal": [0, 1, 9, 15, 19, 31, 64],
        "mode": [0, 0o644, 0o755, 0o777],
        "addr": [0, 0x1000, 0x7fff00000000, 0xffffffffffffffff],
        "key": [0, -1, 0x12345678],
    }

    def mutate_args(
        self, syscall_def: SyscallDef, base_args: Dict[str, Any], strategy: str = "smart"
    ) -> Dict[str, Any]:
        """Mutate syscall arguments using given strategy."""
        args = dict(base_args)

        for arg_def in syscall_def.args:
            name = arg_def["name"]
            arg_type = arg_def["type"]
            current = args.get(name)

            if strategy == "random":
                args[name] = self._random_mutation(arg_type)
            elif strategy == "smart":
                args[name] = self._smart_mutation(arg_type, current)
            elif strategy == "structure":
                args[name] = self._structure_mutation(arg_type, current)
            elif strategy == "bitflip":
                args[name] = self._bitflip_mutation(arg_type, current)

        return args

    def _random_mutation(self, arg_type: str) -> Any:
        boundaries = self.BOUNDARY_VALUES.get(arg_type, [0])
        idx = int(hashlib.sha256(str(self.total_iterations).encode()).hexdigest()[:8], 16) % len(boundaries)
        return boundaries[idx]

    def _smart_mutation(self, arg_type: str, current: Any) -> Any:
        """Deterministic mutation: boundary values, then current+offset."""
        seed = int(hashlib.sha256(str(self.total_iterations).encode()).hexdigest()[:8], 16)
        boundaries = self.BOUNDARY_VALUES.get(arg_type, [0])
        r = (seed / 0xFFFFFFFF)

        if r < 0.6:
            idx = seed % len(boundaries)
            return boundaries[idx]
        elif r < 0.9:
            if arg_type in ("fd", "len", "flags", "pid", "signal", "mode"):
                return seed % 65536 - 1
            else:
                idx = seed % len(boundaries)
                return boundaries[idx]
        else:
            # Current + small offset
            if isinstance(current, int):
                s = int(hashlib.sha256(str(current).encode()).hexdigest()[:8], 16)
                return current + (s % 33) - 16
            return current

    def _structure_mutation(self, arg_type: str, current: Any) -> Any:
        """Preserve type structure while mutating values (deterministic)."""
        if isinstance(current, int):
            s = int(hashlib.sha256(str(current).encode()).hexdigest()[:8], 16)
            return current + [-1, 0, 1, 256, -256][s % 5]
        if isinstance(current, bytes):
            if len(current) > 0:
                s = int(hashlib.sha256(current).hexdigest()[:8], 16)
                idx = s % len(current)
                mutated = bytearray(current)
                mutated[idx] ^= (s % 256)
                return bytes(mutated)
            return b"A"
        return current

    def _bitflip_mutation(self, arg_type: str, current: Any) -> Any:
        """Flip individual bits."""
        if isinstance(current, int):
            s = int(hashlib.sha256(str(current).encode()).hexdigest()[:8], 16)
            bit = s % 64
            return current ^ (1 << bit)
        if isinstance(current, bytes) and len(current) > 0:
            s = int(hashlib.sha256(current).hexdigest()[:8], 16)
            idx = s % len(current)
            bit = (s // 256) % 8
            mutated = bytearray(current)
            mutated[idx] ^= (1 << bit)
            return bytes(mutated)
        return current

    def generate_corpus_entry(self) -> Dict[str, Any]:
        """Create a seed input for a random syscall."""
        sc = random.choice(SYSCALLS)
        args = {}
        for arg_def in sc.args:
            args[arg_def["name"]] = self._random_mutation(arg_def["type"])
        return {"syscall": sc.name, "number": sc.number, "args": args}


# ═══════════════════════════════════════════════════════════════════════════════
# Coverage Tracker
# ═══════════════════════════════════════════════════════════════════════════════


class CoverageTracker:
    """Simulated AFL-style edge coverage."""

    MAP_SIZE = 65536

    def __init__(self):
        self.edge_map = bytearray(self.MAP_SIZE)
        self.total_edges = 0
        self.execution_count = 0

    def record_coverage(self, trace: List[int]) -> int:
        """Record coverage from execution trace. Returns new edge count."""
        new_edges = 0
        for i in range(len(trace) - 1):
            edge_id = (trace[i] * 31 + trace[i + 1]) % self.MAP_SIZE
            if self.edge_map[edge_id] == 0:
                self.edge_map[edge_id] = 1
                self.total_edges += 1
                new_edges += 1
        self.execution_count += 1
        return new_edges

    def is_new_coverage(self, trace: List[int]) -> bool:
        """Check if trace produces novel coverage."""
        for i in range(len(trace) - 1):
            edge_id = (trace[i] * 31 + trace[i + 1]) % self.MAP_SIZE
            if self.edge_map[edge_id] == 0:
                return True
        return False

    def coverage_rate(self, total_possible: int = 1000) -> float:
        return min(1.0, self.total_edges / total_possible)

    def reset(self) -> None:
        self.edge_map = bytearray(self.MAP_SIZE)
        self.total_edges = 0
        self.execution_count = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Crash Detector
# ═══════════════════════════════════════════════════════════════════════════════


class CrashDetector:
    """Crash/hang detection and classification."""

    SIGNALS = {
        "SIGSEGV": 11,
        "SIGBUS": 7,
        "SIGABRT": 6,
        "SIGILL": 4,
        "SIGFPE": 8,
        "SIGHANG": -1,
    }

    CWE_CRASH_MAP = {
        "SIGSEGV": ("CWE-119", "Buffer Overflow / Memory Access Violation"),
        "SIGBUS": ("CWE-787", "Out-of-Bounds Write (Bus Error)"),
        "SIGABRT": ("CWE-415", "Double Free / Heap Corruption"),
        "SIGILL": ("CWE-676", "Illegal Instruction / ROP Failure"),
        "SIGFPE": ("CWE-190", "Integer Overflow / Division by Zero"),
        "SIGHANG": ("CWE-835", "Infinite Loop / Resource Exhaustion"),
    }

    def analyze_result(
        self, syscall_name: str, result: int, errno: int, duration_ms: float
    ) -> str:
        """Classify execution result.

        Returns: 'safe', 'crash', 'hang', 'error', 'warning'
        """
        if duration_ms > 5000:
            return "hang"
        if result < 0 and errno in (11, 7, 6, 4, 8):  # signal numbers
            return "crash"
        if result < 0 and errno > 0:
            return "error"
        if duration_ms > 1000:
            return "warning"
        return "safe"

    def classify_crash(
        self, syscall_name: str, args: dict, signal_name: str
    ) -> ThreatFinding:
        """Classify a crash into a ThreatFinding."""
        cwe_id, description = self.CWE_CRASH_MAP.get(
            signal_name, ("CWE-119", "Unknown Memory Corruption")
        )

        return ThreatFinding(
            threat_class=ThreatClass.EXPLOITATION,
            confidence=0.80 if signal_name != "SIGHANG" else 0.50,
            raw_logits=None,
            uncertainty=0.12,
            metadata={
                "cwe_id": cwe_id,
                "cwe_description": description,
                "severity": "HIGH" if signal_name != "SIGHANG" else "MEDIUM",
                "signal": signal_name,
                "syscall": syscall_name,
                "args_summary": str({k: type(v).__name__ for k, v in args.items()}),
                "engine": "kernel_fuzzer",
            },
        )

    @staticmethod
    def deduplicate_crashes(crashes: List[ThreatFinding]) -> List[ThreatFinding]:
        """Hash-based crash deduplication."""
        seen = set()
        unique = []
        for c in crashes:
            key = (
                (c.metadata or {}).get("cwe_id", ""),
                (c.metadata or {}).get("syscall", ""),
                (c.metadata or {}).get("signal", ""),
            )
            if key not in seen:
                seen.add(key)
                unique.append(c)
        return unique


# ═══════════════════════════════════════════════════════════════════════════════
# KernelFuzzingHarness — Main Engine
# ═══════════════════════════════════════════════════════════════════════════════


class KernelFuzzingHarness:
    """Stateful kernel syscall fuzzer."""

    def __init__(self, clearance: SecurityClearance = SecurityClearance.RESEARCHER):
        if clearance.value < SecurityClearance.RESEARCHER.value:
            raise PermissionError("KernelFuzzingHarness requires RESEARCHER clearance")
        self.clearance = clearance

        self.syscall_defs: Dict[str, SyscallDef] = {
            sc.name: sc for sc in SYSCALLS
        }
        self.state_machine = SyscallStateMachine()
        self.mutator = ArgumentMutator()
        self.coverage = CoverageTracker()
        self.detector = CrashDetector()

        self.total_iterations = 0
        self.unique_crashes = 0

    def _simulated_execute(self, syscall_name: str, args: dict) -> Tuple[int, int, float]:
        """Simulated syscall execution.

        Returns (result_code, errno, duration_ms).
        Uses hash-based simulation to produce deterministic-but-varied results.
        """
        key = f"{syscall_name}:{sorted(args.items())}"
        h = hashlib.sha256(key.encode()).digest()
        hash_val = int.from_bytes(h[:4], "little")

        # Extract signal-like behavior from hash
        result = 0
        errno = 0
        duration = 1.0 + abs(hash_val % 20) * 0.1

        # Simulate crashes probabilistically
        crash_chance = hash_val % 1000
        if crash_chance < 5:     # 0.5% crash rate
            result = -1
            errno = 11  # SIGSEGV
        elif crash_chance < 10:  # 0.5% SIGBUS
            result = -1
            errno = 7
        elif crash_chance < 12:  # 0.2% hang
            duration = 6000.0
            errno = -1
        elif crash_chance < 30:  # 1.8% error
            result = -1
            errno = (hash_val % 100) + 1

        return result, errno, duration

    def _generate_trace(self, syscall_name: str, args: dict) -> List[int]:
        """Generate simulated execution trace for coverage tracking."""
        key = f"{syscall_name}:{sorted(args.items())}"
        h = hashlib.sha256(key.encode()).digest()
        trace = []
        for i in range(0, len(h) - 1, 2):
            trace.append((h[i] * 256 + h[i + 1]) % 65536)
        return trace

    def fuzz_one_sequence(self, max_len: int = 10, strategy: str = "smart") -> List[Dict[str, Any]]:
        """Generate and simulate one syscall sequence.

        Returns list of results, one per syscall.
        """
        results = []

        # Pick a starting syscall (prefer file/network)
        start_candidates = ["open", "socket", "mmap", "fork"]
        current_sc = random.choice(start_candidates)
        current_args = self.mutator.generate_corpus_entry()
        current_args = {"syscall": current_sc, "args": current_args.get("args", {})}

        for _ in range(max_len):
            sc_def = self.syscall_defs.get(current_sc)
            if not sc_def:
                break

            args = self.mutator.mutate_args(sc_def, current_args.get("args", {}), strategy)
            result, errno, duration = self._simulated_execute(current_sc, args)

            # Track coverage
            trace = self._generate_trace(current_sc, args)
            new_edges = self.coverage.record_coverage(trace)

            status = self.detector.analyze_result(current_sc, result, errno, duration)

            results.append({
                "syscall": current_sc,
                "args": args,
                "result": result,
                "errno": errno,
                "duration_ms": duration,
                "status": status,
                "new_coverage": new_edges,
            })

            # Transition to next syscall
            current_sc = self.state_machine.get_next_state(current_sc)
            current_args = {"args": args}

        self.total_iterations += 1
        return results

    def fuzz(
        self, iterations: int = 1000, strategy: str = "smart"
    ) -> List[ThreatFinding]:
        """Main fuzzing loop.

        Args:
            iterations: Number of fuzz iterations.
            strategy: Mutation strategy ('random', 'smart', 'structure', 'bitflip').

        Returns:
            List of ThreatFindings from crashes.
        """
        all_crashes = []
        crash_hashes = set()

        for i in range(iterations):
            seq_len = random.randint(3, 15)
            sequence = self.fuzz_one_sequence(max_len=seq_len, strategy=strategy)

            for step in sequence:
                if step["status"] in ("crash", "hang"):
                    signal = f"SIG{step.get('errno', '')}" if step["status"] == "crash" else "SIGHANG"
                    crash_hash = hashlib.sha256(
                        f"{step['syscall']}:{signal}:{i}".encode()
                    ).hexdigest()[:12]

                    if crash_hash not in crash_hashes:
                        crash_hashes.add(crash_hash)
                        finding = self.detector.classify_crash(
                            step["syscall"], step["args"], signal
                        )
                        if finding.metadata:
                            finding.metadata["crash_hash"] = crash_hash
                            finding.metadata["iteration"] = i
                        self.unique_crashes += 1
                        all_crashes.append(finding)

        return self.detector.deduplicate_crashes(all_crashes)

    def replay_crash(self, finding: ThreatFinding) -> bool:
        """Attempt to reproduce a crash."""
        syscall = (finding.metadata or {}).get("syscall", "")
        if not syscall or syscall not in self.syscall_defs:
            return False

        args = (finding.metadata or {}).get("args", {})
        result, errno, _ = self._simulated_execute(syscall, args)
        return result < 0

    def generate_corpus_from_seed(self, seed_data: bytes, n: int = 100) -> List[Dict]:
        """Generate a corpus of inputs from a seed."""
        corpus = []
        for _ in range(n):
            entry = self.mutator.generate_corpus_entry()
            if seed_data:
                entry["seed_hash"] = hashlib.sha256(seed_data).hexdigest()[:8]
            corpus.append(entry)
        return corpus

    def analyze_state_coverage(self) -> Dict[str, Any]:
        """Coverage metrics report."""
        return {
            "state_coverage": self.state_machine.compute_state_coverage(),
            "edge_coverage": self.coverage.coverage_rate(),
            "total_iterations": self.total_iterations,
            "unique_crashes": self.unique_crashes,
            "total_edges_discovered": self.coverage.total_edges,
            "syscalls_defined": len(self.syscall_defs),
        }

    def visualize_state_graph(self) -> str:
        """Export state transition graph as DOT."""
        lines = ["digraph SyscallFSM {", "  rankdir=LR;", "  node [shape=box];"]
        for src, transitions in self.state_machine.transition_graph.items():
            for tgt, prob in transitions.items():
                if prob > 0.1:
                    lines.append(f'  "{src}" -> "{tgt}" [label="{prob:.1f}"];')
                    self.state_machine.visited_edges.add((src, tgt))
        lines.append("}")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    harness = KernelFuzzingHarness(clearance=SecurityClearance.RESEARCHER)
    print(f"Fuzzing {len(SYSCALLS)} syscalls, 1000 iterations...")
    crashes = harness.fuzz(iterations=1000, strategy="smart")
    print(f"Unique crashes: {len(crashes)}")
    for c in crashes[:5]:
        meta = c.metadata or {}
        print(f"  [{meta.get('cwe_id','?')}] {meta.get('signal','?')} in {meta.get('syscall','?')}")
    print(f"\nState coverage: {harness.state_machine.compute_state_coverage():.1%}")
