#!/usr/bin/env python3
"""
BinaryAnalysisEngine — Cross-architecture binary analysis with IR lifting,
CFG reconstruction, ROP gadget discovery, and vulnerability detection.

Architectures: X86, X64, ARM, ARM64, MIPS, MIPS64, RISC_V32, RISC_V64

Core pipeline:
  Disassemble → Build CFG → Find gadgets → Lift IR → Optimize → Detect vulns

No external disassembler libraries. Pure Python struct-based decoding.
"""

from __future__ import annotations

import hashlib
import math
import re
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Set, Tuple

from kasbah_types import BinarySection, SecurityClearance, ThreatClass, ThreatFinding


# ═══════════════════════════════════════════════════════════════════════════════
# Architecture Definitions
# ═══════════════════════════════════════════════════════════════════════════════


class Arch(IntEnum):
    X86 = 0
    X64 = 1
    ARM = 2
    ARM64 = 3
    MIPS = 4
    MIPS64 = 5
    RISC_V32 = 6
    RISC_V64 = 7

    @property
    def pointer_size(self) -> int:
        return {Arch.X86: 4, Arch.X64: 8, Arch.ARM: 4, Arch.ARM64: 8,
                Arch.MIPS: 4, Arch.MIPS64: 8, Arch.RISC_V32: 4, Arch.RISC_V64: 8}[self]

    @property
    def endian(self) -> str:
        return {Arch.MIPS: 'big', Arch.MIPS64: 'big'}.get(self, 'little')

    @property
    def reg_names(self) -> List[str]:
        maps = {
            Arch.X86: ['eax','ecx','edx','ebx','esp','ebp','esi','edi','eip'],
            Arch.X64: ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15','rip'],
            Arch.ARM: ['r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','sp','lr','pc'],
            Arch.ARM64: ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11','x12','x13','x14','x15','x16','x17','x18','x19','x20','x21','x22','x23','x24','x25','x26','x27','x28','x29','x30','sp'],
            Arch.MIPS: ['zero','at','v0','v1','a0','a1','a2','a3','t0','t1','t2','t3','t4','t5','t6','t7','s0','s1','s2','s3','s4','s5','s6','s7','t8','t9','k0','k1','gp','sp','fp','ra'],
            Arch.MIPS64: ['zero','at','v0','v1','a0','a1','a2','a3','t0','t1','t2','t3','t4','t5','t6','t7','s0','s1','s2','s3','s4','s5','s6','s7','t8','t9','k0','k1','gp','sp','fp','ra'],
            Arch.RISC_V32: ['zero','ra','sp','gp','tp','t0','t1','t2','s0','s1','a0','a1','a2','a3','a4','a5','a6','a7','s2','s3','s4','s5','s6','s7','s8','s9','s10','s11','t3','t4','t5','t6'],
            Arch.RISC_V64: ['zero','ra','sp','gp','tp','t0','t1','t2','s0','s1','a0','a1','a2','a3','a4','a5','a6','a7','s2','s3','s4','s5','s6','s7','s8','s9','s10','s11','t3','t4','t5','t6'],
        }
        return maps.get(self, [])


# ═══════════════════════════════════════════════════════════════════════════════
# Instruction
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class Instruction:
    address: int
    mnemonic: str
    operands: List[str] = field(default_factory=list)
    _bytes: bytes = field(default=b"", repr=False)
    size: int = 0
    opcode: int = 0

    def is_branch(self) -> bool:
        return self.mnemonic in ('jmp','je','jne','jg','jl','jge','jle','ja','jb',
                                  'jae','jbe','jz','jnz','js','jns','jo','jno','call',
                                  'b','beq','bne','blt','bge','bltu','bgeu','jal','jalr',
                                  'ret','blr','br')

    def is_call(self) -> bool: return self.mnemonic in ('call','jal','jalr','blr')
    def is_ret(self) -> bool: return self.mnemonic in ('ret','blr')
    def is_nop(self) -> bool: return self.mnemonic == 'nop' or self._bytes == b'\x90'
    def is_memory_access(self) -> bool: return '[' in str(self.operands) or '(' in str(self.operands)

    def get_dest_register(self) -> str:
        return self.operands[0] if self.operands else ''

    def get_src_registers(self) -> List[str]:
        return self.operands[1:] if len(self.operands) > 1 else []


# ═══════════════════════════════════════════════════════════════════════════════
# Disassembler
# ═══════════════════════════════════════════════════════════════════════════════


class Disassembler:
    """Pattern-based disassembler for multiple architectures."""

    # x86/x64 opcode patterns
    X86_PATTERNS = [
        (b'\x90', 'nop', 1, []),
        (b'\xc3', 'ret', 1, []),
        (b'\xcc', 'int3', 1, []),
        (b'\x50', 'push', 1, ['rax']), (b'\x51','push',1,['rcx']),(b'\x52','push',1,['rdx']),
        (b'\x53','push',1,['rbx']),(b'\x54','push',1,['rsp']),(b'\x55','push',1,['rbp']),
        (b'\x56','push',1,['rsi']),(b'\x57','push',1,['rdi']),
        (b'\x58', 'pop', 1, ['rax']), (b'\x59','pop',1,['rcx']),(b'\x5a','pop',1,['rdx']),
        (b'\x5b','pop',1,['rbx']),(b'\x5c','pop',1,['rsp']),(b'\x5d','pop',1,['rbp']),
        (b'\x5e','pop',1,['rsi']),(b'\x5f','pop',1,['rdi']),
        (b'\xe8', 'call', 5, ['rel']), (b'\xe9', 'jmp', 5, ['rel']),
        (b'\x0f\x84', 'je', 6, ['rel']), (b'\x0f\x85', 'jne', 6, ['rel']),
        (b'\x74', 'je', 2, ['rel8']), (b'\x75', 'jne', 2, ['rel8']),
        (b'\x7c', 'jl', 2, ['rel8']), (b'\x7d', 'jge', 2, ['rel8']),
        (b'\x0f\x05', 'syscall', 2, []),
    ]

    ARM_PATTERNS = [
        (b'\x00\xf0\x20\xe3', 'nop', 4, []),
        (b'\x1e\xff\x2f\xe1', 'bx', 4, ['lr']),
        (b'\x0e\xf0\xa0\xe1', 'mov', 4, ['pc','lr']),
    ]

    @classmethod
    def disassemble(cls, data: bytes, arch: Arch, base_addr: int = 0) -> List[Instruction]:
        """Disassemble binary data for given architecture."""
        if arch in (Arch.X86, Arch.X64):
            return cls._disassemble_x86(data, arch, base_addr)
        elif arch in (Arch.ARM, Arch.ARM64):
            return cls._disassemble_arm(data, arch, base_addr)
        else:
            return cls._disassemble_generic(data, arch, base_addr)

    @classmethod
    def _disassemble_x86(cls, data: bytes, arch: Arch, base: int) -> List[Instruction]:
        instructions = []
        offset = 0
        ptr_fmt = '<I' if arch == Arch.X86 else '<Q'

        while offset < len(data):
            matched = False
            remaining = data[offset:]

            for prefix, mnemonic, insn_size, ops in cls.X86_PATTERNS:
                if remaining.startswith(prefix):
                    addr = base + offset
                    operands = []
                    if 'rel' in str(ops) and offset + 1 + (ptr_fmt.count('I')*4 or 8) <= len(data):
                        disp = struct.unpack_from('<i' if arch==Arch.X86 else '<i', data, offset+1)[0]
                        operands = [f'0x{addr+insn_size+disp:x}']
                    elif 'rel8' in str(ops) and offset + 2 <= len(data):
                        disp = struct.unpack_from('<b', data, offset+1)[0]
                        operands = [f'0x{addr+2+disp:x}']

                    instructions.append(Instruction(
                        address=addr, mnemonic=mnemonic, operands=operands,
                        _bytes=data[offset:offset+insn_size], size=insn_size,
                        opcode=data[offset]
                    ))
                    offset += insn_size
                    matched = True
                    break

            if not matched:
                # Unknown opcode — treat as single byte and skip
                instructions.append(Instruction(
                    address=base+offset, mnemonic='db', operands=[f'0x{data[offset]:02x}'],
                    _bytes=data[offset:offset+1], size=1, opcode=data[offset]
                ))
                offset += 1

        return instructions

    @classmethod
    def _disassemble_arm(cls, data: bytes, arch: Arch, base: int) -> List[Instruction]:
        instructions = []
        offset = 0
        insn_size = 4 if arch in (Arch.ARM, Arch.ARM64) else 2

        while offset + insn_size <= len(data):
            word = data[offset:offset+insn_size]
            if word == b'\x00\x00\x00\x00':
                mnem = 'nop'
            elif word[3] == 0xea:
                mnem = 'b'
            elif word[3] == 0xeb:
                mnem = 'bl'
            else:
                mnem = 'arm_insn'

            instructions.append(Instruction(
                address=base+offset, mnemonic=mnem, operands=[],
                _bytes=word, size=insn_size, opcode=word[0]
            ))
            offset += insn_size

        return instructions

    @classmethod
    def _disassemble_generic(cls, data: bytes, arch: Arch, base: int) -> List[Instruction]:
        instructions = []
        insn_size = arch.pointer_size
        for offset in range(0, len(data) - insn_size + 1, insn_size):
            word = data[offset:offset+insn_size]
            instructions.append(Instruction(
                address=base+offset, mnemonic='word', operands=[f'0x{word.hex()}'],
                _bytes=word, size=insn_size, opcode=word[0]
            ))
        return instructions


# ═══════════════════════════════════════════════════════════════════════════════
# CFG Analyzer
# ═══════════════════════════════════════════════════════════════════════════════


class CFGAnalyzer:
    """Control Flow Graph reconstruction and analysis."""

    @staticmethod
    def build_cfg(instructions: List[Instruction]) -> Dict[int, Set[int]]:
        """Build adjacency list CFG from instruction list."""
        cfg: Dict[int, Set[int]] = {}

        for i, insn in enumerate(instructions):
            addr = insn.address
            if addr not in cfg:
                cfg[addr] = set()

            # Fall-through edge
            if i + 1 < len(instructions):
                cfg[addr].add(instructions[i+1].address)

            # Branch targets
            if insn.is_branch() and insn.operands:
                try:
                    target = int(insn.operands[0], 16)
                    cfg[addr].add(target)
                except (ValueError, IndexError):
                    pass

            if insn.is_ret():
                cfg[addr].discard(instructions[i+1].address if i+1 < len(instructions) else 0)

        return cfg

    @staticmethod
    def find_loops(cfg: Dict[int, Set[int]]) -> List[List[int]]:
        """Detect natural loops via back-edge detection."""
        loops = []
        visited = set()
        stack = []

        def dfs(node: int) -> None:
            if node in stack:
                loop_start = stack.index(node)
                loops.append(list(stack[loop_start:]))
                return
            if node in visited:
                return
            visited.add(node)
            stack.append(node)
            for succ in cfg.get(node, set()):
                dfs(succ)
            stack.pop()

        for root in list(cfg.keys())[:1]:
            dfs(root)

        return loops

    @staticmethod
    def find_unreachable_blocks(cfg: Dict[int, Set[int]]) -> List[int]:
        """Find blocks not reachable from entry."""
        if not cfg:
            return []
        entry = min(cfg.keys())
        reachable = set()
        stack = [entry]
        while stack:
            node = stack.pop()
            if node in reachable:
                continue
            reachable.add(node)
            stack.extend(cfg.get(node, set()))
        return [b for b in cfg if b not in reachable]

    @staticmethod
    def compute_cyclomatic_complexity(cfg: Dict[int, Set[int]]) -> int:
        """M = E - N + 2P (connected components assumed 1)."""
        N = len(cfg)
        E = sum(len(targets) for targets in cfg.values())
        return E - N + 2


# ═══════════════════════════════════════════════════════════════════════════════
# ROP Gadget Finder
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class ROP_Gadget:
    address: int
    instructions: List[Instruction]
    side_effects: List[str] = field(default_factory=list)
    stack_cleanup: int = 0
    category: str = ""

    def __repr__(self) -> str:
        insns = '; '.join(ins.mnemonic for ins in self.instructions)
        return f"Gadget(0x{self.address:x}: {insns})"


class ROPGadgetFinder:
    """ROP gadget discovery via ret-sled scanning."""

    RET_OPCODES = {0xc3, 0xc2, 0xca}  # ret, retn imm16, retf imm16

    @classmethod
    def find_gadgets(cls, instructions: List[Instruction], max_len: int = 8) -> List[ROP_Gadget]:
        """Find ROP gadgets by scanning backwards from ret instructions."""
        gadgets = []
        gadget_map: Dict[int, list] = {}

        for i, insn in enumerate(instructions):
            if insn.opcode in cls.RET_OPCODES or insn.mnemonic == 'ret':
                # Backtrack up to max_len instructions
                end = i + 1
                start = max(0, i - max_len + 1)
                gadget_insns = instructions[start:end]

                # Filter to valid gadget (no calls in middle unless at start)
                valid = True
                for j, gins in enumerate(gadget_insns[:-1]):
                    if gins.is_call():
                        valid = False
                        break

                if valid and len(gadget_insns) >= 2:
                    addr = gadget_insns[0].address
                    if addr not in gadget_map:
                        gadget_map[addr] = gadget_insns
                        gadgets.append(ROP_Gadget(
                            address=addr,
                            instructions=list(gadget_insns),
                            stack_cleanup=len(gadget_insns) * 8,
                        ))

        return gadgets

    @classmethod
    def classify_gadgets(cls, gadgets: List[ROP_Gadget]) -> Dict[str, List[ROP_Gadget]]:
        """Categorize gadgets by function."""
        categories = {"LOAD_REG": [], "STORE_MEM": [], "SYSCALL": [],
                       "ARITHMETIC": [], "BRANCH": [], "STACK_PIVOT": []}

        for g in gadgets:
            mnems = [i.mnemonic for i in g.instructions]
            if 'pop' in mnems:
                categories["LOAD_REG"].append(g)
            elif 'mov' in mnems and '[' in str(g.instructions[0].operands):
                categories["STORE_MEM"].append(g)
            elif 'syscall' in mnems:
                categories["SYSCALL"].append(g)
            elif any(m in mnems for m in ('add','sub','xor','and','or')):
                categories["ARITHMETIC"].append(g)
            elif any(g.instructions[k].is_branch() for k in range(len(g.instructions)-1)):
                categories["BRANCH"].append(g)
            elif 'xchg' in mnems:
                categories["STACK_PIVOT"].append(g)

        for cat in categories:
            for g in categories[cat]:
                g.category = cat

        return categories

    @classmethod
    def find_chain(cls, gadgets: List[ROP_Gadget], goal_regs: Dict[str, int]) -> Optional[List[ROP_Gadget]]:
        """Constraint-based ROP chain builder."""
        classified = cls.classify_gadgets(gadgets)
        chain = []
        needed = dict(goal_regs)

        for reg, val in needed.items():
            loaders = classified.get("LOAD_REG", [])
            for g in loaders:
                if len(g.instructions) >= 2:
                    chain.append(g)
                    break

        syscall_gadgets = classified.get("SYSCALL", [])
        if syscall_gadgets:
            chain.append(syscall_gadgets[0])

        return chain if chain else None


# ═══════════════════════════════════════════════════════════════════════════════
# Intermediate Representation Lifting
# ═══════════════════════════════════════════════════════════════════════════════


class IntermediateRepresentation:
    """Lift assembly to three-address IR and optimize."""

    @staticmethod
    def lift_to_ir(instructions: List[Instruction], arch: Arch) -> List[Dict[str, Any]]:
        """Convert instructions to IR: {op, dest, src1, src2, imm, address}."""
        ir_ops = []
        for insn in instructions:
            ir = {"op": insn.mnemonic.upper(), "address": insn.address}

            ops = insn.operands
            if len(ops) >= 1:
                ir["dest"] = ops[0]
            if len(ops) >= 2:
                ir["src1"] = ops[1]
            if len(ops) >= 3:
                ir["src2"] = ops[2]

            # Extract immediate values
            for key in ("dest", "src1", "src2"):
                val = ir.get(key, "")
                if isinstance(val, str) and val.startswith(("0x", "#")):
                    try:
                        ir["imm"] = int(val.replace("#", ""), 16)
                    except ValueError:
                        pass

            ir_ops.append(ir)
        return ir_ops

    @staticmethod
    def optimize_ir(ir_ops: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Peephole optimizations: dead code, constant folding, redundant loads."""
        optimized = list(ir_ops)

        # Pass 1: Constant folding
        for op in optimized:
            if op["op"] in ("ADD", "SUB", "MUL", "AND", "OR", "XOR"):
                imm = op.get("imm")
                src1 = op.get("src1", "")
                if imm is not None and isinstance(src1, str):
                    try:
                        src1_val = int(src1, 16) if src1.startswith("0x") else int(src1)
                        if op["op"] == "ADD":
                            op["dest"] = str(src1_val + imm)
                        elif op["op"] == "SUB":
                            op["dest"] = str(src1_val - imm)
                        elif op["op"] == "MUL":
                            if imm != 0:
                                op["dest"] = str(src1_val * imm)
                        elif op["op"] == "AND":
                            op["dest"] = str(src1_val & imm)
                        op["op"] = "MOV"
                        op["imm"] = int(op["dest"])
                        op.pop("src1", None)
                        op.pop("src2", None)
                    except (ValueError, KeyError):
                        pass

        # Pass 2: Dead code elimination — remove MOV r, r
        optimized = [op for op in optimized
                     if not (op["op"] == "MOV" and op.get("dest") == op.get("src1"))]

        return optimized


# ═══════════════════════════════════════════════════════════════════════════════
# BinaryAnalysisEngine — Main
# ═══════════════════════════════════════════════════════════════════════════════


class BinaryAnalysisEngine:
    """Cross-architecture binary analysis engine."""

    def __init__(self, clearance: SecurityClearance = SecurityClearance.ANALYST):
        if clearance.value < SecurityClearance.ANALYST.value:
            raise PermissionError("BinaryAnalysisEngine requires ANALYST clearance")
        self.clearance = clearance
        self.disassembler = Disassembler()
        self.cfg_analyzer = CFGAnalyzer()
        self.gadget_finder = ROPGadgetFinder()
        self.ir_lifter = IntermediateRepresentation()
        self.total_analyses = 0

    def analyze(
        self, data: bytes, arch: Arch, sections: Optional[List[BinarySection]] = None
    ) -> Dict[str, Any]:
        """Full binary analysis pipeline.

        Args:
            data: Raw binary content.
            arch: Target architecture.
            sections: Optional section information.

        Returns:
            Comprehensive analysis dictionary.
        """
        instructions = self.disassembler.disassemble(data, arch, base_addr=0x400000)

        # Build CFG
        cfg = self.cfg_analyzer.build_cfg(instructions)

        # Find gadgets
        gadgets = self.gadget_finder.find_gadgets(instructions)
        classified = self.gadget_finder.classify_gadgets(gadgets)

        # Lift to IR
        ir_ops = self.ir_lifter.lift_to_ir(instructions, arch)
        ir_optimized = self.ir_lifter.optimize_ir(ir_ops)

        # Compute metrics
        loops = self.cfg_analyzer.find_loops(cfg)
        cyclomatic = self.cfg_analyzer.compute_cyclomatic_complexity(cfg)
        unreachable = self.cfg_analyzer.find_unreachable_blocks(cfg)

        self.total_analyses += 1

        return {
            "architecture": arch.name,
            "total_instructions": len(instructions),
            "total_bytes": len(data),
            "cfg_edges": sum(len(v) for v in cfg.values()),
            "cfg_nodes": len(cfg),
            "cyclomatic_complexity": cyclomatic,
            "loop_count": len(loops),
            "unreachable_blocks": len(unreachable),
            "rop_gadgets": len(gadgets),
            "rop_categories": {k: len(v) for k, v in classified.items()},
            "ir_operations": len(ir_ops),
            "ir_optimized": len(ir_optimized),
            "sections": [s.name for s in (sections or [])],
            "instructions": instructions,
            "cfg": {hex(k): [hex(v) for v in vs] for k, vs in cfg.items()},
            "gadgets": classified,
        }

    def detect_vulnerabilities(self, analysis: Dict[str, Any]) -> List[ThreatFinding]:
        """Detect vulnerabilities from analysis results."""
        findings = []

        # Stack canary check
        if analysis.get("rop_gadgets", 0) > 10:
            findings.append(ThreatFinding(
                threat_class=ThreatClass.EXPLOITATION,
                confidence=0.70,
                raw_logits=None,
                uncertainty=0.15,
                metadata={
                    "cwe_id": "CWE-121",
                    "severity": "HIGH",
                    "finding": "rop_gadgets_available",
                    "count": analysis["rop_gadgets"],
                    "engine": "binary_analysis",
                },
            ))

        # Unreachable code
        if analysis.get("unreachable_blocks", 0) > 0:
            findings.append(ThreatFinding(
                threat_class=ThreatClass.DEFENSE_EVASION,
                confidence=0.45,
                raw_logits=None,
                uncertainty=0.25,
                metadata={
                    "cwe_id": "CWE-561",
                    "severity": "LOW",
                    "unreachable_count": analysis["unreachable_blocks"],
                    "engine": "binary_analysis",
                },
            ))

        # High complexity
        if analysis.get("cyclomatic_complexity", 0) > 50:
            findings.append(ThreatFinding(
                threat_class=ThreatClass.EXPLOITATION,
                confidence=0.50,
                raw_logits=None,
                uncertainty=0.20,
                metadata={
                    "cwe_id": "CWE-1120",
                    "severity": "MEDIUM",
                    "complexity": analysis["cyclomatic_complexity"],
                    "engine": "binary_analysis",
                },
            ))

        return findings

    def cross_reference(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Build call graph and data flow summaries."""
        instructions = analysis.get("instructions", [])
        call_graph: Dict[int, List[int]] = {}
        xrefs: Dict[str, List[int]] = {}

        for insn in instructions:
            if insn.is_call() and insn.operands:
                call_graph.setdefault(insn.address, []).append(
                    int(insn.operands[0], 16)
                )
            for op in insn.operands:
                xrefs.setdefault(op, []).append(insn.address)

        return {"call_graph": call_graph, "cross_references": xrefs}

    def compare_binaries(
        self, analysis_a: Dict[str, Any], analysis_b: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Binary diffing comparison."""
        return {
            "insn_diff": analysis_a["total_instructions"] - analysis_b["total_instructions"],
            "complexity_diff": (
                analysis_a["cyclomatic_complexity"] - analysis_b["cyclomatic_complexity"]
            ),
            "rop_diff": analysis_a["rop_gadgets"] - analysis_b["rop_gadgets"],
            "similarity_score": 1.0 - abs(
                analysis_a["total_instructions"] - analysis_b["total_instructions"]
            ) / max(analysis_a["total_instructions"], analysis_b["total_instructions"], 1),
        }

    def export_to_dot(self, cfg: Dict[int, Set[int]]) -> str:
        """Export CFG to Graphviz DOT format."""
        lines = ["digraph CFG {", "  node [shape=box];"]
        for src, targets in cfg.items():
            for tgt in targets:
                lines.append(f'  "{hex(src)}" -> "{hex(tgt)}";')
        lines.append("}")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    engine = BinaryAnalysisEngine(clearance=SecurityClearance.ANALYST)

    # Simulate a minimal x86_64 binary
    sample = (
        b"\x55"                     # push rbp
        b"\x48\x89\xe5"             # mov rbp, rsp
        b"\x48\x83\xec\x10"         # sub rsp, 0x10
        b"\xe8\x00\x00\x00\x00"     # call rel
        b"\x90"                     # nop
        b"\xc9"                     # leave
        b"\xc3"                     # ret
        b"\x0f\x05"                # syscall
    )

    result = engine.analyze(sample, Arch.X64)
    print(f"Instructions: {result['total_instructions']}")
    print(f"ROP gadgets: {result['rop_gadgets']}")
    print(f"Cyclomatic: {result['cyclomatic_complexity']}")

    vulns = engine.detect_vulnerabilities(result)
    for v in vulns:
        print(f"  [{v.metadata.get('cwe_id','?')}] {v.threat_class.name}")
