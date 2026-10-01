#!/usr/bin/env python3
"""
KasbahMythos v4.0 — Unified Autonomous Security Research Platform
=================================================================

Wires ALL engines end-to-end:
  kasbah_types       → SecurityClearance, ThreatFinding, AuditEntry
  neuromorphic_engine → MythosNeuromorphicEngine
  zeroday_engine     → ZeroDayDiscoveryEngine
  exploit_pipeline   → ExploitSynthesisPipeline (gated: OFFICER+)
  adversarial_selfplay → AdversarialSelfPlay
  binary_engine      → BinaryAnalysisEngine
  kernel_fuzzer      → KernelFuzzingHarness
  crypto_audit       → ZeroTrustAudit

Clearance Gating:
  PUBLIC     – Read-only: audit queries, status reports
  RESEARCHER – Inference: neuromorphic, self-play, kernel fuzzing
  ANALYST    – + Binary analysis, zero-day discovery
  OFFICER    – + Exploit synthesis (gated, requires approval)
  ADMIN      – + Audit management, configuration, key generation
  SYSTEM     – Root: full subsystem access

Advisory Semantics (bounded, never autonomous DENY):
  CLEAR             – No anomalies detected
  WARN              – Anomaly score above warning threshold
  REQUIRE_APPROVAL  – Anomaly score above critical threshold + ≥2 modules agree

CLI Modes: daemon, interactive, oneshot
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional

# ═══════════════════════════════════════════════════════════════════════════════
# Import all engines with graceful fallback
# ═══════════════════════════════════════════════════════════════════════════════

from kasbah_types import (
    AuditEntry,
    BinarySection,
    ExploitArtifact,
    ExploitType,
    SecurityClearance,
    ThreatClass,
    ThreatFinding,
)

# Engine imports — each wrapped in try/except for graceful degradation
_engine_status: Dict[str, bool] = {}

try:
    from neuromorphic_engine import MythosNeuromorphicEngine
    _engine_status["neuromorphic"] = True
except ImportError as e:
    _engine_status["neuromorphic"] = False
    MythosNeuromorphicEngine = None

try:
    from zeroday_engine import ZeroDayDiscoveryEngine
    _engine_status["zeroday"] = True
except ImportError as e:
    _engine_status["zeroday"] = False
    ZeroDayDiscoveryEngine = None

try:
    from exploit_pipeline import ExploitSynthesisPipeline
    _engine_status["exploit"] = True
except ImportError as e:
    _engine_status["exploit"] = False
    ExploitSynthesisPipeline = None

try:
    from adversarial_selfplay import AdversarialSelfPlay
    _engine_status["selfplay"] = True
except ImportError as e:
    _engine_status["selfplay"] = False
    AdversarialSelfPlay = None

try:
    from binary_engine import BinaryAnalysisEngine, Arch
    _engine_status["binary"] = True
except ImportError as e:
    _engine_status["binary"] = False
    BinaryAnalysisEngine = None
    Arch = None

try:
    from kernel_fuzzer import KernelFuzzingHarness
    _engine_status["fuzzer"] = True
except ImportError as e:
    _engine_status["fuzzer"] = False
    KernelFuzzingHarness = None

try:
    from crypto_audit import ZeroTrustAudit, Ed25519Signer, HashFunctions
    _engine_status["audit"] = True
except ImportError as e:
    _engine_status["audit"] = False
    ZeroTrustAudit = None

# ═══════════════════════════════════════════════════════════════════════════════
# Task Scheduling
# ═══════════════════════════════════════════════════════════════════════════════


class TaskPriority(IntEnum):
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    BACKGROUND = 4


@dataclass
class Task:
    task_id: str
    name: str
    engine: str
    priority: TaskPriority
    args: dict = field(default_factory=dict)
    status: str = "pending"
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Any = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "name": self.name,
            "engine": self.engine,
            "priority": self.priority.name,
            "status": self.status,
            "created_at": self.created_at,
        }


class TaskScheduler:
    """Priority-based async task scheduler."""

    def __init__(self, max_concurrent: int = 10):
        self.tasks: Dict[str, Task] = {}
        self.max_concurrent = max_concurrent
        self.running = 0
        self._lock = asyncio.Lock() if asyncio else None

    def submit(self, name: str, engine: str, priority: TaskPriority, args: dict = None) -> str:
        """Submit a task and return its ID."""
        task_id = uuid.uuid4().hex[:12]
        task = Task(
            task_id=task_id,
            name=name,
            engine=engine,
            priority=priority,
            args=args or {},
        )
        self.tasks[task_id] = task
        return task_id

    def cancel(self, task_id: str) -> bool:
        task = self.tasks.get(task_id)
        if task and task.status == "pending":
            task.status = "cancelled"
            return True
        return False

    def get_status(self, task_id: str) -> Optional[dict]:
        task = self.tasks.get(task_id)
        return task.to_dict() if task else None

    def pending_count(self) -> int:
        return sum(1 for t in self.tasks.values() if t.status == "pending")

    def completed_count(self) -> int:
        return sum(1 for t in self.tasks.values() if t.status == "completed")

    def start_task(self, task_id: str) -> None:
        task = self.tasks.get(task_id)
        if task:
            task.status = "running"
            task.started_at = time.time()

    def complete_task(self, task_id: str, result: Any = None, error: str = None) -> None:
        task = self.tasks.get(task_id)
        if task:
            task.status = "completed" if not error else "failed"
            task.completed_at = time.time()
            task.result = result
            task.error = error


# ═══════════════════════════════════════════════════════════════════════════════
# Engine Registry
# ═══════════════════════════════════════════════════════════════════════════════


class EngineRegistry:
    """Registry pattern for all engine instances."""

    def __init__(self):
        self._engines: Dict[str, Any] = {}

    def register(self, name: str, engine: Any) -> None:
        self._engines[name] = engine

    def get(self, name: str) -> Any:
        engine = self._engines.get(name)
        if engine is None:
            raise KeyError(f"Engine '{name}' not registered")
        return engine

    def list_engines(self) -> List[str]:
        return list(self._engines.keys())

    def health_check(self) -> Dict[str, str]:
        status = {}
        for name, engine in self._engines.items():
            try:
                if hasattr(engine, "clearance"):
                    status[name] = f"OK (clearance: {engine.clearance.name})"
                else:
                    status[name] = "OK"
            except Exception as e:
                status[name] = f"ERROR: {e}"
        return status


# ═══════════════════════════════════════════════════════════════════════════════
# Threat Orchestrator
# ═══════════════════════════════════════════════════════════════════════════════


class ThreatOrchestrator:
    """Coordinates the full threat analysis pipeline across engines."""

    def __init__(self, registry: EngineRegistry):
        self.registry = registry

    def analyze_threats(
        self, data: bytes, arch: Optional[str] = None
    ) -> Dict[str, Any]:
        """Full threat analysis pipeline.

        Pipeline: Binary Analysis → Zero-Day Discovery → Neuromorphic Classification
        """
        all_findings: List[ThreatFinding] = []
        results: Dict[str, Any] = {"findings": [], "summary": {}}

        # Step 1: Binary Analysis
        if "binary" in self.registry.list_engines() and arch:
            try:
                engine = self.registry.get("binary")
                arch_enum = {
                    "x86": 0, "x64": 1, "arm": 2, "arm64": 3,
                    "mips": 4, "mips64": 5, "riscv32": 6, "riscv64": 7,
                }
                arch_val = arch_enum.get(arch.lower().replace("_", ""), 1)
                # Create Arch from int if module loaded
                if Arch:
                    arch_obj = Arch(arch_val)
                    analysis = engine.analyze(data, arch_obj)
                    findings = engine.detect_vulnerabilities(analysis)
                    all_findings.extend(findings)
                    results["binary_analysis"] = {
                        "total_instructions": analysis.get("total_instructions", 0),
                        "rop_gadgets": analysis.get("rop_gadgets", 0),
                        "findings_count": len(findings),
                    }
            except Exception as e:
                results["binary_analysis"] = {"error": str(e)}

        # Step 2: Zero-Day Discovery
        if "zeroday" in self.registry.list_engines():
            try:
                engine = self.registry.get("zeroday")
                findings = engine.analyze(data, mode="hybrid")
                all_findings.extend(findings)
                results["zeroday"] = engine.generate_report()
            except Exception as e:
                results["zeroday"] = {"error": str(e)}

        # Step 3: Neuromorphic Classification
        if "neuromorphic" in self.registry.list_engines():
            try:
                engine = self.registry.get("neuromorphic")
                import numpy as np
                features = np.frombuffer(data[:200], dtype=np.float32)
                if len(features) == 0:
                    features = np.random.randn(50).astype(np.float32)
                nm_findings = engine.forward(features)
                all_findings.extend(nm_findings)
                results["neuromorphic"] = {
                    "uncertainty": engine.compute_uncertainty(),
                    "spikes": engine.lif_layer.get_total_spikes(),
                }
            except Exception as e:
                results["neuromorphic"] = {"error": str(e)}

        # Step 4: Correlate and prioritize
        correlated = self._correlate_findings(all_findings)
        prioritized = self._prioritize_findings(correlated)

        # Step 5: Compute advisory
        advisory = self._compute_advisory(prioritized)

        results["findings"] = prioritized
        results["summary"] = {
            "total_findings": len(all_findings),
            "unique_findings": len(prioritized),
            "advisory": advisory,
            "threat_level": self._compute_threat_level(prioritized),
        }

        return results

    def _correlate_findings(self, findings: List[ThreatFinding]) -> List[ThreatFinding]:
        """Cross-engine correlation — merge findings with same CWE."""
        merged: Dict[str, ThreatFinding] = {}
        for f in findings:
            cwe = (f.metadata or {}).get("cwe_id", hash(str(f.metadata)))
            if cwe in merged:
                merged[cwe].confidence = max(merged[cwe].confidence, f.confidence)
                if f.metadata and merged[cwe].metadata:
                    merged[cwe].metadata["correlated"] = True
                    merged[cwe].metadata["source_count"] = merged[cwe].metadata.get("source_count", 1) + 1
            else:
                merged[cwe] = f
        return list(merged.values())

    def _prioritize_findings(self, findings: List[ThreatFinding]) -> List[ThreatFinding]:
        """Risk-prioritize findings."""
        def key(f: ThreatFinding) -> float:
            severity_weight = {
                "CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1,
            }.get((f.metadata or {}).get("severity", "MEDIUM"), 1)
            return f.confidence * severity_weight
        return sorted(findings, key=key, reverse=True)

    @staticmethod
    def _compute_advisory(findings: List[ThreatFinding]) -> str:
        """Bounded advisory: CLEAR / WARN / REQUIRE_APPROVAL."""
        if not findings:
            return "CLEAR"

        # Count high-confidence CRITICAL/HIGH findings
        critical_count = sum(
            1 for f in findings
            if f.confidence > 0.75
            and (f.metadata or {}).get("severity", "") in ("CRITICAL", "HIGH")
        )

        # Ensemble score
        scores = [
            f.confidence * (
                {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}.get(
                    (f.metadata or {}).get("severity", "MEDIUM"), 1
                ) / 10
            )
            for f in findings
        ]
        ensemble_score = sum(scores) / max(len(scores), 1)

        if ensemble_score >= 0.7 and critical_count >= 2:
            return "REQUIRE_APPROVAL"
        elif ensemble_score >= 0.35:
            return "WARN"
        return "CLEAR"

    @staticmethod
    def _compute_threat_level(findings: List[ThreatFinding]) -> str:
        if not findings:
            return "NONE"
        max_conf = max(f.confidence for f in findings)
        if max_conf > 0.85:
            return "CRITICAL"
        elif max_conf > 0.65:
            return "HIGH"
        elif max_conf > 0.40:
            return "MEDIUM"
        return "LOW"


# ═══════════════════════════════════════════════════════════════════════════════
# Research Pipeline
# ═══════════════════════════════════════════════════════════════════════════════


class ResearchPipeline:
    """Autonomous research loop coordinating all engines."""

    def __init__(self, registry: EngineRegistry, audit: Any = None):
        self.registry = registry
        self.audit = audit
        self.cycles_completed = 0

    def run_research_cycle(self, target_info: dict) -> Dict[str, Any]:
        """Execute one complete research cycle.

        1. Binary analysis (if target has binary)
        2. Kernel fuzzing
        3. Zero-day discovery
        4. Exploit synthesis (gated: OFFICER+)
        5. Self-play training
        6. Record audit trail
        """
        results = {"cycle": self.cycles_completed + 1, "findings": [], "errors": []}

        # Step 1: Binary analysis
        binary_data = target_info.get("binary_data", b"")
        if binary_data and "binary" in self.registry.list_engines():
            try:
                engine = self.registry.get("binary")
                if Arch:
                    analysis = engine.analyze(binary_data, Arch.X64)
                    vulns = engine.detect_vulnerabilities(analysis)
                    results["findings"].extend(vulns)
                    results["binary"] = {"instructions": analysis.get("total_instructions", 0)}
            except Exception as e:
                results["errors"].append(f"binary: {e}")

        # Step 2: Kernel fuzzing
        if "fuzzer" in self.registry.list_engines():
            try:
                engine = self.registry.get("fuzzer")
                crashes = engine.fuzz(iterations=100)
                results["findings"].extend(crashes)
                results["fuzzer"] = engine.analyze_state_coverage()
            except Exception as e:
                results["errors"].append(f"fuzzer: {e}")

        # Step 3: Zero-day discovery
        if binary_data and "zeroday" in self.registry.list_engines():
            try:
                engine = self.registry.get("zeroday")
                z_findings = engine.analyze(binary_data, mode="hybrid")
                results["findings"].extend(z_findings)
            except Exception as e:
                results["errors"].append(f"zeroday: {e}")

        # Step 4: Exploit synthesis (OPERATOR gated)
        if "exploit" in self.registry.list_engines():
            try:
                pipeline = self.registry.get("exploit")
                # Only synthesize if we have findings and OPERATOR clearance
                critical = [f for f in results["findings"]
                           if (f.metadata or {}).get("severity") == "CRITICAL"]
                if critical:
                    artifacts = pipeline.batch_synthesize(critical[:3], target_info)
                    results["exploits"] = [a.exploit_type.name for a in artifacts]
            except PermissionError:
                results["exploits"] = "BLOCKED: insufficient clearance"
            except Exception as e:
                results["errors"].append(f"exploit: {e}")

        # Step 5: Self-play training
        if "selfplay" in self.registry.list_engines():
            try:
                engine = self.registry.get("selfplay")
                train_results = engine.train(10)
                results["selfplay"] = train_results
            except Exception as e:
                results["errors"].append(f"selfplay: {e}")

        # Step 6: Audit trail
        if self.audit:
            try:
                self.audit.record_event(
                    "research_pipeline",
                    "cycle_complete",
                    {"cycle": self.cycles_completed, "findings_count": len(results["findings"])},
                )
            except Exception as e:
                results["errors"].append(f"audit: {e}")

        self.cycles_completed += 1
        return results


# ═══════════════════════════════════════════════════════════════════════════════
# KasbahMythos — MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════


class KasbahMythos:
    """KasbahOS v4.0 Mythos-Class Frontier System — Main Orchestrator.

    Wires all engines, manages clearance, schedules tasks, and coordinates
    the autonomous research pipeline.
    """

    VERSION = "4.0.0"
    CODENAME = "Mythos"

    # Default configuration
    DEFAULT_CONFIG = {
        "timeout_seconds": 3600,
        "max_concurrent_tasks": 10,
        "audit_enabled": True,
        "log_level": "INFO",
        "log_format": "json",
        "selfplay_episodes": 10000,
        "fuzz_iterations": 5000,
        "zeroday_mode": "hybrid",
    }

    def __init__(
        self,
        config_path: Optional[str] = None,
        clearance: SecurityClearance = SecurityClearance.PUBLIC,
    ):
        self.clearance = clearance
        self.config = self._load_config(config_path)
        self.registry = EngineRegistry()
        self.scheduler = TaskScheduler(
            max_concurrent=self.config.get("max_concurrent_tasks", 10)
        )
        self.orchestrator = ThreatOrchestrator(self.registry)
        self.audit: Any = None
        self.pipeline: Optional[ResearchPipeline] = None
        self.running = False
        self.start_time: Optional[float] = None

        # Setup logging
        self._setup_logging()

        # Initialize engines according to clearance
        self._init_engines()

    # ── Configuration ──────────────────────────────────────────────────────

    def _load_config(self, path: Optional[str]) -> dict:
        """Load configuration from file or use defaults."""
        config = dict(self.DEFAULT_CONFIG)
        if path and os.path.exists(path):
            try:
                with open(path) as f:
                    file_config = json.load(f)
                    config.update(file_config)
            except Exception as e:
                logging.warning(f"Failed to load config from {path}: {e}")
        return config

    def _setup_logging(self) -> None:
        """Setup structured logging."""
        level = getattr(logging, self.config.get("log_level", "INFO"), logging.INFO)
        fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        logging.basicConfig(level=level, format=fmt,
                          handlers=[logging.StreamHandler(sys.stderr)])

    # ── Engine Initialization ─────────────────────────────────────────────

    def _init_engines(self) -> None:
        """Initialize engines based on clearance level."""
        logging.info(f"Initializing KasbahMythos v{self.VERSION} "
                     f"with clearance: {self.clearance.name}")

        # Always available: audit (for tracking)
        if ZeroTrustAudit and self.config.get("audit_enabled", True):
            try:
                self.audit = ZeroTrustAudit(
                    clearance=SecurityClearance.ADMIN
                    if self.clearance >= SecurityClearance.ADMIN
                    else self.clearance
                )
                self.registry.register("audit", self.audit)
                logging.info("  [OK] ZeroTrustAudit initialized")
            except PermissionError:
                logging.warning("  [SKIP] ZeroTrustAudit — insufficient clearance")
            except Exception as e:
                logging.warning(f"  [FAIL] ZeroTrustAudit: {e}")

        # RESEARCHER level: neuromorphic, self-play, fuzzer
        if self.clearance >= SecurityClearance.RESEARCHER:
            if MythosNeuromorphicEngine:
                try:
                    engine = MythosNeuromorphicEngine(clearance=self.clearance)
                    self.registry.register("neuromorphic", engine)
                    logging.info("  [OK] MythosNeuromorphicEngine initialized")
                except Exception as e:
                    logging.warning(f"  [FAIL] Neuromorphic: {e}")

            if AdversarialSelfPlay:
                try:
                    engine = AdversarialSelfPlay(clearance=self.clearance)
                    self.registry.register("selfplay", engine)
                    logging.info("  [OK] AdversarialSelfPlay initialized")
                except Exception as e:
                    logging.warning(f"  [FAIL] SelfPlay: {e}")

            if KernelFuzzingHarness:
                try:
                    engine = KernelFuzzingHarness(clearance=self.clearance)
                    self.registry.register("fuzzer", engine)
                    logging.info("  [OK] KernelFuzzingHarness initialized")
                except Exception as e:
                    logging.warning(f"  [FAIL] Fuzzer: {e}")

        # ANALYST level: binary analysis, zero-day discovery
        if self.clearance >= SecurityClearance.ANALYST:
            if BinaryAnalysisEngine and Arch:
                try:
                    engine = BinaryAnalysisEngine(clearance=self.clearance)
                    self.registry.register("binary", engine)
                    logging.info("  [OK] BinaryAnalysisEngine initialized")
                except Exception as e:
                    logging.warning(f"  [FAIL] Binary: {e}")

            if ZeroDayDiscoveryEngine:
                try:
                    engine = ZeroDayDiscoveryEngine(clearance=self.clearance)
                    self.registry.register("zeroday", engine)
                    logging.info("  [OK] ZeroDayDiscoveryEngine initialized")
                except Exception as e:
                    logging.warning(f"  [FAIL] ZeroDay: {e}")

        # OFFICER level: exploit synthesis (gated)
        if self.clearance >= SecurityClearance.OFFICER:
            if ExploitSynthesisPipeline:
                try:
                    pipeline = ExploitSynthesisPipeline(
                        operator_clearance=self.clearance
                    )
                    self.registry.register("exploit", pipeline)
                    logging.info("  [OK] ExploitSynthesisPipeline initialized (GATED)")
                except PermissionError as e:
                    logging.warning(f"  [SKIP] Exploit pipeline blocked: {e}")
                except Exception as e:
                    logging.warning(f"  [FAIL] Exploit: {e}")

        # Research pipeline
        self.pipeline = ResearchPipeline(self.registry, self.audit)

        active = self.registry.list_engines()
        logging.info(f"Active engines ({len(active)}): {', '.join(active)}")

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def startup(self) -> bool:
        """Initialize and verify all engines."""
        self.start_time = time.time()
        self.running = True

        health = self.registry.health_check()
        all_ok = all("OK" in v for v in health.values())

        if self.audit:
            self.audit.record_event("kasbah_mythos", "startup", {
                "version": self.VERSION,
                "clearance": self.clearance.name,
                "engines": self.registry.list_engines(),
                "health": health,
            })

        logging.info(f"KasbahMythos v{self.VERSION} started. Health: {'ALL OK' if all_ok else health}")
        return all_ok

    def shutdown(self) -> bool:
        """Graceful shutdown."""
        self.running = False

        if self.audit:
            self.audit.record_event("kasbah_mythos", "shutdown", {
                "uptime_seconds": time.time() - (self.start_time or time.time()),
                "tasks_completed": self.scheduler.completed_count(),
            })

        logging.info("KasbahMythos shutdown complete.")
        return True

    def status(self) -> Dict[str, Any]:
        """Complete system status."""
        return {
            "version": self.VERSION,
            "codename": self.CODENAME,
            "clearance": self.clearance.name,
            "uptime_seconds": time.time() - (self.start_time or time.time()),
            "running": self.running,
            "engines": self.registry.health_check(),
            "engine_status": _engine_status,
            "tasks_pending": self.scheduler.pending_count(),
            "tasks_completed": self.scheduler.completed_count(),
            "audit_enabled": self.audit is not None,
        }

    # ── Task Submission ───────────────────────────────────────────────────

    def submit_binary_analysis(self, data: bytes, arch: str) -> str:
        """Submit binary analysis task."""
        return self.scheduler.submit(
            "binary_analysis", "binary",
            TaskPriority.HIGH, {"data": data, "arch": arch}
        )

    def submit_fuzzing(self, target_info: dict) -> str:
        """Submit kernel fuzzing task."""
        return self.scheduler.submit(
            "kernel_fuzzing", "fuzzer",
            TaskPriority.MEDIUM, target_info
        )

    def submit_exploit_synthesis(self, findings: list, target_info: dict) -> str:
        """Submit exploit synthesis task (gated)."""
        if self.clearance.value < SecurityClearance.OFFICER.value:
            raise PermissionError("Exploit synthesis requires OFFICER clearance")
        return self.scheduler.submit(
            "exploit_synthesis", "exploit",
            TaskPriority.CRITICAL, {"findings": findings, "target": target_info}
        )

    def submit_selfplay_training(self, episodes: int = 100) -> str:
        """Submit self-play training task."""
        return self.scheduler.submit(
            "selfplay_training", "selfplay",
            TaskPriority.BACKGROUND, {"episodes": episodes}
        )

    # ── Reports ───────────────────────────────────────────────────────────

    def get_audit_report(self) -> dict:
        """Get complete audit report."""
        if not self.audit:
            return {"error": "Audit subsystem not available"}
        return self.audit.generate_audit_report()

    def get_threat_intelligence(self) -> dict:
        """Aggregated threat intelligence."""
        findings_list: List[ThreatFinding] = []

        # Collect from all engines
        for name in self.registry.list_engines():
            engine = self.registry.get(name)
            if hasattr(engine, "findings"):
                findings_list.extend(engine.findings)
            if hasattr(engine, "artifacts"):
                findings_list.extend(
                    ThreatFinding(
                        threat_class=ThreatClass.EXPLOITATION,
                        confidence=a.reliability,
                        raw_logits=None,
                        uncertainty=0.15,
                        metadata={"exploit_type": a.exploit_type.name},
                    )
                    for a in engine.artifacts
                )

        return {
            "total_findings": len(findings_list),
            "advisory": ThreatOrchestrator._compute_advisory(findings_list),
            "threat_level": ThreatOrchestrator._compute_threat_level(findings_list),
            "timestamp": time.time(),
        }

    # ── Main Loop ─────────────────────────────────────────────────────────

    async def main_loop(self) -> None:
        """Async main event loop."""
        logging.info("Entering main event loop...")
        cycle = 0

        while self.running:
            cycle += 1
            logging.debug(f"Main loop cycle {cycle}")

            # Run a quick research cycle if we have targets
            # (In daemon mode, this would be driven by external inputs)

            await asyncio.sleep(5)  # 5-second heartbeat

    def run(self, mode: str = "interactive") -> None:
        """Run KasbahMythos in the specified mode."""
        self.startup()

        if mode == "daemon":
            asyncio.run(self.main_loop())
        elif mode == "interactive":
            self._interactive_repl()
        elif mode == "oneshot":
            status = self.status()
            print(json.dumps(status, indent=2, default=str))
        else:
            logging.error(f"Unknown mode: {mode}")

        self.shutdown()

    def _interactive_repl(self) -> None:
        """Interactive REPL for manual operation."""
        print(f"\n{'='*60}")
        print(f"  KasbahMythos v{self.VERSION} ({self.CODENAME})")
        print(f"  Clearance: {self.clearance.name}")
        print(f"  Engines: {', '.join(self.registry.list_engines())}")
        print(f"  Advisory: CLEAR | WARN | REQUIRE_APPROVAL (bounded)")
        print(f"{'='*60}")
        print("  Commands: status, audit, engines, research, quit/exit")
        print(f"{'='*60}\n")

        while self.running:
            try:
                cmd = input("kasbah> ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                break

            if cmd in ("quit", "exit", "q"):
                break
            elif cmd == "status":
                print(json.dumps(self.status(), indent=2, default=str))
            elif cmd == "audit":
                print(json.dumps(self.get_audit_report(), indent=2, default=str))
            elif cmd == "engines":
                print(json.dumps(self.registry.health_check(), indent=2))
            elif cmd == "research":
                if self.pipeline:
                    result = self.pipeline.run_research_cycle({
                        "binary_data": b"\x90" * 100,
                    })
                    print(json.dumps(result, indent=2, default=str)[:2000])
                else:
                    print("Research pipeline not available")
            elif cmd == "help":
                print("Commands: status, audit, engines, research, quit/exit")
            elif cmd:
                print(f"Unknown command: {cmd}")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═══════════════════════════════════════════════════════════════════════════════


def main():
    parser = argparse.ArgumentParser(
        description="KasbahMythos v4.0 — Mythos-Class Frontier System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--clearance", type=str, default="PUBLIC",
                       choices=[c.name for c in SecurityClearance],
                       help="Security clearance level")
    parser.add_argument("--config", type=str, default=None,
                       help="Path to JSON configuration file")
    parser.add_argument("--mode", type=str, default="interactive",
                       choices=["daemon", "interactive", "oneshot"],
                       help="Operating mode")
    parser.add_argument("--target", type=str, default=None,
                       help="Target binary path for oneshot mode")
    parser.add_argument("--binary", type=str, default=None,
                       help="Binary data file for analysis")

    args = parser.parse_args()

    clearance = SecurityClearance[args.clearance.upper()]
    kasbah = KasbahMythos(
        config_path=args.config,
        clearance=clearance,
    )

    # Handle signals for graceful shutdown
    def handle_signal(signum, frame):
        logging.info(f"Received signal {signum}, shutting down...")
        kasbah.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    kasbah.run(mode=args.mode)


if __name__ == "__main__":
    main()
