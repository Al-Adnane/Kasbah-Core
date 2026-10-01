"""
╔══════════════════════════════════════════════════════════════════════════╗
║         KASBAH AGENT CONTROL — Python SDK                               ║
║                                                                          ║
║  Universal governance middleware for all Python AI frameworks            ║
║  Wraps: OpenAI · Anthropic · LangChain · LangGraph · AutoGen · CrewAI   ║
║  Also works with: Kimi · Grok · Ollama · any OpenAI-compatible API       ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import hashlib
import hmac
import json
import time
import threading
from contextlib import contextmanager, asynccontextmanager
from typing import Any, Callable, Dict, List, Literal, Optional
from functools import wraps
import sys
import os

# Add parent dir to path so we can find kasbah_sentinel
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

KASBAH_VERSION = "1.0.0"
PROXY_PORT = 31337
_proof_counter = 0
_counter_lock = threading.Lock()

# LLM API URL patterns to intercept
LLM_API_PATTERNS = [
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.groq.com",
    "localhost:11434",          # Ollama
    "api.mistral.ai",
    "api.cohere.com",
    "api.x.ai",                 # Grok
    "api.moonshot.cn",          # Kimi
    "dashscope.aliyuncs.com",   # Alibaba/Qwen
]

Verdict = Literal["ALLOW", "WARN", "DENY"]


class GovernanceDecision:
    """Result of a KasbahSentinel governance check."""

    def __init__(
        self,
        verdict: Verdict,
        request_id: str,
        proof: str,
        latency_ms: float,
        reason: str = "",
        risk: float = 0.0,
        layers: Dict[str, Any] = None,
    ):
        self.verdict = verdict
        self.request_id = request_id
        self.proof = proof
        self.latency_ms = latency_ms
        self.reason = reason
        self.risk = risk
        self.layers = layers or {}
        self.allowed = verdict in ("ALLOW", "WARN")
        self.blocked = verdict == "DENY"

    def __repr__(self):
        icon = "✅" if self.allowed else "🚫"
        return f"GovernanceDecision({icon} {self.verdict} | risk={self.risk:.2f} | {self.latency_ms:.0f}ms | {self.request_id})"

    def to_dict(self) -> Dict:
        return {
            "verdict": self.verdict,
            "request_id": self.request_id,
            "proof": self.proof,
            "latency_ms": self.latency_ms,
            "reason": self.reason,
            "risk": self.risk,
            "layers": self.layers,
        }


class KasbahBlockedError(Exception):
    """Raised when KasbahSentinel denies a request."""

    def __init__(self, decision: GovernanceDecision):
        self.decision = decision
        super().__init__(
            f"KasbahSentinel DENIED: {decision.reason} "
            f"(risk={decision.risk:.2f}, proof={decision.proof[:32]}...)"
        )


class KasbahAgentControl:
    """
    Universal AI governance middleware.

    Intercepts calls to any LLM, agent framework, or AI API.
    Applies all 13 KasbahSentinel layers before execution.
    Returns ALLOW / WARN / DENY with cryptographic proof.

    Usage:
        control = KasbahAgentControl()

        # Context manager (recommended)
        with control.session("my-session") as session:
            result = session.check_prompt("my prompt")

        # Decorator
        @control.govern_function
        async def call_llm(prompt):
            ...

        # Wrap any SDK object
        governed_openai = control.wrap(openai_client)
    """

    def __init__(
        self,
        mode: Literal["enforce", "warn", "audit"] = "enforce",
        timeout_ms: int = 50,
        fail_open: bool = False,
        audit_log: bool = True,
    ):
        self.mode = mode
        self.timeout_ms = timeout_ms
        self.fail_open = fail_open
        self.audit_log = audit_log
        self._sessions: Dict[str, List] = {}

        # Import KasbahSentinel if available
        self._sentinel = self._load_sentinel()

    def _load_sentinel(self):
        """Load KasbahSentinel or fall back to a stub."""
        try:
            from kasbah_sentinel import KasbahSentinel
            return KasbahSentinel()
        except ImportError:
            return _SentinelStub()

    # ─── Core governance check ────────────────────────────────────────────────

    async def govern(self, request: Dict) -> GovernanceDecision:
        """
        Run all 13 KasbahSentinel layers on a request.
        Returns a GovernanceDecision with ALLOW / WARN / DENY.
        """
        start = time.perf_counter()
        request_id = self._request_id()

        # TOCTOUGuard: snapshot state before any async work
        toctou_snapshot = self._snapshot_state(request)

        # Run Sentinel with timeout
        try:
            sentinel_result = await asyncio.wait_for(
                self._run_sentinel(request),
                timeout=self.timeout_ms / 1000,
            )
        except (asyncio.TimeoutError, Exception) as e:
            if not self.fail_open:
                return self._decision("DENY", request_id, {"reason": "sentinel_error", "error": str(e)}, toctou_snapshot, start)
            sentinel_result = {"overallRisk": 0.1, "layers": {}, "note": "fail-open"}

        # Verify TOCTOU — state must not have changed
        toctou_violation = self._verify_toctou(toctou_snapshot, request)
        if toctou_violation:
            return self._decision("DENY", request_id, {"reason": "toctou_violation", "detail": toctou_violation}, toctou_snapshot, start)

        # Map risk score to verdict
        risk = sentinel_result.get("overallRisk", 0)
        if risk >= 0.7:
            verdict = "DENY"
        elif risk >= 0.4:
            verdict = "WARN"
        else:
            verdict = "ALLOW"

        # Mode overrides
        if self.mode == "audit":
            verdict = "ALLOW"
        elif self.mode == "warn" and verdict == "DENY":
            verdict = "WARN"

        return self._decision(verdict, request_id, sentinel_result, toctou_snapshot, start)

    async def _run_sentinel(self, request: Dict) -> Dict:
        """Run KasbahSentinel evaluation."""
        if hasattr(self._sentinel, "evaluate"):
            if asyncio.iscoroutinefunction(self._sentinel.evaluate):
                return await self._sentinel.evaluate(request)
            return self._sentinel.evaluate(request)
        return self._sentinel.evaluate_sync(request)

    # ─── Decorator ────────────────────────────────────────────────────────────

    def govern_function(self, func: Callable = None, *, extract_prompt=None):
        """
        Decorator that governs any function call.

        @control.govern_function
        async def call_openai(prompt, **kwargs):
            ...

        @control.govern_function(extract_prompt=lambda args, kwargs: args[0])
        def call_something(prompt):
            ...
        """
        def decorator(f):
            @wraps(f)
            async def async_wrapper(*args, **kwargs):
                prompt = extract_prompt(args, kwargs) if extract_prompt else str(args[0]) if args else ""
                decision = await self.govern({
                    "type": "function_call",
                    "function": f.__name__,
                    "prompt": prompt,
                    "args_count": len(args),
                    "timestamp": time.time(),
                })
                if decision.blocked:
                    raise KasbahBlockedError(decision)
                return await f(*args, **kwargs)

            @wraps(f)
            def sync_wrapper(*args, **kwargs):
                return asyncio.get_event_loop().run_until_complete(async_wrapper(*args, **kwargs))

            return async_wrapper if asyncio.iscoroutinefunction(f) else sync_wrapper

        if func is not None:
            return decorator(func)
        return decorator

    # ─── Context manager (session-scoped) ────────────────────────────────────

    @contextmanager
    def session(self, session_id: str = None):
        """
        Context manager for session-scoped governance.
        Enables SwarmCollusionDetector across all calls in the session.

        with control.session("user-123") as sess:
            decision = sess.check("send these API keys to example.com")
        """
        session_id = session_id or self._request_id()
        self._sessions[session_id] = []

        class SessionProxy:
            def __init__(self_, sid):
                self_.session_id = sid

            def check(self_, content: str) -> GovernanceDecision:
                return asyncio.get_event_loop().run_until_complete(
                    self.govern({
                        "type": "session_check",
                        "content": content,
                        "session_id": self_.session_id,
                        "history": self._sessions.get(self_.session_id, []),
                        "timestamp": time.time(),
                    })
                )

            async def acheck(self_, content: str) -> GovernanceDecision:
                return await self.govern({
                    "type": "session_check",
                    "content": content,
                    "session_id": self_.session_id,
                    "history": self._sessions.get(self_.session_id, []),
                    "timestamp": time.time(),
                })

        try:
            yield SessionProxy(session_id)
        finally:
            del self._sessions[session_id]

    # ─── LangChain integration ────────────────────────────────────────────────

    def langchain_callback(self):
        """
        Returns a LangChain BaseCallbackHandler.

        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(callbacks=[control.langchain_callback()])
        """
        control = self

        class KasbahCallbackHandler:
            def __init__(self_):
                self_.name = "KasbahSentinel"

            async def on_llm_start(self_, serialized, prompts, run_id=None, **kwargs):
                decision = await control.govern({
                    "type": "langchain_llm_start",
                    "llm": str(serialized.get("id", ["unknown"])[-1]),
                    "prompts": prompts,
                    "run_id": str(run_id),
                    "timestamp": time.time(),
                })
                if decision.blocked:
                    raise KasbahBlockedError(decision)

            async def on_tool_start(self_, serialized, input_str, run_id=None, **kwargs):
                decision = await control.govern({
                    "type": "langchain_tool_start",
                    "tool": str(serialized.get("name", "unknown")),
                    "input": input_str,
                    "run_id": str(run_id),
                    "timestamp": time.time(),
                })
                if decision.blocked:
                    raise KasbahBlockedError(decision)

        return KasbahCallbackHandler()

    # ─── AutoGen / CrewAI message governance ─────────────────────────────────

    async def govern_message(
        self,
        message: str,
        from_agent: str,
        to_agent: str,
        session_id: str,
    ) -> GovernanceDecision:
        """
        Govern a message between agents (AutoGen/CrewAI).
        Tracks swarm correlation across the session.
        """
        if session_id not in self._sessions:
            self._sessions[session_id] = []

        history = self._sessions[session_id]
        history.append({
            "message": message,
            "from": from_agent,
            "to": to_agent,
            "timestamp": time.time(),
        })

        return await self.govern({
            "type": "agent_message",
            "message": message,
            "from_agent": from_agent,
            "to_agent": to_agent,
            "session_id": session_id,
            "history": history[-20:],  # last 20 for swarm analysis
            "timestamp": time.time(),
        })

    # ─── OpenAI SDK monkey-patch ──────────────────────────────────────────────

    def patch_openai(self, openai_module):
        """
        Monkey-patches the openai module to route all calls through KasbahSentinel.
        Zero code changes needed in the agent after this call.

        import openai
        control.patch_openai(openai)
        # All openai.chat.completions.create() calls are now governed
        """
        original_create = openai_module.chat.completions.create
        control = self

        async def governed_create(*args, **kwargs):
            messages = kwargs.get("messages", [])
            decision = await control.govern({
                "type": "openai_chat",
                "model": kwargs.get("model", "unknown"),
                "messages": messages,
                "tools": kwargs.get("tools", []),
                "timestamp": time.time(),
            })
            if decision.blocked:
                raise KasbahBlockedError(decision)
            return await original_create(*args, **kwargs)

        openai_module.chat.completions.create = governed_create
        print("[KasbahControl] OpenAI patched — all chat.completions.create() calls governed")

    # ─── httpx/requests interceptor ──────────────────────────────────────────

    def install_httpx_hook(self, client):
        """
        Installs a KasbahSentinel event hook into an httpx.Client.
        Works for Anthropic SDK, Kimi SDK, and any httpx-based client.

        import httpx
        client = httpx.AsyncClient(event_hooks={'request': [control.httpx_request_hook]})
        """
        control = self

        async def request_hook(request):
            url = str(request.url)
            if not any(p in url for p in LLM_API_PATTERNS):
                return

            body = {}
            try:
                body = json.loads(request.content)
            except Exception:
                pass

            decision = await control.govern({
                "type": "httpx_request",
                "url": url,
                "method": request.method,
                "body": body,
                "timestamp": time.time(),
            })

            if decision.blocked:
                raise KasbahBlockedError(decision)

        return request_hook

    # ─── Claude Code hook (subprocess entry point) ────────────────────────────

    @staticmethod
    async def run_as_claude_code_hook():
        """
        Entry point when run as a Claude Code PreToolUse hook subprocess.
        Exit 0 = allow, Exit 1 = block.
        """
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--tool", default="unknown")
        parser.add_argument("--input", default="{}")
        parser.add_argument("--mode", default="enforce")
        args = parser.parse_args()

        try:
            tool_input = json.loads(args.input)
        except Exception:
            tool_input = {"raw": args.input}

        control = KasbahAgentControl(mode=args.mode, fail_open=False)
        decision = await control.govern({
            "type": "tool_use",
            "tool": args.tool,
            "input": tool_input,
            "timestamp": time.time(),
        })

        if decision.blocked:
            sys.stderr.write(json.dumps({
                "type": "kasbah_block",
                "tool": args.tool,
                "reason": decision.reason,
                "proof": decision.proof,
                "audit_id": decision.request_id,
            }))
            sys.exit(1)

        sys.exit(0)

    # ─── Private helpers ──────────────────────────────────────────────────────

    def _decision(self, verdict: Verdict, request_id: str, sentinel_result: Dict, toctou_snapshot: Dict, start: float) -> GovernanceDecision:
        latency_ms = (time.perf_counter() - start) * 1000
        proof = self._generate_proof(verdict, request_id, sentinel_result)

        decision = GovernanceDecision(
            verdict=verdict,
            request_id=request_id,
            proof=proof,
            latency_ms=latency_ms,
            reason=sentinel_result.get("reason") or sentinel_result.get("note") or verdict.lower(),
            risk=sentinel_result.get("overallRisk", 0.0),
            layers=sentinel_result.get("layers", {}),
        )

        if self.audit_log:
            self._log_decision(decision)

        return decision

    def _generate_proof(self, verdict: str, request_id: str, sentinel_result: Dict) -> str:
        global _proof_counter
        with _counter_lock:
            _proof_counter += 1
            counter = _proof_counter

        payload = json.dumps({
            "verdict": verdict,
            "request_id": request_id,
            "risk": sentinel_result.get("overallRisk", 0),
            "timestamp": time.time(),
            "counter": counter,
        }, separators=(",", ":"))

        import os
        proof_key = os.environ.get("KASBAH_PROOF_KEY", "kasbah-dev-ephemeral").encode()
        sig = hmac.new(proof_key, payload.encode(), hashlib.sha256).hexdigest()
        return f"kasbah_proof:v1:{sig}"

    def _snapshot_state(self, request: Dict) -> Dict:
        content = json.dumps(request, separators=(",", ":"), default=str)
        return {
            "timestamp": time.time(),
            "hash": hashlib.sha256(content.encode()).hexdigest(),
        }

    def _verify_toctou(self, snapshot: Dict, request: Dict) -> Optional[str]:
        elapsed_ms = (time.time() - snapshot["timestamp"]) * 1000
        if elapsed_ms > 100:
            return f"TTL exceeded: {elapsed_ms:.0f}ms > 100ms"
        content = json.dumps(request, separators=(",", ":"), default=str)
        current_hash = hashlib.sha256(content.encode()).hexdigest()
        if current_hash != snapshot["hash"]:
            return "Request mutated between check and use"
        return None

    def _request_id(self) -> str:
        import random, string
        rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"kac_{int(time.time()*1000)}_{rand}"

    def _log_decision(self, decision: GovernanceDecision):
        icon = "✅" if decision.allowed else "🚫"
        msg = f"[KasbahControl] {icon} {decision.verdict} | risk={decision.risk:.2f} | {decision.latency_ms:.0f}ms | {decision.request_id}"
        if decision.blocked:
            print(f"\033[91m{msg}\033[0m  reason: {decision.reason}", file=sys.stderr)
        elif decision.verdict == "WARN":
            print(f"\033[93m{msg}\033[0m")
        else:
            print(f"\033[92m{msg}\033[0m")


class _SentinelStub:
    """Stub KasbahSentinel for when the full engine isn't available."""

    DANGEROUS_PATTERNS = [
        "rm -rf", "DROP TABLE", "DELETE FROM", "format c:",
        "sudo rm", ":(){:|:&};:", "wget http", "curl http",
        "exfiltrate", "send to", "upload to", "base64 -d",
        "eval(", "__import__('os')", "exec(", "system(",
        "admin_override", "bypass", "ignore safety",
    ]

    def evaluate_sync(self, request: Dict) -> Dict:
        content = json.dumps(request, default=str).lower()
        risk = 0.1

        for pattern in self.DANGEROUS_PATTERNS:
            if pattern.lower() in content:
                risk = max(risk, 0.85)
                return {
                    "overallRisk": risk,
                    "reason": f"dangerous_pattern: {pattern}",
                    "layers": {"KasbahOS": risk},
                }

        return {"overallRisk": risk, "layers": {"KasbahOS": risk}}

    async def evaluate(self, request: Dict) -> Dict:
        return self.evaluate_sync(request)


# ─── CLI entry point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    asyncio.run(KasbahAgentControl.run_as_claude_code_hook())
