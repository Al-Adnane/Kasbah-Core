"""
KasbahOS Python SDK — govern raw OpenAI and Anthropic Python SDK calls.

This client talks HTTP to the real /v1/govern endpoint served by
packages/api-server (the same endpoint the Node auto-instrument SDK
and kasbah-agent-control.js call). It does not reimplement any
detection logic itself — it is a thin HTTP client plus two SDK wrappers
that reuse the already-validated server-side governance decision.

Usage:
    from kasbah_sdk import Kasbah

    kasbah = Kasbah(api_key="kg_...", api_url="http://127.0.0.1:8788")

    result = kasbah.govern("some user prompt")
    if result["verdict"] == "DENY":
        raise RuntimeError("blocked: " + ",".join(result.get("threats", [])))

    # Or wrap a client so every call is governed automatically:
    from openai import OpenAI
    client = kasbah.wrap_openai(OpenAI())

    from anthropic import Anthropic
    client = kasbah.wrap_anthropic(Anthropic())
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

__version__ = "0.1.0"

DEFAULT_API_URL = "https://api.bekasbah.com"


class KasbahBlockedError(Exception):
    """Raised when auto_block is enabled and a call is denied."""

    def __init__(self, result: Dict[str, Any]):
        self.result = result
        threats = ", ".join(result.get("threats") or []) or "policy violation"
        super().__init__(f"[Kasbah] Request blocked: {threats}")


class Kasbah:
    """Minimal governance client for raw OpenAI / Anthropic Python SDKs."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
        passport_id: Optional[str] = None,
        auto_block: bool = False,
        timeout: float = 5.0,
        silent: bool = False,
    ):
        self.api_key = api_key or os.environ.get("KASBAH_API_KEY")
        self.api_url = (api_url or os.environ.get("KASBAH_API_URL") or DEFAULT_API_URL).rstrip("/")
        self.passport_id = passport_id or os.environ.get("KASBAH_PASSPORT_ID")
        self.auto_block = auto_block or os.environ.get("KASBAH_AUTO_BLOCK") == "true"
        self.timeout = timeout
        self.silent = silent or os.environ.get("KASBAH_SILENT") == "true"

    # ── Core HTTP call ──────────────────────────────────────────────────────

    def govern(self, prompt: str, **meta: Any) -> Dict[str, Any]:
        """
        Send `prompt` to POST {api_url}/v1/govern and return the parsed
        JSON response. Fails open (returns ALLOW) on any network error or
        timeout, matching the Node auto-instrument SDK's behavior.
        """
        body = {
            "prompt": str(prompt)[:4000],
            "passportId": self.passport_id,
            "agent": meta.pop("model", None) or "kasbah-python-sdk",
        }
        body.update(meta)

        data = json.dumps(body).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "x-kasbah-sdk": f"kasbah-sdk-python/{__version__}",
        }
        if self.api_key:
            headers["x-api-key"] = self.api_key

        req = urllib.request.Request(
            f"{self.api_url}/v1/govern", data=data, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read().decode("utf-8"))
            except Exception:
                return {"verdict": "ALLOW", "riskScore": 0, "error": str(e)}
        except Exception as e:
            if not self.silent:
                print(f"[kasbah] govern() call failed, failing open: {e}")
            return {"verdict": "ALLOW", "riskScore": 0, "error": str(e)}

    # Verdicts that mean "do not let this call proceed" when auto_block is on.
    # DENY is the obvious case; REQUIRE_APPROVAL is the live /v1/govern
    # endpoint's verdict for high-risk requests that need a human in the
    # loop before continuing — from a Python SDK caller's point of view
    # that also means "block it here," since there is no human to approve.
    _BLOCKING_VERDICTS = ("DENY", "REQUIRE_APPROVAL")

    def _enforce(self, result: Dict[str, Any]) -> None:
        if self.auto_block and result.get("verdict") in self._BLOCKING_VERDICTS:
            raise KasbahBlockedError(result)

    @staticmethod
    def _extract_user_text(messages: List[Dict[str, Any]]) -> str:
        parts = []
        for m in messages or []:
            if m.get("role") != "user":
                continue
            content = m.get("content")
            parts.append(content if isinstance(content, str) else json.dumps(content))
        return "\n".join(parts)

    # ── OpenAI wrapper ───────────────────────────────────────────────────────

    def wrap_openai(self, client: Any) -> Any:
        """
        Wrap an `openai.OpenAI` client instance so every
        `client.chat.completions.create(...)` call is governed first.
        Returns the same client object with the method patched in place.
        """
        kasbah = self
        original_create = client.chat.completions.create

        def governed_create(*args, **kwargs):
            messages = kwargs.get("messages", [])
            user_text = kasbah._extract_user_text(messages)
            if user_text:
                result = kasbah.govern(user_text, model=kwargs.get("model", "openai"))
                if not kasbah.silent:
                    print(f"[kasbah] OpenAI call governed: {result.get('verdict')} "
                          f"(risk={result.get('riskScore')})")
                kasbah._enforce(result)
            return original_create(*args, **kwargs)

        client.chat.completions.create = governed_create
        return client

    # ── Anthropic wrapper ────────────────────────────────────────────────────

    def wrap_anthropic(self, client: Any) -> Any:
        """
        Wrap an `anthropic.Anthropic` client instance so every
        `client.messages.create(...)` call is governed first.
        """
        kasbah = self
        original_create = client.messages.create

        def governed_create(*args, **kwargs):
            messages = kwargs.get("messages", [])
            user_text = kasbah._extract_user_text(messages)
            if user_text:
                result = kasbah.govern(user_text, model=kwargs.get("model", "anthropic"))
                if not kasbah.silent:
                    print(f"[kasbah] Anthropic call governed: {result.get('verdict')} "
                          f"(risk={result.get('riskScore')})")
                kasbah._enforce(result)
            return original_create(*args, **kwargs)

        client.messages.create = governed_create
        return client


__all__ = ["Kasbah", "KasbahBlockedError", "__version__"]
