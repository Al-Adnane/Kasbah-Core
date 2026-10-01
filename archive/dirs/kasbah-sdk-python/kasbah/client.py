"""Kasbah Guard Python SDK - Client"""

import os
import random
import threading
import time
import requests
from typing import Optional, List, Dict, Any
from .models import ScanResult, Decision


class _CircuitBreaker:
    """Simple circuit breaker: closed → open (after 5 failures) → half-open (after 30s)."""

    MAX_FAILURES = 5
    OPEN_DURATION = 30  # seconds

    def __init__(self):
        self._failures = 0
        self._state = "closed"  # "closed" | "open" | "half-open"
        self._opened_at: float = 0.0
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            if self._state == "open":
                if time.monotonic() - self._opened_at >= self.OPEN_DURATION:
                    self._state = "half-open"
                    return True
                return False
            return True

    def on_success(self):
        with self._lock:
            self._failures = 0
            self._state = "closed"

    def on_failure(self):
        with self._lock:
            self._failures += 1
            if self._state == "half-open" or self._failures >= self.MAX_FAILURES:
                self._state = "open"
                self._opened_at = time.monotonic()


_RETRYABLE_STATUS = {429, 502, 503, 504}


class KasbahClient:
    """
    Kasbah Guard client for secret detection and DLP.

    Example:
        client = KasbahClient(api_key="kg_live_...")
        result = client.scan("AKIAIOSFODNN7EXAMPLE")
        print(result.decision)  # DENY
    """

    DEFAULT_BASE_URL = "https://api.bekasbah.com"

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
    ):
        """
        Initialize Kasbah Guard client.

        Args:
            api_key: Your Kasbah Guard API key. Falls back to KASBAH_API_KEY env var.
            base_url: API base URL (default: https://api.bekasbah.com)
            timeout: Request timeout in seconds (default: 30)

        Raises:
            ValueError: If no API key is provided and KASBAH_API_KEY is not set.
        """
        resolved_key = api_key or os.environ.get("KASBAH_API_KEY")
        if not resolved_key:
            raise ValueError(
                "api_key is required. Pass it directly or set the KASBAH_API_KEY environment variable."
            )
        self.api_key = resolved_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "kasbah-guard-python/1.0.0",
        })
        self._cb = _CircuitBreaker()

    # ── Core scanning ──────────────────────────────────────────────────────────

    def scan(self, text: str) -> ScanResult:
        """
        Scan text for secrets and sensitive data.

        Args:
            text: Text content to scan.

        Returns:
            ScanResult with risk score, decision, and violations.

        Raises:
            Exception: On HTTP or network errors.
        """
        response = self._retry_request(
            "POST", f"{self.base_url}/api/scan", json={"text": text}
        )
        response.raise_for_status()
        data = response.json()
        return ScanResult(
            risk=data.get("risk", 0),
            decision=Decision(data.get("decision", "ALLOW")),
            reason=data.get("reason", ""),
            violations=data.get("violations", []),
        )

    def scan_file(self, file_path: str) -> ScanResult:
        """
        Scan a file for secrets and sensitive data.

        Args:
            file_path: Absolute path to the file to scan.

        Returns:
            ScanResult with risk score, decision, and violations.

        Raises:
            FileNotFoundError: If the file does not exist.
            Exception: On HTTP or network errors.
        """
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        return self.scan(content)

    def redact(self, text: str) -> str:
        """
        Redact secrets from text.

        Args:
            text: Text content to redact.

        Returns:
            Redacted text string with secrets replaced by [REDACTED::TYPE] tokens.

        Raises:
            Exception: On HTTP or network errors.
        """
        response = self._retry_request(
            "POST", f"{self.base_url}/api/scan", json={"text": text, "redact": True}
        )
        response.raise_for_status()
        data = response.json()
        return data.get("redacted", text)

    # ── Health & account ───────────────────────────────────────────────────────

    def health(self) -> Dict[str, Any]:
        """Check API health. Returns {'status': 'ok'} on success."""
        response = self._retry_request("GET", f"{self.base_url}/health")
        response.raise_for_status()
        return response.json()

    # ── Frontier Disruption Technology Methods ─────────────────────────────────

    def get_brittleness_report(self) -> Dict[str, Any]:
        """
        Get system brittleness report from the Kasbah moat system.
        Shows indicator diversity, over-relied signals, and recommendations.

        Returns:
            Brittleness report with resource scores and recommendations.

        Raises:
            Exception: On HTTP or network errors.
        """
        response = self._retry_request("GET", f"{self.base_url}/api/moats/brittleness")
        response.raise_for_status()
        return response.json()

    def get_threat_forecast(self, forecast_hours: int = 24) -> Dict[str, Any]:
        """
        Get predictive threat forecast from the Kasbah moat system.
        Returns predictions, probabilities, mitigations for the next N hours.

        Args:
            forecast_hours: Hours to forecast ahead (default 24, max 168).

        Returns:
            Threat forecast with predictions and recommended actions.

        Raises:
            Exception: On HTTP or network errors.
        """
        response = self._retry_request("GET", f"{self.base_url}/api/moats/forecast", params={"hours": forecast_hours})
        response.raise_for_status()
        return response.json()

    def get_integrity_index(self) -> Dict[str, Any]:
        """
        Get system integrity index (Ψ) from the Kasbah moat system.
        Returns composite integrity score with component breakdown.

        Returns:
            Integrity index result with component scores.

        Raises:
            Exception: On HTTP or network errors.
        """
        response = self._retry_request("GET", f"{self.base_url}/api/moats/integrity")
        response.raise_for_status()
        return response.json()

    def get_modulated_threshold(self, base_threshold: Optional[float] = None) -> Dict[str, Any]:
        """
        Get dynamically modulated detection threshold.
        Threshold adjusts based on system integrity (higher when integrity drops).

        Args:
            base_threshold: Optional base threshold override.

        Returns:
            Modulated threshold value with integrity modifier.

        Raises:
            Exception: On HTTP or network errors.
        """
        params = {}
        if base_threshold is not None:
            params["base"] = base_threshold
        response = self._retry_request("GET", f"{self.base_url}/api/moats/threshold", params=params)
        response.raise_for_status()
        return response.json()

    def record_threat_event(
        self,
        vector: str,
        severity: str = "medium",
        category: str = "evasion",
        source: str = "sdk"
    ) -> Dict[str, Any]:
        """
        Record a threat event for predictive forecasting.

        Args:
            vector: Threat type description.
            severity: Severity level (low, medium, high, critical).
            category: Threat category (evasion, injection, exfiltration, manipulation, bypass).
            source: Source of threat (default: sdk).

        Returns:
            Recorded threat event with event_id and timestamp.

        Raises:
            Exception: On HTTP or network errors.
        """
        response = self._retry_request(
            "POST", f"{self.base_url}/api/moats/threats",
            json={"vector": vector, "severity": severity, "category": category, "source": source}
        )
        response.raise_for_status()
        return response.json()

    def get_resource_optimization(self) -> Dict[str, Any]:
        """
        Get resource optimization recommendations.
        Analyzes usage patterns and suggests resource allocation changes.

        Returns:
            Resource optimization recommendations with expected improvements.

        Raises:
            Exception: On HTTP or network errors.
        """
        response = self._retry_request("GET", f"{self.base_url}/api/moats/optimize")
        response.raise_for_status()
        return response.json()

    def get_receipt(self, receipt_id: str) -> Dict[str, Any]:
        """
        Get cryptographic receipt for an execution.
        Returns the signed receipt with chain of custody.

        Args:
            receipt_id: Receipt identifier.

        Returns:
            Cryptographic receipt with signature and state.

        Raises:
            Exception: On HTTP or network errors.
        """
        response = self._retry_request("GET", f"{self.base_url}/api/moats/receipt/{receipt_id}")
        response.raise_for_status()
        return response.json()

    def export_audit_ledger(
        self,
        format: str = "json",
        start_time: Optional[int] = None,
        end_time: Optional[int] = None
    ) -> Any:
        """
        Export audit ledger for compliance.
        Returns hash-chained audit trail in specified format.

        Args:
            format: Export format (json, csv, stix).
            start_time: Start timestamp (optional).
            end_time: End timestamp (optional).

        Returns:
            Exported audit data.

        Raises:
            Exception: On HTTP or network errors.
        """
        params = {"format": format}
        if start_time is not None:
            params["start"] = start_time
        if end_time is not None:
            params["end"] = end_time
        response = self._retry_request("GET", f"{self.base_url}/api/moats/audit/export", params=params)
        response.raise_for_status()
        return response.json()

    def verify_audit_ledger(self) -> Dict[str, Any]:
        """
        Verify audit ledger integrity.
        Checks hash chain and returns verification result.

        Returns:
            Verification result with valid status and entry counts.

        Raises:
            Exception: On HTTP or network errors.
        """
        response = self._retry_request("POST", f"{self.base_url}/api/moats/audit/verify")
        response.raise_for_status()
        return response.json()

    def generate_compliance_report(
        self,
        framework: str,
        days: int = 90
    ) -> Dict[str, Any]:
        """
        Generate compliance report for a specific framework.

        Args:
            framework: Compliance framework (SOC2, HIPAA, GDPR, PCI_DSS, ISO27001).
            days: Number of days to include (default 90).

        Returns:
            Compliance report with findings and attestation hash.

        Raises:
            Exception: On HTTP or network errors.
        """
        response = self._retry_request("GET", f"{self.base_url}/api/moats/compliance/{framework}", params={"days": days})
        response.raise_for_status()
        return response.json()

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _retry_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Execute an HTTP request with exponential backoff retry and circuit breaker."""
        if not self._cb.allow():
            raise Exception("Circuit breaker open: service temporarily unavailable")

        max_retries = 3
        initial_delay = 0.2  # seconds

        last_exc: Exception = Exception("No attempts made")
        for attempt in range(max_retries + 1):
            if attempt > 0:
                delay = initial_delay * (2 ** (attempt - 1))
                jitter = random.uniform(0, 0.1)
                time.sleep(delay + jitter)

            try:
                response = self._session.request(method, url, timeout=self.timeout, **kwargs)
                status = response.status_code
                if status in _RETRYABLE_STATUS:
                    last_exc = Exception(f"API error: status {status}")
                    continue
                if 400 <= status < 500:
                    # Client error — don't retry, fail immediately
                    self._cb.on_failure()
                    response.raise_for_status()
                self._cb.on_success()
                return response
            except requests.exceptions.ConnectionError as e:
                last_exc = e
            except requests.exceptions.Timeout as e:
                last_exc = e
            except Exception as e:
                # Non-retryable exception (e.g. raise_for_status 4xx)
                raise

        self._cb.on_failure()
        raise last_exc

    def _post(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """POST to a path with a JSON body. Returns parsed JSON."""
        response = self._retry_request("POST", f"{self.base_url}{path}", json=data)
        response.raise_for_status()
        return response.json()

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """GET a path with optional query params. Returns parsed JSON."""
        response = self._retry_request("GET", f"{self.base_url}{path}", params=params)
        response.raise_for_status()
        return response.json()

    # ── Detection methods ──────────────────────────────────────────────────────

    def detect_text(self, text: str) -> dict:
        """Detect AI-generated text."""
        return self._post("/api/detect/text", {"text": text})

    def detect_deepfake(self, image_base64: str, mime: str = "image/jpeg") -> dict:
        """Detect deepfake in image."""
        return self._post("/api/detect/deepfake", {"image": image_base64, "mime": mime})

    def detect_voice(self, audio_base64: str) -> dict:
        """Detect voice cloning."""
        return self._post("/api/detect/voice", {"audio": audio_base64})

    def detect_code(self, source_code: str, language: str = "javascript") -> dict:
        """Detect AI-generated code."""
        return self._post("/api/detect/code", {"source_code": source_code, "language": language})

    def check_brittleness(self, resources: list) -> dict:
        """Check resource brittleness."""
        return self._post("/api/brittleness", {"resources": resources})

    def mint_receipt(self, tool_name: str, args: dict, risk_score: float, principal: str, session_id: str) -> dict:
        """Mint a cryptographic receipt."""
        return self._post("/api/receipts", {
            "tool_name": tool_name,
            "args": args,
            "risk_score": risk_score,
            "principal": principal,
            "session_id": session_id
        })

    def verify_receipt(self, receipt_id: str) -> dict:
        """Verify a cryptographic receipt."""
        return self._get(f"/api/receipts/{receipt_id}")

    def append_audit(self, event_type: str, subject: str, object_: str, action: str, metadata: dict = None, compliance_frameworks: list = None) -> dict:
        """Append to audit ledger."""
        payload = {"event_type": event_type, "subject": subject, "object": object_, "action": action}
        if metadata:
            payload["metadata"] = metadata
        if compliance_frameworks:
            payload["compliance_frameworks"] = compliance_frameworks
        return self._post("/api/audit/ledger", payload)

    def get_audit_ledger(self) -> dict:
        """Get audit ledger status."""
        return self._get("/api/audit/ledger")

    def analyze_ksi(self, technical_risk: float, cultural_sensitivity: float, intent_class: float, novelty: float, identity_certainty: float, sacred_content_risk: float, text: str = None, detections: list = None) -> dict:
        """Analyze with KSI (Kasbah Synthesis Intelligence)."""
        payload = {
            "technical_risk": technical_risk,
            "cultural_sensitivity": cultural_sensitivity,
            "intent_class": intent_class,
            "novelty": novelty,
            "identity_certainty": identity_certainty,
            "sacred_content_risk": sacred_content_risk
        }
        if text:
            payload["text"] = text
        if detections:
            payload["detections"] = detections
        return self._post("/api/ksi/analyze", payload)

    def get_innovations(self) -> dict:
        """Get list of all innovations and endpoints."""
        return self._get("/api/innovations")

    # ── Session management ─────────────────────────────────────────────────────

    def close(self):
        """Close the underlying HTTP session."""
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
