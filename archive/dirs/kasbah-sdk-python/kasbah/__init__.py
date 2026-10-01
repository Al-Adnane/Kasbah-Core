"""
Kasbah Guard Python SDK

Detect and block secrets, API keys, and sensitive data in your applications.

Example:
    from kasbah import KasbahClient

    client = KasbahClient(api_key="kg_live_...")
    result = client.scan("AKIAIOSFODNN7EXAMPLE")
    print(result.decision)  # DENY

Homepage: https://bekasbah.com
API:      https://api.bekasbah.com
"""

from .client import KasbahClient
from .models import (
    ScanResult,
    Decision,
    GeneratorInfo,
    CalibrationStats,
    MaqasidScores,
    EthicsEvaluation,
)

__version__ = "1.0.0"
__all__ = [
    "KasbahClient",
    "ScanResult",
    "Decision",
    "GeneratorInfo",
    "CalibrationStats",
    "MaqasidScores",
    "EthicsEvaluation",
]
