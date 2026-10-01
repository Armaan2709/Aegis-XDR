"""
AbuseIPDB IP Reputation Connector Placeholder.
"""

from typing import Any, Dict
from app.integrations.base import BaseIntegration


class AbuseIPDBIntegration(BaseIntegration):
    """AbuseIPDB integration connector stub."""

    def __init__(self, api_key: str = ""):
        super().__init__(name="AbuseIPDB", api_key=api_key)

    async def query_ioc(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """Query AbuseIPDB for IP confidence score."""
        return {
            "integration": self.name,
            "ioc": ioc,
            "ioc_type": ioc_type,
            "status": "placeholder",
            "abuse_confidence_score": 0,
        }

    async def health_check(self) -> bool:
        """Verify connection to AbuseIPDB API."""
        return True
