"""
Threat Intelligence Provider Interface & Mock Providers.

Defines standard provider abstraction interface and mock providers for VirusTotal,
AbuseIPDB, AlienVault OTX, MISP, URLHaus, OpenPhish, GreyNoise, Shodan, and CrowdSec.
No live external API calls are performed.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
from pydantic import BaseModel, Field
from app.threat_intelligence.models import IOCType, ThreatReputationLevel


class ProviderEnrichmentResult(BaseModel):
    """Normalized payload returned by a threat intelligence provider."""

    provider_name: str
    ioc_value: str
    reputation_score: float = Field(..., ge=0.0, le=100.0)
    reputation_level: ThreatReputationLevel
    categories: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    raw_details: Dict[str, Any] = Field(default_factory=dict)


class BaseThreatProvider(ABC):
    """Abstract interface for external/offline threat intelligence feeds."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the threat intelligence provider."""
        pass

    @abstractmethod
    async def enrich(self, ioc_type: IOCType, value: str) -> ProviderEnrichmentResult:
        """Enrich IOC value with provider reputation metrics."""
        pass


class MockVirusTotalProvider(BaseThreatProvider):
    """Mock VirusTotal Provider."""

    @property
    def provider_name(self) -> str:
        return "VirusTotal"

    async def enrich(self, ioc_type: IOCType, value: str) -> ProviderEnrichmentResult:
        is_malicious = "malware" in value.lower() or "bad" in value.lower() or value.startswith("192.168.99")
        score = 88.0 if is_malicious else 12.0
        level = ThreatReputationLevel.MALICIOUS if is_malicious else ThreatReputationLevel.BENIGN
        return ProviderEnrichmentResult(
            provider_name=self.provider_name,
            ioc_value=value,
            reputation_score=score,
            reputation_level=level,
            categories=["trojan", "stealer"] if is_malicious else ["clean"],
            tags=["vt-detected"] if is_malicious else ["vt-clean"],
            raw_details={"positives": 42 if is_malicious else 0, "total": 70},
        )


class MockAbuseIPDBProvider(BaseThreatProvider):
    """Mock AbuseIPDB Provider."""

    @property
    def provider_name(self) -> str:
        return "AbuseIPDB"

    async def enrich(self, ioc_type: IOCType, value: str) -> ProviderEnrichmentResult:
        is_bad = ioc_type in (IOCType.IPV4, IOCType.IPV6) and (value.startswith("10.99") or "evil" in value)
        score = 95.0 if is_bad else 5.0
        level = ThreatReputationLevel.HIGH if is_bad else ThreatReputationLevel.LOW
        return ProviderEnrichmentResult(
            provider_name=self.provider_name,
            ioc_value=value,
            reputation_score=score,
            reputation_level=level,
            categories=["ssh-bruteforce"] if is_bad else [],
            tags=["abuseipdb-reported"] if is_bad else [],
            raw_details={"abuse_confidence_score": score},
        )


class MockAlienVaultOTXProvider(BaseThreatProvider):
    """Mock AlienVault OTX Provider."""

    @property
    def provider_name(self) -> str:
        return "AlienVault OTX"

    async def enrich(self, ioc_type: IOCType, value: str) -> ProviderEnrichmentResult:
        return ProviderEnrichmentResult(
            provider_name=self.provider_name,
            ioc_value=value,
            reputation_score=50.0,
            reputation_level=ThreatReputationLevel.INFORMATIONAL,
            tags=["otx-pulse"],
            raw_details={"pulse_count": 2},
        )


class MockMISPProvider(BaseThreatProvider):
    """Mock MISP Provider."""

    @property
    def provider_name(self) -> str:
        return "MISP"

    async def enrich(self, ioc_type: IOCType, value: str) -> ProviderEnrichmentResult:
        return ProviderEnrichmentResult(
            provider_name=self.provider_name,
            ioc_value=value,
            reputation_score=40.0,
            reputation_level=ThreatReputationLevel.MEDIUM,
            tags=["misp-attribute"],
            raw_details={"event_id": 1024},
        )


class MockURLHausProvider(BaseThreatProvider):
    """Mock URLHaus Provider."""

    @property
    def provider_name(self) -> str:
        return "URLHaus"

    async def enrich(self, ioc_type: IOCType, value: str) -> ProviderEnrichmentResult:
        return ProviderEnrichmentResult(
            provider_name=self.provider_name,
            ioc_value=value,
            reputation_score=20.0,
            reputation_level=ThreatReputationLevel.LOW,
            raw_details={"status": "online"},
        )


class MockOpenPhishProvider(BaseThreatProvider):
    """Mock OpenPhish Provider."""

    @property
    def provider_name(self) -> str:
        return "OpenPhish"

    async def enrich(self, ioc_type: IOCType, value: str) -> ProviderEnrichmentResult:
        return ProviderEnrichmentResult(
            provider_name=self.provider_name,
            ioc_value=value,
            reputation_score=15.0,
            reputation_level=ThreatReputationLevel.LOW,
            raw_details={"phish_detected": False},
        )


class MockGreyNoiseProvider(BaseThreatProvider):
    """Mock GreyNoise Provider."""

    @property
    def provider_name(self) -> str:
        return "GreyNoise"

    async def enrich(self, ioc_type: IOCType, value: str) -> ProviderEnrichmentResult:
        return ProviderEnrichmentResult(
            provider_name=self.provider_name,
            ioc_value=value,
            reputation_score=30.0,
            reputation_level=ThreatReputationLevel.INFORMATIONAL,
            tags=["greynoise-noise"],
            raw_details={"classification": "benign"},
        )


class MockShodanProvider(BaseThreatProvider):
    """Mock Shodan Provider."""

    @property
    def provider_name(self) -> str:
        return "Shodan"

    async def enrich(self, ioc_type: IOCType, value: str) -> ProviderEnrichmentResult:
        return ProviderEnrichmentResult(
            provider_name=self.provider_name,
            ioc_value=value,
            reputation_score=25.0,
            reputation_level=ThreatReputationLevel.INFORMATIONAL,
            raw_details={"open_ports": [80, 443, 22]},
        )


class MockCrowdSecProvider(BaseThreatProvider):
    """Mock CrowdSec Provider."""

    @property
    def provider_name(self) -> str:
        return "CrowdSec"

    async def enrich(self, ioc_type: IOCType, value: str) -> ProviderEnrichmentResult:
        return ProviderEnrichmentResult(
            provider_name=self.provider_name,
            ioc_value=value,
            reputation_score=35.0,
            reputation_level=ThreatReputationLevel.INFORMATIONAL,
            raw_details={"behavior": "http-probing"},
        )


# Default provider registry
DEFAULT_THREAT_PROVIDERS: List[BaseThreatProvider] = [
    MockVirusTotalProvider(),
    MockAbuseIPDBProvider(),
    MockAlienVaultOTXProvider(),
    MockMISPProvider(),
    MockURLHausProvider(),
    MockOpenPhishProvider(),
    MockGreyNoiseProvider(),
    MockShodanProvider(),
    MockCrowdSecProvider(),
]
