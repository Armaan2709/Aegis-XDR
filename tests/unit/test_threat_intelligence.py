"""
Unit Tests for Enterprise Threat Intelligence Engine.

Verifies IOC validation, auto-type detection, normalization, provider enrichment,
caching abstractions, and threat reputation scoring.
"""

import pytest
from pydantic import ValidationError

from app.threat_intelligence.models import IOCType, ThreatReputationLevel
from app.threat_intelligence.ioc import IOCValidator
from app.threat_intelligence.providers import (
    MockVirusTotalProvider,
    MockAbuseIPDBProvider,
    DEFAULT_THREAT_PROVIDERS,
)
from app.threat_intelligence.enrichment import ThreatEnrichmentEngine
from app.threat_intelligence.cache import InMemoryThreatCache
from app.threat_intelligence.schemas import IOCCreate, ThreatFeedCreate


def test_ioc_validator_ipv4_detection():
    """Verify IPv4 validation and normalization."""
    raw_ip = " 192.168.1.100 "
    detected_type, normalized = IOCValidator.detect_and_normalize(raw_ip)
    assert detected_type == IOCType.IPV4
    assert normalized == "192.168.1.100"


def test_ioc_validator_sha256_detection():
    """Verify SHA256 validation and normalization."""
    hash_val = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    detected_type, normalized = IOCValidator.detect_and_normalize(hash_val)
    assert detected_type == IOCType.SHA256
    assert normalized == hash_val.lower()


def test_ioc_validator_registry_detection():
    """Verify Registry Key validation and normalization."""
    reg_val = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    detected_type, normalized = IOCValidator.detect_and_normalize(reg_val)
    assert detected_type == IOCType.REGISTRY_KEY
    assert normalized == reg_val


@pytest.mark.anyio
async def test_mock_virustotal_enrichment():
    """Verify mock VirusTotal provider returns enrichment payload."""
    provider = MockVirusTotalProvider()
    res = await provider.enrich(IOCType.FILENAME, "malware_sample.exe")
    assert res.provider_name == "VirusTotal"
    assert res.reputation_level == ThreatReputationLevel.MALICIOUS
    assert res.reputation_score >= 80.0


@pytest.mark.anyio
async def test_threat_enrichment_engine():
    """Verify multi-provider threat enrichment aggregation engine."""
    cache = InMemoryThreatCache()
    engine = ThreatEnrichmentEngine(cache=cache)

    summary = await engine.enrich_ioc(IOCType.DOMAIN, "malicious-phishing-site.com")
    assert summary.ioc_value == "malicious-phishing-site.com"
    assert len(summary.provider_results) == len(DEFAULT_THREAT_PROVIDERS)
    assert summary.consolidated_threat_score >= 0.0


def test_in_memory_cache_ttl():
    """Verify InMemoryThreatCache set, get, and clear."""
    cache = InMemoryThreatCache()
    cache.set("test_key", {"status": "ok"}, ttl_seconds=60)

    val = cache.get("test_key")
    assert val == {"status": "ok"}

    cache.clear()
    assert cache.get("test_key") is None


def test_ioc_create_schema_validation():
    """Verify IOCCreate Pydantic v2 schema."""
    dto = IOCCreate(
        value="10.0.0.1",
        reputation=ThreatReputationLevel.HIGH,
        threat_score=85.0,
        tags=["botnet", "command-and-control"],
    )
    assert dto.value == "10.0.0.1"
    assert dto.reputation == ThreatReputationLevel.HIGH
    assert dto.threat_score == 85.0
