"""
Threat Intelligence Enrichment Engine.

Orchestrates multi-provider IOC enrichment, cache management,
and consolidated threat reputation score aggregation.
"""

from typing import List, Dict, Any, Optional, Set
from pydantic import BaseModel, Field

from app.threat_intelligence.models import IOCType, ThreatReputationLevel
from app.threat_intelligence.providers import (
    BaseThreatProvider,
    ProviderEnrichmentResult,
    DEFAULT_THREAT_PROVIDERS,
)
from app.threat_intelligence.cache import default_threat_cache, ThreatIntelCache


class EnrichmentSummary(BaseModel):
    """Aggregated multi-provider threat intelligence enrichment summary."""

    ioc_value: str
    ioc_type: IOCType
    consolidated_threat_score: float = Field(..., ge=0.0, le=100.0)
    reputation_level: ThreatReputationLevel
    provider_results: List[ProviderEnrichmentResult] = Field(default_factory=list)
    aggregated_tags: List[str] = Field(default_factory=list)
    aggregated_categories: List[str] = Field(default_factory=list)


class ThreatEnrichmentEngine:
    """Orchestrator for IOC threat intelligence enrichment."""

    def __init__(
        self,
        providers: Optional[List[BaseThreatProvider]] = None,
        cache: Optional[ThreatIntelCache] = None,
    ):
        self.providers = providers or DEFAULT_THREAT_PROVIDERS
        self.cache = cache or default_threat_cache

    @staticmethod
    def map_score_to_reputation_level(score: float) -> ThreatReputationLevel:
        """Map numerical threat score (0-100) to reputation level."""
        if score >= 85.0:
            return ThreatReputationLevel.MALICIOUS
        elif score >= 70.0:
            return ThreatReputationLevel.CRITICAL
        elif score >= 50.0:
            return ThreatReputationLevel.HIGH
        elif score >= 30.0:
            return ThreatReputationLevel.MEDIUM
        elif score >= 15.0:
            return ThreatReputationLevel.LOW
        elif score > 0.0:
            return ThreatReputationLevel.INFORMATIONAL
        else:
            return ThreatReputationLevel.BENIGN

    async def enrich_ioc(self, ioc_type: IOCType, value: str) -> EnrichmentSummary:
        """
        Enrich an IOC across providers with cache check and score aggregation.
        """
        cache_key = f"ti:enrich:{ioc_type.value}:{value}"
        cached = self.cache.get(cache_key)
        if cached:
            return EnrichmentSummary.model_validate(cached)

        provider_results: List[ProviderEnrichmentResult] = []
        scores: List[float] = []
        tags: Set[str] = set()
        categories: Set[str] = set()

        for provider in self.providers:
            res = await provider.enrich(ioc_type, value)
            provider_results.append(res)
            scores.append(res.reputation_score)
            tags.update(res.tags)
            categories.update(res.categories)

        overall_score = max(scores) if scores else 0.0
        overall_level = self.map_score_to_reputation_level(overall_score)

        summary = EnrichmentSummary(
            ioc_value=value,
            ioc_type=ioc_type,
            consolidated_threat_score=round(overall_score, 1),
            reputation_level=overall_level,
            provider_results=provider_results,
            aggregated_tags=sorted(list(tags)),
            aggregated_categories=sorted(list(categories)),
        )

        self.cache.set(cache_key, summary.model_dump(), ttl_seconds=3600)
        return summary
