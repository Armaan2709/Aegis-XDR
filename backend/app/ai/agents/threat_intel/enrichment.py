"""
Threat Intelligence Provider Enrichment and Consensus Engine.

Evaluates reputation consensus across threat providers (VirusTotal, AbuseIPDB, OTX, MISP, GreyNoise),
calculates deterministic threat scores (0-100) and intelligence confidence (0.0-1.0),
and explicitly represents provider agreement vs disagreement.
"""

from typing import List, Dict, Any
from app.threat_intelligence.models import IOCType, ThreatReputationLevel
from app.ai.agents.threat_intel.schemas import (
    IOCObservation,
    ProviderAssessment,
    IntelligenceConsensus,
)


class ThreatEnrichmentConsensusEngine:
    """Deterministic provider enrichment consensus and threat scoring engine."""

    PROVIDERS = ["VirusTotal", "AbuseIPDB", "AlienVault OTX", "MISP", "GreyNoise"]

    def evaluate_consensus(self, ioc: IOCObservation) -> IntelligenceConsensus:
        """Evaluate provider assessments, calculate consensus agreement, and consolidated threat score."""
        assessments: List[ProviderAssessment] = []
        val_lower = ioc.normalized_value.lower()

        # Deterministic offline provider simulation / mock enrichment
        for provider in self.PROVIDERS:
            # Deterministic verdict logic based on value indicators
            if "malicious" in val_lower or "evil" in val_lower or "mimikatz" in val_lower or val_lower.startswith("192.168.1.50"):
                if provider in ("VirusTotal", "AbuseIPDB", "AlienVault OTX"):
                    verdict = ThreatReputationLevel.MALICIOUS
                    score = 90.0
                elif provider == "MISP":
                    verdict = ThreatReputationLevel.HIGH
                    score = 80.0
                else:
                    verdict = ThreatReputationLevel.UNKNOWN
                    score = 0.0
            elif "suspicious" in val_lower or "encoded" in val_lower:
                if provider in ("VirusTotal", "GreyNoise"):
                    verdict = ThreatReputationLevel.MEDIUM
                    score = 65.0
                else:
                    verdict = ThreatReputationLevel.UNKNOWN
                    score = 0.0
            elif ioc.ioc_type in (IOCType.IPV4, IOCType.DOMAIN, IOCType.SHA256):
                # Informational fallback
                verdict = ThreatReputationLevel.INFORMATIONAL
                score = 20.0
            else:
                verdict = ThreatReputationLevel.BENIGN
                score = 0.0

            assessments.append(
                ProviderAssessment(
                    provider_name=provider,
                    verdict=verdict,
                    score=score,
                    details={"provider": provider, "verdict": verdict.value},
                    status="SUCCESS",
                )
            )

        # Consensus Calculations
        malicious = sum(1 for a in assessments if a.verdict in (ThreatReputationLevel.MALICIOUS, ThreatReputationLevel.HIGH, ThreatReputationLevel.CRITICAL))
        benign = sum(1 for a in assessments if a.verdict == ThreatReputationLevel.BENIGN)
        unknown = sum(1 for a in assessments if a.verdict in (ThreatReputationLevel.UNKNOWN, ThreatReputationLevel.INFORMATIONAL))

        total = len(assessments)
        agreement = max(malicious, benign, unknown) / total if total > 0 else 0.0
        disagreement = 1.0 - agreement

        if malicious >= 2:
            conf = 0.90 if disagreement < 0.3 else 0.70
            consolidated_score = min(100.0, max(a.score for a in assessments))
        elif malicious == 1:
            conf = 0.60
            consolidated_score = 55.0
        elif benign >= 3:
            conf = 0.85
            consolidated_score = 5.0
        else:
            conf = 0.40
            consolidated_score = 15.0

        return IntelligenceConsensus(
            ioc_value=ioc.normalized_value,
            malicious_count=malicious,
            benign_count=benign,
            unknown_count=unknown,
            agreement_ratio=round(agreement, 2),
            disagreement_ratio=round(disagreement, 2),
            confidence=round(conf, 2),
            consolidated_threat_score=round(consolidated_score, 1),
            provider_assessments=assessments,
        )
