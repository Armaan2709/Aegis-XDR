"""
Threat Hunter Hypothesis Engine.

Formulates and evaluates threat hypotheses deterministically based on security observables,
MITRE ATT&CK techniques, and evidence quality.
Enforces evidence validation before marking hypotheses as SUPPORTED.
"""

from typing import List, Dict, Any
from app.ai.agents.threat_hunter.schemas import ObservableItem, ObservableType, ThreatHypothesis, HypothesisStatus
from app.ai.orchestrator.state import InvestigationState


class HypothesisEngine:
    """Deterministic hypothesis generation and evaluation engine."""

    def generate_hypotheses(
        self, observables: List[ObservableItem], state: InvestigationState
    ) -> List[ThreatHypothesis]:
        """Generate candidate threat hypotheses based on extracted observables and state context."""
        hypotheses: List[ThreatHypothesis] = []

        obs_values = [o.value.lower() for o in observables]
        obs_by_type = {o: [item for item in observables if item.type == o] for o in ObservableType}


        # 1. PowerShell Execution Hypothesis
        ps_obs = [o for o in observables if "powershell" in o.value.lower() or "-enc" in o.value.lower() or "invoke" in o.value.lower()]
        if ps_obs:
            evidence_items = [{"observable": o.value, "source": o.source} for o in ps_obs]
            has_encoded = any("-enc" in o.value.lower() or "downloadstring" in o.value.lower() for o in ps_obs)
            status = HypothesisStatus.SUPPORTED if has_encoded else HypothesisStatus.INVESTIGATING
            
            hypotheses.append(
                ThreatHypothesis(
                    title="Obfuscated PowerShell Script Execution",
                    description="Adversaries may use obfuscated PowerShell commands to execute malicious payloads and bypass security controls.",
                    evidence=evidence_items,
                    supporting_indicators=[o.value for o in ps_obs],
                    mitre_techniques=["T1059.001"],
                    confidence=0.85 if has_encoded else 0.5,
                    risk_score=75.0 if has_encoded else 40.0,
                    status=status,
                )
            )

        # 2. Credential Theft Hypothesis
        lsass_obs = [o for o in observables if "lsass" in o.value.lower() or "mimikatz" in o.value.lower() or "dmp" in o.value.lower()]
        if lsass_obs:
            evidence_items = [{"observable": o.value, "source": o.source} for o in lsass_obs]
            hypotheses.append(
                ThreatHypothesis(
                    title="LSASS Memory Dumping / Credential Theft",
                    description="Adversaries may attempt to dump memory from lsass.exe to extract cleartext credentials or NTLM hashes.",
                    evidence=evidence_items,
                    supporting_indicators=[o.value for o in lsass_obs],
                    mitre_techniques=["T1003.001"],
                    confidence=0.9,
                    risk_score=90.0,
                    status=HypothesisStatus.SUPPORTED,
                )
            )

        # 3. Persistence Hypothesis
        persist_obs = [o for o in observables if "schtasks" in o.value.lower() or "reg.exe" in o.value.lower() or "run" in o.value.lower()]
        if persist_obs:
            evidence_items = [{"observable": o.value, "source": o.source} for o in persist_obs]
            hypotheses.append(
                ThreatHypothesis(
                    title="Persistence via Scheduled Tasks or Registry Run Keys",
                    description="Adversaries may configure persistence via scheduled tasks or registry autorun locations.",
                    evidence=evidence_items,
                    supporting_indicators=[o.value for o in persist_obs],
                    mitre_techniques=["T1053.005", "T1547.001"],
                    confidence=0.75,
                    risk_score=65.0,
                    status=HypothesisStatus.INVESTIGATING,
                )
            )

        # 4. Command and Control (C2) Hypothesis
        c2_ips = [o for o in observables if o.type == ObservableType.IP_ADDRESS and o.value not in ("127.0.0.1", "10.0.0.1")]
        if c2_ips or state.threat_intelligence:
            evidence_items = [{"observable": o.value, "source": o.source} for o in c2_ips]
            ti_matches = [ti.get("ioc_value") for ti in state.threat_intelligence if ti.get("ioc_value")]
            has_ti_match = bool(ti_matches)
            status = HypothesisStatus.SUPPORTED if has_ti_match else HypothesisStatus.INCONCLUSIVE

            hypotheses.append(
                ThreatHypothesis(
                    title="Command and Control (C2) Channel Established",
                    description="Host may be communicating with known malicious C2 infrastructure.",
                    evidence=evidence_items,
                    supporting_indicators=[o.value for o in c2_ips] + ti_matches,
                    mitre_techniques=["T1071.001"],
                    confidence=0.88 if has_ti_match else 0.40,
                    risk_score=85.0 if has_ti_match else 30.0,
                    status=status,
                )
            )

        # 5. Default Baseline Hypothesis if no specific patterns triggered
        if not hypotheses:
            hypotheses.append(
                ThreatHypothesis(
                    title="Suspicious Activity Baseline Review",
                    description="Evaluating general security telemetry for subtle attacker indicators.",
                    evidence=[],
                    supporting_indicators=[],
                    mitre_techniques=["T1078"],
                    confidence=0.3,
                    risk_score=25.0,
                    status=HypothesisStatus.INCONCLUSIVE,
                )
            )

        return hypotheses
