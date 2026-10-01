"""
SQLAlchemy Entity Models Registry for AegisAI XDR.
"""

from app.models.base import Base
from app.models.user import User
from app.models.audit import AuditLog
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.incident import (
    Incident,
    IncidentSeverity,
    IncidentPriority,
    IncidentStatus,
    IncidentCategory,
    ContainmentStatus,
    RecoveryStatus,
)
from app.models.investigation import (
    Investigation,
    InvestigationStatus,
    InvestigationPriority,
    InvestigationPhase,
)
from app.models.evidence import (
    Evidence,
    EvidenceType,
    EvidenceClassification,
)
from app.models.timeline import (
    TimelineEvent,
    TimelineEventType,
    TimelineEventCategory,
    TimelineEventSeverity,
)
from app.case_management.models import (
    Case,
    CaseComment,
    CaseAttachment,
    CaseTask,
    CaseApproval,
    CaseActivity,
    CaseAssignment,
)
from app.playbooks.models import (
    Playbook,
    PlaybookStep,
    PlaybookExecution,
    PlaybookStepExecution,
)
from app.detection_engine.models import (
    RuleCategory,
    RuleTag,
    DetectionRule,
    RuleVersion,
    RuleExecution,
    RuleStatistics,
    RuleValidation,
    RuleTemplate,
)
from app.threat_intelligence.models import (
    ThreatCategory,
    ThreatTag,
    ThreatSource,
    ThreatFeed,
    IOC,
    ThreatIndicator,
    ThreatReputation,
    ThreatEnrichment,
    IOCRelationship,
    IndicatorReference,
)
from app.mitre.models import (
    MitreTactic,
    MitreTechnique,
    MitreSubTechnique,
    IncidentTechnique,
    EvidenceTechnique,
    TimelineTechnique,
    MitreMapping,
    MitreCoverage,
)

__all__ = [
    "Base",
    "User",
    "AuditLog",
    "Alert",
    "AlertSeverity",
    "AlertStatus",
    "Incident",
    "IncidentSeverity",
    "IncidentPriority",
    "IncidentStatus",
    "IncidentCategory",
    "ContainmentStatus",
    "RecoveryStatus",
    "Investigation",
    "InvestigationStatus",
    "InvestigationPriority",
    "InvestigationPhase",
    "Evidence",
    "EvidenceType",
    "EvidenceClassification",
    "TimelineEvent",
    "TimelineEventType",
    "TimelineEventCategory",
    "TimelineEventSeverity",
    "Case",
    "CaseComment",
    "CaseAttachment",
    "CaseTask",
    "CaseApproval",
    "CaseActivity",
    "CaseAssignment",
    "Playbook",
    "PlaybookStep",
    "PlaybookExecution",
    "PlaybookStepExecution",
    "RuleCategory",
    "RuleTag",
    "DetectionRule",
    "RuleVersion",
    "RuleExecution",
    "RuleStatistics",
    "RuleValidation",
    "RuleTemplate",
    "ThreatCategory",
    "ThreatTag",
    "ThreatSource",
    "ThreatFeed",
    "IOC",
    "ThreatIndicator",
    "ThreatReputation",
    "ThreatEnrichment",
    "IOCRelationship",
    "IndicatorReference",
    "MitreTactic",
    "MitreTechnique",
    "MitreSubTechnique",
    "IncidentTechnique",
    "EvidenceTechnique",
    "TimelineTechnique",
    "MitreMapping",
    "MitreCoverage",
]







