"""
MITRE ATT&CK Mapping Engine Package.

Provides deterministic mapping of Security Alerts, Incidents, Evidence artifacts,
and Timeline Events to MITRE Tactics, Techniques, and Sub-Techniques, along with
matrix coverage calculation and a local offline knowledge base layer.
"""

from app.mitre.models import (
    MitreTacticEnum,
    MitreTactic,
    MitreTechnique,
    MitreSubTechnique,
    IncidentTechnique,
    EvidenceTechnique,
    TimelineTechnique,
    MitreMapping,
    MitreCoverage,
)
from app.mitre.schemas import (
    MitreTechniqueCreate,
    MitreTechniqueUpdate,
    MitreTechniqueRead,
    MitreSubTechniqueCreate,
    MitreSubTechniqueRead,
    MitreMappingCreate,
    MitreMappingRead,
    MitreFilterParams,
    ArtifactMappingRequest,
)
from app.mitre.mapper import MitreMapper, MitreMappingMatch
from app.mitre.coverage import MitreCoverageCalculator, MitreCoverageReport
from app.mitre.knowledge_base import MitreKnowledgeBase
from app.mitre.repositories import MitreRepository
from app.mitre.services import MitreService

__all__ = [
    "MitreTacticEnum",
    "MitreTactic",
    "MitreTechnique",
    "MitreSubTechnique",
    "IncidentTechnique",
    "EvidenceTechnique",
    "TimelineTechnique",
    "MitreMapping",
    "MitreCoverage",
    "MitreTechniqueCreate",
    "MitreTechniqueUpdate",
    "MitreTechniqueRead",
    "MitreSubTechniqueCreate",
    "MitreSubTechniqueRead",
    "MitreMappingCreate",
    "MitreMappingRead",
    "MitreFilterParams",
    "ArtifactMappingRequest",
    "MitreMapper",
    "MitreMappingMatch",
    "MitreCoverageCalculator",
    "MitreCoverageReport",
    "MitreKnowledgeBase",
    "MitreRepository",
    "MitreService",
]

