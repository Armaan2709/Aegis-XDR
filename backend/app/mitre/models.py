"""
MITRE ATT&CK Domain SQLAlchemy Entities.

Models Tactics, Techniques, Sub-Techniques, Artifact Mapping Junctions,
and Environment/Incident MITRE ATT&CK coverage statistics.
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, Integer, Float, Enum, JSON, ForeignKey, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class MitreTacticEnum(str, enum.Enum):
    """The 14 core MITRE ATT&CK tactics categories."""
    RECONNAISSANCE = "RECONNAISSANCE"
    RESOURCE_DEVELOPMENT = "RESOURCE_DEVELOPMENT"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COLLECTION = "COLLECTION"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    EXFILTRATION = "EXFILTRATION"
    IMPACT = "IMPACT"


class MitreTactic(Base):
    """MITRE ATT&CK Tactic Category Model (e.g. TA0002 Execution)."""

    __tablename__ = "mitre_tactics"

    tactic_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class MitreTechnique(Base):
    """MITRE ATT&CK Technique Model (e.g. T1059 Command and Scripting Interpreter)."""

    __tablename__ = "mitre_techniques"

    technique_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    tactic: Mapped[MitreTacticEnum] = mapped_column(
        Enum(MitreTacticEnum, native_enum=False),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    platforms: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    detection_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    data_sources: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    mitigation_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class MitreSubTechnique(Base):
    """MITRE ATT&CK Sub-Technique Model (e.g. T1059.001 PowerShell)."""

    __tablename__ = "mitre_subtechniques"

    subtechnique_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    parent_technique_id: Mapped[str] = mapped_column(String(50), ForeignKey("mitre_techniques.technique_id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    platforms: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    detection_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class IncidentTechnique(Base):
    """Junction entity mapping an Incident to a MITRE Technique."""

    __tablename__ = "incident_techniques"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    technique_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    tactic: Mapped[MitreTacticEnum] = mapped_column(
        Enum(MitreTacticEnum, native_enum=False),
        nullable=False,
    )
    confidence_score: Mapped[float] = mapped_column(Float, default=100.0, nullable=False)


class EvidenceTechnique(Base):
    """Junction entity mapping Evidence artifact to a MITRE Technique."""

    __tablename__ = "evidence_techniques"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    technique_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    tactic: Mapped[MitreTacticEnum] = mapped_column(
        Enum(MitreTacticEnum, native_enum=False),
        nullable=False,
    )
    confidence_score: Mapped[float] = mapped_column(Float, default=100.0, nullable=False)


class TimelineTechnique(Base):
    """Junction entity mapping Timeline event to a MITRE Technique."""

    __tablename__ = "timeline_techniques"

    timeline_event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("timeline_events.id", ondelete="CASCADE"), nullable=False, index=True
    )
    technique_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    tactic: Mapped[MitreTacticEnum] = mapped_column(
        Enum(MitreTacticEnum, native_enum=False),
        nullable=False,
    )
    confidence_score: Mapped[float] = mapped_column(Float, default=100.0, nullable=False)


class MitreMapping(Base):
    """Unified security artifact MITRE ATT&CK mapping record."""

    __tablename__ = "mitre_mappings"

    artifact_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # INCIDENT, EVIDENCE, TIMELINE, ALERT
    artifact_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    technique_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    subtechnique_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    tactic: Mapped[MitreTacticEnum] = mapped_column(
        Enum(MitreTacticEnum, native_enum=False),
        nullable=False,
        index=True,
    )
    confidence_score: Mapped[float] = mapped_column(Float, default=100.0, nullable=False)
    
    evidence_references: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    timeline_references: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    incident_references: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)

    metadata_info: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)


class MitreCoverage(Base):
    """Aggregated MITRE ATT&CK matrix coverage metrics snapshot."""

    __tablename__ = "mitre_coverage_snapshots"

    scope: Mapped[str] = mapped_column(String(50), default="ENVIRONMENT", nullable=False, index=True)  # ENVIRONMENT, INCIDENT, INVESTIGATION
    target_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    total_techniques_mapped: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tactics_coverage: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    heatmap_matrix: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
