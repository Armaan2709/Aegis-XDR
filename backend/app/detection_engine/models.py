"""
Detection Rule Engine SQLAlchemy Entities.

Models Detection Rules, Versions, Categories, Tags, Executions,
Validation Records, Statistics, and Rule Templates.
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, Integer, Float, Enum, JSON, ForeignKey, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class RuleType(str, enum.Enum):
    """Supported detection rule formats."""
    SIGMA = "SIGMA"
    YARA = "YARA"
    SURICATA = "SURICATA"
    CUSTOM = "CUSTOM"


class RuleStatus(str, enum.Enum):
    """Lifecycle status of a detection rule."""
    DRAFT = "DRAFT"
    TESTING = "TESTING"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    ARCHIVED = "ARCHIVED"


class RuleSeverity(str, enum.Enum):
    """Rule alert severity levels."""
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RuleCategory(Base):
    """Rule classification category (e.g. Malware, Exploitation, Reconnaissance)."""

    __tablename__ = "detection_rule_categories"

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class RuleTag(Base):
    """Tag associated with detection rules."""

    __tablename__ = "detection_rule_tags"

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)


class DetectionRule(Base):
    """Detection Rule main entity."""

    __tablename__ = "detection_rules"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    rule_type: Mapped[RuleType] = mapped_column(Enum(RuleType, native_enum=False), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(100), nullable=False, default="GENERAL", index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[RuleSeverity] = mapped_column(Enum(RuleSeverity, native_enum=False), default=RuleSeverity.MEDIUM, nullable=False, index=True)
    status: Mapped[RuleStatus] = mapped_column(Enum(RuleStatus, native_enum=False), default=RuleStatus.DRAFT, nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    author: Mapped[str] = mapped_column(String(100), default="SOC Analyst", nullable=False)
    source: Mapped[str] = mapped_column(String(100), default="INTERNAL", nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    validation_status: Mapped[str] = mapped_column(String(50), default="VALID", nullable=False)
    execution_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    match_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_triggered: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    tags: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    metadata_info: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class RuleVersion(Base):
    """Rule version history record for rollbacks and audits."""

    __tablename__ = "detection_rule_versions"

    rule_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    change_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(100), default="System", nullable=False)


class RuleExecution(Base):
    """Historical record of rule dry-run execution or test run."""

    __tablename__ = "detection_rule_executions"

    rule_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    execution_type: Mapped[str] = mapped_column(String(50), default="DRY_RUN", nullable=False)
    matched: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    execution_time_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    matches_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    details: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class RuleStatistics(Base):
    """Aggregated performance metrics for a detection rule."""

    __tablename__ = "detection_rule_statistics"

    rule_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    total_executions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_matches: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    avg_execution_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    false_positive_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)


class RuleValidation(Base):
    """Rule syntax & metadata validation record."""

    __tablename__ = "detection_rule_validations"

    rule_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    is_valid: Mapped[bool] = mapped_column(Boolean, nullable=False)
    errors: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    warnings: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)


class RuleTemplate(Base):
    """Reusable template for rule creation (Sigma, YARA, Suricata)."""

    __tablename__ = "detection_rule_templates"

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    rule_type: Mapped[RuleType] = mapped_column(Enum(RuleType, native_enum=False), nullable=False)
    template_content: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
