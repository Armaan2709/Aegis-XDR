"""
Unit Tests for MITRE ATT&CK Mapping Engine.

Verifies schema validation, sub-techniques, deterministic signature mapping,
ATT&CK matrix coverage calculations, and knowledge base catalog seeding.
"""

import uuid
import pytest
from pydantic import ValidationError

from app.mitre.models import MitreTacticEnum
from app.mitre.schemas import (
    MitreTechniqueCreate,
    MitreTechniqueUpdate,
    MitreSubTechniqueCreate,
    MitreMappingCreate,
    ArtifactMappingRequest,
    MitreFilterParams,
)
from app.mitre.mapper import MitreMapper
from app.mitre.coverage import MitreCoverageCalculator
from app.mitre.knowledge_base import MitreKnowledgeBase


def test_mitre_technique_schema_valid_creation():
    """Verify MitreTechniqueCreate schema validation."""
    tech_in = MitreTechniqueCreate(
        technique_id="T1059",
        tactic=MitreTacticEnum.EXECUTION,
        name="Command and Scripting Interpreter",
        description="Adversaries may abuse command and script interpreters to execute commands.",
        platforms=["Windows", "Linux", "macOS"],
        detection_notes="Monitor process creation for powershell.exe and cmd.exe.",
        data_sources=["Process: Process Creation"],
    )

    assert tech_in.technique_id == "T1059"
    assert tech_in.tactic == MitreTacticEnum.EXECUTION
    assert "Windows" in tech_in.platforms


def test_mitre_subtechnique_schema():
    """Verify MitreSubTechniqueCreate schema validation."""
    sub_in = MitreSubTechniqueCreate(
        subtechnique_id="T1059.001",
        parent_technique_id="T1059",
        name="PowerShell",
        description="Adversaries may abuse PowerShell commands for execution.",
        platforms=["Windows"],
    )

    assert sub_in.subtechnique_id == "T1059.001"
    assert sub_in.parent_technique_id == "T1059"


def test_deterministic_mapper_powershell():
    """Verify deterministic signature matching for PowerShell process execution."""
    artifact = {
        "id": str(uuid.uuid4()),
        "title": "Suspicious Encoded Script",
        "process_name": "powershell.exe",
        "description": "Executed with -enc base64 payload",
    }

    matches = MitreMapper.map_artifact(artifact)
    assert len(matches) >= 1
    t1059_matches = [m for m in matches if m.technique_id == "T1059"]
    assert len(t1059_matches) == 1
    match = t1059_matches[0]
    assert match.subtechnique_id == "T1059.001"
    assert match.tactic == MitreTacticEnum.EXECUTION
    assert match.confidence_score >= 90.0


def test_deterministic_mapper_lsass_dump():
    """Verify deterministic signature matching for LSASS memory access."""
    artifact = {
        "id": str(uuid.uuid4()),
        "title": "Credential Access via Mimikatz",
        "process_name": "mimikatz.exe",
        "description": "Attempted minidump access on lsass.exe",
    }

    matches = MitreMapper.map_artifact(artifact)
    assert len(matches) >= 1
    t1003_matches = [m for m in matches if m.technique_id == "T1003"]
    assert len(t1003_matches) == 1
    match = t1003_matches[0]
    assert match.tactic == MitreTacticEnum.CREDENTIAL_ACCESS
    assert match.confidence_score == 98.0


def test_coverage_calculator():
    """Verify ATT&CK coverage report and heatmap generation."""
    mappings = [
        {"technique_id": "T1059", "tactic": "EXECUTION"},
        {"technique_id": "T1003", "tactic": "CREDENTIAL_ACCESS"},
        {"technique_id": "T1053", "tactic": "PERSISTENCE"},
    ]

    report = MitreCoverageCalculator.calculate_coverage(mappings, scope="INCIDENT")
    assert report.total_techniques_mapped == 3
    assert report.covered_tactics_count == 3
    assert report.overall_coverage_percentage > 0.0
    assert "T1059" in report.heatmap_matrix


def test_knowledge_base_defaults():
    """Verify local offline knowledge base default catalog loading."""
    tactics = MitreKnowledgeBase.get_tactics()
    techniques = MitreKnowledgeBase.get_techniques()
    subtechniques = MitreKnowledgeBase.get_subtechniques()

    assert len(tactics) == 12
    assert len(techniques) >= 5
    assert len(subtechniques) >= 3
