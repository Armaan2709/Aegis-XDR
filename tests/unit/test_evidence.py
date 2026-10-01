"""
Unit Tests for Evidence Domain.

Verifies schema validations, hash format constraints (SHA256, MD5, SHA1),
evidence types, custody transfer models, and query parameter filtering.
"""

import uuid
import pytest
from pydantic import ValidationError

from app.models.evidence import EvidenceType, EvidenceClassification
from app.domains.evidence.schemas import (
    EvidenceCreate,
    EvidenceUpdate,
    EvidenceCustodyTransfer,
    EvidenceFilterParams,
)


def test_evidence_schema_valid_creation():
    """Verify EvidenceCreate schema validation with valid hash and DFIR properties."""
    investigation_id = uuid.uuid4()
    incident_id = uuid.uuid4()

    valid_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    valid_md5 = "d41d8cd98f00b204e9800998ecf8427e"
    valid_sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    evidence_in = EvidenceCreate(
        investigation_id=investigation_id,
        incident_id=incident_id,
        name="LSASS Memory Dump Artifact",
        evidence_type=EvidenceType.MEMORY,
        classification=EvidenceClassification.CRITICAL_EVIDENCE,
        source="Volatility 3",
        source_hostname="WKSTN-SEC-01",
        file_name="lsass_dump.dmp",
        sha256=valid_sha256,
        md5=valid_md5,
        sha1=valid_sha1,
        process_name="lsass.exe",
        process_id=672,
    )

    assert evidence_in.investigation_id == investigation_id
    assert evidence_in.evidence_type == EvidenceType.MEMORY
    assert evidence_in.sha256 == valid_sha256
    assert evidence_in.md5 == valid_md5
    assert evidence_in.sha1 == valid_sha1
    assert evidence_in.process_id == 672


def test_evidence_schema_invalid_hash_formats():
    """Verify hash format validations (SHA256 hex length 64, MD5 hex length 32, SHA1 hex length 40)."""
    investigation_id = uuid.uuid4()
    incident_id = uuid.uuid4()

    # Invalid SHA256 length
    with pytest.raises(ValidationError):
        EvidenceCreate(
            investigation_id=investigation_id,
            incident_id=incident_id,
            name="Invalid SHA256 Test",
            evidence_type=EvidenceType.FILE,
            sha256="invalid_short_hash",
        )

    # Invalid MD5 length
    with pytest.raises(ValidationError):
        EvidenceCreate(
            investigation_id=investigation_id,
            incident_id=incident_id,
            name="Invalid MD5 Test",
            evidence_type=EvidenceType.FILE,
            md5="12345",
        )

    # Invalid SHA1 length
    with pytest.raises(ValidationError):
        EvidenceCreate(
            investigation_id=investigation_id,
            incident_id=incident_id,
            name="Invalid SHA1 Test",
            evidence_type=EvidenceType.FILE,
            sha1="not_a_valid_sha1_hash_string",
        )


def test_evidence_custody_transfer_schema():
    """Verify EvidenceCustodyTransfer schema serialization."""
    transfer = EvidenceCustodyTransfer(
        transferred_to="Lead DFIR Analyst - SOC Vault 02",
        purpose="Offline malware reverse engineering",
        notes="Transferred on encrypted NVMe drive",
    )
    assert transfer.transferred_to == "Lead DFIR Analyst - SOC Vault 02"
    assert transfer.purpose == "Offline malware reverse engineering"


def test_evidence_filter_params_defaults():
    """Verify EvidenceFilterParams default values."""
    params = EvidenceFilterParams(page=1, page_size=20)
    assert params.page == 1
    assert params.page_size == 20
    assert params.sort_by == "created_at"
    assert params.sort_order == "desc"
