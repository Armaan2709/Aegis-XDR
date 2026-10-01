"""
Unit Tests for Enterprise Detection Rule Engine.

Verifies Sigma, YARA, Suricata & Custom parsers, deterministic validation,
version diff comparisons, dry-run rule testing, and schemas.
"""

import pytest

from app.detection_engine.models import RuleType, RuleSeverity, RuleStatus
from app.detection_engine.rule_parser import RuleParser
from app.detection_engine.rule_validator import RuleValidator
from app.detection_engine.rule_tester import RuleTester, RuleTestRequest
from app.detection_engine.rule_versions import RuleVersionManager
from app.detection_engine.schemas import DetectionRuleCreate


SIGMA_SAMPLE = """title: Suspicious Process Execution
id: 12345678-1234-1234-1234-123456789abc
description: Detects powershell.exe with -enc argument
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'powershell.exe'
        CommandLine: '-enc'
    condition: selection
level: high
tags:
    - attack.execution"""

YARA_SAMPLE = """rule Detect_Malicious_Strings {
    strings:
        $s1 = "malicious_payload"
    condition:
        $s1
}"""

SURICATA_SAMPLE = 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Suspicious User-Agent"; content:"Meterpreter"; sid:2000001; rev:1;)'


def test_rule_parser_sigma():
    """Verify parsing of Sigma YAML rule."""
    parsed = RuleParser.parse(SIGMA_SAMPLE)
    assert parsed.rule_type == RuleType.SIGMA
    assert parsed.title == "Suspicious Process Execution"
    assert parsed.severity == RuleSeverity.HIGH
    assert "attack.execution" in parsed.tags


def test_rule_parser_yara():
    """Verify parsing of YARA rule."""
    parsed = RuleParser.parse(YARA_SAMPLE)
    assert parsed.rule_type == RuleType.YARA
    assert parsed.title == "Detect_Malicious_Strings"


def test_rule_parser_suricata():
    """Verify parsing of Suricata IDS rule."""
    parsed = RuleParser.parse(SURICATA_SAMPLE)
    assert parsed.rule_type == RuleType.SURICATA
    assert "ET MALWARE" in parsed.title
    assert parsed.metadata.get("sid") == "2000001"


def test_rule_validator():
    """Verify rule validator behavior."""
    val_valid = RuleValidator.validate("Test Rule", SIGMA_SAMPLE, RuleType.SIGMA, RuleSeverity.HIGH)
    assert val_valid.is_valid is True
    assert len(val_valid.errors) == 0

    val_invalid = RuleValidator.validate("", "", RuleType.SIGMA, RuleSeverity.HIGH)
    assert val_invalid.is_valid is False
    assert len(val_invalid.errors) > 0


def test_rule_tester_dry_run():
    """Verify dry-run rule tester matching."""
    req = RuleTestRequest(
        rule_type=RuleType.SIGMA,
        rule_content=SIGMA_SAMPLE,
        sample_data="Process creation: powershell.exe executed with argument -enc AAAA==",
    )
    result = RuleTester.test_rule(req)
    assert result.matched is True
    assert result.matches_count > 0
    assert result.execution_time_ms >= 0.0


def test_rule_version_diff():
    """Verify line-by-line version diff engine."""
    content_v1 = "title: Test Rule V1\nlevel: medium"
    content_v2 = "title: Test Rule V2\nlevel: high"

    diff = RuleVersionManager.compare_contents(content_v1, content_v2, 1, 2)
    assert diff.has_changes is True
    assert len(diff.diff_lines) > 0


def test_detection_rule_create_schema():
    """Verify DetectionRuleCreate Pydantic v2 schema."""
    dto = DetectionRuleCreate(
        name="PowerShell Encoded Command",
        rule_type=RuleType.SIGMA,
        category="EXECUTION",
        severity=RuleSeverity.HIGH,
        content=SIGMA_SAMPLE,
    )
    assert dto.name == "PowerShell Encoded Command"
    assert dto.rule_type == RuleType.SIGMA
    assert dto.severity == RuleSeverity.HIGH
