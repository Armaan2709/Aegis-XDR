"""
Deterministic Detection Rule Parser.

Parses Sigma (YAML), YARA, Suricata, and Custom detection rules,
extracting normalized metadata, tags, severity levels, and structural components.
"""

import re
import yaml
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from app.detection_engine.models import RuleType, RuleSeverity


class ParsedRuleResult(BaseModel):
    """Normalized payload output by rule parsers."""

    rule_type: RuleType
    title: str
    description: Optional[str] = None
    severity: RuleSeverity = Field(RuleSeverity.MEDIUM)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    raw_content: str


class RuleParser:
    """Deterministic parser engine for multi-format detection rules."""

    @classmethod
    def parse(cls, content: str, explicit_type: Optional[RuleType] = None) -> ParsedRuleResult:
        """
        Detect rule format or parse given explicit_type.
        """
        raw = content.strip()
        r_type = explicit_type or cls.detect_type(raw)

        if r_type == RuleType.SIGMA:
            return cls.parse_sigma(raw)
        elif r_type == RuleType.YARA:
            return cls.parse_yara(raw)
        elif r_type == RuleType.SURICATA:
            return cls.parse_suricata(raw)
        else:
            return cls.parse_custom(raw)

    @classmethod
    def detect_type(cls, raw: str) -> RuleType:
        """Detect rule format from signature markers."""
        if "title:" in raw and "logsource:" in raw:
            return RuleType.SIGMA
        elif re.search(r"rule\s+[A-Za-z0-9_]+\s*\{", raw):
            return RuleType.YARA
        elif re.search(r"^(alert|drop|pass|reject)\s+(ip|tcp|udp|icmp|http)", raw, re.IGNORECASE):
            return RuleType.SURICATA
        return RuleType.CUSTOM

    @classmethod
    def parse_sigma(cls, raw: str) -> ParsedRuleResult:
        """Parse Sigma YAML rule format."""
        try:
            data = yaml.safe_load(raw) or {}
            title = str(data.get("title", "Untitled Sigma Rule"))
            description = str(data.get("description", ""))
            level = str(data.get("level", "medium")).lower()

            severity_map = {
                "informational": RuleSeverity.INFORMATIONAL,
                "low": RuleSeverity.LOW,
                "medium": RuleSeverity.MEDIUM,
                "high": RuleSeverity.HIGH,
                "critical": RuleSeverity.CRITICAL,
            }
            severity = severity_map.get(level, RuleSeverity.MEDIUM)
            tags = data.get("tags", [])
            if isinstance(tags, str):
                tags = [tags]

            return ParsedRuleResult(
                rule_type=RuleType.SIGMA,
                title=title,
                description=description,
                severity=severity,
                tags=tags,
                metadata={"logsource": data.get("logsource", {}), "author": data.get("author")},
                raw_content=raw,
            )
        except Exception as e:
            return ParsedRuleResult(
                rule_type=RuleType.SIGMA,
                title="Invalid Sigma Rule",
                description=f"Parsing error: {str(e)}",
                severity=RuleSeverity.MEDIUM,
                raw_content=raw,
            )

    @classmethod
    def parse_yara(cls, raw: str) -> ParsedRuleResult:
        """Parse YARA rule format."""
        match = re.search(r"rule\s+([A-Za-z0-9_]+)", raw)
        rule_name = match.group(1) if match else "Untitled_Yara_Rule"

        return ParsedRuleResult(
            rule_type=RuleType.YARA,
            title=rule_name,
            description="YARA Memory/File Detection Rule",
            severity=RuleSeverity.HIGH,
            tags=["yara", "malware"],
            metadata={"rule_name": rule_name},
            raw_content=raw,
        )

    @classmethod
    def parse_suricata(cls, raw: str) -> ParsedRuleResult:
        """Parse Suricata IDS rule format."""
        msg_match = re.search(r'msg\s*:\s*"([^"]+)"', raw)
        sid_match = re.search(r"sid\s*:\s*(\d+)", raw)

        title = msg_match.group(1) if msg_match else "Suricata IDS Rule"
        sid = sid_match.group(1) if sid_match else None

        return ParsedRuleResult(
            rule_type=RuleType.SURICATA,
            title=title,
            description="Suricata Network Signature",
            severity=RuleSeverity.HIGH,
            tags=["suricata", "network-ids"],
            metadata={"sid": sid},
            raw_content=raw,
        )

    @classmethod
    def parse_custom(cls, raw: str) -> ParsedRuleResult:
        """Parse generic custom detection rule."""
        return ParsedRuleResult(
            rule_type=RuleType.CUSTOM,
            title="Custom Detection Rule",
            description="Custom user-defined security rule",
            severity=RuleSeverity.MEDIUM,
            tags=["custom"],
            raw_content=raw,
        )
