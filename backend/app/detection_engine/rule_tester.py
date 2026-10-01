"""
Deterministic Detection Rule Testing Engine.

Provides dry-run simulation, test log matching, pattern detection,
and execution speed benchmarking without modifying live traffic.
"""

import time
import re
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from app.detection_engine.models import RuleType


class RuleTestRequest(BaseModel):
    """Payload to trigger dry-run rule evaluation against sample log data."""

    rule_type: RuleType
    rule_content: str
    sample_data: str = Field(..., description="Sample log line, event JSON, or raw text to test rule against")


class RuleTestResult(BaseModel):
    """Result payload from dry-run rule test execution."""

    matched: bool
    matches_count: int = 0
    execution_time_ms: float
    matched_patterns: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


class RuleTester:
    """Deterministic dry-run test framework for detection rules."""

    @classmethod
    def test_rule(cls, request: RuleTestRequest) -> RuleTestResult:
        """
        Execute deterministic dry-run matching of rule against sample log data.
        """
        start_time = time.perf_counter()

        sample_str = request.sample_data.lower()
        matched_patterns: List[str] = []

        if request.rule_type == RuleType.SIGMA:
            # Extract keywords or field patterns from Sigma content
            keywords = re.findall(r"['\"]([A-Za-z0-9_\-\.\\]+)['\"]", request.rule_content.lower())
            for kw in keywords:
                if len(kw) > 2 and kw in sample_str:
                    matched_patterns.append(kw)

        elif request.rule_type == RuleType.YARA:
            # Extract YARA string definitions
            strings = re.findall(r"\$([A-Za-z0-9_]+)\s*=\s*[\"']([^\"']+)[\"']", request.rule_content)
            for var_name, pattern_val in strings:
                if pattern_val.lower() in sample_str:
                    matched_patterns.append(f"${var_name}:{pattern_val}")

        elif request.rule_type == RuleType.SURICATA:
            # Extract Suricata content strings
            contents = re.findall(r'content\s*:\s*"([^"]+)"', request.rule_content)
            for c_val in contents:
                if c_val.lower() in sample_str:
                    matched_patterns.append(f"content:{c_val}")

        else:
            # Custom keyword match
            raw_lines = [line.strip().lower() for line in request.rule_content.splitlines() if line.strip()]
            for line in raw_lines:
                if line in sample_str:
                    matched_patterns.append(line)

        execution_time_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
        matched = len(matched_patterns) > 0

        return RuleTestResult(
            matched=matched,
            matches_count=len(matched_patterns),
            execution_time_ms=execution_time_ms,
            matched_patterns=matched_patterns,
            details={"tested_length": len(request.sample_data)},
        )
