"""
Detection Rule Version Management & Diff Engine.

Manages rule version history, change tracking, version comparison diffs,
and content rollback operations.
"""

import difflib
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class VersionDiffResult(BaseModel):
    """Result of diff comparison between two rule versions."""

    version_a: int
    version_b: int
    diff_lines: List[str] = Field(default_factory=list)
    has_changes: bool = False


class RuleVersionManager:
    """Version control helper for detection rules."""

    @staticmethod
    def compare_contents(content_a: str, content_b: str, version_a: int = 1, version_b: int = 2) -> VersionDiffResult:
        """
        Compare rule content text line-by-line using unified diff.
        """
        lines_a = content_a.splitlines(keepends=True)
        lines_b = content_b.splitlines(keepends=True)

        diff = list(
            difflib.unified_diff(
                lines_a,
                lines_b,
                fromfile=f"Version_{version_a}",
                tofile=f"Version_{version_b}",
            )
        )

        has_changes = len(diff) > 0
        return VersionDiffResult(
            version_a=version_a,
            version_b=version_b,
            diff_lines=[line.strip() for line in diff],
            has_changes=has_changes,
        )
