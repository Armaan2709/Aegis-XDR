"""
Case Management Approval System & Policy Abstraction Submodule.

Defines AutoApprovalPolicy engine abstraction.
NOTE: Auto approval is strictly a placeholder policy evaluation.
Does NOT automatically execute security actions or SOAR response workflows.
"""

from typing import Optional, Dict, Any, Tuple
from app.case_management.models import ApprovalStatus, CaseSeverity


class AutoApprovalPolicy:
    """Placeholder policy engine for evaluating auto-approval criteria."""

    @staticmethod
    def evaluate_auto_approval(
        title: str,
        description: Optional[str],
        case_severity: CaseSeverity,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        """Evaluate if approval request qualifies for placeholder auto-approval."""
        # Policy rule: Informational or Low severity routine maintenance approvals can be auto-approved
        if case_severity == CaseSeverity.LOW:
            return True, "Policy Rule AAP-101: Auto-approved based on LOW severity routine policy"

        # Check for auto-approve flag in title/description keywords
        text = f"{title} {description or ''}".lower()
        if "routine maintenance" in text or "standard triage" in text:
            return True, "Policy Rule AAP-102: Auto-approved based on standard triage routine keywords"

        return False, "Manual supervisor approval required by governance policy"

