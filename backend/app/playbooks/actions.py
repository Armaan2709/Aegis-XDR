"""
SOAR Playbook Engine Action Abstraction & Safe Mock Execution Layer.

Provides abstract base class BasePlaybookAction and 12 safe simulated mock action implementations.
GUARANTEE: No real network, host, process, file, or credential modifications occur.
All actions return deterministic simulated execution metadata.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Type
from app.playbooks.models import ActionType
from app.core.exceptions import ValidationError


class BasePlaybookAction(ABC):
    """Abstract interface for all playbook action executors."""

    @abstractmethod
    async def execute(self, config: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute action given step configuration and workflow context."""
        pass


class BlockIPAction(BasePlaybookAction):
    """Simulated IP blocking action executor."""

    async def execute(self, config: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        target_ip = config.get("ip_address") or config.get("target") or context.get("ip_address") or "192.168.1.100"
        return {
            "status": "simulated",
            "action": ActionType.BLOCK_IP.value,
            "target": target_ip,
            "output": f"Simulated firewall IP block applied for '{target_ip}'",
            "execution_mode": "MOCK_SIMULATION",
        }


class IsolateHostAction(BasePlaybookAction):
    """Simulated host isolation action executor."""

    async def execute(self, config: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        target_host = config.get("hostname") or config.get("host_id") or context.get("hostname") or "WKSTN-FIN-01"
        return {
            "status": "simulated",
            "action": ActionType.ISOLATE_HOST.value,
            "target": target_host,
            "output": f"Simulated EDR network isolation applied for host '{target_host}'",
            "execution_mode": "MOCK_SIMULATION",
        }


class DisableAccountAction(BasePlaybookAction):
    """Simulated user account disabling action executor."""

    async def execute(self, config: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        target_user = config.get("username") or config.get("user_id") or context.get("username") or "user.compromised"
        return {
            "status": "simulated",
            "action": ActionType.DISABLE_ACCOUNT.value,
            "target": target_user,
            "output": f"Simulated Identity Directory account disabled for user '{target_user}'",
            "execution_mode": "MOCK_SIMULATION",
        }


class CollectEvidenceAction(BasePlaybookAction):
    """Simulated DFIR evidence collection action executor."""

    async def execute(self, config: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        evidence_type = config.get("evidence_type") or "MEMORY_DUMP"
        source = config.get("source") or context.get("hostname") or "UNKNOWN_SOURCE"
        return {
            "status": "simulated",
            "action": ActionType.COLLECT_EVIDENCE.value,
            "target": source,
            "output": f"Simulated evidence artifact collection requested for '{evidence_type}' from '{source}'",
            "execution_mode": "MOCK_SIMULATION",
        }


class QueryThreatIntelAction(BasePlaybookAction):
    """Simulated Threat Intelligence enrichment query executor."""

    async def execute(self, config: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        ioc = config.get("ioc") or context.get("ioc") or "10.0.0.1"
        return {
            "status": "simulated",
            "action": ActionType.QUERY_THREAT_INTEL.value,
            "target": ioc,
            "output": f"Simulated Threat Intelligence reputation query completed for IOC '{ioc}'",
            "reputation_score": 88.5,
            "threat_level": "MALICIOUS",
            "execution_mode": "MOCK_SIMULATION",
        }


class CreateCaseAction(BasePlaybookAction):
    """Simulated Case creation action executor."""

    async def execute(self, config: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        title = config.get("title") or f"Auto-Generated Case for {context.get('incident_id', 'Security Event')}"
        return {
            "status": "simulated",
            "action": ActionType.CREATE_CASE.value,
            "target": title,
            "output": f"Simulated Case workspace created: '{title}'",
            "generated_case_number": "CASE-2026-SIM-001",
            "execution_mode": "MOCK_SIMULATION",
        }


class CreateIncidentAction(BasePlaybookAction):
    """Simulated Incident creation action executor."""

    async def execute(self, config: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        title = config.get("title") or "Auto-Generated High Severity Alert Incident"
        return {
            "status": "simulated",
            "action": ActionType.CREATE_INCIDENT.value,
            "target": title,
            "output": f"Simulated Incident created: '{title}'",
            "generated_incident_id": "INC-2026-SIM-99",
            "execution_mode": "MOCK_SIMULATION",
        }


class SendNotificationAction(BasePlaybookAction):
    """Simulated notification dispatch action executor."""

    async def execute(self, config: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        channel = config.get("channel") or "SOC-Slack-Alerts"
        message = config.get("message") or f"Playbook notification triggered for {context.get('playbook_id', 'Workflow')}"
        return {
            "status": "simulated",
            "action": ActionType.SEND_NOTIFICATION.value,
            "target": channel,
            "output": f"Simulated notification sent to channel '{channel}': {message}",
            "execution_mode": "MOCK_SIMULATION",
        }


class AddTagAction(BasePlaybookAction):
    """Simulated tag attachment action executor."""

    async def execute(self, config: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        tag = config.get("tag") or "SOAR_AUTOMATED"
        target_entity = config.get("target_entity") or context.get("incident_id") or "TARGET_ENTITY"
        return {
            "status": "simulated",
            "action": ActionType.ADD_TAG.value,
            "target": str(target_entity),
            "output": f"Simulated tag '{tag}' attached to '{target_entity}'",
            "execution_mode": "MOCK_SIMULATION",
        }


class UpdateIncidentAction(BasePlaybookAction):
    """Simulated Incident status/metadata update action executor."""

    async def execute(self, config: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        incident_id = config.get("incident_id") or context.get("incident_id") or "INC-001"
        new_status = config.get("status") or "CONTAINED"
        return {
            "status": "simulated",
            "action": ActionType.UPDATE_INCIDENT.value,
            "target": str(incident_id),
            "output": f"Simulated Incident '{incident_id}' status updated to '{new_status}'",
            "execution_mode": "MOCK_SIMULATION",
        }


class RunDetectionAction(BasePlaybookAction):
    """Simulated Detection Engine rule rerun executor."""

    async def execute(self, config: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        rule_id = config.get("rule_id") or "RULE-YARA-001"
        return {
            "status": "simulated",
            "action": ActionType.RUN_DETECTION.value,
            "target": str(rule_id),
            "output": f"Simulated Detection Rule '{rule_id}' execution sweep triggered",
            "matches_found": 1,
            "execution_mode": "MOCK_SIMULATION",
        }


class GenerateReportAction(BasePlaybookAction):
    """Simulated executive summary report generator executor."""

    async def execute(self, config: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        report_type = config.get("report_type") or "INCIDENT_POST_MORTEM"
        return {
            "status": "simulated",
            "action": ActionType.GENERATE_REPORT.value,
            "target": report_type,
            "output": f"Simulated PDF report generated for type '{report_type}'",
            "report_download_url": "https://aegis.local/reports/simulated_post_mortem.pdf",
            "execution_mode": "MOCK_SIMULATION",
        }


class ActionRegistry:
    """Registry mapping ActionType enum values to their safe mock action executors."""

    _EXECUTORS: Dict[ActionType, Type[BasePlaybookAction]] = {
        ActionType.BLOCK_IP: BlockIPAction,
        ActionType.ISOLATE_HOST: IsolateHostAction,
        ActionType.DISABLE_ACCOUNT: DisableAccountAction,
        ActionType.COLLECT_EVIDENCE: CollectEvidenceAction,
        ActionType.QUERY_THREAT_INTEL: QueryThreatIntelAction,
        ActionType.CREATE_CASE: CreateCaseAction,
        ActionType.CREATE_INCIDENT: CreateIncidentAction,
        ActionType.SEND_NOTIFICATION: SendNotificationAction,
        ActionType.ADD_TAG: AddTagAction,
        ActionType.UPDATE_INCIDENT: UpdateIncidentAction,
        ActionType.RUN_DETECTION: RunDetectionAction,
        ActionType.GENERATE_REPORT: GenerateReportAction,
    }

    @classmethod
    def get_executor(cls, action_type: ActionType) -> BasePlaybookAction:
        """Resolve action type to an initialized mock executor instance."""
        executor_cls = cls._EXECUTORS.get(action_type)
        if not executor_cls:
            raise ValidationError(f"No mock executor registered for ActionType '{action_type}'")
        return executor_cls()
