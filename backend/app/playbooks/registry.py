"""
SOAR Playbook Engine Playbook Registry.

Provides in-memory registry abstractions for registering, searching, filtering,
and resolving active playbooks by category, severity trigger, and version.
"""

from typing import Dict, List, Optional
import uuid

from app.playbooks.models import Playbook, PlaybookCategory, PlaybookSeverity, PlaybookStatus


class PlaybookRegistry:
    """Registry engine for managing runtime playbook definitions."""

    def __init__(self):
        self._playbooks: Dict[uuid.UUID, Playbook] = {}
        self._name_index: Dict[str, uuid.UUID] = {}

    def register(self, playbook: Playbook) -> None:
        """Register or update a playbook in the registry index."""
        self._playbooks[playbook.id] = playbook
        self._name_index[playbook.name.lower()] = playbook.id

    def lookup_by_id(self, playbook_id: uuid.UUID) -> Optional[Playbook]:
        """Fetch playbook by UUID from registry."""
        return self._playbooks.get(playbook_id)

    def lookup_by_name(self, name: str) -> Optional[Playbook]:
        """Fetch playbook by unique name from registry."""
        pb_id = self._name_index.get(name.lower())
        return self._playbooks.get(pb_id) if pb_id else None

    def search(self, query: str) -> List[Playbook]:
        """Search playbooks by query matching name, description, or author."""
        q = query.lower()
        results = []
        for pb in self._playbooks.values():
            if (
                q in pb.name.lower()
                or (pb.description and q in pb.description.lower())
                or (pb.author and q in pb.author.lower())
            ):
                results.append(pb)
        return results

    def filter_by_category(self, category: PlaybookCategory) -> List[Playbook]:
        """Filter registered playbooks by security category."""
        return [pb for pb in self._playbooks.values() if pb.category == category]

    def filter_by_severity(self, severity: PlaybookSeverity) -> List[Playbook]:
        """Filter registered playbooks by severity trigger."""
        return [
            pb for pb in self._playbooks.values()
            if pb.severity_trigger in (severity, PlaybookSeverity.ALL)
        ]

    def get_active_playbooks(self) -> List[Playbook]:
        """Retrieve all active, non-disabled playbooks."""
        return [
            pb for pb in self._playbooks.values()
            if pb.is_active and pb.status == PlaybookStatus.ACTIVE
        ]

    def enable_playbook(self, playbook_id: uuid.UUID) -> Optional[Playbook]:
        """Enable a registered playbook."""
        pb = self._playbooks.get(playbook_id)
        if pb:
            pb.is_active = True
            pb.status = PlaybookStatus.ACTIVE
        return pb

    def disable_playbook(self, playbook_id: uuid.UUID) -> Optional[Playbook]:
        """Disable a registered playbook."""
        pb = self._playbooks.get(playbook_id)
        if pb:
            pb.is_active = False
            pb.status = PlaybookStatus.DISABLED
        return pb
