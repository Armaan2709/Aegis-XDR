"""
Periodic Task Scheduler Interface.

Defines the contract for cron and periodic task execution engines.
"""

from abc import ABC, abstractmethod


class BaseTaskScheduler(ABC):
    """Abstract interface for cron/periodic task scheduling."""

    @abstractmethod
    def start(self) -> None:
        """Start periodic task scheduler loop."""
        pass

    @abstractmethod
    def shutdown(self) -> None:
        """Gracefully stop scheduled tasks."""
        pass
