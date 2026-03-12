"""Base connector interface. All connectors use credentials from config only."""

from abc import ABC, abstractmethod
from typing import Any


class BaseConnector(ABC):
    """Abstract pull connector. Implement pull() and test_connection()."""

    @property
    @abstractmethod
    def source_id(self) -> str:
        """Source identifier (e.g. 'sentinel', 'guardduty') for ingest."""
        ...

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Display name for logs (e.g. 'Sentinel', 'GuardDuty')."""
        ...

    @abstractmethod
    async def test_connection(self) -> tuple[bool, str]:
        """
        Verify credentials and connectivity. Returns (success, message).
        Must not log secrets.
        """
        ...

    @abstractmethod
    async def pull(self) -> list[dict[str, Any]]:
        """
        Fetch new events from the source. Return list of event dicts
        in the format expected by the parser for this source.
        """
        ...
