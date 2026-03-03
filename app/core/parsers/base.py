"""Base parser and ParsedEvent type for source-specific log parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


def parse_timestamp(value: Any) -> datetime:
    """Parse timestamp from various formats to timezone-aware UTC datetime."""
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except Exception:
            pass
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        except Exception:
            pass
    return datetime.now(timezone.utc)


@dataclass
class ParsedEvent:
    """Normalized result of parsing a single log event."""

    title: str
    severity: str
    category: str
    asset_id: str | None
    user_id: str | None
    source_ip: str | None
    dest_ip: str | None
    timestamp: datetime
    raw: dict[str, Any]


class BaseParser(ABC):
    """Abstract base for source-specific log parsers."""

    @abstractmethod
    def parse(self, event: dict[str, Any]) -> ParsedEvent:
        """Parse a raw event into a ParsedEvent."""
        ...

    @abstractmethod
    def get_severity(self, event: dict[str, Any]) -> str:
        """Extract severity from event."""
        ...

    @abstractmethod
    def get_category(self, event: dict[str, Any]) -> str:
        """Extract category from event."""
        ...

    @abstractmethod
    def extract_title(self, event: dict[str, Any]) -> str:
        """Extract title from event."""
        ...

    @abstractmethod
    def extract_asset_id(self, event: dict[str, Any]) -> str | None:
        """Extract asset/host identifier from event."""
        ...

    @abstractmethod
    def extract_user_id(self, event: dict[str, Any]) -> str | None:
        """Extract user identifier from event."""
        ...

    @abstractmethod
    def extract_source_ip(self, event: dict[str, Any]) -> str | None:
        """Extract source IP from event."""
        ...
