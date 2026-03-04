"""Ingest request/response schemas with strict validation (OWASP-aligned)."""

import json
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator


ALLOWED_INGEST_SOURCES = frozenset(
    {
        "Sentinel",
        "Suricata",
        "GuardDuty",
        "WindowsEventLog",
        "Defender",
        "Syslog",
        "Snort",
        "Zeek",
        "Elastic",
        "Splunk",
        "QRadar",
    }
)

MAX_EVENTS_PAYLOAD_BYTES = 10_000_000  # 10MB


class IngestSchema(BaseModel):
    """Strict schema for ingest payloads. No extra fields, validated source and size."""

    model_config = ConfigDict(strict=True, extra="forbid")

    source: Annotated[
        str,
        Field(
            min_length=1,
            max_length=100,
            pattern=r"^[a-zA-Z0-9_\-\s]+$",
            description="Log source identifier",
        ),
    ]
    events: Annotated[
        list[dict],
        Field(
            min_length=1,
            max_length=1000,
            description="List of raw event objects",
        ),
    ]

    @field_validator("source")
    @classmethod
    def validate_source(cls, v: str) -> str:
        if v not in ALLOWED_INGEST_SOURCES:
            raise ValueError(f"Unknown source: {v}. Allowed: {sorted(ALLOWED_INGEST_SOURCES)}")
        return v

    @field_validator("events")
    @classmethod
    def validate_events_size(cls, v: list[dict]) -> list[dict]:
        try:
            size = len(json.dumps(v).encode("utf-8"))
        except (TypeError, ValueError) as e:
            raise ValueError("Events payload is not serializable") from e
        if size > MAX_EVENTS_PAYLOAD_BYTES:
            raise ValueError(
                f"Events payload too large ({size} bytes, max {MAX_EVENTS_PAYLOAD_BYTES})"
            )
        return v


class IngestResponseSchema(BaseModel):
    """Response after accepting ingest."""

    model_config = ConfigDict(strict=True, extra="forbid")

    status: str = "ok"
    ingested: int
    alerts: list[str]
    errors: list[str] = []
