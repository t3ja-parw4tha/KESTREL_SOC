"""Alert request/response schemas with strict validation (OWASP-aligned)."""

from typing import Annotated, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.security.sanitization import sanitize_text

AlertStatus = Literal["new", "investigating", "resolved", "dismissed"]
SeverityLevel = Literal["critical", "high", "medium", "low", "info"]

ALLOWED_STATUSES: frozenset[str] = frozenset(get_args(AlertStatus))


class AlertUpdateSchema(BaseModel):
    """Update alert (e.g. status only). No extra fields, status from enum."""

    model_config = ConfigDict(strict=True, extra="forbid")

    status: Annotated[
        AlertStatus,
        Field(description="New status for the alert"),
    ]

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        if v not in ALLOWED_STATUSES:
            raise ValueError(f"Invalid status: {v}. Allowed: {sorted(ALLOWED_STATUSES)}")
        return v


class AlertCreateSchema(BaseModel):
    """Create alert (internal/ingest). Strict limits and sanitized text."""

    model_config = ConfigDict(strict=True, extra="forbid")

    title: Annotated[str, Field(min_length=1, max_length=500)]
    severity: Annotated[SeverityLevel, Field()]
    source: Annotated[str, Field(min_length=1, max_length=100)]
    description: str | None = None

    @field_validator("title", "source")
    @classmethod
    def sanitize_string_fields(cls, v: str) -> str:
        if not v or not v.strip():
            return v
        return sanitize_text(v.strip())

    @field_validator("description")
    @classmethod
    def sanitize_description(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        return sanitize_text(v.strip())[:5000]


class CommentSchema(BaseModel):
    """Comment on an alert/incident. Text max 5000 chars, sanitized."""

    model_config = ConfigDict(strict=True, extra="forbid")

    text: Annotated[str, Field(min_length=1, max_length=5000)]

    @field_validator("text")
    @classmethod
    def sanitize_text_field(cls, v: str) -> str:
        return sanitize_text(v.strip())
