"""Decision engine request/response schemas with strict validation (OWASP-aligned)."""

import re
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


class DecisionRunSchema(BaseModel):
    """Request to run decision engine on an alert. alert_id must be valid UUID format."""

    model_config = ConfigDict(strict=True, extra="forbid")

    alert_id: Annotated[str, Field(min_length=1, max_length=64)]

    @field_validator("alert_id")
    @classmethod
    def validate_alert_id_format(cls, v: str) -> str:
        v = v.strip()
        # Accept UUID or integer ID (for current schema)
        if UUID_PATTERN.match(v):
            return v
        if v.isdigit() and 1 <= len(v) <= 20:
            return v
        raise ValueError("alert_id must be a valid UUID or numeric id")


class DecisionResponseSchema(BaseModel):
    """Decision engine output (for API response)."""

    model_config = ConfigDict(strict=True, extra="forbid")

    alert_id: str
    action: str
    confidence: float
    score: float
    reasoning: str | None = None
