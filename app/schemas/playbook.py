"""Pydantic schemas for Automation Playbooks."""

from typing import Literal
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field

# ─── Condition Models ─────────────────────────────────────────────────────────

class PlaybookCondition(BaseModel):
    """A single condition evaluating a field against a value."""
    field: str = Field(..., description="The field on the alert to evaluate (e.g., 'severity', 'source', 'mitre_tactic')")
    operator: Literal["equals", "not_equals", "contains", "not_contains"] = Field(..., description="Comparison operator")
    value: str = Field(..., description="The value to compare against")

# ─── Action Models ────────────────────────────────────────────────────────────

class PlaybookAction(BaseModel):
    """A single action to execute when conditions match."""
    type: Literal["set_severity", "set_status", "add_tag", "assign_to"] = Field(..., description="The type of action to perform")
    value: str = Field(..., description="The value for the action (e.g., 'High', 'closed', 'auto-resolved')")

# ─── API Schema Models ────────────────────────────────────────────────────────

class PlaybookBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str | None = Field(None, max_length=512)
    is_active: bool = True
    trigger_type: str = Field("alert_created", max_length=64)
    conditions: list[PlaybookCondition] = Field(default_factory=list, description="List of conditions that must ALL be met (AND logic)")
    actions: list[PlaybookAction] = Field(default_factory=list, description="List of actions to execute sequentially")

class PlaybookCreate(PlaybookBase):
    """Payload for creating a new playbook."""
    pass

class PlaybookUpdate(BaseModel):
    """Payload for updating an existing playbook."""
    name: str | None = Field(None, min_length=1, max_length=128)
    description: str | None = Field(None, max_length=512)
    is_active: bool | None = None
    trigger_type: str | None = Field(None, max_length=64)
    conditions: list[PlaybookCondition] | None = None
    actions: list[PlaybookAction] | None = None

class PlaybookResponse(PlaybookBase):
    """Response model for a playbook."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_by_id: int | None
    created_at: datetime
    updated_at: datetime | None


class PlaybookTemplateResponse(BaseModel):
    """Read-only representation of a built-in playbook template."""

    key: str
    name: str
    description: str
    trigger_type: str
    conditions: list[PlaybookCondition]
    actions: list[PlaybookAction]


class InstallPlaybookLibraryRequest(BaseModel):
    """Install one or more built-in templates into the playbooks table."""

    template_keys: list[str] = Field(default_factory=list, min_length=1)
    overwrite_existing: bool = False
    activate: bool = True


class InstallPlaybookLibraryResponse(BaseModel):
    """Summary of library installation results."""

    installed: list[str]
    skipped: list[str]
