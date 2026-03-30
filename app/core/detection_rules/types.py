"""Detection rule typing helpers."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


RuleType = Literal["sigma", "custom"]
ConditionOperator = Literal["equals", "not_equals", "contains", "regex", "in"]


class RuleCondition(BaseModel):
	"""A basic condition used by custom rule execution."""

	field: str = Field(..., min_length=1, max_length=128)
	operator: ConditionOperator
	value: str | list[str]
