"""Detection rules execution engine for custom and simplified SIGMA rules."""

from __future__ import annotations

import re
from typing import Any

from app.core.detection_rules.types import RuleCondition


def _to_text(value: Any) -> str:
	if value is None:
		return ""
	if isinstance(value, (list, dict)):
		return str(value)
	return str(value)


def _match_condition(event: dict[str, Any], condition: RuleCondition) -> bool:
	raw_value = event.get(condition.field)
	event_text = _to_text(raw_value).lower()
	op = condition.operator

	if op == "equals":
		return event_text == _to_text(condition.value).lower()
	if op == "not_equals":
		return event_text != _to_text(condition.value).lower()
	if op == "contains":
		return _to_text(condition.value).lower() in event_text
	if op == "regex":
		try:
			return re.search(_to_text(condition.value), _to_text(raw_value)) is not None
		except re.error:
			return False
	if op == "in":
		values = condition.value if isinstance(condition.value, list) else [_to_text(condition.value)]
		return event_text in {_to_text(v).lower() for v in values}
	return False


def evaluate_custom_rule(event: dict[str, Any], conditions: list[dict[str, Any]] | None) -> bool:
	"""Return True when all custom conditions evaluate to true."""
	if not conditions:
		return False
	typed = [RuleCondition.model_validate(c) for c in conditions]
	return all(_match_condition(event, cond) for cond in typed)


def evaluate_sigma_rule(event: dict[str, Any], sigma_rule: dict[str, Any]) -> bool:
	"""Very small SIGMA subset evaluator for detection.selection exact/contains matching."""
	detection = sigma_rule.get("detection") if isinstance(sigma_rule, dict) else None
	selection = detection.get("selection") if isinstance(detection, dict) else None
	if not isinstance(selection, dict) or not selection:
		return False

	for field, expected in selection.items():
		actual_text = _to_text(event.get(field)).lower()
		if isinstance(expected, list):
			expected_values = [_to_text(v).lower() for v in expected]
			if actual_text not in expected_values:
				return False
			continue

		expected_text = _to_text(expected).lower()
		if expected_text.endswith("*"):
			if not actual_text.startswith(expected_text[:-1]):
				return False
		elif expected_text not in actual_text:
			return False
	return True
