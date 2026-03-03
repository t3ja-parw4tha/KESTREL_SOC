"""
SQL injection prevention and safe query building.

- Enforce SQLAlchemy ORM for ALL database queries; never use raw SQL or string formatting.
- safe_query() validates filter parameters against an allowlist and applies depth limiting.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.sql import Select

from app.security.exceptions import SecurityError

# Maximum depth for nested/joined queries (e.g. join depth or subquery depth).
MAX_QUERY_DEPTH = 3

# Whitelist of allowed filter column names per model. Only these may be used in filters.
ALLOWED_ALERT_FILTERS = frozenset(
    {"id", "severity", "status", "source", "timestamp", "incident_id", "created_at"}
)
ALLOWED_INCIDENT_FILTERS = frozenset(
    {"id", "status", "severity", "created_at", "updated_at"}
)
ALLOWED_DECISION_FILTERS = frozenset(
    {"id", "alert_id", "action", "created_at"}
)

# Map model name / table to allowed filters for safe_query().
ALLOWED_FILTERS_BY_MODEL: dict[str, frozenset[str]] = {
    "alerts": ALLOWED_ALERT_FILTERS,
    "decisions": ALLOWED_DECISION_FILTERS,
    "incidents": ALLOWED_INCIDENT_FILTERS,
}


def _get_allowed_filters(model: type[DeclarativeBase]) -> frozenset[str]:
    """Resolve allowlist for the given model."""
    name = getattr(model, "__tablename__", None) or model.__name__.lower()
    return ALLOWED_FILTERS_BY_MODEL.get(name, frozenset())


def _validate_filters(
    filters: dict[str, Any],
    allowed: frozenset[str],
) -> None:
    """
    Validate that all filter keys are in the allowlist.
    Reject anything else with SecurityError (caller should map to 400).
    """
    disallowed = set(filters) - allowed
    if disallowed:
        raise SecurityError(
            f"Disallowed filter field(s): {sorted(disallowed)}. "
            f"Allowed: {sorted(allowed)}."
        )


def _estimate_query_depth(statement: Select[Any]) -> int:
    """
    Estimate depth of a SQLAlchemy select. safe_query() builds flat selects (depth 1).
    When composing with joins/subqueries, depth should stay <= MAX_QUERY_DEPTH.
    """
    # Current safe_query() only builds single-entity selects; depth 1.
    return 1


def safe_query(
    model: type[DeclarativeBase],
    *,
    filters: dict[str, Any] | None = None,
    order_by: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> Select[Any]:
    """
    Build a safe SQLAlchemy ORM Select for the given model.

    - Only allowed filter keys (from allowlist) are permitted; others raise SecurityError.
    - No raw SQL or string formatting; all filtering is via ORM.
    - Query depth is limited (e.g. when used with joins) via MAX_QUERY_DEPTH.

    Caller must execute this with the session (e.g. session.execute(stmt)).
    Never pass user input as raw SQL or use execute("...") with string formatting.
    """
    allowed = _get_allowed_filters(model)
    filters = filters or {}

    _validate_filters(filters, allowed)

    stmt = select(model)

    for key, value in filters.items():
        if key not in allowed:
            continue
        column = getattr(model, key, None)
        if column is None:
            raise SecurityError(f"Unknown column for filter: {key}")
        stmt = stmt.where(column == value)

    if order_by:
        if order_by not in allowed:
            raise SecurityError(
                f"Disallowed order_by field: {order_by}. Allowed: {sorted(allowed)}."
            )
        col = getattr(model, order_by, None)
        if col is not None:
            stmt = stmt.order_by(col)

    if limit is not None:
        if not isinstance(limit, int) or limit < 0 or limit > 10_000:
            raise SecurityError("Invalid limit: must be int in 0..10000")
        stmt = stmt.limit(limit)
    if offset is not None:
        if not isinstance(offset, int) or offset < 0:
            raise SecurityError("Invalid offset: must be non-negative int")
        stmt = stmt.offset(offset)

    depth = _estimate_query_depth(stmt)
    if depth > MAX_QUERY_DEPTH:
        raise SecurityError(
            f"Query depth {depth} exceeds maximum allowed ({MAX_QUERY_DEPTH})."
        )

    return stmt
