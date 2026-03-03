"""
Secrets handling: never log secret values, mask in repr/str, audit env access.

Use MaskedSecret for in-memory secrets; use pydantic SecretStr in Settings.
"""

from typing import Any


class MaskedSecret:
    """Wrapper that masks values in logs and repr. Never log the inner value."""

    __slots__ = ("_value",)

    def __init__(self, value: str | bytes) -> None:
        self._value = value.decode("utf-8") if isinstance(value, bytes) else value

    def __repr__(self) -> str:
        return "***MASKED***"

    def __str__(self) -> str:
        return "***MASKED***"

    def get_secret_value(self) -> str:
        return self._value

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, MaskedSecret):
            return self._value == other._value
        return False


def validate_secrets(
    *,
    secret_key: str | None = None,
    database_url: str | None = None,
    is_production: bool | None = None,
) -> None:
    """
    Fail fast at startup if required secrets are missing.
    When called from config validator, pass secret_key and database_url from settings.
    """
    if is_production is None:
        try:
            from app.security.config_hardening import is_production as _prod
            is_production = _prod()
        except Exception:
            is_production = False
    if not is_production:
        return
    if not secret_key or not secret_key.strip():
        raise RuntimeError("Missing required secret: SECRET_KEY")
    if secret_key.strip() == "change-me-in-production":
        raise RuntimeError("SECRET_KEY must be changed from default in production")
    if not database_url or not database_url.strip():
        raise RuntimeError("Missing required secret: DATABASE_URL")


def mask_for_log(value: str | None) -> str:
    """Return a safe string for logging (never log raw secrets)."""
    if value is None or not value:
        return "<not set>"
    if len(value) <= 4:
        return "****"
    return value[:2] + "****" + value[-2:] if len(value) > 4 else "****"
