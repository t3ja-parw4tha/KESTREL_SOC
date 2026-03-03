"""Security-related exceptions."""


class SecurityError(Exception):
    """Raised when a security check fails (path traversal, invalid input, etc.)."""

    pass
