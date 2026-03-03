"""Log sanitization to prevent log injection and sensitive data leakage."""

import re

SENSITIVE_PATTERNS = [
    r'password["\s]*[:=]["\s]*\S+',
    r'token["\s]*[:=]["\s]*\S+',
    r'api.?key["\s]*[:=]["\s]*\S+',
    r'secret["\s]*[:=]["\s]*\S+',
    r'bearer\s+\S+',
    r'authorization:\s+\S+',
]


def sanitize_for_log(value: str) -> str:
    """Sanitize user input for safe logging (log injection prevention, redaction)."""
    if not isinstance(value, str):
        return str(value)
    # Remove newlines (log injection prevention)
    value = value.replace('\n', ' ').replace('\r', ' ')
    # Remove ANSI escape codes
    value = re.sub(r'\x1b\[[0-9;]*m', '', value)
    # Redact sensitive patterns
    for pattern in SENSITIVE_PATTERNS:
        value = re.sub(pattern, '[REDACTED]', value, flags=re.IGNORECASE)
    # Truncate to 1000 chars
    return value[:1000]
