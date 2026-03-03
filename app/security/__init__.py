"""Security module: validation, sanitization, middleware, secrets, crypto, OWASP-aligned hardening."""

from app.security.exceptions import SecurityError
from app.security.sanitization import (
    sanitize_text,
    sanitize_json,
    sanitize_log_data,
    sanitize_for_log,
    safe_path,
    safe_subprocess,
)
from app.security.validation import safe_query, ALLOWED_ALERT_FILTERS, ALLOWED_INCIDENT_FILTERS
from app.security.middleware import setup_security, get_real_ip
from app.security.secrets import MaskedSecret, validate_secrets, mask_for_log
from app.security.crypto import (
    token_urlsafe,
    generate_id,
    file_checksum_sha256,
    generate_api_key_prefix,
    create_fernet_key,
    encrypt_fernet,
    decrypt_fernet,
)

__all__ = [
    "SecurityError",
    "sanitize_text",
    "sanitize_json",
    "sanitize_log_data",
    "sanitize_for_log",
    "safe_path",
    "safe_subprocess",
    "safe_query",
    "ALLOWED_ALERT_FILTERS",
    "ALLOWED_INCIDENT_FILTERS",
    "setup_security",
    "get_real_ip",
    "MaskedSecret",
    "validate_secrets",
    "mask_for_log",
    "token_urlsafe",
    "generate_id",
    "file_checksum_sha256",
    "generate_api_key_prefix",
    "create_fernet_key",
    "encrypt_fernet",
    "decrypt_fernet",
]
