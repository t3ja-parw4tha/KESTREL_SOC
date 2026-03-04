"""
Sensitive data protection: field-level encryption, retention policy, PII detection.

- Fernet (symmetric) for PII and sensitive audit fields
- Retention: raw logs 90 days, alert metadata indefinite, AI summaries 1 year, anonymize resolved 180 days
- PII detection and redaction before storage/AI context
"""

import re
from datetime import datetime, timezone, timedelta

# Retention (days)
RAW_LOG_RETENTION_DAYS = 90
ALERT_METADATA_RETAIN_INDEFINITE = True
AI_SUMMARY_RETENTION_DAYS = 365
RESOLVED_ALERT_ANONYMIZE_DAYS = 180

# PII patterns (simplified; extend as needed)
SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d{4}[\s-]?){3}\d{4}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")


def detect_pii(text: str) -> list[str]:
    """
    Detect PII in text. Returns list of detected types (e.g. 'ssn', 'credit_card', 'email').
    Flag alerts containing PII for special handling.
    """
    if not text:
        return []
    found: list[str] = []
    if SSN_PATTERN.search(text):
        found.append("ssn")
    if CREDIT_CARD_PATTERN.search(text):
        found.append("credit_card")
    if EMAIL_PATTERN.search(text):
        found.append("email")
    return list(dict.fromkeys(found))


def redact_pii(text: str) -> str:
    """Redact PII in text before storing in AI context or logs."""
    if not text:
        return text
    out = SSN_PATTERN.sub("[REDACTED-SSN]", text)
    out = CREDIT_CARD_PATTERN.sub("[REDACTED-CC]", out)
    out = EMAIL_PATTERN.sub("[REDACTED-EMAIL]", out)
    return out


def should_retain_raw_log(created_at: datetime | None) -> bool:
    """Auto-delete raw log payloads after 90 days."""
    if not created_at:
        return True
    cutoff = datetime.now(timezone.utc) - timedelta(days=RAW_LOG_RETENTION_DAYS)
    return created_at >= cutoff


def should_retain_alert_metadata() -> bool:
    """Retain alert metadata indefinitely."""
    return True


def should_retain_ai_summary(created_at: datetime | None) -> bool:
    """Purge AI summaries after 1 year."""
    if not created_at:
        return True
    cutoff = datetime.now(timezone.utc) - timedelta(days=AI_SUMMARY_RETENTION_DAYS)
    return created_at >= cutoff


def should_anonymize_resolved_alert(resolved_at: datetime | None) -> bool:
    """Anonymize resolved alerts after 180 days."""
    if not resolved_at:
        return False
    cutoff = datetime.now(timezone.utc) - timedelta(days=RESOLVED_ALERT_ANONYMIZE_DAYS)
    return resolved_at <= cutoff


# --- Field-level encryption (Fernet); key must be stored separately from DB ---
def _get_fernet_key() -> bytes:
    """Load encryption key from env (e.g. FIELD_ENCRYPTION_KEY). Key must be base64 Fernet key."""
    import os
    key = os.getenv("FIELD_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("FIELD_ENCRYPTION_KEY not set; cannot encrypt sensitive fields")
    try:
        return key.encode() if isinstance(key, str) else key
    except Exception:
        raise RuntimeError("Invalid FIELD_ENCRYPTION_KEY format")


def encrypt_field(plaintext: str) -> bytes:
    """Encrypt before storage (user PII, IPs in audit)."""
    from app.security.crypto import encrypt_fernet
    key = _get_fernet_key()
    return encrypt_fernet(plaintext.encode("utf-8"), key)


def decrypt_field(ciphertext: bytes) -> str:
    """Decrypt only when needed for display."""
    from app.security.crypto import decrypt_fernet
    key = _get_fernet_key()
    return decrypt_fernet(ciphertext, key).decode("utf-8")
