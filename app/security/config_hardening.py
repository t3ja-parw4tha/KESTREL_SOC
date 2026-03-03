"""
Configuration hardening: production checks, secret entropy, DB URL, TLS guidance.

- Enforce DEBUG=False in production
- Validate SECRET_KEY length and entropy
- Reject SQLite in production; require PostgreSQL with SSL
- TLS 1.2 minimum, strong ciphers (documentation)
"""

import os
import re
from urllib.parse import urlparse


def is_production() -> bool:
    """Detect production via ENV (e.g. PRODUCTION=1 or ENVIRONMENT=production)."""
    env = (os.getenv("ENVIRONMENT") or os.getenv("ENV") or "").lower()
    prod_flag = os.getenv("PRODUCTION", "").lower() in ("1", "true", "yes")
    return env == "production" or prod_flag


def validate_debug(debug: bool) -> None:
    """Enforce DEBUG=False in production."""
    if is_production() and debug:
        raise ValueError("DEBUG must be False in production")


def validate_secret_key(key: str) -> None:
    """Validate SECRET_KEY: minimum 32 chars and sufficient entropy."""
    if not key or len(key) < 32:
        raise ValueError("SECRET_KEY must be at least 32 characters")
    unique_chars = len(set(key))
    entropy = unique_chars / len(key) if key else 0
    if entropy < 0.5:
        raise ValueError("SECRET_KEY has low entropy (use high-entropy random value)")


def validate_database_url(url: str) -> None:
    """
    Harden database URL:
    - Reject SQLite in production (enforce PostgreSQL)
    - Require SSL for PostgreSQL in production
    - Validate connection string format
    """
    if not url or not url.strip():
        raise ValueError("DATABASE_URL is required")
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if is_production():
        if scheme == "sqlite":
            raise ValueError("SQLite is not allowed in production; use PostgreSQL")
        if "postgres" in scheme or scheme == "postgresql":
            if "sslmode" not in (parsed.query or "").lower() and "ssl" not in (url or "").lower():
                raise ValueError("PostgreSQL connections must use SSL in production (sslmode=require)")


def get_tls_guidance() -> dict[str, str]:
    """
    TLS configuration guidance (for README / ops):
    Minimum TLS 1.2, prefer 1.3; strong cipher suites only.
    """
    return {
        "minimum_tls": "1.2",
        "prefer_tls": "1.3",
        "cipher_suites": "Strong suites only (e.g. TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256)",
        "hsts": "Submit to HSTS preload list when using HTTPS in production",
    }
