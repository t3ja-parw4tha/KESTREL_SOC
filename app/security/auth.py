"""
Production-grade authentication: JWT (RS256), password policy, lockout, sessions.

OWASP Authentication guidelines: asymmetric JWT, strong passwords, account lockout,
session limits, refresh rotation.
"""

import hashlib
import logging
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from app.config import get_settings
from app.models import ApiKey, FailedLogin, Session, TokenBlocklist
from app.security.common_passwords import COMMON_PASSWORDS
from app.security.exceptions import SecurityError

logger = logging.getLogger(__name__)

ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7
REFRESH_TOKEN_COOKIE = "soc_refresh_token"
API_KEY_PREFIX = "soc_"
PASSWORD_MIN_LENGTH = 12
PROGRESSIVE_DELAYS = (1, 2, 4, 8, 16)  # seconds between attempts
ALERT_FAILURE_THRESHOLD = 3
MAX_SESSIONS_PER_USER = 3
ABSOLUTE_SESSION_TIMEOUT_HOURS = 8

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

_ph = PasswordHasher()

KEY_DIR = Path("data/keys")
PRIVATE_KEY_PATH = KEY_DIR / "jwt_private.pem"
PUBLIC_KEY_PATH = KEY_DIR / "jwt_public.pem"


def ensure_jwt_keys() -> None:
    """Generate RSA key pair on first startup if keys don't exist."""
    if not PRIVATE_KEY_PATH.exists():
        KEY_DIR.mkdir(parents=True, exist_ok=True)
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        PRIVATE_KEY_PATH.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        PUBLIC_KEY_PATH.write_bytes(
            private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def get_or_create_rsa_keys() -> tuple[str, str]:
    """Return JWT key pair; ensure keys exist first (e.g. created at startup)."""
    ensure_jwt_keys()
    return PRIVATE_KEY_PATH.read_text(), PUBLIC_KEY_PATH.read_text()


def _get_jwt_keys() -> tuple[str, str]:
    return get_or_create_rsa_keys()


def create_access_token(user_id: int, role: str) -> tuple[str, str]:
    """Return (access_token, jti)."""
    private_pem, _ = _get_jwt_keys()
    settings = get_settings()
    expire_min = getattr(settings, "access_token_expire_minutes", ACCESS_TOKEN_EXPIRE_MINUTES)
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=expire_min)
    jti = str(uuid.uuid4())
    payload = {
        "sub": str(user_id),
        "role": role,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "type": "access",
    }
    token = jwt.encode(payload, private_pem, algorithm=ALGORITHM)
    return token, jti


def create_refresh_token(user_id: int, role: str) -> tuple[str, str]:
    """Return (refresh_token, jti)."""
    private_pem, _ = _get_jwt_keys()
    settings = get_settings()
    expire_days = getattr(settings, "refresh_token_expire_days", REFRESH_TOKEN_EXPIRE_DAYS)
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=expire_days)
    jti = str(uuid.uuid4())
    payload = {
        "sub": str(user_id),
        "role": role,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "type": "refresh",
    }
    token = jwt.encode(payload, private_pem, algorithm=ALGORITHM)
    return token, jti


def verify_token(token: str) -> dict:
    """Decode and validate JWT; raises SecurityError if invalid or blocklisted."""
    _, public_pem = _get_jwt_keys()
    try:
        payload = jwt.decode(token, public_pem, algorithms=[ALGORITHM])
    except JWTError as e:
        raise SecurityError("Invalid or expired token") from e
    return payload


async def blocklist_add(db: AsyncSession, jti: str, exp: datetime) -> None:
    """Add jti to blocklist (logout/revocation)."""
    block = TokenBlocklist(jti=jti, exp=exp)
    db.add(block)
    await db.flush()


async def blocklist_check(db: AsyncSession, jti: str) -> bool:
    """True if jti is blocklisted."""
    stmt = select(TokenBlocklist).where(TokenBlocklist.jti == jti)
    result = await db.execute(stmt)
    return result.scalar_one_or_none() is not None


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, plain)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


PASSWORD_SPECIAL = re.compile(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]")


def validate_password_policy(password: str, username: str | None = None) -> None:
    """Enforce password requirements. Raises SecurityError if invalid."""
    if len(password) < PASSWORD_MIN_LENGTH:
        raise SecurityError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters")
    if not re.search(r"[A-Z]", password):
        raise SecurityError("Password must contain an uppercase letter")
    if not re.search(r"[a-z]", password):
        raise SecurityError("Password must contain a lowercase letter")
    if not re.search(r"\d", password):
        raise SecurityError("Password must contain a number")
    if not PASSWORD_SPECIAL.search(password):
        raise SecurityError("Password must contain a special character")
    if password.lower() in COMMON_PASSWORDS:
        raise SecurityError("Password is too common")
    if username and username.lower() in password.lower():
        raise SecurityError("Password must not contain username")


def get_progressive_delay(attempt_count: int) -> int:
    """Seconds to delay before next attempt (1, 2, 4, 8, 16)."""
    idx = min(attempt_count, len(PROGRESSIVE_DELAYS)) - 1
    return PROGRESSIVE_DELAYS[max(0, idx)]


async def get_recent_failure_count(db: AsyncSession, username: str) -> int:
    """Count failed login attempts in the last lockout window."""
    settings = get_settings()
    lock_min = getattr(settings, "lockout_minutes", 15)
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=lock_min)
    stmt = select(FailedLogin).where(
        FailedLogin.username == username,
        FailedLogin.attempted_at >= cutoff,
    )
    result = await db.execute(stmt)
    return len(result.scalars().all())


async def check_lockout(db: AsyncSession, username: str) -> tuple[bool, datetime | None]:
    """Return (is_locked, locked_until)."""
    settings = get_settings()
    lock_min = getattr(settings, "lockout_minutes", 15)
    max_attempts = getattr(settings, "lockout_attempts", 5)
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=lock_min)
    stmt = (
        select(FailedLogin)
        .where(FailedLogin.username == username, FailedLogin.attempted_at >= cutoff)
        .order_by(FailedLogin.attempted_at.desc())
    )
    result = await db.execute(stmt)
    rows = result.scalars().all()
    if not rows:
        return False, None
    latest = rows[0]
    if latest.locked_until and latest.locked_until > datetime.now(timezone.utc):
        return True, latest.locked_until
    if len(rows) >= max_attempts:
        locked_until = datetime.now(timezone.utc) + timedelta(minutes=lock_min)
        latest.locked_until = locked_until
        await db.flush()
        return True, locked_until
    return False, None


async def record_failed_login(
    db: AsyncSession,
    username: str,
    ip_address: str | None,
) -> int:
    """Record failed attempt; return current consecutive failure count."""
    fl = FailedLogin(username=username, ip_address=ip_address)
    db.add(fl)
    await db.flush()
    settings = get_settings()
    lock_min = getattr(settings, "lockout_minutes", 15)
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=lock_min)
    stmt = (
        select(FailedLogin)
        .where(FailedLogin.username == username, FailedLogin.attempted_at >= cutoff)
        .order_by(FailedLogin.attempted_at.desc())
    )
    result = await db.execute(stmt)
    count = len(result.scalars().all())
    if count >= ALERT_FAILURE_THRESHOLD:
        logger.warning(
            "SOC alert: %d consecutive failed logins for user=%s from ip=%s",
            count,
            username,
            ip_address or "unknown",
        )
    return count


async def clear_failed_logins(db: AsyncSession, username: str) -> None:
    """Clear failed attempts after successful login."""
    stmt = select(FailedLogin).where(FailedLogin.username == username)
    result = await db.execute(stmt)
    for row in result.scalars().all():
        await db.delete(row)
    await db.flush()


async def create_session(
    db: AsyncSession,
    user_id: int,
    refresh_jti: str,
    ip_address: str | None,
    user_agent: str | None,
) -> Session:
    """Create session; enforce max sessions per user (revoke oldest)."""
    settings = get_settings()
    max_sessions = getattr(settings, "max_sessions_per_user", MAX_SESSIONS_PER_USER)
    stmt = select(Session).where(Session.user_id == user_id).order_by(Session.created_at.asc())
    result = await db.execute(stmt)
    sessions = list(result.scalars().all())
    while len(sessions) >= max_sessions and sessions:
        oldest = sessions.pop(0)
        await db.delete(oldest)
    session = Session(
        user_id=user_id,
        refresh_jti=refresh_jti,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(session)
    await db.flush()
    return session


async def get_user_sessions(db: AsyncSession, user_id: int) -> list[Session]:
    """List active sessions for user (within absolute timeout)."""
    settings = get_settings()
    timeout_hours = getattr(settings, "absolute_session_timeout_hours", ABSOLUTE_SESSION_TIMEOUT_HOURS)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=timeout_hours)
    stmt = select(Session).where(Session.user_id == user_id, Session.created_at >= cutoff)
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def revoke_session_by_id(db: AsyncSession, session_id: int, user_id: int) -> bool:
    """Revoke session if it belongs to user. Return True if found and deleted."""
    stmt = select(Session).where(Session.id == session_id, Session.user_id == user_id)
    result = await db.execute(stmt)
    session = result.scalar_one_or_none()
    if session:
        await db.delete(session)
        await db.flush()
        return True
    return False


def hash_api_key(plain: str) -> str:
    return hashlib.sha256(plain.encode()).hexdigest()


def generate_api_key(permissions: list[str]) -> tuple[str, str]:
    """Return (plain_key, key_hash). Plain key format: soc_{32_chars}."""
    random_part = secrets.token_urlsafe(32).replace("-", "").replace("_", "")[:32]
    plain = f"{API_KEY_PREFIX}{random_part}"
    return plain, hash_api_key(plain)


async def verify_api_key(db: AsyncSession, plain_key: str) -> ApiKey | None:
    """Return ApiKey if valid and not revoked."""
    if not plain_key.startswith(API_KEY_PREFIX) or len(plain_key) < 40:
        return None
    key_hash = hash_api_key(plain_key)
    stmt = select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.revoked_at.is_(None))
    result = await db.execute(stmt)
    return result.scalar_one_or_none()
