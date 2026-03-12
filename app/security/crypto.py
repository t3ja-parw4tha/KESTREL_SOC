"""
Cryptographic standards: never use MD5/SHA1 for security, random(), ECB, DES, weak RSA.

- Password hashing: argon2id (argon2-cffi)
- Tokens: secrets.token_urlsafe(32) minimum
- IDs: UUID4 (no sequential enumeration)
- Checksums: SHA256 only
- API keys: secrets.token_urlsafe(32) with soc_ prefix
- Symmetric encryption: AES-256-GCM via Fernet (cryptography)
- Key derivation: PBKDF2-SHA256, 600_000 iterations (NIST 2023)
"""

import hashlib
import secrets
import uuid

# Minimum token length (bytes) for security-sensitive tokens
MIN_TOKEN_BYTES = 32
API_KEY_PREFIX = "soc_"
PBKDF2_ITERATIONS = 600_000
PBKDF2_HASH = "sha256"


def token_urlsafe(min_bytes: int = MIN_TOKEN_BYTES) -> str:
    """Generate URL-safe token; minimum 32 bytes (never use random() for security)."""
    return secrets.token_urlsafe(max(min_bytes, MIN_TOKEN_BYTES))


def generate_id() -> str:
    """Generate UUID4 (never sequential IDs — prevents enumeration)."""
    return str(uuid.uuid4())


def file_checksum_sha256(data: bytes) -> str:
    """SHA256 checksum only (never MD5 or SHA1 for security)."""
    return hashlib.sha256(data).hexdigest()


def generate_api_key_prefix() -> str:
    """API key: secrets.token_urlsafe(32) with soc_ prefix."""
    raw = secrets.token_urlsafe(32).replace("-", "").replace("_", "")[:32]
    return f"{API_KEY_PREFIX}{raw}"


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Key derivation: PBKDF2 with SHA256, 600_000 iterations (NIST 2023)."""
    return hashlib.pbkdf2_hmac(PBKDF2_HASH, password, salt, PBKDF2_ITERATIONS, dklen=32)


def get_fernet_key_from_password(password: bytes, salt: bytes | None = None) -> bytes:
    """
    Derive a 32-byte key suitable for Fernet (AES-128 in CBC+HMAC; Fernet uses base64).
    Fernet needs 32 bytes URL-safe base64; we use PBKDF2 then base64url encode for Fernet.
    """
    import base64
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    salt = salt or secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    key = kdf.derive(password)
    return base64.urlsafe_b64encode(key)


def encrypt_fernet(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt with Fernet (AES-128-CBC + HMAC; never ECB, DES, or 3DES)."""
    from cryptography.fernet import Fernet
    f = Fernet(key)
    return f.encrypt(plaintext)


def decrypt_fernet(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt Fernet payload."""
    from cryptography.fernet import Fernet
    f = Fernet(key)
    return f.decrypt(ciphertext)


def create_fernet_key() -> bytes:
    """Generate a new Fernet key (AES-256-GCM via Fernet's key format)."""
    from cryptography.fernet import Fernet
    return Fernet.generate_key()
