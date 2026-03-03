"""
Input sanitization: XSS, path traversal, command injection, log injection.

OWASP-aligned: sanitize all user-supplied and external data before use or storage.
"""

import html
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import bleach

from app.security.exceptions import SecurityError

# --- Limits ---
MAX_TEXT_LENGTH = 10_000
MAX_JSON_DEPTH = 10
MAX_JSON_ARRAY_LENGTH = 1_000
MAX_JSON_BYTES = 10 * 1024 * 1024  # 10MB
MAX_LOG_VALUE_LENGTH = 500

# --- XSS / dangerous patterns (reject if present) ---
DANGEROUS_PATTERNS = re.compile(
    r"<script\b|javascript\s*:|on\w+\s*=\s*[\"']?|data\s*:\s*text/html",
    re.IGNORECASE | re.DOTALL,
)

# --- Sensitive keys to redact in log data (case-insensitive) ---
SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "credit_card",
        "creditcard",
        "ssn",
        "session_id",
        "cookie",
    }
)

# --- Path traversal indicators ---
PATH_TRAVERSAL_PATTERN = re.compile(
    r"\.\.[/\\]|%2e%2e[/\\]|\.\.%2e|%2e%2e|\x00",
    re.IGNORECASE,
)

# --- ANSI escape sequence pattern ---
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\].[^\x07]*\x07?")

# --- Allowed executables for safe_subprocess (extend as needed) ---
ALLOWED_EXECUTABLES = frozenset(
    {
        "python",
        "python3",
        "pwsh",
        "powershell",
        "cmd",
        "bash",
        "sh",
        "curl",
        "wget",
        "tar",
        "gzip",
    }
)


def sanitize_text(input_str: str) -> str:
    """
    Sanitize user-supplied text for safe display and storage (XSS prevention).

    - Strip all HTML tags (bleach with strip=True).
    - Encode special chars: < > & " ' / to HTML entities.
    - Remove null bytes.
    - Limit length to MAX_TEXT_LENGTH.
    - Reject strings containing <script, javascript:, on[event]=, data:text/html.
    """
    if not isinstance(input_str, str):
        raise SecurityError("sanitize_text requires str input")
    if DANGEROUS_PATTERNS.search(input_str):
        raise SecurityError("Input contains disallowed pattern (e.g. script, javascript:, event handler)")
    s = input_str.replace("\x00", "")
    s = bleach.clean(s, strip=True, tags=[], attributes={})
    s = html.escape(s, quote=True)
    if len(s) > MAX_TEXT_LENGTH:
        s = s[:MAX_TEXT_LENGTH]
    return s


def _sanitize_string_value(val: str) -> str:
    """Sanitize a string value for use inside JSON (XSS-safe)."""
    if not isinstance(val, str):
        return val
    s = val.replace("\x00", "")
    s = bleach.clean(s, strip=True, tags=[], attributes={})
    s = html.escape(s, quote=True)
    return s[:MAX_TEXT_LENGTH]


def sanitize_json(
    data: dict[str, Any],
    *,
    max_depth: int = MAX_JSON_DEPTH,
    max_array_length: int = MAX_JSON_ARRAY_LENGTH,
    max_total_bytes: int = MAX_JSON_BYTES,
) -> dict[str, Any]:
    """
    Recursively sanitize all string values in a JSON-like dict.

    - Enforce max nesting depth (prevent deep object attacks).
    - Limit array length to max_array_length.
    - Limit total JSON size to max_total_bytes (approximate).
    - Remove keys that start with __ (dunder injection).
    """
    if not isinstance(data, dict):
        raise SecurityError("sanitize_json requires dict input")

    def _size_ok(obj: Any) -> bool:
        try:
            return len(json.dumps(obj).encode("utf-8")) <= max_total_bytes
        except Exception:
            return False

    if not _size_ok(data):
        raise SecurityError("JSON payload exceeds maximum allowed size")

    def _sanitize(obj: Any, depth: int) -> Any:
        if depth > max_depth:
            raise SecurityError(f"JSON depth exceeds maximum ({max_depth})")
        if isinstance(obj, dict):
            out: dict[str, Any] = {}
            for k, v in obj.items():
                if isinstance(k, str) and k.startswith("__"):
                    continue
                out[k] = _sanitize(v, depth + 1)
            return out
        if isinstance(obj, list):
            if len(obj) > max_array_length:
                raise SecurityError(
                    f"Array length {len(obj)} exceeds maximum ({max_array_length})"
                )
            return [_sanitize(item, depth + 1) for item in obj]
        if isinstance(obj, str):
            return _sanitize_string_value(obj)
        return obj

    return _sanitize(data, 0)


def _is_sensitive_key(key: str) -> bool:
    return key.lower().strip() in SENSITIVE_KEYS


def sanitize_log_data(data: dict[str, Any]) -> dict[str, Any]:
    """
    Sanitize raw log payloads before storing.

    - Redact sensitive fields (password, secret, token, api_key, credit_card, ssn, etc.).
    - Preserve security-relevant fields: IPs, usernames, event IDs, timestamps.
    - Return a sanitized copy; never mutate the original.
    """
    if not isinstance(data, dict):
        return {}

    def _redact(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: "[REDACTED]" if _is_sensitive_key(k) else _redact(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_redact(x) for x in obj]
        return obj

    return _redact(data)


def safe_path(base_dir: str | Path, user_input: str) -> Path:
    """
    Resolve a path from user input and ensure it stays under base_dir (path traversal prevention).

    - Resolve to absolute path.
    - Verify resolved path starts with base_dir.
    - Reject paths containing: ../, ..\\, %2e%2e, null bytes.
    - Raises SecurityError if path escapes base directory.
    """
    base = Path(base_dir).resolve()
    if not base.is_dir():
        raise SecurityError("base_dir must be an existing directory")
    if not isinstance(user_input, str):
        raise SecurityError("Path input must be str")
    if PATH_TRAVERSAL_PATTERN.search(user_input):
        raise SecurityError("Path contains invalid traversal sequence")
    try:
        resolved = (base / user_input.strip()).resolve()
        if not str(resolved).startswith(str(base)):
            raise SecurityError("Resolved path escapes base directory")
        return resolved
    except SecurityError:
        raise
    except Exception as e:
        raise SecurityError(f"Invalid path: {e}") from e


def safe_subprocess(
    cmd: list[str],
    *,
    timeout: int = 30,
    allowed_executables: frozenset[str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """
    Run a subprocess safely (command injection prevention).

    - Only accepts list form (never shell string).
    - Whitelist allowed executables (basename of first element).
    - Timeout to prevent resource exhaustion.
    - stderr is sanitized before it should be logged (caller should use sanitize_for_log).
    """
    if not isinstance(cmd, list) or not cmd:
        raise SecurityError("safe_subprocess requires non-empty list of arguments")
    for c in cmd:
        if not isinstance(c, str):
            raise SecurityError("All command arguments must be strings")
    allowed = allowed_executables or ALLOWED_EXECUTABLES
    exe = Path(cmd[0]).name.lower()
    if exe not in allowed:
        raise SecurityError(f"Executable not in allowlist: {cmd[0]}")
    if timeout <= 0 or timeout > 300:
        raise SecurityError("Timeout must be between 1 and 300 seconds")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            shell=False,
            text=False,
        )
        return result
    except subprocess.TimeoutExpired as e:
        raise SecurityError(f"Subprocess timed out after {timeout}s") from e
    except Exception as e:
        raise SecurityError(f"Subprocess failed: {e}") from e


def sanitize_for_log(value: str) -> str:
    """
    Sanitize a value before writing to logs (log injection prevention).

    - Remove newlines (\\n, \\r) to prevent log forging.
    - Remove ANSI escape sequences.
    - Truncate to MAX_LOG_VALUE_LENGTH.
    - Escape or remove other characters that could break log format (optional).
    """
    if not isinstance(value, str):
        value = str(value)
    s = value.replace("\n", " ").replace("\r", " ")
    s = ANSI_ESCAPE.sub("", s)
    if len(s) > MAX_LOG_VALUE_LENGTH:
        s = s[:MAX_LOG_VALUE_LENGTH] + "..."
    return s
