"""
Utility for redacting credential-like fields from JSONB configuration data.

Applied at the BFF layer before returning Configuration and Drift tab data
to the frontend — prevents accidental leakage of secrets stored in emitted_fields,
previous_state, and current_state JSONB columns.
"""

from typing import Any

_SENSITIVE_KEYS = frozenset({
    "password",
    "passwd",
    "secret",
    "secret_key",
    "access_key",
    "access_key_id",
    "connection_string",
    "jdbc",
    "token",
    "auth_token",
    "private_key",
    "credential",
    "api_key",
})

_REDACTED = "[REDACTED]"


def _is_sensitive_key(key: str) -> bool:
    """Return True if key contains any sensitive substring (case-insensitive)."""
    key_lower = key.lower()
    return any(s in key_lower for s in _SENSITIVE_KEYS)


def scrub_config_fields(data: Any) -> Any:
    """Recursively redact values whose key matches a credential-like pattern.

    Traverses dicts and lists. Replaces matching values with "[REDACTED]".
    Keys are not modified — only values. Non-dict/list scalars are returned
    unchanged (including None, int, bool, str).

    Args:
        data: Arbitrary Python object (dict, list, str, int, None, etc.)

    Returns:
        Same structure with sensitive values replaced by "[REDACTED]".
    """
    if isinstance(data, dict):
        return {
            k: _REDACTED if _is_sensitive_key(k) else scrub_config_fields(v)
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [scrub_config_fields(item) for item in data]
    return data
