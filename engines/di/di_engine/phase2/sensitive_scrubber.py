"""
Phase 2 — Sensitive Field Scrubber

Removes known sensitive keys from raw_response JSONB before any DB write.
This is a SECURITY GATE — no exceptions, no configurable bypass.

Recursive: scrubs nested dicts and lists.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Set

logger = logging.getLogger("di.phase2.scrubber")

# Canonical set of sensitive field names (case-sensitive exact match)
_SENSITIVE_KEYS: Set[str] = frozenset({
    # AWS credentials / secrets
    "MasterUserPassword",
    "MasterPassword",
    "Password",
    "password",
    "AccessKeyId",
    "SecretAccessKey",
    "SessionToken",
    "SecurityToken",
    "AuthToken",
    "AuthorizationToken",
    "Credentials",
    # Connection strings
    "ConnectionString",
    "connection_string",
    "DatabasePassword",
    "database_password",
    "DBPassword",
    "db_password",
    # Secret Manager / KMS
    "SecretString",
    "SecretBinary",
    "KeyMaterial",
    "PrivateKey",
    "private_key",
    "PrivateKeyPem",
    # Azure
    "clientSecret",
    "client_secret",
    "tenantSecret",
    # GCP / IBM
    "private_key_id",
    "service_account_key",
    # Certificate / TLS
    "CertificateBody",
    "CertificateChain",
    "PrivateKeyBody",
    # SSH / API keys
    "KeyFingerprint",
    "SshKeyBody",
    "api_key",
    "ApiKey",
    "apiKey",
    "token",
    "Token",
    "access_token",
    "refresh_token",
    "id_token",
    # Generic
    "secret",
    "Secret",
    "credential",
    "Credential",
})

_REDACTED = "[REDACTED]"


def scrub(data: Any) -> Any:
    """Recursively scrub sensitive keys from a dict or list.

    Args:
        data: The value to scrub (dict, list, or scalar).

    Returns:
        Scrubbed copy with sensitive values replaced by '[REDACTED]'.
    """
    if isinstance(data, dict):
        return {
            k: (_REDACTED if k in _SENSITIVE_KEYS else scrub(v))
            for k, v in data.items()
        }
    elif isinstance(data, list):
        return [scrub(item) for item in data]
    else:
        return data


def scrub_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Scrub the raw_response and emitted_fields of a single asset row.

    Modifies in-place and returns the row for chaining.
    This MUST be called before any DB write.
    """
    if "raw_response" in row and row["raw_response"]:
        row["raw_response"] = scrub(row["raw_response"])
    if "emitted_fields" in row and row["emitted_fields"]:
        row["emitted_fields"] = scrub(row["emitted_fields"])
    return row
