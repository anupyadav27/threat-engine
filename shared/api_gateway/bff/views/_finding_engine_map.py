"""Engine routing map for the universal-finding BFF (JNY-06).

Canonical engine slugs are LONG (matches K8s service names + JNY-05 §1).
Short-slug aliases (network, container, ai) are NOT accepted at the URL boundary.

Each entry maps a slug to:
  - conn:      callable returning a psycopg2 connection (read-only access from BFF)
  - table:     finding table to query for Tab 1
  - perm:      permission required to view findings from this engine
  - supported: False for engines deferred to a later phase (returns 501)
"""

from __future__ import annotations

from typing import Callable, Dict, Literal, TypedDict

from engine_common.db_connections import (
    get_ai_security_conn,
    get_check_conn,
    get_ciem_conn,
    get_container_sec_conn,
    get_datasec_conn,
    get_dbsec_conn,
    get_encryption_conn,
    get_iam_conn,
    get_network_conn,
    get_threat_conn,
)


# Canonical LONG slugs — these are the only values accepted at the BFF boundary.
EngineSlug = Literal[
    "check",
    "threat",
    "iam",
    "network-security",
    "datasec",
    "encryption",
    "container-security",
    "dbsec",
    "ai-security",
    "ciem",
    "secops",
]


class EngineConfig(TypedDict):
    conn: Callable  # psycopg2 conn factory; None when not supported
    table: str
    perm: str
    supported: bool


# NOTE: secops is deferred (B4): no get_secops_conn helper exists; the dedicated
# spin-off story STORY-ENG-SECOPS-FINDING-TABLE will deliver the conn helper +
# canonical finding table. Until then, the BFF returns 501 for this engine.
ENGINE_MAP: Dict[str, EngineConfig] = {
    "check": {
        "conn": get_check_conn,
        "table": "check_findings",
        "perm": "check:read",
        "supported": True,
    },
    "threat": {
        "conn": get_threat_conn,
        "table": "threat_findings",
        "perm": "threat:read",
        "supported": True,
    },
    "iam": {
        "conn": get_iam_conn,
        "table": "iam_findings",
        "perm": "iam:read",
        "supported": True,
    },
    "network-security": {
        "conn": get_network_conn,
        "table": "network_findings",
        "perm": "network-security:read",
        "supported": True,
    },
    "datasec": {
        "conn": get_datasec_conn,
        "table": "datasec_findings",
        "perm": "datasec:read",
        "supported": True,
    },
    "encryption": {
        "conn": get_encryption_conn,
        "table": "encryption_findings",
        "perm": "encryption:read",
        "supported": True,
    },
    "container-security": {
        "conn": get_container_sec_conn,
        "table": "container_sec_findings",
        "perm": "container-security:read",
        "supported": True,
    },
    "dbsec": {
        "conn": get_dbsec_conn,
        "table": "dbsec_findings",
        "perm": "dbsec:read",
        "supported": True,
    },
    "ai-security": {
        "conn": get_ai_security_conn,
        "table": "ai_security_findings",
        "perm": "ai-security:read",
        "supported": True,
    },
    "ciem": {
        "conn": get_ciem_conn,
        "table": "ciem_findings",
        "perm": "ciem:read",
        "supported": True,
    },
    "secops": {
        # Deferred — STORY-ENG-SECOPS-FINDING-TABLE.
        "conn": None,  # type: ignore[typeddict-item]
        "table": "",
        "perm": "secops:read",
        "supported": False,
    },
}


# Standard 14 mandatory columns selected from every finding table.
STD_COLUMNS = (
    "finding_id",
    "scan_run_id",
    "tenant_id",
    "account_id",
    "credential_ref",
    "credential_type",
    "provider",
    "region",
    "resource_uid",
    "resource_type",
    "severity",
    "status",
    "first_seen_at",
    "last_seen_at",
)
