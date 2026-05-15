"""
DB and Neo4j connection factories for threat_v1 graph builder.

Each function reads from env vars — no credentials in code. All
cross-engine DB connections use read-only credentials per ADR-006.
"""
from __future__ import annotations

import os
from typing import Any

import psycopg2
import psycopg2.extras
from neo4j import GraphDatabase, Driver


def _pg_conn(
    host_var: str,
    port_var: str,
    db_var: str,
    user_var: str,
    pwd_var: str,
    default_db: str,
) -> Any:
    """Generic psycopg2 connection factory using named env vars."""
    return psycopg2.connect(
        host=os.environ[host_var],
        port=int(os.environ.get(port_var, "5432")),
        dbname=os.environ.get(db_var, default_db),
        user=os.environ[user_var],
        password=os.environ[pwd_var],
        sslmode=os.environ.get("DB_SSLMODE", "prefer"),
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


def get_threat_conn() -> Any:
    """Return a psycopg2 connection to the threat_v1 Postgres DB.

    Used for: scan_orchestration ownership validation, threat_scan_runs_v1.
    """
    return _pg_conn(
        "THREAT_DB_HOST", "THREAT_DB_PORT", "THREAT_DB_NAME",
        "THREAT_DB_USER", "THREAT_DB_PASSWORD",
        "threat_engine_threat",
    )


def get_check_conn() -> Any:
    """Return a read-only psycopg2 connection to the check engine DB.

    Used for: check_findings, rule_metadata (cross-engine read per ADR-006).
    """
    return _pg_conn(
        "CHECK_DB_HOST", "CHECK_DB_PORT", "CHECK_DB_NAME",
        "CHECK_DB_USER", "CHECK_DB_PASSWORD",
        "threat_engine_check",
    )


def get_vuln_conn() -> Any:
    """Return a read-only psycopg2 connection to the vulnerability engine DB.

    Used for: scan_vulnerabilities, cve_attack_mappings.
    """
    return _pg_conn(
        "VULN_DB_HOST", "VULN_DB_PORT", "VULN_DB_NAME",
        "VULN_DB_USER", "VULN_DB_PASSWORD",
        "threat_engine_vuln",
    )


def get_cdr_conn() -> Any:
    """Return a read-only psycopg2 connection to the CDR engine DB.

    Used for: cdr_findings (tenant-wide, no account_id filter per W-04).
    """
    return _pg_conn(
        "CDR_DB_HOST", "CDR_DB_PORT", "CDR_DB_NAME",
        "CDR_DB_USER", "CDR_DB_PASSWORD",
        "threat_engine_cdr",
    )


def get_inventory_conn() -> Any:
    """Return a read-only psycopg2 connection to the inventory engine DB.

    Used for: inventory_findings, inventory_relationships,
              resource_inventory_identifier.
    """
    return _pg_conn(
        "INVENTORY_DB_HOST", "INVENTORY_DB_PORT", "INVENTORY_DB_NAME",
        "INVENTORY_DB_USER", "INVENTORY_DB_PASSWORD",
        "threat_engine_inventory",
    )


def get_neo4j_driver() -> Driver:
    """Return a Neo4j driver connected to the Aura instance.

    All sessions must explicitly use database='threat_v1'.
    """
    uri = os.environ["NEO4J_URI"]
    username = os.environ.get("NEO4J_USERNAME", "neo4j")
    password = os.environ["NEO4J_PASSWORD"]
    return GraphDatabase.driver(uri, auth=(username, password))
