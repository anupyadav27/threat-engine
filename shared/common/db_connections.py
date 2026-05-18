"""
Centralized DB connection factories for all domain engines.

Every engine uses the same pattern:
  - Engine-specific env vars (e.g. DISCOVERIES_DB_HOST) with DB_* fallbacks.
  - Password resolution: engine-specific → DB_PASSWORD → DISCOVERIES_DB_PASSWORD
    (K8s Job pods get DISCOVERIES_DB_PASSWORD via secretKeyRef, not DB_PASSWORD)
  - sslmode controlled by DB_SSLMODE (default: prefer).

Import as:
    from engine_common.db_connections import get_discoveries_conn, get_check_conn
"""

import os
import psycopg2


def _resolve_password(prefix: str) -> str:
    """Resolve DB password with three-level fallback.

    K8s Job pods receive individual engine passwords (e.g. NETWORK_DB_PASSWORD)
    and DISCOVERIES_DB_PASSWORD via the threat-engine-db-passwords secret.
    DB_PASSWORD is also injected via job_creator for compatibility.
    """
    p = prefix.upper()
    return (
        os.getenv(f"{p}_DB_PASSWORD")
        or os.getenv("DB_PASSWORD")
        or os.getenv("DISCOVERIES_DB_PASSWORD", "")
    )


def _make_conn(prefix: str, default_db: str) -> psycopg2.extensions.connection:
    p = prefix.upper()
    return psycopg2.connect(
        host=os.getenv(f"{p}_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv(f"{p}_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv(f"{p}_DB_NAME", default_db),
        user=os.getenv(f"{p}_DB_USER", os.getenv("DB_USER", "postgres")),
        password=_resolve_password(p),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


# ── Per-engine factories ───────────────────────────────────────────────────────

def get_discoveries_conn() -> psycopg2.extensions.connection:
    return _make_conn("DISCOVERIES", "threat_engine_discoveries")


def get_check_conn() -> psycopg2.extensions.connection:
    return _make_conn("CHECK", "threat_engine_check")


def get_inventory_conn() -> psycopg2.extensions.connection:
    return _make_conn("INVENTORY", "threat_engine_inventory")


def get_onboarding_conn() -> psycopg2.extensions.connection:
    return _make_conn("ONBOARDING", "threat_engine_onboarding")


def get_threat_conn() -> psycopg2.extensions.connection:
    return _make_conn("THREAT", "threat_engine_threat")


def get_compliance_conn() -> psycopg2.extensions.connection:
    return _make_conn("COMPLIANCE", "threat_engine_compliance")


def get_iam_conn() -> psycopg2.extensions.connection:
    return _make_conn("IAM", "threat_engine_iam")


def get_datasec_conn() -> psycopg2.extensions.connection:
    return _make_conn("DATASEC", "threat_engine_datasec")


def get_network_conn() -> psycopg2.extensions.connection:
    return _make_conn("NETWORK", "threat_engine_network")


def get_cdr_conn() -> psycopg2.extensions.connection:
    return _make_conn("CDR", "threat_engine_cdr")


def get_risk_conn() -> psycopg2.extensions.connection:
    return _make_conn("RISK", "threat_engine_risk")


def get_encryption_conn() -> psycopg2.extensions.connection:
    return _make_conn("ENCRYPTION", "threat_engine_encryption")


def get_container_sec_conn() -> psycopg2.extensions.connection:
    return _make_conn("CSEC", "threat_engine_container_security")


def get_dbsec_conn() -> psycopg2.extensions.connection:
    return _make_conn("DBSEC", "threat_engine_dbsec")


def get_ai_security_conn() -> psycopg2.extensions.connection:
    return _make_conn("AI_SECURITY", "threat_engine_ai_security")


def get_attack_path_conn() -> psycopg2.extensions.connection:
    return _make_conn("ATTACK_PATH", "threat_engine_attack_path")


def get_api_security_conn() -> psycopg2.extensions.connection:
    return _make_conn("API_SECURITY", "threat_engine_api_security")
