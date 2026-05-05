"""Idempotent MITRE ATT&CK reference loader (JNY-01 — REWORKED).

Loads the bundled CSV seed (``mitre_technique_reference.csv``) into the
EXISTING ``mitre_technique_reference`` table in the ``threat_engine_threat``
database without overwriting curated data.

Schema reality (MV-1 verified 2026-05-04):
    The table already exists in production with 102 curated rows and these
    columns: id, technique_id, technique_name, tactics (JSONB),
    sub_techniques (JSONB), description, url, platforms (JSONB), aws_checks,
    azure_checks, gcp_checks, ibm_keywords, k8s_keywords, ocp_keywords,
    aws_service_coverage, detection_keywords, detection_guidance,
    remediation_guidance, severity_base, created_at, updated_at.

    Migration ``threat_mitre_technique_ref_001.sql`` adds 9 new columns:
    parent_id, is_subtechnique, kill_chain_phases, mitigations,
    d3fend_mappings, revoked, deprecated, version, last_modified.

UPSERT policy:
    - NEW columns are always set from CSV (CSV is the source of truth for
      these — they didn't exist before).
    - LEGACY columns (technique_name, description, tactics, sub_techniques,
      platforms, url, severity_base) are set ONLY if the CSV has a non-empty
      value AND the existing column is NULL. This preserves the 102 curated
      rows without overwriting them.

Security:
    The CSV is a security-sensitive bundled artifact (drives detection
    severity / kill-chain mapping in the UI). Before parsing, this loader
    verifies the CSV's SHA-256 against the sibling ``.sha256`` file. If the
    hash does not match, the loader **fails loud** — no rows are written.

Idempotency:
    Uses ``INSERT ... ON CONFLICT (technique_id) DO UPDATE``. Re-running with
    an unchanged CSV is a no-op for unchanged rows.

Invocation:
    python -m scripts.load_mitre_reference
    python /app/scripts/load_mitre_reference.py
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import sys
from typing import Iterator, List, Optional, Tuple

import psycopg2
from psycopg2.extensions import connection as PgConnection
from psycopg2.extras import execute_values

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [load_mitre_reference] %(message)s",
)
logger = logging.getLogger(__name__)


# ── Paths ────────────────────────────────────────────────────────────────────
DEFAULT_SEED_PATH = "/app/seeds/mitre_technique_reference.csv"
SEED_PATH: str = os.environ.get("MITRE_SEED_CSV", DEFAULT_SEED_PATH)
SHA256_PATH: str = SEED_PATH + ".sha256"

CHUNK_SIZE: int = 500


# ── DB connection (mirrors engine_common.db_connections.get_threat_conn) ─────
def _get_threat_conn() -> PgConnection:
    """Open a psycopg2 connection to threat_engine_threat using THREAT_* env vars."""
    host = os.environ.get("THREAT_DB_HOST", os.environ.get("DB_HOST", "localhost"))
    port = int(os.environ.get("THREAT_DB_PORT", os.environ.get("DB_PORT", "5432")))
    user = os.environ.get("THREAT_DB_USER", os.environ.get("DB_USER", "postgres"))
    password = os.environ.get(
        "THREAT_DB_PASSWORD", os.environ.get("DB_PASSWORD", "")
    )
    dbname = os.environ.get(
        "THREAT_DB_NAME", os.environ.get("DB_NAME", "threat_engine_threat")
    )
    return psycopg2.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        dbname=dbname,
        connect_timeout=10,
    )


# ── SHA-256 verification ─────────────────────────────────────────────────────
def _read_expected_hash(sha256_path: str) -> str:
    """Read the expected SHA-256 from the sibling ``.sha256`` file."""
    with open(sha256_path, "r", encoding="utf-8") as f:
        first_token = f.readline().strip().split()
        if not first_token:
            raise ValueError(f"Empty .sha256 file: {sha256_path}")
        return first_token[0].lower()


def _compute_sha256(path: str) -> str:
    """Return the lowercase hex SHA-256 of the file at ``path``."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_csv_integrity(csv_path: str, sha256_path: str) -> str:
    """Verify CSV SHA-256 matches sibling .sha256 file.

    Returns:
        The verified hex digest (lowercase).

    Raises:
        FileNotFoundError: If either file is missing.
        ValueError: If the hashes do not match.
    """
    expected = _read_expected_hash(sha256_path)
    actual = _compute_sha256(csv_path)
    if actual != expected:
        raise ValueError(
            "MITRE seed CSV SHA-256 mismatch — refusing to load. "
            f"expected={expected} actual={actual} path={csv_path}"
        )
    logger.info("MITRE seed CSV SHA-256 verified: %s", actual)
    return actual


# ── CSV parsing ──────────────────────────────────────────────────────────────
_BOOL_TRUE = {"true", "1", "yes", "y", "t"}


def _to_bool(s: Optional[str]) -> bool:
    return (s or "").strip().lower() in _BOOL_TRUE


def _to_jsonb_or_empty_array(s: Optional[str]) -> str:
    """JSONB literal for new array columns. Empty -> '[]'."""
    raw = (s or "").strip()
    if not raw:
        return "[]"
    json.loads(raw)  # validate
    return raw


def _to_jsonb_or_null(s: Optional[str]) -> Optional[str]:
    """JSONB literal for legacy columns. Empty -> None (so COALESCE preserves DB value)."""
    raw = (s or "").strip()
    if not raw:
        return None
    json.loads(raw)  # validate
    return raw


def _str_or_none(s: Optional[str]) -> Optional[str]:
    raw = (s or "").strip()
    return raw or None


def _rows(path: str) -> Iterator[Tuple]:
    """Yield psycopg2-ready tuples from the CSV.

    Tuple order MUST match _UPSERT_SQL VALUES placeholders.
    """
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            yield (
                # PK
                r["technique_id"].strip(),
                # Legacy columns (None when CSV cell empty -> COALESCE keeps DB value)
                _str_or_none(r.get("technique_name")),
                _str_or_none(r.get("description")),
                _to_jsonb_or_null(r.get("tactics")),
                _to_jsonb_or_null(r.get("sub_techniques")),
                _to_jsonb_or_null(r.get("platforms")),
                _str_or_none(r.get("url")),
                _str_or_none(r.get("severity_base")),
                # New columns (always written from CSV)
                _str_or_none(r.get("parent_id")),
                _to_bool(r.get("is_subtechnique")),
                _to_jsonb_or_empty_array(r.get("kill_chain_phases")),
                _to_jsonb_or_empty_array(r.get("mitigations")),
                _to_jsonb_or_empty_array(r.get("d3fend_mappings")),
                _to_bool(r.get("revoked")),
                _to_bool(r.get("deprecated")),
                _str_or_none(r.get("version")),
                _str_or_none(r.get("last_modified")),
            )


# ── Upsert SQL ───────────────────────────────────────────────────────────────
# For LEGACY columns we use COALESCE(target.col, EXCLUDED.col) so:
#   - INSERT path: EXCLUDED is taken (target row is being created).
#   - UPDATE path: existing curated value is preserved when non-NULL; CSV fills
#     NULL gaps only.
# For NEW columns we always overwrite with EXCLUDED — CSV is the source of truth.
_UPSERT_SQL = """
INSERT INTO mitre_technique_reference (
    technique_id,
    technique_name, description, tactics, sub_techniques, platforms, url, severity_base,
    parent_id, is_subtechnique, kill_chain_phases, mitigations, d3fend_mappings,
    revoked, deprecated, version, last_modified
) VALUES %s
ON CONFLICT (technique_id) DO UPDATE SET
    technique_name    = COALESCE(mitre_technique_reference.technique_name,    EXCLUDED.technique_name),
    description       = COALESCE(mitre_technique_reference.description,       EXCLUDED.description),
    tactics           = COALESCE(mitre_technique_reference.tactics,           EXCLUDED.tactics),
    sub_techniques    = COALESCE(mitre_technique_reference.sub_techniques,    EXCLUDED.sub_techniques),
    platforms         = COALESCE(mitre_technique_reference.platforms,         EXCLUDED.platforms),
    url               = COALESCE(mitre_technique_reference.url,               EXCLUDED.url),
    severity_base     = COALESCE(mitre_technique_reference.severity_base,     EXCLUDED.severity_base),
    parent_id         = EXCLUDED.parent_id,
    is_subtechnique   = EXCLUDED.is_subtechnique,
    kill_chain_phases = EXCLUDED.kill_chain_phases,
    mitigations       = EXCLUDED.mitigations,
    d3fend_mappings   = EXCLUDED.d3fend_mappings,
    revoked           = EXCLUDED.revoked,
    deprecated        = EXCLUDED.deprecated,
    version           = EXCLUDED.version,
    last_modified     = EXCLUDED.last_modified,
    updated_at        = NOW()
RETURNING (xmax = 0) AS inserted
"""

# Template ensures JSONB columns are cast correctly from JSON-text bind params.
# Order matches the columns list in _UPSERT_SQL exactly.
_VALUES_TEMPLATE = (
    "("
    "%s, "                                    # technique_id
    "%s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s, "  # legacy: name, desc, tactics, sub_t, platforms, url, sev
    "%s, %s, %s::jsonb, %s::jsonb, %s::jsonb, "          # parent_id, is_sub, kill_chain, mitigations, d3fend
    "%s, %s, %s, %s::timestamptz"                          # revoked, deprecated, version, last_modified
    ")"
)


# ── Loader ───────────────────────────────────────────────────────────────────
def load(conn: PgConnection, csv_path: str) -> Tuple[int, int]:
    """Upsert all rows from ``csv_path`` in a single transaction.

    Returns:
        (inserted_count, updated_count)
    """
    inserted = 0
    updated = 0
    with conn.cursor() as cur:
        batch: List[Tuple] = []

        def _flush() -> None:
            nonlocal inserted, updated
            if not batch:
                return
            results = execute_values(
                cur, _UPSERT_SQL, batch, template=_VALUES_TEMPLATE, fetch=True
            )
            for row in results:
                if row[0]:
                    inserted += 1
                else:
                    updated += 1
            batch.clear()

        for row in _rows(csv_path):
            batch.append(row)
            if len(batch) >= CHUNK_SIZE:
                _flush()
        _flush()

    conn.commit()
    return inserted, updated


def main() -> int:
    """Entry point.

    Returns:
        Process exit code (0 on success, 1 on hash mismatch / DB failure).
    """
    if not os.path.isfile(SEED_PATH):
        logger.error("Seed CSV not found at %s", SEED_PATH)
        return 1
    if not os.path.isfile(SHA256_PATH):
        logger.error("Seed .sha256 not found at %s", SHA256_PATH)
        return 1

    try:
        verify_csv_integrity(SEED_PATH, SHA256_PATH)
    except (FileNotFoundError, ValueError) as exc:
        logger.error("Integrity check FAILED: %s", exc)
        return 1

    try:
        conn = _get_threat_conn()
    except psycopg2.OperationalError as exc:
        logger.error("Could not connect to threat_engine_threat: %s", exc)
        return 1

    try:
        inserted, updated = load(conn, SEED_PATH)
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM mitre_technique_reference")
            total = cur.fetchone()[0]
        logger.info(
            "MITRE reference load OK: inserted=%d updated=%d table_total=%d",
            inserted,
            updated,
            total,
        )
    except psycopg2.DatabaseError as exc:
        conn.rollback()
        logger.error("DB error during MITRE reference load: %s", exc)
        return 1
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
