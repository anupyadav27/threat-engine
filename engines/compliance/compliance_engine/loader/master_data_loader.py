"""
Master Data Loader

Loads compliance_master.json into DB tables:
  - compliance_frameworks (upsert)
  - compliance_controls (upsert, add new columns)
  - rule_control_mapping (insert, skip duplicates)
"""

import os
import json
import logging
import psycopg2
from psycopg2.extras import execute_values
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


def _get_conn():
    return psycopg2.connect(
        host=os.getenv("COMPLIANCE_DB_HOST", "localhost"),
        port=int(os.getenv("COMPLIANCE_DB_PORT", "5432")),
        database=os.getenv("COMPLIANCE_DB_NAME", "threat_engine_compliance"),
        user=os.getenv("COMPLIANCE_DB_USER", "postgres"),
        password=os.getenv("COMPLIANCE_DB_PASSWORD", ""),
    )


def _ensure_columns(conn):
    """Add new columns to compliance_controls if they don't exist."""
    with conn.cursor() as cur:
        for col, typ in [
            ("assessment_type", "VARCHAR(20)"),
            ("provider", "VARCHAR(20)"),
            ("profile_level", "VARCHAR(10)"),
            ("rationale", "TEXT"),
            ("audit_procedure", "TEXT"),
            ("audit_cli", "TEXT"),
            ("remediation", "TEXT"),
            ("remediation_cli", "TEXT"),
            ("default_value", "TEXT"),
            ("impact", "TEXT"),
            ('"references"', "JSONB"),
        ]:
            try:
                cur.execute(
                    f"ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS {col} {typ}"
                )
            except Exception as e:
                logger.debug(f"Column {col} may already exist: {e}")
                conn.rollback()
    conn.commit()


def load_master_data(master_path: Optional[str] = None) -> Dict[str, int]:
    """Load compliance_master.json into DB tables.

    Returns dict with counts of rows upserted per table.
    """
    if not master_path:
        # Look in standard locations
        for p in [
            "/app/data/compliance_master.json",
            os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "compliance_master.json"),
            os.path.join(os.path.dirname(__file__), "..", "..", "data", "compliance_master.json"),
        ]:
            if os.path.exists(p):
                master_path = p
                break

    if not master_path or not os.path.exists(master_path):
        raise FileNotFoundError(f"compliance_master.json not found at {master_path}")

    with open(master_path) as f:
        master = json.load(f)

    conn = _get_conn()
    try:
        _ensure_columns(conn)

        fw_count = _upsert_frameworks(conn, master.get("frameworks", []))
        ctrl_count = _upsert_controls(conn, master.get("controls", []))
        mapping_count = _upsert_rule_mappings(conn, master.get("controls", []))

        conn.commit()
        result = {
            "frameworks": fw_count,
            "controls": ctrl_count,
            "rule_mappings": mapping_count,
        }
        logger.info(f"Master data loaded: {result}")
        return result

    except Exception as e:
        conn.rollback()
        raise RuntimeError(f"Failed to load master data: {e}") from e
    finally:
        conn.close()


def _upsert_frameworks(conn, frameworks: List[Dict]) -> int:
    """Upsert compliance_frameworks."""
    count = 0
    with conn.cursor() as cur:
        for fw in frameworks:
            cur.execute("""
                INSERT INTO compliance_frameworks (
                    framework_id, framework_name, version, description,
                    authority, category, is_active, framework_data
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (framework_id) DO UPDATE SET
                    framework_name = COALESCE(EXCLUDED.framework_name, compliance_frameworks.framework_name),
                    version = COALESCE(EXCLUDED.version, compliance_frameworks.version),
                    description = COALESCE(EXCLUDED.description, compliance_frameworks.description),
                    authority = COALESCE(EXCLUDED.authority, compliance_frameworks.authority),
                    category = COALESCE(EXCLUDED.category, compliance_frameworks.category),
                    is_active = EXCLUDED.is_active,
                    updated_at = NOW()
            """, (
                fw["framework_id"],
                fw.get("framework_name"),
                fw.get("version"),
                fw.get("description"),
                fw.get("authority"),
                fw.get("category"),
                fw.get("is_active", True),
                json.dumps({"provider": fw.get("provider"), "total_controls": fw.get("total_controls", 0)}),
            ))
            count += 1
    return count


def _upsert_controls(conn, controls: List[Dict]) -> int:
    """Upsert compliance_controls with all fields."""
    count = 0
    batch = []
    BATCH_SIZE = 500

    for c in controls:
        batch.append((
            c["control_id"],
            c["framework_id"],
            c.get("control_number"),
            c.get("control_name") or c["control_id"],  # NOT NULL — fallback to control_id
            c.get("control_description"),
            c.get("control_type"),
            c.get("severity"),
            c.get("control_family"),
            c.get("implementation_guidance"),
            c.get("testing_procedures"),
            c.get("is_active", True),
            c.get("assessment_type", "automated"),
            c.get("provider"),
            c.get("profile_level"),
            c.get("rationale"),
            c.get("audit_procedure"),
            c.get("remediation"),
            c.get("default_value"),
            c.get("impact"),
            json.dumps(c.get("references")) if c.get("references") else None,
        ))

        if len(batch) >= BATCH_SIZE:
            count += _insert_control_batch(conn, batch)
            batch = []

    if batch:
        count += _insert_control_batch(conn, batch)
    return count


def _insert_control_batch(conn, batch):
    with conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO compliance_controls (
                control_id, framework_id, control_number, control_name,
                control_description, control_type, severity, control_family,
                implementation_guidance, testing_procedures, is_active,
                assessment_type, provider, profile_level,
                rationale, audit_procedure, remediation, default_value,
                impact, "references"
            ) VALUES %s
            ON CONFLICT (control_id) DO UPDATE SET
                control_name = COALESCE(EXCLUDED.control_name, compliance_controls.control_name),
                control_description = COALESCE(EXCLUDED.control_description, compliance_controls.control_description),
                severity = COALESCE(EXCLUDED.severity, compliance_controls.severity),
                control_family = COALESCE(EXCLUDED.control_family, compliance_controls.control_family),
                implementation_guidance = COALESCE(EXCLUDED.implementation_guidance, compliance_controls.implementation_guidance),
                testing_procedures = COALESCE(EXCLUDED.testing_procedures, compliance_controls.testing_procedures),
                assessment_type = COALESCE(EXCLUDED.assessment_type, compliance_controls.assessment_type),
                provider = COALESCE(EXCLUDED.provider, compliance_controls.provider),
                updated_at = NOW()
        """, batch, page_size=500)
    return len(batch)


def _upsert_rule_mappings(conn, controls: List[Dict]) -> int:
    """Insert rule_control_mapping from master controls' mapped_rules."""
    count = 0
    batch = []
    BATCH_SIZE = 500

    import uuid as _uuid
    for c in controls:
        for rule in c.get("mapped_rules", []):
            batch.append((
                str(_uuid.uuid4()),
                rule["rule_id"],
                c["control_id"],
                c["framework_id"],
                "automated",
                100,
                True,
            ))
            if len(batch) >= BATCH_SIZE:
                count += _insert_mapping_batch(conn, batch)
                batch = []

    if batch:
        count += _insert_mapping_batch(conn, batch)
    return count


def _insert_mapping_batch(conn, batch):
    with conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO rule_control_mapping (
                mapping_id, rule_id, control_id, framework_id,
                mapping_type, coverage_percentage, is_active
            ) VALUES %s
            ON CONFLICT (rule_id, control_id) DO NOTHING
        """, batch, page_size=500)
    return len(batch)
