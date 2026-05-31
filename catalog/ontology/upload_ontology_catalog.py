"""
Upload resource_ontology.yaml to resource_ontology_catalog table in threat_engine_di.

Usage (production):
    kubectl cp catalog/ontology/resource_ontology.yaml \\
        threat-engine-engines/<pod>:/tmp/resource_ontology.yaml
    kubectl cp catalog/ontology/upload_ontology_catalog.py \\
        threat-engine-engines/<pod>:/tmp/upload_ontology_catalog.py
    kubectl exec -n threat-engine-engines <pod> -- python3 /tmp/upload_ontology_catalog.py
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import psycopg2
import psycopg2.extras
import yaml

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("upload_ontology_catalog")

YAML_PATH = Path(__file__).parent / "resource_ontology.yaml"

DELETE_SQL = """
DELETE FROM resource_ontology_catalog
WHERE csp = %(csp)s
  AND resource_type = %(resource_type)s
  AND COALESCE(entry_point_category,   '') = COALESCE(%(entry_point_category)s,   '')
  AND COALESCE(attack_target_category, '') = COALESCE(%(attack_target_category)s, '')
"""

INSERT_SQL = """
INSERT INTO resource_ontology_catalog (
    csp, resource_type, entry_point_category, attack_target_category,
    is_conditional, condition_field, condition_value, condition_operator,
    description, is_active, updated_at
) VALUES (
    %(csp)s, %(resource_type)s, %(entry_point_category)s, %(attack_target_category)s,
    %(is_conditional)s, %(condition_field)s, %(condition_value)s, %(condition_operator)s,
    %(description)s, TRUE, NOW()
)
"""


def _get_conn() -> "psycopg2.connection":
    host     = os.environ.get("DI_DB_HOST") or os.environ.get("INVENTORY_DB_HOST", "")
    port     = int(os.environ.get("DI_DB_PORT") or os.environ.get("INVENTORY_DB_PORT", "5432"))
    dbname   = os.environ.get("DI_DB_NAME") or os.environ.get("INVENTORY_DB_NAME", "threat_engine_di")
    user     = os.environ.get("DI_DB_USER") or os.environ.get("INVENTORY_DB_USER", "")
    password = os.environ.get("DI_DB_PASSWORD") or os.environ.get("INVENTORY_DB_PASSWORD", "")
    if not host or not user:
        raise RuntimeError("DB env vars not set: DI_DB_HOST / DI_DB_USER / DI_DB_PASSWORD")
    return psycopg2.connect(host=host, port=port, dbname=dbname, user=user, password=password)


def _build_rows(catalog: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for r in catalog.get("resources", []):
        rows.append({
            "csp":                   r["csp"],
            "resource_type":         r["resource_type"],
            "entry_point_category":  r.get("entry_point_category"),
            "attack_target_category": r.get("attack_target_category"),
            "is_conditional":        r.get("is_conditional", False),
            "condition_field":       r.get("condition_field"),
            "condition_value":       str(r["condition_value"]) if r.get("condition_value") is not None else None,
            "condition_operator":    r.get("condition_operator", "eq"),
            "description":           r.get("description"),
        })
    return rows


def upload() -> None:
    yaml_path = YAML_PATH
    if not yaml_path.exists():
        # When running from /tmp, look for the file there
        yaml_path = Path("/tmp/resource_ontology.yaml")
    if not yaml_path.exists():
        raise FileNotFoundError(f"resource_ontology.yaml not found at {YAML_PATH} or /tmp/")

    catalog = yaml.safe_load(yaml_path.read_text())
    rows = _build_rows(catalog)
    if not rows:
        logger.error("No resources found in YAML")
        sys.exit(1)

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            # Delete-then-insert upsert: handles COALESCE unique index correctly
            psycopg2.extras.execute_batch(cur, DELETE_SQL, rows, page_size=100)
            psycopg2.extras.execute_batch(cur, INSERT_SQL, rows, page_size=100)
        conn.commit()

        # Count by CSP
        with conn.cursor() as cur:
            cur.execute("""
                SELECT csp,
                       COUNT(*) FILTER (WHERE entry_point_category IS NOT NULL) AS entry_pts,
                       COUNT(*) FILTER (WHERE attack_target_category IS NOT NULL) AS targets,
                       COUNT(*) AS total
                FROM resource_ontology_catalog
                WHERE is_active = TRUE
                GROUP BY csp ORDER BY csp
            """)
            logger.info("Upload complete — %d total rules", len(rows))
            for row in cur.fetchall():
                logger.info(
                    "  csp=%-10s  entry_points=%d  targets=%d  total=%d",
                    *row
                )
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    try:
        upload()
    except Exception as exc:
        logger.error("Upload failed: %s", exc)
        sys.exit(1)
