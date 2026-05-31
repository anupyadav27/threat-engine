"""
Upload infrastructure attachment relationship rules to resource_relationship_catalog
in threat_engine_di.

Usage (local dev):
    python catalog/relationships/upload_relationship_catalog.py

Usage via kubectl (production):
    kubectl exec -n threat-engine-engines deployment/engine-di -- python3 -c "
    import subprocess, sys
    subprocess.run([sys.executable, 'catalog/relationships/upload_relationship_catalog.py'],
                   cwd='/app', check=True)
    "

The script walks catalog/relationships/{csp}/infrastructure_attachment.yaml for each CSP,
upserts every rule into resource_relationship_catalog, and reports counts.
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
logger = logging.getLogger("upload_relationship_catalog")

CATALOG_DIR = Path(__file__).parent
CSPS = ["aws", "azure", "gcp", "oci", "alicloud", "ibm", "k8s"]

UPSERT_SQL = """
INSERT INTO resource_relationship_catalog (
    csp, source_resource_type, target_resource_type, relation_type,
    relationship_category, field_path, field_path_type,
    target_identifier_field, policy_principal_key, policy_effect_filter,
    attack_path_category, description, is_active, graph_role, updated_at
) VALUES (
    %(csp)s, %(source_resource_type)s, %(target_resource_type)s, %(relation_type)s,
    %(relationship_category)s, %(field_path)s, %(field_path_type)s,
    %(target_identifier_field)s, %(policy_principal_key)s, %(policy_effect_filter)s,
    %(attack_path_category)s, %(description)s, %(is_active)s, %(graph_role)s, NOW()
)
ON CONFLICT (csp, source_resource_type, relation_type, field_path)
DO UPDATE SET
    target_resource_type    = EXCLUDED.target_resource_type,
    relationship_category   = EXCLUDED.relationship_category,
    field_path_type         = EXCLUDED.field_path_type,
    target_identifier_field = EXCLUDED.target_identifier_field,
    policy_principal_key    = EXCLUDED.policy_principal_key,
    policy_effect_filter    = EXCLUDED.policy_effect_filter,
    attack_path_category    = EXCLUDED.attack_path_category,
    description             = EXCLUDED.description,
    is_active               = EXCLUDED.is_active,
    graph_role              = EXCLUDED.graph_role,
    updated_at              = NOW()
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


def _load_yaml(path: Path) -> Dict[str, Any]:
    with path.open() as f:
        return yaml.safe_load(f)


def _build_rows(csp: str, catalog: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert YAML catalog entries into DB row dicts."""
    category = catalog.get("category", "infrastructure")
    rows = []
    for rule in catalog.get("rules", []):
        rows.append({
            "csp":                   csp,
            "source_resource_type":  rule["source_resource_type"],
            "target_resource_type":  rule["target_resource_type"],
            "relation_type":         rule["relation_type"],
            "relationship_category": category,
            "field_path":            rule["field_path"],
            "field_path_type":       rule.get("field_path_type", "field_ref"),
            "target_identifier_field": rule.get("target_identifier_field"),
            "policy_principal_key":  rule.get("policy_principal_key"),
            "policy_effect_filter":  rule.get("policy_effect_filter"),
            "attack_path_category":  rule.get("attack_path_category"),
            "description":           rule.get("description"),
            "is_active":             rule.get("is_active", True),
            "graph_role":            rule.get("graph_role", "context"),
        })
    return rows


def upload() -> None:
    conn = _get_conn()
    total_upserted = 0

    try:
        for csp in CSPS:
            yaml_path = CATALOG_DIR / csp / "infrastructure_attachment.yaml"
            if not yaml_path.exists():
                logger.debug("No catalog for csp=%s (path %s not found)", csp, yaml_path)
                continue

            catalog = _load_yaml(yaml_path)
            rows = _build_rows(csp, catalog)
            if not rows:
                logger.warning("csp=%s: no rules found in %s", csp, yaml_path)
                continue

            with conn.cursor() as cur:
                psycopg2.extras.execute_batch(cur, UPSERT_SQL, rows, page_size=100)
            conn.commit()

            logger.info("csp=%-10s  upserted %d rules", csp, len(rows))
            total_upserted += len(rows)

        logger.info("Upload complete — %d total rules across all CSPs", total_upserted)

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
