"""
Upload IAM resource policy rules and action→resource mappings to threat_engine_iam.

Tables written:
  iam_resource_policy_rules   — which resource types carry resource-based policies
  iam_action_resource_map     — action prefix → resource types for wildcard expansion

Usage (local dev):
    python catalog/iam/upload_iam_policy_rules.py

Usage via kubectl (production):
    kubectl exec -n threat-engine-engines deployment/engine-iam -- python3 -c "
    import subprocess, sys
    subprocess.run([sys.executable, 'catalog/iam/upload_iam_policy_rules.py'],
                   cwd='/app', check=True)
    "
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
logger = logging.getLogger("upload_iam_policy_rules")

CATALOG_DIR = Path(__file__).parent
CSPS = ["aws", "azure", "gcp", "oci", "alicloud", "ibm"]

UPSERT_RPR = """
INSERT INTO iam_resource_policy_rules (
    csp, resource_type, policy_field, principal_key,
    relation_type, attack_path_category, description, is_active
) VALUES (
    %(csp)s, %(resource_type)s, %(policy_field)s, %(principal_key)s,
    %(relation_type)s, %(attack_path_category)s, %(description)s, %(is_active)s
)
ON CONFLICT (csp, resource_type, policy_field, principal_key)
DO UPDATE SET
    relation_type        = EXCLUDED.relation_type,
    attack_path_category = EXCLUDED.attack_path_category,
    description          = EXCLUDED.description,
    is_active            = EXCLUDED.is_active
"""

UPSERT_ARM = """
INSERT INTO iam_action_resource_map (
    csp, action_prefix, resource_types, attack_path_category, description, is_active
) VALUES (
    %(csp)s, %(action_prefix)s, %(resource_types)s,
    %(attack_path_category)s, %(description)s, %(is_active)s
)
ON CONFLICT (csp, action_prefix)
DO UPDATE SET
    resource_types       = EXCLUDED.resource_types,
    attack_path_category = EXCLUDED.attack_path_category,
    description          = EXCLUDED.description,
    is_active            = EXCLUDED.is_active
"""


def _get_conn() -> "psycopg2.connection":
    host     = os.environ.get("IAM_DB_HOST", "")
    port     = int(os.environ.get("IAM_DB_PORT", "5432"))
    dbname   = os.environ.get("IAM_DB_NAME", "threat_engine_iam")
    user     = os.environ.get("IAM_DB_USER", "")
    password = os.environ.get("IAM_DB_PASSWORD", "")
    if not host or not user:
        raise RuntimeError("IAM DB env vars not set: IAM_DB_HOST / IAM_DB_USER / IAM_DB_PASSWORD")
    return psycopg2.connect(host=host, port=port, dbname=dbname, user=user, password=password)


def _load_yaml(path: Path) -> Dict[str, Any]:
    with path.open() as f:
        return yaml.safe_load(f)


def _rpr_rows(csp: str, catalog: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for rule in catalog.get("rules", []):
        rows.append({
            "csp":                  csp,
            "resource_type":        rule["resource_type"],
            "policy_field":         rule["policy_field"],
            "principal_key":        rule.get("principal_key"),
            "relation_type":        rule.get("relation_type", "GRANTS_ACCESS_TO"),
            "attack_path_category": rule.get("attack_path_category", "data_access"),
            "description":          rule.get("description"),
            "is_active":            rule.get("is_active", True),
        })
    return rows


def _arm_rows(csp: str, catalog: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for rule in catalog.get("rules", []):
        rows.append({
            "csp":                  csp,
            "action_prefix":        rule["action_prefix"],
            "resource_types":       rule["resource_types"],
            "attack_path_category": rule.get("attack_path_category", "lateral_movement"),
            "description":          rule.get("description"),
            "is_active":            rule.get("is_active", True),
        })
    return rows


def upload() -> None:
    conn = _get_conn()
    total_rpr = 0
    total_arm = 0

    try:
        for csp in CSPS:
            # resource_policy_rules
            rpr_path = CATALOG_DIR / csp / "resource_policy_rules.yaml"
            if rpr_path.exists():
                catalog = _load_yaml(rpr_path)
                rows = _rpr_rows(csp, catalog)
                if rows:
                    with conn.cursor() as cur:
                        psycopg2.extras.execute_batch(cur, UPSERT_RPR, rows, page_size=100)
                    conn.commit()
                    logger.info("csp=%-10s  resource_policy_rules: upserted %d", csp, len(rows))
                    total_rpr += len(rows)

            # action_resource_map
            arm_path = CATALOG_DIR / csp / "action_resource_map.yaml"
            if arm_path.exists():
                catalog = _load_yaml(arm_path)
                rows = _arm_rows(csp, catalog)
                if rows:
                    with conn.cursor() as cur:
                        psycopg2.extras.execute_batch(cur, UPSERT_ARM, rows, page_size=100)
                    conn.commit()
                    logger.info("csp=%-10s  action_resource_map:   upserted %d", csp, len(rows))
                    total_arm += len(rows)

        logger.info(
            "Upload complete — resource_policy_rules=%d  action_resource_map=%d",
            total_rpr, total_arm,
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
