"""
Upload attack objective catalog to attack_objective_catalog table in threat_engine_di.

Reads every *.yaml file in this directory, upserts all target_resources rows,
and reports counts per objective type.

Usage (local dev):
    python catalog/attack_objectives/upload_objective_catalog.py

Usage via kubectl (production):
    kubectl exec -n threat-engine-engines deployment/engine-di -- python3 /app/catalog/attack_objectives/upload_objective_catalog.py
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
logger = logging.getLogger("upload_objective_catalog")

CATALOG_DIR = Path(__file__).parent

UPSERT_SQL = """
INSERT INTO attack_objective_catalog (
    objective_type, description, provider, resource_type,
    service_category, service_subcategory,
    required_capability, crown_jewel_type, mitre_technique,
    is_active, updated_at
)
VALUES (
    %(objective_type)s, %(description)s, %(provider)s, %(resource_type)s,
    %(service_category)s, %(service_subcategory)s,
    %(required_capability)s, %(crown_jewel_type)s, %(mitre_technique)s,
    TRUE, NOW()
)
ON CONFLICT (objective_type, provider, resource_type) DO UPDATE SET
    description         = EXCLUDED.description,
    service_category    = EXCLUDED.service_category,
    service_subcategory = EXCLUDED.service_subcategory,
    required_capability = EXCLUDED.required_capability,
    crown_jewel_type    = EXCLUDED.crown_jewel_type,
    mitre_technique     = EXCLUDED.mitre_technique,
    is_active           = TRUE,
    updated_at          = NOW()
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


def _build_rows(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    objective_type      = doc["objective_type"]
    description         = doc.get("description", "")
    required_capability = doc["required_capability"]
    crown_jewel_type    = doc.get("crown_jewel_type")
    mitre_technique     = doc.get("mitre_technique")

    rows = []
    for res in doc.get("target_resources", []):
        rows.append({
            "objective_type":      objective_type,
            "description":         description,
            "provider":            res["provider"],
            "resource_type":       res["resource_type"],
            "service_category":    res.get("service_category"),
            "service_subcategory": res.get("service_subcategory"),
            "required_capability": required_capability,
            "crown_jewel_type":    crown_jewel_type,
            "mitre_technique":     mitre_technique,
        })
    return rows


def run() -> None:
    yaml_files = sorted(CATALOG_DIR.glob("*.yaml"))
    if not yaml_files:
        logger.error("No YAML files found in %s", CATALOG_DIR)
        sys.exit(1)

    conn = _get_conn()
    total = 0

    try:
        with conn.cursor() as cur:
            for path in yaml_files:
                doc = _load_yaml(path)
                rows = _build_rows(doc)
                if not rows:
                    continue
                psycopg2.extras.execute_batch(cur, UPSERT_SQL, rows, page_size=200)
                logger.info("  %-30s  %d rows", doc["objective_type"], len(rows))
                total += len(rows)

        conn.commit()

        # Summary
        with conn.cursor() as cur:
            cur.execute(
                "SELECT objective_type, COUNT(*) FROM attack_objective_catalog "
                "WHERE is_active=TRUE GROUP BY objective_type ORDER BY objective_type"
            )
            rows_summary = cur.fetchall()

        logger.info("─" * 60)
        logger.info("UPLOAD COMPLETE — %d rows in attack_objective_catalog", total)
        logger.info("%-30s  %s", "objective_type", "rows")
        for obj_type, cnt in rows_summary:
            logger.info("  %-28s  %d", obj_type, cnt)

    finally:
        conn.close()


if __name__ == "__main__":
    run()
