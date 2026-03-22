"""
Check Findings Reader for DataSec Engine

Reads check_findings from the check engine and maps them to datasec modules
using the rule_metadata.data_security JSONB field.

This is the primary data source for DataSec — the check engine has already
evaluated encryption, access control, lifecycle, logging, etc. against raw
discovery data. DataSec just needs to categorize these results into its
7 modules.

=== DATABASE & TABLE MAP ===
Database: threat_engine_check
Env: CHECK_DB_HOST / CHECK_DB_PORT / CHECK_DB_NAME / CHECK_DB_USER / CHECK_DB_PASSWORD

Tables READ:
  - check_findings    : PASS/FAIL results per rule per resource
  - rule_metadata     : data_security JSONB with {modules, categories, impact, priority}
Tables WRITTEN: None (read-only)
===
"""

import os
import logging
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG_AVAILABLE = True
except ImportError:
    PSYCOPG_AVAILABLE = False

logger = logging.getLogger(__name__)

# Data store services whose check findings are datasec-relevant
DATA_STORE_SERVICES = frozenset({
    's3', 'rds', 'dynamodb', 'redshift', 'glacier', 'documentdb', 'docdb',
    'neptune', 'glue', 'lakeformation', 'macie', 'ecr',
    'kms', 'elasticache', 'dax', 'efs', 'fsx',
})


def _get_check_db_connection():
    """Get Check DB connection using individual parameters."""
    return psycopg2.connect(
        host=os.getenv("CHECK_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("CHECK_DB_PORT", os.getenv("DB_PORT", "5432"))),
        database=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("CHECK_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


class CheckFindingsReader:
    """
    Reads check_findings and maps them to datasec modules using
    rule_metadata.data_security JSONB field.
    """

    def __init__(self):
        self._conn = None
        self._ds_mapping: Dict[str, Dict] = {}  # rule_id -> data_security dict

    def _get_conn(self):
        if self._conn is not None and not self._conn.closed:
            if self._conn.info.transaction_status == psycopg2.extensions.TRANSACTION_STATUS_INERROR:
                self._conn.rollback()
            return self._conn
        if not PSYCOPG_AVAILABLE:
            raise RuntimeError("psycopg2 required for CheckFindingsReader")
        self._conn = _get_check_db_connection()
        return self._conn

    def close(self):
        if self._conn and not self._conn.closed:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def load_datasec_rule_mapping(self, provider: str = "aws") -> Dict[str, Dict]:
        """
        Load rule_metadata.data_security mapping for all data-store service rules.

        Returns:
            Dict mapping rule_id -> {modules: [...], categories: [...], impact: {...}, priority: str}
        """
        conn = self._get_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT rule_id, service, severity, title, description,
                           remediation, domain, data_security,
                           compliance_frameworks
                    FROM rule_metadata
                    WHERE provider = %s
                      AND data_security IS NOT NULL
                      AND data_security::text != 'null'
                      AND data_security::text != '{}'
                """, (provider,))
                rows = cur.fetchall()

            mapping = {}
            for row in rows:
                ds = row.get("data_security") or {}
                if not ds.get("applicable"):
                    continue
                mapping[row["rule_id"]] = {
                    "modules": ds.get("modules", []),
                    "categories": ds.get("categories", []),
                    "impact": ds.get("impact", {}),
                    "priority": ds.get("priority", "medium"),
                    "service": row["service"],
                    "severity": row["severity"],
                    "title": row["title"],
                    "description": row["description"],
                    "remediation": row["remediation"],
                    "domain": row["domain"],
                    "compliance_frameworks": row.get("compliance_frameworks") or [],
                    "sensitive_data_context": ds.get("sensitive_data_context"),
                }

            self._ds_mapping = mapping
            logger.info(f"Loaded {len(mapping)} datasec-mapped rules from rule_metadata")
            return mapping

        except Exception as e:
            logger.error(f"Error loading datasec rule mapping: {e}")
            conn.rollback()
            return {}

    def load_check_findings(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """
        Load check_findings for data-store services, enriched with
        datasec module mapping.

        Only returns findings whose rule_id has a data_security mapping.

        Returns:
            List of finding dicts with added 'datasec_modules' and 'datasec_categories' fields.
        """
        if not self._ds_mapping:
            self.load_datasec_rule_mapping()

        if not self._ds_mapping:
            logger.warning("No datasec rule mapping loaded — no findings will be produced")
            return []

        conn = self._get_conn()
        mapped_rule_ids = list(self._ds_mapping.keys())

        try:
            # Query check_findings for mapped rules
            # Note: check_findings uses 'id' not 'finding_id', and has no 'severity'/'account_id' columns
            placeholders = ",".join(["%s"] * len(mapped_rule_ids))
            query = f"""
                SELECT id AS finding_id, scan_run_id, tenant_id,
                       rule_id, status,
                       resource_type, resource_id, resource_uid,
                       account_id, region,
                       checked_fields, finding_data
                FROM check_findings
                WHERE scan_run_id = %s
                  AND tenant_id = %s
                  AND rule_id IN ({placeholders})
                ORDER BY rule_id, resource_uid
            """
            params = [scan_run_id, tenant_id] + mapped_rule_ids

            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                rows = cur.fetchall()

            findings = []
            for row in rows:
                rule_id = row["rule_id"]
                ds_info = self._ds_mapping.get(rule_id, {})

                finding = dict(row)
                finding["severity"] = ds_info.get("severity", "medium")
                finding["account_id"] = finding.get("account_id", "")
                finding["datasec_modules"] = ds_info.get("modules", [])
                finding["datasec_categories"] = ds_info.get("categories", [])
                finding["datasec_impact"] = ds_info.get("impact", {})
                finding["datasec_priority"] = ds_info.get("priority", "medium")
                finding["title"] = ds_info.get("title", "")
                finding["description"] = ds_info.get("description", "")
                finding["remediation"] = ds_info.get("remediation", "")
                finding["compliance_frameworks"] = ds_info.get("compliance_frameworks", [])
                finding["sensitive_data_context"] = ds_info.get("sensitive_data_context")
                findings.append(finding)

            logger.info(
                f"Loaded {len(findings)} datasec-relevant check findings "
                f"({sum(1 for f in findings if f['status'] == 'FAIL')} FAIL, "
                f"{sum(1 for f in findings if f['status'] == 'PASS')} PASS)"
            )
            return findings

        except Exception as e:
            logger.error(f"Error loading check findings: {e}")
            conn.rollback()
            return []

    def group_by_module(
        self, findings: List[Dict]
    ) -> Dict[str, List[Dict]]:
        """Group findings by datasec module."""
        grouped: Dict[str, List[Dict]] = defaultdict(list)
        for f in findings:
            for module in f.get("datasec_modules", []):
                grouped[module].append(f)
        return dict(grouped)

    def to_module_results(
        self, findings: List[Dict]
    ) -> Dict[str, List]:
        """
        Convert check findings to ModuleResult objects grouped by module.

        This is the bridge between check_findings and the existing
        datasec db_writer which expects Dict[str, List[ModuleResult]].
        """
        from ..modules.base_module import ModuleResult

        grouped = self.group_by_module(findings)
        results: Dict[str, list] = {}

        for module, module_findings in grouped.items():
            module_results = []
            for f in module_findings:
                module_results.append(ModuleResult(
                    rule_id=f["rule_id"],
                    resource_uid=f.get("resource_uid", ""),
                    resource_id=f.get("resource_id", ""),
                    resource_type=f.get("resource_type", ""),
                    status=f["status"],
                    severity=f.get("severity", "medium"),
                    category=module,
                    title=f.get("title", ""),
                    description=f.get("description", ""),
                    remediation=f.get("remediation", ""),
                    compliance_frameworks=f.get("compliance_frameworks", []),
                    sensitive_data_types=f.get("sensitive_data_context") or [],
                    evidence={
                        "check_finding_id": f.get("finding_id", ""),
                        "checked_fields": f.get("checked_fields") or [],
                        "datasec_categories": f.get("datasec_categories", []),
                        "datasec_impact": f.get("datasec_impact", {}),
                    },
                    confidence=1.0,
                ))
            results[module] = module_results

        return results
