"""
MisconfigLoader — reads check_findings + rule_metadata, writes Resource nodes
and MisconfigFinding nodes to Neo4j with HAS_MISCONFIG edges.

Resource nodes are MERGED (upsert) so multiple loaders building the same graph
in the same scan run do not produce duplicate nodes. All merges are keyed on
(resource_uid, tenant_id).

Security: all Cypher parameters are bound via $param — no f-string interpolation
into Cypher strings (CP1-01).
"""
from __future__ import annotations

import os

import hashlib
import logging
from typing import Any, Dict, List, Optional

from neo4j import Driver

logger = logging.getLogger(__name__)

# Cypher: upsert Resource node and set all scalar properties
_MERGE_RESOURCE = """
MERGE (r:Resource {resource_uid: $resource_uid, tenant_id: $tid})
SET r.resource_type     = $resource_type,
    r.account_id        = $account_id,
    r.region            = $region,
    r.provider          = $provider,
    r.has_high_misconfig = CASE WHEN $has_high_misconfig THEN true ELSE r.has_high_misconfig END,
    r.has_critical_cve  = COALESCE(r.has_critical_cve, false),
    r.internet_exposed  = COALESCE(r.internet_exposed, false),
    r.is_admin_role     = COALESCE(r.is_admin_role, false),
    r.is_crown_jewel    = COALESCE(r.is_crown_jewel, false),
    r.cdr_actor_seen    = COALESCE(r.cdr_actor_seen, false),
    r.on_attack_path    = COALESCE(r.on_attack_path, false)
"""

# Cypher: upsert MisconfigFinding node, then create the HAS_MISCONFIG edge
_MERGE_MISCONFIG = """
MERGE (f:MisconfigFinding {finding_id: $finding_id, tenant_id: $tid})
SET f.rule_id          = $rule_id,
    f.severity         = $severity,
    f.title            = $title,
    f.mitre_techniques = $mitre_techniques,
    f.mitre_tactics    = $mitre_tactics,
    f.status           = $status
WITH f
MATCH (r:Resource {resource_uid: $resource_uid, tenant_id: $tid})
MERGE (r)-[:HAS_MISCONFIG]->(f)
"""


def _finding_id(rule_id: str, resource_uid: str, scan_run_id: str) -> str:
    """Stable sha256-based ID matching the check engine convention."""
    raw = f"{rule_id}|{resource_uid}|{scan_run_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _extract_list(val: Any) -> List[str]:
    """Normalize a DB value that may be a list, None, or string."""
    if isinstance(val, list):
        return val
    if isinstance(val, str) and val:
        return [val]
    return []


class MisconfigLoader:
    """Loads check_findings into the Neo4j threat graph."""

    def __init__(self, check_conn: Any, neo4j_driver: Driver) -> None:
        self._check_conn = check_conn
        self._driver = neo4j_driver

    def load(
        self,
        tenant_id: str,
        account_id: str,
        scan_run_id: str,
    ) -> Dict[str, int]:
        """Load all FAIL/WARN check findings for the given scan into Neo4j.

        Returns:
            Dict with resource_count and finding_count.
        """
        rows = self._fetch_findings(tenant_id, account_id, scan_run_id)
        if not rows:
            logger.warning(
                "No check findings found for scan %s / tenant %s / account %s",
                scan_run_id, tenant_id, account_id,
            )
            return {"resource_count": 0, "finding_count": 0}

        resources_seen: set = set()
        finding_count = 0

        with self._driver.session(database=os.environ.get("NEO4J_DATABASE", "neo4j")) as session:
            for row in rows:
                uid = row["resource_uid"]
                has_high = row.get("severity", "").lower() in ("critical", "high")

                if uid not in resources_seen:
                    session.run(
                        _MERGE_RESOURCE,
                        resource_uid=uid,
                        tid=tenant_id,
                        resource_type=row.get("resource_type", "Unknown"),
                        account_id=account_id,
                        region=row.get("region", ""),
                        provider=row.get("provider", "aws"),
                        has_high_misconfig=has_high,
                    )
                    resources_seen.add(uid)
                elif has_high:
                    # Update the flag if a later finding upgrades this resource
                    session.run(
                        """
                        MATCH (r:Resource {resource_uid: $uid, tenant_id: $tid})
                        SET r.has_high_misconfig = true
                        """,
                        uid=uid, tid=tenant_id,
                    )

                fid = self._stable_finding_id(row, scan_run_id)
                session.run(
                    _MERGE_MISCONFIG,
                    finding_id=fid,
                    tid=tenant_id,
                    rule_id=row.get("rule_id", ""),
                    severity=row.get("severity", ""),
                    title=row.get("title", row.get("rule_id", "")),
                    mitre_techniques=_extract_list(row.get("mitre_techniques")),
                    mitre_tactics=_extract_list(row.get("mitre_tactics")),
                    status=row.get("status", "FAIL"),
                    resource_uid=uid,
                )
                finding_count += 1

        logger.info(
            "MisconfigLoader complete: %d resources, %d findings",
            len(resources_seen),
            finding_count,
            extra={"tenant_id": tenant_id, "scan_run_id": scan_run_id},
        )
        return {"resource_count": len(resources_seen), "finding_count": finding_count}

    def _fetch_findings(
        self,
        tenant_id: str,
        account_id: str,
        scan_run_id: str,
    ) -> List[Dict[str, Any]]:
        """Query check_findings JOIN rule_metadata for FAIL/WARN rows."""
        cur = self._check_conn.cursor()
        cur.execute(
            """
            SELECT
                cf.finding_id,
                cf.resource_uid,
                cf.resource_type,
                cf.account_id,
                cf.region,
                cf.provider,
                cf.severity,
                cf.status,
                cf.scan_run_id,
                rm.rule_id,
                rm.title,
                rm.mitre_techniques,
                rm.mitre_tactics
            FROM check_findings cf
            LEFT JOIN rule_metadata rm
                ON rm.rule_id = cf.rule_id
            WHERE cf.tenant_id    = %s
              AND cf.account_id   = %s
              AND cf.scan_run_id  = %s
              AND cf.status       IN ('FAIL', 'WARN')
            """,
            (tenant_id, account_id, scan_run_id),
        )
        rows = cur.fetchall()
        cur.close()
        return list(rows)

    def _stable_finding_id(self, row: Dict[str, Any], scan_run_id: str) -> str:
        # Prefer the DB-generated finding_id if present
        fid = row.get("finding_id")
        if fid:
            return str(fid)
        return _finding_id(
            row.get("rule_id", ""),
            row.get("resource_uid", ""),
            scan_run_id,
        )
