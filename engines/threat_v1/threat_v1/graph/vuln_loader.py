"""
VulnLoader — reads scan_vulnerabilities (+ cve_attack_mappings) and writes
VulnFinding nodes to Neo4j with HAS_CVE edges on existing Resource nodes.

Resources must already exist in the graph (MisconfigLoader runs first).
Resources found in vuln data but not yet in the graph are still created
here — a resource can have a CVE without a check finding.

CP1-01: all Cypher values passed as $parameter bindings.
"""
from __future__ import annotations

import os

import logging
from typing import Any, Dict, List, Optional

from neo4j import Driver

logger = logging.getLogger(__name__)

# Upsert Resource (may already exist from misconfig_loader)
_MERGE_RESOURCE_VULN = """
MERGE (r:Resource {resource_uid: $resource_uid, tenant_id: $tid})
SET r.account_id       = COALESCE(r.account_id, $account_id),
    r.resource_type    = COALESCE(r.resource_type, $resource_type),
    r.region           = COALESCE(r.region, $region),
    r.provider         = COALESCE(r.provider, $provider),
    r.has_critical_cve = CASE WHEN $has_critical_cve THEN true ELSE r.has_critical_cve END,
    r.has_high_misconfig = COALESCE(r.has_high_misconfig, false),
    r.internet_exposed  = COALESCE(r.internet_exposed, false),
    r.is_admin_role     = COALESCE(r.is_admin_role, false),
    r.is_crown_jewel    = COALESCE(r.is_crown_jewel, false),
    r.cdr_actor_seen    = COALESCE(r.cdr_actor_seen, false),
    r.on_attack_path    = COALESCE(r.on_attack_path, false)
"""

_MERGE_VULN_FINDING = """
MERGE (v:VulnFinding {cve_id: $cve_id, resource_uid: $resource_uid, tenant_id: $tid})
SET v.cvss_score        = $cvss_score,
    v.epss_score        = $epss_score,
    v.has_known_exploit = $has_known_exploit,
    v.mitre_technique   = $mitre_technique,
    v.package           = $package,
    v.fixed_version     = $fixed_version
WITH v
MATCH (r:Resource {resource_uid: $resource_uid, tenant_id: $tid})
MERGE (r)-[:HAS_CVE]->(v)
"""

_CRITICAL_CVSS_THRESHOLD = 9.0


class VulnLoader:
    """Loads vulnerability findings into the Neo4j threat graph."""

    def __init__(self, vuln_conn: Any, neo4j_driver: Driver) -> None:
        self._vuln_conn = vuln_conn
        self._driver = neo4j_driver

    def load(
        self,
        tenant_id: str,
        account_id: str,
        scan_run_id: str,
    ) -> Dict[str, int]:
        """Load all vulnerability findings for the given scan into Neo4j.

        Returns:
            Dict with resource_count and vuln_count.
        """
        rows = self._fetch_vulns(tenant_id, account_id, scan_run_id)
        if not rows:
            logger.info(
                "No vuln findings for scan %s / tenant %s / account %s",
                scan_run_id, tenant_id, account_id,
            )
            return {"resource_count": 0, "vuln_count": 0}

        resources_updated: set = set()
        vuln_count = 0

        with self._driver.session(database=os.environ.get("NEO4J_DATABASE", "neo4j")) as session:
            for row in rows:
                uid = row["resource_uid"]
                cvss = float(row.get("cvss_score") or 0.0)
                is_critical = cvss >= _CRITICAL_CVSS_THRESHOLD

                session.run(
                    _MERGE_RESOURCE_VULN,
                    resource_uid=uid,
                    tid=tenant_id,
                    account_id=account_id,
                    resource_type=row.get("resource_type", "Unknown"),
                    region=row.get("region", ""),
                    provider=row.get("provider", "aws"),
                    has_critical_cve=is_critical,
                )
                resources_updated.add(uid)

                session.run(
                    _MERGE_VULN_FINDING,
                    cve_id=row.get("cve_id", ""),
                    resource_uid=uid,
                    tid=tenant_id,
                    cvss_score=cvss,
                    epss_score=float(row.get("epss_score") or 0.0),
                    has_known_exploit=bool(row.get("has_known_exploit", False)),
                    mitre_technique=row.get("mitre_technique") or "",
                    package=row.get("package_name") or "",
                    fixed_version=row.get("fixed_version") or "",
                )
                vuln_count += 1

        logger.info(
            "VulnLoader complete: %d resources, %d CVEs",
            len(resources_updated),
            vuln_count,
            extra={"tenant_id": tenant_id, "scan_run_id": scan_run_id},
        )
        return {"resource_count": len(resources_updated), "vuln_count": vuln_count}

    def _fetch_vulns(
        self,
        tenant_id: str,
        account_id: str,
        scan_run_id: str,
    ) -> List[Dict[str, Any]]:
        """Query scan_vulnerabilities LEFT JOIN cve_attack_mappings."""
        cur = self._vuln_conn.cursor()
        cur.execute(
            """
            SELECT
                sv.resource_uid,
                sv.resource_type,
                sv.account_id,
                sv.region,
                sv.provider,
                sv.cve_id,
                sv.cvss_score,
                sv.epss_score,
                sv.has_known_exploit,
                sv.package_name,
                sv.fixed_version,
                cam.mitre_technique
            FROM scan_vulnerabilities sv
            LEFT JOIN cve_attack_mappings cam
                ON cam.cve_id = sv.cve_id
            WHERE sv.tenant_id   = %s
              AND sv.account_id  = %s
              AND sv.scan_run_id = %s
            """,
            (tenant_id, account_id, scan_run_id),
        )
        rows = cur.fetchall()
        cur.close()
        return list(rows)
