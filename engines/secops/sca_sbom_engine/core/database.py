"""
Database manager for SBOM Engine.
Creates and manages SBOM-specific tables.
Reads from cves + osv_advisory for enrichment (read-only queries).
  - cves table:         in vulnerability_db (vuln_pool)
  - osv_advisory table: in vulnerability_db (vuln_pool)
"""

import asyncpg
import logging
import json
import os
import re
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

_SQL_DIR = Path(__file__).resolve().parent.parent / "db" / "create_sbom_tables.sql"


class SBOMDatabaseManager:

    def __init__(self):
        self.pool = None
        self.vuln_pool = None  # separate pool for vulnerability_db (osv_advisory)
        self.config = {
            "host":     os.getenv("DB_HOST", "localhost"),
            "port":     int(os.getenv("DB_PORT", 5432)),
            "database": os.getenv("DB_NAME", "threat_engine_secops"),
            "user":     os.getenv("DB_USER", "postgres"),
            "password": os.getenv("DB_PASSWORD", "password"),
            "max_size": int(os.getenv("DB_MAX_CONNECTIONS", 20)),
            "min_size": int(os.getenv("DB_MIN_CONNECTIONS", 5)),
        }
        self.vuln_config = {
            "host":     os.getenv("VULN_DB_HOST", os.getenv("DB_HOST", "localhost")),
            "port":     int(os.getenv("VULN_DB_PORT", os.getenv("DB_PORT", 5432))),
            "database": os.getenv("VULN_DB_NAME", "vulnerability_db"),
            "user":     os.getenv("VULN_DB_USER", os.getenv("DB_USER", "postgres")),
            "password": os.getenv("VULN_DB_PASSWORD", os.getenv("DB_PASSWORD", "password")),
            "max_size": 5,
            "min_size": 1,
        }

    async def initialize(self):
        if self.pool:
            return
        try:
            self.pool = await asyncpg.create_pool(
                host=self.config["host"],
                port=self.config["port"],
                database=self.config["database"],
                user=self.config["user"],
                password=self.config["password"],
                min_size=self.config["min_size"],
                max_size=self.config["max_size"],
                command_timeout=120,
                ssl="prefer",
            )
            await self._ensure_tables()
            logger.info("SBOM Engine database pool initialized")
        except Exception as e:
            safe = str(e).replace(self.config.get("password", ""), "***")
            logger.error(f"DB init failed: {safe}")
            raise

        # Initialize vulnerability_db pool for osv_advisory (non-fatal if unavailable)
        try:
            self.vuln_pool = await asyncpg.create_pool(
                host=self.vuln_config["host"],
                port=self.vuln_config["port"],
                database=self.vuln_config["database"],
                user=self.vuln_config["user"],
                password=self.vuln_config["password"],
                min_size=self.vuln_config["min_size"],
                max_size=self.vuln_config["max_size"],
                command_timeout=60,
                ssl="prefer",
            )
            logger.info("SBOM Engine vulnerability_db pool initialized (osv_advisory)")
        except Exception as e:
            safe = str(e).replace(self.vuln_config.get("password", ""), "***")
            logger.warning(f"vulnerability_db pool init failed (OSV enrichment disabled): {safe}")
            self.vuln_pool = None

    async def close(self):
        if self.pool:
            await self.pool.close()
            logger.info("SBOM Engine DB pool closed")
        if self.vuln_pool:
            await self.vuln_pool.close()
            logger.info("SBOM Engine vulnerability_db pool closed")

    async def check_connection(self) -> bool:
        try:
            if not self.pool:
                return False
            async with self.pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
                return True
        except Exception:
            return False

    async def _ensure_tables(self):
        sql = _SQL_DIR.read_text(encoding="utf-8")
        async with self.pool.acquire() as conn:
            await conn.execute(sql)
        logger.info("SBOM tables ensured")

    # ── SBOM ID generation ───────────────────────────────────────────────────

    def generate_sbom_id(self) -> str:
        """Generate unique SBOM ID: urn:uuid:..."""
        return f"urn:uuid:{uuid.uuid4()}"

    # ── SBOM Document CRUD ───────────────────────────────────────────────────

    async def save_sbom_document(self, doc: Dict) -> str:
        """Insert sbom_document row; returns sbom_id."""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO sbom_documents (
                    sbom_id, host_id, application_name,
                    sbom_format, spec_version, version,
                    parent_sbom_id, component_count, vulnerability_count,
                    source, raw_document, created_by
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                ON CONFLICT (sbom_id) DO UPDATE SET
                    component_count     = EXCLUDED.component_count,
                    vulnerability_count = EXCLUDED.vulnerability_count,
                    raw_document        = EXCLUDED.raw_document
            """,
                doc["sbom_id"],
                doc.get("host_id"),
                doc.get("application_name"),
                doc["sbom_format"],
                doc.get("spec_version"),
                doc.get("version", 1),
                doc.get("parent_sbom_id"),
                doc.get("component_count", 0),
                doc.get("vulnerability_count", 0),
                doc.get("source"),
                json.dumps(doc.get("raw_document")) if doc.get("raw_document") else None,
                doc.get("created_by"),
            )
        return doc["sbom_id"]

    async def get_sbom_document(self, sbom_id: str) -> Optional[Dict]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM sbom_documents WHERE sbom_id = $1", sbom_id
            )
        return dict(row) if row else None

    async def list_sbom_documents(
        self,
        host_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict]:
        async with self.pool.acquire() as conn:
            if host_id:
                rows = await conn.fetch(
                    "SELECT sbom_id, host_id, application_name, sbom_format, "
                    "spec_version, version, component_count, vulnerability_count, "
                    "source, created_at, created_by "
                    "FROM sbom_documents WHERE host_id = $1 "
                    "ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                    host_id, limit, offset,
                )
            else:
                rows = await conn.fetch(
                    "SELECT sbom_id, host_id, application_name, sbom_format, "
                    "spec_version, version, component_count, vulnerability_count, "
                    "source, created_at, created_by "
                    "FROM sbom_documents "
                    "ORDER BY created_at DESC LIMIT $1 OFFSET $2",
                    limit, offset,
                )
        return [dict(r) for r in rows]

    async def get_latest_sbom_for_host(self, host_id: str) -> Optional[Dict]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM sbom_documents WHERE host_id = $1 "
                "ORDER BY created_at DESC LIMIT 1",
                host_id,
            )
        return dict(row) if row else None

    async def delete_sbom_document(self, sbom_id: str) -> bool:
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM sbom_documents WHERE sbom_id = $1", sbom_id
            )
        return result == "DELETE 1"

    # ── SBOM Components ──────────────────────────────────────────────────────

    async def save_sbom_components(self, sbom_id: str, components: List[Dict]) -> int:
        """Batch-insert components; returns count inserted."""
        if not components:
            return 0
        rows = []
        for c in components:
            rows.append((
                sbom_id,
                c.get("bom_ref"),
                c.get("component_type", "library"),
                c["name"],
                c.get("version"),
                c.get("purl"),
                c.get("cpe"),
                c.get("ecosystem"),
                c.get("licenses") or [],
                c.get("license_expression"),
                json.dumps(c.get("hashes")) if c.get("hashes") else None,
                c.get("supplier"),
                c.get("author"),
                c.get("description"),
                c.get("scope"),
                c.get("is_vulnerable", False),
                c.get("vulnerability_ids") or [],
            ))
        async with self.pool.acquire() as conn:
            await conn.executemany("""
                INSERT INTO sbom_components (
                    sbom_id, bom_ref, component_type, name, version,
                    purl, cpe, ecosystem, licenses, license_expression,
                    hashes, supplier, author, description, scope,
                    is_vulnerable, vulnerability_ids
                ) VALUES (
                    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
                    $11,$12,$13,$14,$15,$16,$17
                )
            """, rows)
        return len(rows)

    async def get_sbom_components(self, sbom_id: str) -> List[Dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM sbom_components WHERE sbom_id = $1 "
                "ORDER BY name, version",
                sbom_id,
            )
        return [dict(r) for r in rows]

    async def get_vulnerable_components(self, sbom_id: str) -> List[Dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM sbom_components "
                "WHERE sbom_id = $1 AND is_vulnerable = TRUE "
                "ORDER BY name",
                sbom_id,
            )
        return [dict(r) for r in rows]

    # ── VEX Statements ───────────────────────────────────────────────────────

    async def save_vex_statement(self, vex: Dict) -> int:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO sbom_vex_statements (
                    sbom_id, vulnerability_id, status,
                    component_purl, component_name,
                    justification, impact_statement, action_statement,
                    created_by
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                ON CONFLICT (vulnerability_id, component_purl) DO UPDATE SET
                    status           = EXCLUDED.status,
                    justification    = EXCLUDED.justification,
                    impact_statement = EXCLUDED.impact_statement,
                    action_statement = EXCLUDED.action_statement,
                    created_by       = EXCLUDED.created_by,
                    created_at       = NOW()
                RETURNING id
            """,
                vex.get("sbom_id"),
                vex["vulnerability_id"],
                vex["status"],
                vex.get("component_purl"),
                vex.get("component_name"),
                vex.get("justification"),
                vex.get("impact_statement"),
                vex.get("action_statement"),
                vex.get("created_by"),
            )
        return row["id"]

    async def get_vex_statements(
        self,
        vulnerability_id: Optional[str] = None,
        sbom_id: Optional[str] = None,
        component_purl: Optional[str] = None,
    ) -> List[Dict]:
        async with self.pool.acquire() as conn:
            if vulnerability_id:
                rows = await conn.fetch(
                    "SELECT * FROM sbom_vex_statements "
                    "WHERE vulnerability_id = $1 ORDER BY created_at DESC",
                    vulnerability_id,
                )
            elif sbom_id:
                rows = await conn.fetch(
                    "SELECT * FROM sbom_vex_statements "
                    "WHERE sbom_id = $1 ORDER BY vulnerability_id",
                    sbom_id,
                )
            elif component_purl:
                rows = await conn.fetch(
                    "SELECT * FROM sbom_vex_statements "
                    "WHERE component_purl = $1 ORDER BY created_at DESC",
                    component_purl,
                )
            else:
                rows = await conn.fetch(
                    "SELECT * FROM sbom_vex_statements ORDER BY created_at DESC LIMIT 200"
                )
        return [dict(r) for r in rows]

    # ── Read-only queries on shared tables ──────────────────────────────────

    async def query_osv_advisory(
        self, pkg_name: str, ecosystem: str
    ) -> List[Dict]:
        """Read-only query on the osv_advisory table (now in vulnerability_db)."""
        if not self.vuln_pool:
            logger.debug("vuln_pool unavailable — skipping OSV advisory lookup")
            return []
        async with self.vuln_pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT advisory_id, ecosystem, pkg_name,
                       affected_ranges, affected_versions, fixed_version,
                       severity, cvss_score, cvss_vector,
                       cve_aliases, description, source,
                       published_at, modified_at
                FROM osv_advisory
                WHERE LOWER(pkg_name) = LOWER($1)
                  AND LOWER(ecosystem) = LOWER($2)
            """, pkg_name, ecosystem)
        return [dict(r) for r in rows]

    # ── SecOps shared output tables ──────────────────────────────────────────

    async def save_secops_report(
        self,
        secops_scan_id: str,
        tenant_id: str,
        project_name: str,
        repo_url: str,
        component_count: int,
        vulnerability_count: int,
        summary: Dict,
        metadata: Optional[Dict] = None,
    ) -> str:
        """Insert a row into secops_report for this SCA scan. Returns secops_scan_id."""
        import uuid as _uuid
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO secops_report (
                    secops_scan_id, tenant_id,
                    project_name, repo_url,
                    scan_type, status,
                    scan_timestamp, completed_at,
                    total_findings,
                    summary, metadata
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                ON CONFLICT (secops_scan_id) DO NOTHING
            """,
                secops_scan_id,
                tenant_id,
                project_name,
                repo_url,
                "sca",
                "completed",
                now,
                now,
                vulnerability_count,
                json.dumps(summary),
                json.dumps(metadata or {}),
            )
        logger.info("SecOps report row saved: %s", secops_scan_id)
        return secops_scan_id

    async def save_secops_findings(
        self,
        secops_scan_id: str,
        tenant_id: str,
        findings: List[Dict],
    ) -> int:
        """Batch-insert SCA vulnerability findings into secops_findings. Returns count inserted."""
        if not findings:
            return 0
        rows = []
        for f in findings:
            rows.append((
                secops_scan_id,
                tenant_id,
                f.get("component_purl") or f.get("component_name", ""),  # file_path
                f.get("ecosystem", "sca"),                                 # language
                f.get("vulnerability_id", ""),                             # rule_id
                (f.get("severity") or "info").lower(),
                f.get("description") or f.get("vulnerability_id", ""),    # message
                None,                                                       # line_number
                "violation",
                None,                                                       # resource
                "sca",
                json.dumps({
                    "component_name":    f.get("component_name"),
                    "component_version": f.get("component_version"),
                    "component_purl":    f.get("component_purl"),
                    "vulnerability_id":  f.get("vulnerability_id"),
                    "cvss_score":        f.get("cvss_score"),
                    "cvss_vector":       f.get("cvss_vector"),
                    "epss_score":        f.get("epss_score"),
                    "in_cisa_kev":       f.get("in_cisa_kev", False),
                    "fixed_version":     f.get("fixed_version"),
                }),
            ))
        async with self.pool.acquire() as conn:
            await conn.executemany("""
                INSERT INTO secops_findings (
                    secops_scan_id, tenant_id,
                    file_path, language, rule_id,
                    severity, message,
                    line_number, status, resource,
                    scan_type, metadata
                ) VALUES (
                    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12
                )
            """, rows)
        logger.info("SecOps findings saved: %d rows for scan %s", len(rows), secops_scan_id)
        return len(rows)

    async def enrich_from_cves(self, cve_id: str) -> Optional[Dict]:
        """Read-only query on the cves table (in vulnerability_db, via vuln_pool)."""
        if not self.vuln_pool:
            logger.debug("vuln_pool unavailable — skipping CVE enrichment lookup")
            return None
        async with self.vuln_pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT cve_id,
                       COALESCE(cvss_v4_score, cvss_v3_score, cvss_v2_score) AS cvss_score,
                       COALESCE(cvss_v4_vector, cvss_v3_vector, cvss_v2_vector) AS cvss_vector,
                       severity
                FROM cves WHERE cve_id = $1
            """, cve_id)
        return dict(row) if row else None
