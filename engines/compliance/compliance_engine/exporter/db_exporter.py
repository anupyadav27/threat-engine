"""
Database Exporter - Exports compliance reports to PostgreSQL.
Uses ONLY consolidated database system from consolidated_services/database.
"""

import json
import os
import sys
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime
import psycopg2
from psycopg2.extras import execute_values
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Import local database config
from ..database.connection.database_config import get_database_config

from ..schemas.enterprise_report_schema import EnterpriseComplianceReport


def _build_connection_string(
    connection_string: Optional[str] = None,
    db_host: Optional[str] = None,
    db_port: Optional[int] = None,
    db_name: Optional[str] = None,
    db_user: Optional[str] = None,
    db_password: Optional[str] = None,
) -> str:
    """
    Build connection string using consolidated database system.
    Parameters are kept for backward compatibility but ignored in favor of consolidated DB.
    """
    # Use consolidated database config
    try:
        db_config = get_database_config("compliance")
        url = db_config.connection_string
    except Exception as e:
        raise RuntimeError(f"Failed to get consolidated DB config: {e}") from e
    
    # Set schema search_path for engine_compliance and engine_shared
    schema = os.getenv("DB_SCHEMA", "engine_compliance,engine_shared")
    sep = "&" if "?" in url else "?"
    url = f"{url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"
    return url


class DatabaseExporter:
    """Exports enterprise compliance reports to PostgreSQL."""

    def __init__(
        self,
        db_host: str = None,
        db_port: int = None,
        db_name: str = None,
        db_user: str = None,
        db_password: str = None,
        connection_string: str = None,
    ):
        self.connection_string = _build_connection_string(
            connection_string=connection_string,
            db_host=db_host,
            db_port=db_port,
            db_name=db_name,
            db_user=db_user,
            db_password=db_password,
        )

    def _get_connection(self):
        """Get database connection using env vars (bypasses Pydantic BaseSettings defaults)."""
        return psycopg2.connect(
            host=os.getenv("COMPLIANCE_DB_HOST", "localhost"),
            port=int(os.getenv("COMPLIANCE_DB_PORT", "5432")),
            database=os.getenv("COMPLIANCE_DB_NAME", "threat_engine_compliance"),
            user=os.getenv("COMPLIANCE_DB_USER", "postgres"),
            password=os.getenv("COMPLIANCE_DB_PASSWORD", ""),
            sslmode=os.getenv("DB_SSLMODE", "prefer"),
        )

    def create_schema(self):
        """Create database schema. No-op when using consolidated DB (DB_SCHEMA set)."""
        if (os.getenv("DB_SCHEMA") or "").strip():
            return
        schema_sql = """
        -- Tenants Table
        CREATE TABLE IF NOT EXISTS tenants (
            tenant_id VARCHAR(255) PRIMARY KEY,
            tenant_name VARCHAR(255),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        -- Compliance Report Table
        CREATE TABLE IF NOT EXISTS compliance_report (
            scan_run_id VARCHAR(255) PRIMARY KEY,
            tenant_id VARCHAR(255) NOT NULL,
            cloud VARCHAR(50) NOT NULL,
            trigger_type VARCHAR(50) NOT NULL,
            collection_mode VARCHAR(50) NOT NULL,
            started_at TIMESTAMP WITH TIME ZONE NOT NULL,
            completed_at TIMESTAMP WITH TIME ZONE NOT NULL,
            total_controls INTEGER NOT NULL DEFAULT 0,
            controls_passed INTEGER NOT NULL DEFAULT 0,
            controls_failed INTEGER NOT NULL DEFAULT 0,
            total_findings INTEGER NOT NULL DEFAULT 0,
            report_data JSONB NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            
            CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
        );

        -- Compliance Findings Table
        CREATE TABLE IF NOT EXISTS compliance_findings (
            finding_id VARCHAR(255) PRIMARY KEY,
            scan_run_id VARCHAR(255) NOT NULL,
            tenant_id VARCHAR(255) NOT NULL,
            rule_id VARCHAR(255) NOT NULL,
            rule_version VARCHAR(50),
            category VARCHAR(100),
            severity VARCHAR(20) NOT NULL,
            confidence VARCHAR(20) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'open',
            first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
            last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
            resource_type VARCHAR(100),
            resource_id VARCHAR(255),
            resource_arn TEXT,
            region VARCHAR(50),
            finding_data JSONB NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            
            CONSTRAINT fk_report FOREIGN KEY (scan_run_id) REFERENCES compliance_report(scan_run_id) ON DELETE CASCADE,
            CONSTRAINT fk_tenant_finding FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
        );

        -- Indexes
        CREATE INDEX IF NOT EXISTS idx_report_tenant_scan ON compliance_report(tenant_id, scan_run_id);
        CREATE INDEX IF NOT EXISTS idx_report_completed_at ON compliance_report(completed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_report_cloud ON compliance_report(cloud);

        CREATE INDEX IF NOT EXISTS idx_finding_tenant_scan ON compliance_findings(tenant_id, scan_run_id);
        CREATE INDEX IF NOT EXISTS idx_finding_severity ON compliance_findings(severity);
        CREATE INDEX IF NOT EXISTS idx_finding_status ON compliance_findings(status);
        CREATE INDEX IF NOT EXISTS idx_finding_rule_id ON compliance_findings(rule_id);
        CREATE INDEX IF NOT EXISTS idx_finding_resource_type ON compliance_findings(resource_type);
        CREATE INDEX IF NOT EXISTS idx_finding_last_seen ON compliance_findings(last_seen_at DESC);

        CREATE INDEX IF NOT EXISTS idx_report_data_gin ON compliance_report USING gin(report_data);
        CREATE INDEX IF NOT EXISTS idx_finding_data_gin ON compliance_findings USING gin(finding_data);

        CREATE INDEX IF NOT EXISTS idx_finding_severity_status ON compliance_findings(severity, status);
        CREATE INDEX IF NOT EXISTS idx_finding_rule_status ON compliance_findings(rule_id, status);
        CREATE INDEX IF NOT EXISTS idx_finding_tenant_severity ON compliance_findings(tenant_id, severity, last_seen_at DESC);
        """
        
        conn = self._get_connection()
        try:
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            cursor = conn.cursor()
            cursor.execute(schema_sql)
            conn.commit()
        finally:
            conn.close()
    
    @staticmethod
    def _parse_ts(ts_str) -> Optional[datetime]:
        """Parse a timestamp string that may have double timezone indicator (+00:00Z)."""
        if ts_str is None:
            return None
        if isinstance(ts_str, datetime):
            return ts_str
        s = str(ts_str)
        # Remove trailing Z if already has +HH:MM offset (e.g. "2026-02-15T16:49:14+00:00Z")
        if s.endswith('Z') and ('+' in s[:-1] or s[:-1].count('-') > 2):
            s = s[:-1]
        # Replace trailing Z with +00:00 for fromisoformat
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        try:
            return datetime.fromisoformat(s)
        except Exception:
            return datetime.now()

    def export_report(self, report: EnterpriseComplianceReport) -> str:
        """
        Export enterprise compliance report to PostgreSQL.

        Args:
            report: EnterpriseComplianceReport to export

        Returns:
            scan_run_id string
        """
        scan_run_id = report.scan_context.scan_run_id or str(uuid.uuid4())

        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Insert or update tenant
            cursor.execute("""
                INSERT INTO tenants (tenant_id, tenant_name)
                VALUES (%s, %s)
                ON CONFLICT (tenant_id) DO UPDATE
                SET tenant_name = EXCLUDED.tenant_name
            """, (report.tenant.tenant_id, report.tenant.tenant_name))

            # Insert report
            cursor.execute("""
                INSERT INTO compliance_report (
                    scan_run_id, tenant_id, cloud, trigger_type,
                    collection_mode, started_at, completed_at,
                    total_controls, controls_passed, controls_failed,
                    total_findings, report_data
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                scan_run_id,
                report.tenant.tenant_id,
                report.scan_context.cloud.value,
                report.scan_context.trigger_type.value,
                report.scan_context.collection_mode.value,
                self._parse_ts(report.scan_context.started_at),
                self._parse_ts(report.scan_context.completed_at),
                report.posture_summary.total_controls,
                report.posture_summary.controls_passed,
                report.posture_summary.controls_failed,
                report.posture_summary.total_findings,
                # Slim summary — exclude findings/assets/frameworks to avoid multi-GB JSONB blob
                json.dumps({
                    'scan_run_id': report.scan_context.scan_run_id,
                    'cloud': report.scan_context.cloud.value,
                    'posture_summary': {
                        'total_controls': report.posture_summary.total_controls,
                        'controls_passed': report.posture_summary.controls_passed,
                        'controls_failed': report.posture_summary.controls_failed,
                        'total_findings': report.posture_summary.total_findings,
                        'findings_by_severity': report.posture_summary.findings_by_severity,
                    },
                    'framework_ids': [f.framework_id for f in report.frameworks],
                    'generated_at': report.integrity.generated_at if report.integrity else None,
                }, default=str)
            ))

            # Insert findings
            if report.findings:
                finding_rows = []
                for finding in report.findings:
                    resource_arn = None
                    resource_type = None
                    resource_id = None
                    region = None

                    if finding.affected_assets:
                        first_asset = finding.affected_assets[0]
                        resource_arn = first_asset.arn
                        resource_type = first_asset.resource_type
                        resource_id = first_asset.resource_id
                        region = first_asset.region

                    finding_rows.append((
                        finding.finding_id,
                        scan_run_id,
                        report.tenant.tenant_id,
                        finding.rule_id,
                        finding.rule_version,
                        finding.category,
                        finding.severity.value,
                        finding.confidence.value,
                        finding.status.value,
                        self._parse_ts(finding.first_seen_at),
                        self._parse_ts(finding.last_seen_at),
                        resource_type,
                        resource_id,
                        resource_arn,
                        region,
                        # Slim finding_data — only compliance mappings (full model_dump OOMs at scale)
                        json.dumps({
                            'compliance_mappings': [
                                {'framework_id': m.framework_id, 'control_id': m.control_id,
                                 'control_title': m.control_title}
                                for m in (finding.compliance_mappings or [])
                            ],
                            'remediation': finding.remediation.description if finding.remediation else None,
                        }, default=str)
                    ))

                execute_values(
                    cursor,
                    """
                    INSERT INTO compliance_findings (
                        finding_id, scan_run_id, tenant_id,
                        rule_id, rule_version, category, severity, confidence,
                        status, first_seen_at, last_seen_at,
                        resource_type, resource_id, resource_uid, region,
                        finding_data
                    ) VALUES %s
                    ON CONFLICT (finding_id) DO UPDATE
                    SET last_seen_at = EXCLUDED.last_seen_at,
                        status = EXCLUDED.status,
                        finding_data = EXCLUDED.finding_data
                    """,
                    finding_rows
                )

            conn.commit()
            return scan_run_id

        except Exception as e:
            conn.rollback()
            raise Exception(f"Failed to export report to database: {str(e)}")
        finally:
            conn.close()

    def get_report(self, scan_run_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve report from database."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT report_data FROM compliance_report WHERE scan_run_id = %s
            """, (scan_run_id,))

            row = cursor.fetchone()
            if row:
                d = row[0]
                return d if isinstance(d, dict) else json.loads(d)
            return None
        finally:
            conn.close()

    def get_findings(
        self,
        tenant_id: str,
        status: str = None,
        severity: str = None,
        rule_id: str = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Query findings from database."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            query = """
                SELECT finding_data FROM compliance_findings
                WHERE tenant_id = %s
            """
            params = [tenant_id]

            if status:
                query += " AND status = %s"
                params.append(status)

            if severity:
                query += " AND severity = %s"
                params.append(severity)

            if rule_id:
                query += " AND rule_id = %s"
                params.append(rule_id)

            query += " ORDER BY last_seen_at DESC LIMIT %s"
            params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()

            return [json.loads(row[0]) for row in rows]
        finally:
            conn.close()

    def list_reports(
        self,
        tenant_id: str = None,
        csp: str = None,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """List compliance reports from DB with pagination."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            conditions: List[str] = []
            params: List[Any] = []

            if tenant_id:
                conditions.append("tenant_id = %s")
                params.append(tenant_id)
            if csp:
                conditions.append("cloud = %s")
                params.append(csp)

            where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

            cursor.execute(f"SELECT COUNT(*) FROM compliance_report {where}", params)
            total = cursor.fetchone()[0]

            cursor.execute(f"""
                SELECT scan_run_id, tenant_id, cloud,
                       started_at, completed_at,
                       total_controls, controls_passed, controls_failed, total_findings,
                       created_at, report_data
                FROM compliance_report
                {where}
                ORDER BY completed_at DESC NULLS LAST
                LIMIT %s OFFSET %s
            """, params + [limit, offset])

            rows = cursor.fetchall()
            result_rows = []
            for row in rows:
                rd = row[10] if isinstance(row[10], dict) else (json.loads(row[10]) if row[10] else {})
                result_rows.append({
                    'report_id': row[0],
                    'scan_run_id': row[0],
                    'tenant_id': row[1],
                    'scan_id': row[0],
                    'csp': row[2],
                    'started_at': row[3].isoformat() if row[3] else None,
                    'completed_at': row[4].isoformat() if row[4] else None,
                    'total_controls': row[5],
                    'controls_passed': row[6],
                    'controls_failed': row[7],
                    'total_findings': row[8],
                    'generated_at': row[9].isoformat() if row[9] else None,
                    'framework_ids': rd.get('framework_ids', []),
                    'posture_summary': rd.get('posture_summary'),
                })

            return {'total': total, 'reports': result_rows}
        finally:
            conn.close()

