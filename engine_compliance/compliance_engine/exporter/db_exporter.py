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
        """Get database connection."""
        return psycopg2.connect(self.connection_string)

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

        -- Report Index Table
        CREATE TABLE IF NOT EXISTS report_index (
            report_id UUID PRIMARY KEY,
            tenant_id VARCHAR(255) NOT NULL,
            scan_run_id VARCHAR(255) NOT NULL,
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

        -- Finding Index Table
        CREATE TABLE IF NOT EXISTS finding_index (
            finding_id VARCHAR(255) PRIMARY KEY,
            report_id UUID NOT NULL,
            tenant_id VARCHAR(255) NOT NULL,
            scan_run_id VARCHAR(255) NOT NULL,
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
            
            CONSTRAINT fk_report FOREIGN KEY (report_id) REFERENCES report_index(report_id) ON DELETE CASCADE,
            CONSTRAINT fk_tenant_finding FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
        );

        -- Indexes
        CREATE INDEX IF NOT EXISTS idx_report_tenant_scan ON report_index(tenant_id, scan_run_id);
        CREATE INDEX IF NOT EXISTS idx_report_completed_at ON report_index(completed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_report_cloud ON report_index(cloud);

        CREATE INDEX IF NOT EXISTS idx_finding_tenant_scan ON finding_index(tenant_id, scan_run_id);
        CREATE INDEX IF NOT EXISTS idx_finding_severity ON finding_index(severity);
        CREATE INDEX IF NOT EXISTS idx_finding_status ON finding_index(status);
        CREATE INDEX IF NOT EXISTS idx_finding_rule_id ON finding_index(rule_id);
        CREATE INDEX IF NOT EXISTS idx_finding_resource_type ON finding_index(resource_type);
        CREATE INDEX IF NOT EXISTS idx_finding_last_seen ON finding_index(last_seen_at DESC);

        CREATE INDEX IF NOT EXISTS idx_report_data_gin ON report_index USING gin(report_data);
        CREATE INDEX IF NOT EXISTS idx_finding_data_gin ON finding_index USING gin(finding_data);

        CREATE INDEX IF NOT EXISTS idx_finding_severity_status ON finding_index(severity, status);
        CREATE INDEX IF NOT EXISTS idx_finding_rule_status ON finding_index(rule_id, status);
        CREATE INDEX IF NOT EXISTS idx_finding_tenant_severity ON finding_index(tenant_id, severity, last_seen_at DESC);
        """
        
        conn = self._get_connection()
        try:
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            cursor = conn.cursor()
            cursor.execute(schema_sql)
            conn.commit()
        finally:
            conn.close()
    
    def export_report(self, report: EnterpriseComplianceReport) -> str:
        """
        Export enterprise compliance report to PostgreSQL.
        
        Args:
            report: EnterpriseComplianceReport to export
        
        Returns:
            Report ID (UUID)
        """
        report_id = str(uuid.uuid4())
        
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
                INSERT INTO report_index (
                    report_id, tenant_id, scan_run_id, cloud, trigger_type,
                    collection_mode, started_at, completed_at,
                    total_controls, controls_passed, controls_failed,
                    total_findings, report_data
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                report_id,
                report.tenant.tenant_id,
                report.scan_context.scan_run_id,
                report.scan_context.cloud.value,
                report.scan_context.trigger_type.value,
                report.scan_context.collection_mode.value,
                report.scan_context.started_at,
                report.scan_context.completed_at,
                report.posture_summary.total_controls,
                report.posture_summary.controls_passed,
                report.posture_summary.controls_failed,
                report.posture_summary.total_findings,
                json.dumps(report.model_dump(), default=str)
            ))
            
            # Insert findings
            if report.findings:
                finding_rows = []
                for finding in report.findings:
                    # Extract resource info from first affected asset
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
                        report_id,
                        report.tenant.tenant_id,
                        report.scan_context.scan_run_id,
                        finding.rule_id,
                        finding.rule_version,
                        finding.category,
                        finding.severity.value,
                        finding.confidence.value,
                        finding.status.value,
                        finding.first_seen_at,
                        finding.last_seen_at,
                        resource_type,
                        resource_id,
                        resource_arn,
                        region,
                        json.dumps(finding.model_dump(), default=str)
                    ))
                
                execute_values(
                    cursor,
                    """
                    INSERT INTO finding_index (
                        finding_id, report_id, tenant_id, scan_run_id,
                        rule_id, rule_version, category, severity, confidence,
                        status, first_seen_at, last_seen_at,
                        resource_type, resource_id, resource_arn, region,
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
            return report_id
            
        except Exception as e:
            conn.rollback()
            raise Exception(f"Failed to export report to database: {str(e)}")
        finally:
            conn.close()
    
    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve report from database."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT report_data FROM report_index WHERE report_id = %s
            """, (report_id,))
            
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
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
                SELECT finding_data FROM finding_index
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

