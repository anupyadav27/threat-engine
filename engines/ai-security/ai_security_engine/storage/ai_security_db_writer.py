"""
AI Security DB Writer.

Writes ai_security_report, ai_security_findings, and ai_security_inventory
tables to the threat_engine_ai_security database.
"""

import os
import json
import hashlib
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import execute_values, Json

logger = logging.getLogger(__name__)


def _get_ai_security_conn():
    """Get connection to the AI Security database."""
    return psycopg2.connect(
        host=os.getenv("AI_SECURITY_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("AI_SECURITY_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("AI_SECURITY_DB_NAME", "threat_engine_ai_security"),
        user=os.getenv("AI_SECURITY_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("AI_SECURITY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


def generate_finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    """Deterministic finding_id: ai_{sha256(rule_id|resource_uid|account|region)[:16]}."""
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return f"ai_{hashlib.sha256(raw.encode()).hexdigest()[:16]}"


class AISecurityDBWriter:
    """Writes AI security scan results to threat_engine_ai_security database."""

    def __init__(self):
        self.db_config = {
            "host": os.getenv("AI_SECURITY_DB_HOST", os.getenv("DB_HOST", "localhost")),
            "port": int(os.getenv("AI_SECURITY_DB_PORT", os.getenv("DB_PORT", "5432"))),
            "dbname": os.getenv("AI_SECURITY_DB_NAME", "threat_engine_ai_security"),
            "user": os.getenv("AI_SECURITY_DB_USER", os.getenv("DB_USER", "postgres")),
            "password": os.getenv("AI_SECURITY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
            "sslmode": os.getenv("DB_SSLMODE", "prefer"),
        }

    def _get_connection(self):
        """Get a new database connection."""
        return psycopg2.connect(**self.db_config)

    def ensure_tenant(self, tenant_id: str, tenant_name: Optional[str] = None) -> None:
        """Upsert tenant to satisfy FK constraints.

        Args:
            tenant_id: Tenant identifier.
            tenant_name: Optional display name (defaults to tenant_id).
        """
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) "
                    "ON CONFLICT DO NOTHING",
                    (tenant_id, tenant_name or tenant_id),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            logger.exception("Failed to upsert tenant %s", tenant_id)
            raise
        finally:
            conn.close()

    def create_report(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        provider: str,
    ) -> None:
        """Pre-create report row with status='running'.

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant identifier.
            account_id: Cloud account identifier.
            provider: Cloud provider (aws, azure, gcp).
        """
        conn = self._get_connection()
        now = datetime.now(timezone.utc)
        try:
            with conn.cursor() as cur:
                # Ensure tenant FK
                cur.execute(
                    "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) "
                    "ON CONFLICT DO NOTHING",
                    (tenant_id, tenant_id),
                )
                cur.execute("""
                    INSERT INTO ai_security_report (
                        scan_run_id,
                        tenant_id, account_id, provider,
                        status, started_at, created_at
                    )
                    VALUES (%s, %s, %s, %s, 'running', %s, %s)
                    ON CONFLICT (scan_run_id) DO UPDATE SET
                        status = 'running',
                        started_at = EXCLUDED.started_at
                """, (
                    scan_run_id,
                    tenant_id, account_id, provider,
                    now, now,
                ))
            conn.commit()
            logger.info("Created AI security report row for scan %s", scan_run_id)
        except Exception:
            conn.rollback()
            logger.exception("Failed to create report for scan %s", scan_run_id)
            raise
        finally:
            conn.close()

    def update_report(
        self,
        scan_run_id: str,
        scores: Dict[str, Any],
        inventory: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        status: str = "completed",
    ) -> None:
        """Update report with final results.

        Args:
            scan_run_id: Pipeline scan run identifier.
            scores: Dict with coverage metrics, risk_score, framework_compliance.
            inventory: List of ML resource inventory dicts.
            findings: List of finding dicts.
            status: Final status (completed, failed).
        """
        conn = self._get_connection()
        now = datetime.now(timezone.utc)

        # Compute severity counts
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        pass_count = 0
        fail_count = 0
        for f in findings:
            sev = (f.get("severity") or "medium").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1
            st = (f.get("status") or "").upper()
            if st == "PASS":
                pass_count += 1
            elif st == "FAIL":
                fail_count += 1

        # Build category breakdown: {category: {total, pass, fail}}
        category_breakdown: Dict[str, Dict[str, int]] = {}
        for f in findings:
            cat = f.get("category", "uncategorized")
            if cat not in category_breakdown:
                category_breakdown[cat] = {"total": 0, "pass": 0, "fail": 0}
            category_breakdown[cat]["total"] += 1
            st = (f.get("status") or "").upper()
            if st == "PASS":
                category_breakdown[cat]["pass"] += 1
            elif st == "FAIL":
                category_breakdown[cat]["fail"] += 1

        # Build service breakdown: {service: {total, pass, fail}}
        service_breakdown: Dict[str, Dict[str, int]] = {}
        for f in findings:
            svc = f.get("ml_service", "unknown")
            if svc not in service_breakdown:
                service_breakdown[svc] = {"total": 0, "pass": 0, "fail": 0}
            service_breakdown[svc]["total"] += 1
            st = (f.get("status") or "").upper()
            if st == "PASS":
                service_breakdown[svc]["pass"] += 1
            elif st == "FAIL":
                service_breakdown[svc]["fail"] += 1

        # Build top failing rules: [{rule_id, count, severity}]
        fail_rule_counts: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            if (f.get("status") or "").upper() == "FAIL":
                rid = f.get("rule_id", "unknown")
                if rid not in fail_rule_counts:
                    fail_rule_counts[rid] = {
                        "rule_id": rid,
                        "count": 0,
                        "severity": f.get("severity", "medium"),
                    }
                fail_rule_counts[rid]["count"] += 1
        top_failing = sorted(
            fail_rule_counts.values(), key=lambda x: x["count"], reverse=True
        )[:20]

        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE ai_security_report SET
                        total_ml_resources      = %s,
                        total_findings          = %s,
                        critical_findings       = %s,
                        high_findings           = %s,
                        medium_findings         = %s,
                        low_findings            = %s,
                        pass_count              = %s,
                        fail_count              = %s,
                        vpc_isolation_pct       = %s,
                        encryption_rest_pct     = %s,
                        encryption_transit_pct  = %s,
                        model_card_pct          = %s,
                        monitoring_pct          = %s,
                        guardrails_pct          = %s,
                        category_breakdown      = %s::jsonb,
                        service_breakdown       = %s::jsonb,
                        framework_compliance    = %s::jsonb,
                        top_failing_rules       = %s::jsonb,
                        risk_score              = %s,
                        completed_at            = %s,
                        scan_duration_ms        = %s,
                        status                  = %s
                    WHERE scan_run_id = %s
                """, (
                    len(inventory),
                    len(findings),
                    sev_counts["critical"],
                    sev_counts["high"],
                    sev_counts["medium"],
                    sev_counts["low"],
                    pass_count,
                    fail_count,
                    scores.get("vpc_isolation_pct", 0),
                    scores.get("encryption_rest_pct", 0),
                    scores.get("encryption_transit_pct", 0),
                    scores.get("model_card_pct", 0),
                    scores.get("monitoring_pct", 0),
                    scores.get("guardrails_pct", 0),
                    json.dumps(category_breakdown),
                    json.dumps(service_breakdown),
                    json.dumps(scores.get("framework_compliance", {})),
                    json.dumps(top_failing),
                    scores.get("risk_score", 0),
                    now,
                    scores.get("scan_duration_ms"),
                    status,
                    scan_run_id,
                ))
            conn.commit()
            logger.info(
                "Updated AI security report for scan %s — %d findings, %d resources",
                scan_run_id, len(findings), len(inventory),
            )
        except Exception:
            conn.rollback()
            logger.exception("Failed to update report for scan %s", scan_run_id)
            raise
        finally:
            conn.close()

    def save_findings(self, scan_run_id: str, findings: List[Dict[str, Any]]) -> int:
        """Batch insert findings into ai_security_findings.

        Uses execute_values for performance.
        ON CONFLICT on finding_id (VARCHAR PK) updates
        severity, status, detail, and remediation.

        Args:
            scan_run_id: Pipeline scan run identifier.
            findings: List of finding dicts with keys matching schema columns.

        Returns:
            Number of findings saved.
        """
        if not findings:
            return 0

        conn = self._get_connection()
        now = datetime.now(timezone.utc)

        # Build values tuples
        values = []
        for f in findings:
            finding_id = f.get("finding_id") or generate_finding_id(
                f.get("rule_id", ""),
                f.get("resource_uid") or f.get("resource_arn", ""),
                f.get("account_id", ""),
                f.get("region", ""),
            )
            values.append((
                finding_id,
                scan_run_id,
                f.get("tenant_id"),
                f.get("rule_id"),
                f.get("resource_id") or f.get("resource_uid"),
                f.get("resource_type"),
                f.get("resource_uid") or f.get("resource_arn"),
                f.get("ml_service"),
                f.get("model_type"),
                f.get("severity", "medium"),
                f.get("status", "FAIL"),
                f.get("category"),
                f.get("title"),
                f.get("detail"),
                f.get("remediation"),
                f.get("frameworks") or [],              # TEXT[]
                f.get("mitre_techniques") or [],        # TEXT[]
                f.get("account_id"),
                f.get("region"),
                f.get("provider") or f.get("csp", "aws"),
                now,
                now,
            ))

        sql = """
            INSERT INTO ai_security_findings (
                finding_id, scan_run_id, tenant_id,
                rule_id, resource_id, resource_type, resource_uid,
                ml_service, model_type,
                severity, status, category,
                title, detail, remediation,
                frameworks, mitre_techniques,
                account_id, region, provider, first_seen_at, last_seen_at
            )
            VALUES %s
            ON CONFLICT (finding_id) DO UPDATE SET
                severity = EXCLUDED.severity,
                status = EXCLUDED.status,
                detail = EXCLUDED.detail,
                remediation = EXCLUDED.remediation,
                last_seen_at = EXCLUDED.last_seen_at
        """

        try:
            with conn.cursor() as cur:
                execute_values(
                    cur, sql, values,
                    template="(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
                             "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    page_size=500,
                )
            conn.commit()
            count = len(values)
            logger.info("Saved %d AI security findings for scan %s", count, scan_run_id)
            return count
        except Exception:
            conn.rollback()
            logger.exception("Failed to save findings for scan %s", scan_run_id)
            raise
        finally:
            conn.close()

    def save_inventory(self, scan_run_id: str, inventory: List[Dict[str, Any]],
                       tenant_id: str = None) -> int:
        """Batch insert ML resource inventory into ai_security_inventory.

        Clears previous inventory for the scan, then batch-inserts new records.

        Args:
            scan_run_id: Pipeline scan run identifier.
            inventory: List of ML resource inventory dicts.
            tenant_id: Tenant identifier (used if not present in each dict).

        Returns:
            Number of inventory records saved.
        """
        if not inventory:
            return 0

        conn = self._get_connection()
        now = datetime.now(timezone.utc)

        values = []
        for r in inventory:
            values.append((
                scan_run_id,
                r.get("tenant_id") or tenant_id,
                r.get("resource_id") or r.get("resource_uid"),
                r.get("resource_type"),
                r.get("resource_uid") or r.get("resource_arn"),
                r.get("resource_name"),
                r.get("ml_service"),
                r.get("model_type"),
                r.get("framework"),
                r.get("deployment_type"),
                r.get("is_public_endpoint", False),
                r.get("auth_type"),
                r.get("has_guardrails", False),
                r.get("risk_score", 0),
                r.get("account_id"),
                r.get("region"),
                r.get("provider") or r.get("csp", "aws"),
                Json(r.get("tags", {})),
                now,
            ))

        sql = """
            INSERT INTO ai_security_inventory (
                scan_run_id, tenant_id,
                resource_id, resource_type, resource_uid, resource_name,
                ml_service, model_type, framework, deployment_type,
                is_public_endpoint, auth_type, has_guardrails, risk_score,
                account_id, region, provider, tags, created_at
            )
            VALUES %s
        """

        try:
            with conn.cursor() as cur:
                # Clear previous inventory for this scan
                cur.execute(
                    "DELETE FROM ai_security_inventory WHERE scan_run_id = %s",
                    (scan_run_id,),
                )
                execute_values(
                    cur, sql, values,
                    template="(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
                             "%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    page_size=500,
                )
            conn.commit()
            count = len(values)
            logger.info("Saved %d AI security inventory records for scan %s", count, scan_run_id)
            return count
        except Exception:
            conn.rollback()
            logger.exception("Failed to save inventory for scan %s", scan_run_id)
            raise
        finally:
            conn.close()

    def cleanup_old_scans(self, tenant_id: str, keep_latest: int = 3) -> int:
        """Retention cleanup -- keep only the N most recent scans per tenant.

        Deletes findings, inventory, and report rows for scans beyond keep_latest.

        Args:
            tenant_id: Tenant identifier.
            keep_latest: Number of most recent scans to retain.

        Returns:
            Number of scans cleaned up.
        """
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                # Get all scan IDs for tenant ordered by started_at DESC
                cur.execute("""
                    SELECT scan_run_id
                    FROM ai_security_report
                    WHERE tenant_id = %s
                    ORDER BY started_at DESC
                """, (tenant_id,))
                rows = cur.fetchall()

                if len(rows) <= keep_latest:
                    return 0

                old_scan_ids = [r[0] for r in rows[keep_latest:]]
                old_ids_tuple = tuple(str(sid) for sid in old_scan_ids)

                # Delete findings for old scans
                cur.execute(
                    "DELETE FROM ai_security_findings WHERE scan_run_id IN %s",
                    (old_ids_tuple,),
                )
                # Delete inventory for old scans
                cur.execute(
                    "DELETE FROM ai_security_inventory WHERE scan_run_id IN %s",
                    (old_ids_tuple,),
                )
                # Delete report rows
                cur.execute(
                    "DELETE FROM ai_security_report WHERE scan_run_id IN %s",
                    (old_ids_tuple,),
                )

            conn.commit()
            cleaned = len(old_scan_ids)
            logger.info(
                "Cleaned up %d old AI security scans for tenant %s",
                cleaned, tenant_id,
            )
            return cleaned
        except Exception:
            conn.rollback()
            logger.exception("Failed to cleanup old scans for tenant %s", tenant_id)
            raise
        finally:
            conn.close()

    def mark_failed(self, scan_run_id: str, error_message: str) -> None:
        """Mark report as failed with error message.

        Args:
            scan_run_id: Pipeline scan run identifier.
            error_message: Description of the failure.
        """
        conn = self._get_connection()
        now = datetime.now(timezone.utc)
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE ai_security_report SET
                        status = 'failed',
                        error_message = %s,
                        completed_at = %s
                    WHERE scan_run_id = %s
                """, (error_message, now, scan_run_id))
            conn.commit()
            logger.info("Marked scan %s as failed: %s", scan_run_id, error_message)
        except Exception:
            conn.rollback()
            logger.exception("Failed to mark scan %s as failed", scan_run_id)
            raise
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Module-level convenience functions (match encryption/dbsec pattern)
# ---------------------------------------------------------------------------

def save_findings_to_db(
    scan_run_id: str,
    tenant_id: str,
    provider: str,
    findings: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> int:
    """Save AI security findings and update report summary.

    Convenience wrapper matching the encryption/dbsec function signature.

    Args:
        scan_run_id: Pipeline scan run identifier.
        tenant_id: Tenant identifier.
        provider: Cloud provider (aws, azure, gcp).
        findings: List of AI security finding dicts.
        summary: Report summary dict with scores and breakdowns.

    Returns:
        Number of findings written.
    """
    conn = _get_ai_security_conn()
    now = datetime.now(timezone.utc)
    count = 0

    try:
        with conn.cursor() as cur:
            # Ensure tenant exists
            cur.execute(
                "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) "
                "ON CONFLICT DO NOTHING",
                (tenant_id, tenant_id),
            )

            # Update report with summary
            cur.execute("""
                UPDATE ai_security_report SET
                    status = 'completed',
                    total_ml_resources      = %s,
                    total_findings          = %s,
                    critical_findings       = %s,
                    high_findings           = %s,
                    medium_findings         = %s,
                    low_findings            = %s,
                    pass_count              = %s,
                    fail_count              = %s,
                    vpc_isolation_pct       = %s,
                    encryption_rest_pct     = %s,
                    encryption_transit_pct  = %s,
                    model_card_pct          = %s,
                    monitoring_pct          = %s,
                    guardrails_pct          = %s,
                    category_breakdown      = %s::jsonb,
                    service_breakdown       = %s::jsonb,
                    framework_compliance    = %s::jsonb,
                    top_failing_rules       = %s::jsonb,
                    risk_score              = %s,
                    completed_at            = %s
                WHERE scan_run_id = %s
            """, (
                summary.get("total_ml_resources", 0),
                summary.get("total_findings", 0),
                summary.get("critical_findings", 0),
                summary.get("high_findings", 0),
                summary.get("medium_findings", 0),
                summary.get("low_findings", 0),
                summary.get("pass_count", 0),
                summary.get("fail_count", 0),
                summary.get("vpc_isolation_pct", 0),
                summary.get("encryption_rest_pct", 0),
                summary.get("encryption_transit_pct", 0),
                summary.get("model_card_pct", 0),
                summary.get("monitoring_pct", 0),
                summary.get("guardrails_pct", 0),
                json.dumps(summary.get("category_breakdown", {})),
                json.dumps(summary.get("service_breakdown", {})),
                json.dumps(summary.get("framework_compliance", {})),
                json.dumps(summary.get("top_failing_rules", [])),
                summary.get("risk_score", 0),
                now,
                scan_run_id,
            ))

            # Insert findings
            for f in findings:
                finding_id = f.get("finding_id") or generate_finding_id(
                    f.get("rule_id", ""),
                    f.get("resource_uid") or f.get("resource_arn", ""),
                    f.get("account_id", ""),
                    f.get("region", ""),
                )
                cur.execute("""
                    INSERT INTO ai_security_findings (
                        finding_id, scan_run_id, tenant_id,
                        rule_id, resource_id, resource_type, resource_uid,
                        ml_service, model_type,
                        severity, status, category,
                        title, detail, remediation,
                        frameworks, mitre_techniques,
                        account_id, region, provider,
                        first_seen_at, last_seen_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (finding_id) DO UPDATE SET
                        severity = EXCLUDED.severity,
                        status = EXCLUDED.status,
                        detail = EXCLUDED.detail,
                        remediation = EXCLUDED.remediation,
                        last_seen_at = EXCLUDED.last_seen_at
                """, (
                    finding_id,
                    scan_run_id,
                    tenant_id,
                    f.get("rule_id"),
                    f.get("resource_id") or f.get("resource_uid"),
                    f.get("resource_type"),
                    f.get("resource_uid") or f.get("resource_arn"),
                    f.get("ml_service"),
                    f.get("model_type"),
                    f.get("severity", "medium"),
                    f.get("status", "FAIL"),
                    f.get("category"),
                    f.get("title"),
                    f.get("detail"),
                    f.get("remediation"),
                    f.get("frameworks") or [],
                    f.get("mitre_techniques") or [],
                    f.get("account_id"),
                    f.get("region"),
                    f.get("provider") or f.get("csp") or provider,
                    now,
                    now,
                ))
                count += 1

        conn.commit()
        logger.info("Saved %d AI security findings to DB for scan %s", count, scan_run_id)
        return count
    except Exception:
        conn.rollback()
        logger.exception("Failed to save findings for scan %s", scan_run_id)
        raise
    finally:
        conn.close()


def save_ai_inventory(
    scan_run_id: str,
    tenant_id: str,
    inventory: List[Dict[str, Any]],
) -> int:
    """Save ML resource inventory entries.

    Args:
        scan_run_id: Pipeline scan run identifier.
        tenant_id: Tenant identifier.
        inventory: List of ML resource inventory dicts.

    Returns:
        Number of inventory entries written.
    """
    conn = _get_ai_security_conn()
    count = 0
    now = datetime.now(timezone.utc)
    try:
        with conn.cursor() as cur:
            # Clear previous inventory for this scan
            cur.execute(
                "DELETE FROM ai_security_inventory "
                "WHERE scan_run_id = %s AND tenant_id = %s",
                (scan_run_id, tenant_id),
            )
            for r in inventory:
                cur.execute("""
                    INSERT INTO ai_security_inventory (
                        scan_run_id, tenant_id,
                        resource_id, resource_type, resource_uid, resource_name,
                        ml_service, model_type, framework, deployment_type,
                        is_public_endpoint, auth_type, has_guardrails, risk_score,
                        account_id, region, provider, tags, created_at
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                """, (
                    scan_run_id, tenant_id,
                    r.get("resource_id") or r.get("resource_uid"),
                    r.get("resource_type"),
                    r.get("resource_uid") or r.get("resource_arn"),
                    r.get("resource_name"),
                    r.get("ml_service"),
                    r.get("model_type"),
                    r.get("framework"),
                    r.get("deployment_type"),
                    r.get("is_public_endpoint", False),
                    r.get("auth_type"),
                    r.get("has_guardrails", False),
                    r.get("risk_score", 0),
                    r.get("account_id"),
                    r.get("region"),
                    r.get("provider") or r.get("csp", "aws"),
                    json.dumps(r.get("tags", {}), default=str),
                    now,
                ))
                count += 1
        conn.commit()
        logger.info("Saved %d AI security inventory entries for scan %s", count, scan_run_id)
        return count
    except Exception:
        conn.rollback()
        logger.exception("Failed to save inventory for scan %s", scan_run_id)
        raise
    finally:
        conn.close()
