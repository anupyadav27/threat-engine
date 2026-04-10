"""
DataSec Database Writer

Writes data security reports to RDS:
- datasec_report (main report, PK: scan_run_id)
- datasec_findings (individual data security findings)
"""

import os
import json
import uuid
from typing import Dict, Any, List
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import Json


def _get_datasec_db_connection():
    """Get DataSec DB connection using individual parameters."""
    return psycopg2.connect(
        host=os.getenv("DATASEC_DB_HOST", "localhost"),
        port=int(os.getenv("DATASEC_DB_PORT", "5432")),
        database=os.getenv("DATASEC_DB_NAME", "threat_engine_datasec"),
        user=os.getenv("DATASEC_DB_USER", "postgres"),
        password=os.getenv("DATASEC_DB_PASSWORD", "")
    )


def save_module_results_to_db(
    scan_run_id: str,
    tenant_id: str,
    provider: str,
    module_results: Dict[str, List],
    summary: Dict[str, Any],
    account_id: str = "",
    credential_ref: str = "",
    credential_type: str = "",
) -> None:
    """
    Save ModuleResult objects from the new modular architecture.
    Updates datasec_report with summary + posture scores, inserts datasec_findings.
    """
    import logging
    from collections import Counter
    logger = logging.getLogger(__name__)

    conn = _get_datasec_db_connection()
    now = datetime.now(timezone.utc)

    try:
        with conn.cursor() as cur:
            # Ensure tenant
            cur.execute(
                "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (tenant_id, tenant_id),
            )

            # ── Compute severity counts and per-module posture scores ─────
            severity_counts = Counter()
            module_severity = {}  # {module: Counter}
            total_findings = 0
            fail_count = 0
            unique_resources = set()
            encrypted_resources = set()
            public_stores = set()

            for category, results in module_results.items():
                mod_counter = Counter()
                for r in results:
                    total_findings += 1
                    if r.status == "FAIL":
                        severity_counts[r.severity] += 1
                        mod_counter[r.severity] += 1
                        fail_count += 1
                    unique_resources.add(r.resource_uid)

                    # Track encryption and public access from evidence
                    evidence = r.evidence if isinstance(r.evidence, dict) else {}
                    if "encryption" in category.lower() and r.status == "PASS":
                        encrypted_resources.add(r.resource_uid)
                    if evidence.get("public_access") or evidence.get("is_public"):
                        public_stores.add(r.resource_uid)

                module_severity[category] = mod_counter

            # Risk score: (critical*10 + high*5 + medium*2 + low*1) / max(total,1) * 10
            data_risk_score = 0
            if total_findings > 0:
                raw = (severity_counts.get("critical", 0) * 10
                       + severity_counts.get("high", 0) * 5
                       + severity_counts.get("medium", 0) * 2
                       + severity_counts.get("low", 0) * 1) / max(total_findings, 1) * 10
                data_risk_score = min(int(round(raw)), 100)

            # Per-module scores (100 = no failures, 0 = all critical)
            def _module_score(mod_counter):
                total = sum(mod_counter.values())
                if total == 0:
                    return 100
                penalty = mod_counter.get("critical", 0) * 20 + mod_counter.get("high", 0) * 10 + mod_counter.get("medium", 0) * 3
                return max(0, 100 - penalty)

            encryption_score = _module_score(module_severity.get("data_protection_encryption", Counter()))
            access_score = _module_score(module_severity.get("data_access_control", Counter()))
            classification_score = _module_score(module_severity.get("data_classification", Counter()))
            lifecycle_score = _module_score(module_severity.get("data_lifecycle", Counter()))
            residency_score = _module_score(module_severity.get("data_residency", Counter()))
            monitoring_score = _module_score(module_severity.get("data_logging_monitoring", Counter()))

            total_stores = len(unique_resources)
            encrypted_pct = round(len(encrypted_resources) / max(total_stores, 1) * 100, 1)

            # ── Update report with scores ─────────────────────────────────
            cur.execute("""
                UPDATE datasec_report SET
                    total_findings = %s,
                    datasec_relevant_findings = %s,
                    critical_findings = %s,
                    high_findings = %s,
                    medium_findings = %s,
                    low_findings = %s,
                    data_risk_score = %s,
                    encryption_score = %s,
                    access_score = %s,
                    classification_score = %s,
                    lifecycle_score = %s,
                    residency_score = %s,
                    monitoring_score = %s,
                    total_data_stores = %s,
                    encrypted_pct = %s,
                    public_data_stores = %s,
                    account_id = %s,
                    findings_by_module = %s::jsonb,
                    findings_by_status = %s::jsonb,
                    severity_breakdown = %s::jsonb,
                    report_data = %s::jsonb,
                    status = 'completed',
                    completed_at = %s,
                    generated_at = %s
                WHERE scan_run_id = %s
            """, (
                total_findings,
                fail_count,
                severity_counts.get("critical", 0),
                severity_counts.get("high", 0),
                severity_counts.get("medium", 0),
                severity_counts.get("low", 0),
                data_risk_score,
                encryption_score,
                access_score,
                classification_score,
                lifecycle_score,
                residency_score,
                monitoring_score,
                total_stores,
                encrypted_pct,
                len(public_stores),
                account_id,
                json.dumps(summary.get("findings_by_module", {})),
                json.dumps({"FAIL": fail_count, "PASS": total_findings - fail_count}),
                json.dumps(dict(severity_counts)),
                json.dumps(summary),
                now,
                now,
                scan_run_id,
            ))

            # ── Insert findings from all modules ──────────────────────────
            count = 0
            for category, results in module_results.items():
                for r in results:
                    if r.status == "PASS":
                        continue
                    finding_id = f"ds_{uuid.uuid4().hex[:16]}"
                    cur.execute("""
                        INSERT INTO datasec_findings (
                            finding_id, scan_run_id, tenant_id,
                            account_id, credential_ref, credential_type,
                            provider, region,
                            rule_id, datasec_modules, severity, status,
                            resource_type, resource_uid,
                            data_classification, sensitivity_score,
                            finding_data, first_seen_at, last_seen_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                        ON CONFLICT (finding_id) DO NOTHING
                    """, (
                        finding_id,
                        scan_run_id,
                        tenant_id,
                        account_id,
                        credential_ref,
                        credential_type,
                        provider,
                        getattr(r, 'region', '') or (r.evidence.get('region', '') if isinstance(r.evidence, dict) else ''),
                        r.rule_id,
                        [r.category],
                        r.severity,
                        r.status,
                        r.resource_type,
                        r.resource_uid,
                        r.sensitive_data_types if isinstance(r.sensitive_data_types, list) else ([r.sensitive_data_types] if r.sensitive_data_types else []),
                        r.confidence,
                        json.dumps({
                            "title": r.title,
                            "description": r.description,
                            "remediation": r.remediation,
                            "evidence": r.evidence,
                            "compliance_frameworks": r.compliance_frameworks,
                        }, default=str),
                        now,
                        now,
                    ))
                    count += 1

        conn.commit()
        logger.info(f"Saved {count} datasec findings to DB for scan {scan_run_id} "
                     f"(risk_score={data_risk_score}, encryption={encryption_score}, access={access_score})")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def save_datasec_report_to_db(report: Dict[str, Any]) -> str:
    """
    Save data security report to database.
    
    Args:
        report: Full data security report dict
    
    Returns:
        scan_run_id string
    """
    scan_run_id = str(report.get("scan_run_id") or report.get("report_id") or uuid.uuid4())
    tenant_id = report.get("tenant_id", "default")
    scan_context = report.get("scan_context", {})
    # Do NOT overwrite scan_run_id — it was already set from report dict
    cloud = scan_context.get("csp", "aws")
    
    # Parse timestamp
    generated_at_str = scan_context.get("generated_at", "")
    try:
        generated_at = datetime.fromisoformat(generated_at_str.replace('Z', '+00:00'))
    except Exception:
        generated_at = datetime.now(timezone.utc)
    
    # Extract summary
    summary = report.get("summary", {})
    total_findings = summary.get("total_findings", 0)
    datasec_relevant = summary.get("data_security_relevant_findings", 0)
    findings_by_module = summary.get("findings_by_module", {})
    
    classification_summary = summary.get("classification", {})
    classified_resources = classification_summary.get("classified_resources", 0)
    classification_types = classification_summary.get("classification_types", {})
    
    residency_summary = summary.get("residency", {})
    
    total_data_stores = scan_context.get("total_data_stores", 0)
    
    conn = _get_datasec_db_connection()
    
    try:
        with conn.cursor() as cur:
            # Upsert tenant
            cur.execute("""
                INSERT INTO tenants (tenant_id, tenant_name)
                VALUES (%s, %s)
                ON CONFLICT (tenant_id) DO NOTHING
            """, (tenant_id, tenant_id))
            
            # Insert report
            cur.execute("""
                INSERT INTO datasec_report (
                    scan_run_id, tenant_id, cloud, generated_at,
                    total_findings, datasec_relevant_findings,
                    classified_resources, total_data_stores,
                    findings_by_module, classification_summary, residency_summary,
                    report_data
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb)
                ON CONFLICT (scan_run_id) DO UPDATE SET
                    generated_at = EXCLUDED.generated_at,
                    total_findings = EXCLUDED.total_findings,
                    datasec_relevant_findings = EXCLUDED.datasec_relevant_findings,
                    classified_resources = EXCLUDED.classified_resources,
                    total_data_stores = EXCLUDED.total_data_stores,
                    findings_by_module = EXCLUDED.findings_by_module,
                    classification_summary = EXCLUDED.classification_summary,
                    residency_summary = EXCLUDED.residency_summary,
                    report_data = EXCLUDED.report_data
            """, (
                scan_run_id,
                tenant_id,
                cloud,
                generated_at,
                total_findings,
                datasec_relevant,
                classified_resources,
                total_data_stores,
                json.dumps(findings_by_module),
                json.dumps(classification_types),
                json.dumps(residency_summary),
                json.dumps(report, default=str)
            ))
            
            # Insert findings
            findings = report.get("findings", [])
            classification = report.get("classification", [])
            
            # Create classification lookup
            classification_map = {}
            for cls in classification:
                resource_id = cls.get("resource_id")
                if resource_id:
                    classification_map[resource_id] = {
                        "types": cls.get("classification", []),
                        "confidence": cls.get("confidence", 0.0)
                    }
            
            for finding in findings:
                if finding.get("status") == "FAIL":  # Only store failures
                    finding_id = str(uuid.uuid4())
                    # Resource fields are at top level (from threat_db_reader), with nested fallback
                    f_resource_type = finding.get("resource_type") or finding.get("resource", {}).get("type")
                    f_resource_id = finding.get("resource_id") or finding.get("resource", {}).get("id")
                    f_resource_uid = finding.get("resource_uid") or finding.get("resource_arn") or finding.get("resource", {}).get("arn")
                    resource_id = f_resource_id or f_resource_uid

                    # Get classification for this resource
                    cls_info = classification_map.get(resource_id, {})
                    data_classification = cls_info.get("types", [])
                    sensitivity = cls_info.get("confidence", 0.0)

                    cur.execute("""
                        INSERT INTO datasec_findings (
                            finding_id, scan_run_id, tenant_id,
                            rule_id, datasec_modules, severity, status,
                            resource_type, resource_id, resource_uid, account_id, region,
                            data_classification, sensitivity_score,
                            finding_data, first_seen_at, last_seen_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                        ON CONFLICT (finding_id) DO NOTHING
                    """, (
                        finding_id,
                        scan_run_id,
                        tenant_id,
                        finding.get("rule_id"),
                        finding.get("data_security_modules", []),
                        finding.get("severity", "medium"),
                        finding.get("status"),
                        f_resource_type,
                        f_resource_id,
                        f_resource_uid,
                        finding.get("account_id"),
                        finding.get("region"),
                        data_classification,
                        sensitivity,
                        json.dumps(finding, default=str),
                        generated_at,
                        generated_at
                    ))
        
        conn.commit()
        return scan_run_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── New enrichment writers (Phase 2) ─────────────────────────────────────────

import logging as _logging
_logger = _logging.getLogger(__name__)


def save_data_catalog(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
    metadata: Dict[str, Dict],
) -> int:
    """Save enriched data catalog entries from discovery metadata."""
    if not metadata:
        return 0

    conn = _get_datasec_db_connection()
    try:
        with conn.cursor() as cur:
            count = 0
            for uid, meta in metadata.items():
                cur.execute("""
                    INSERT INTO datasec_data_catalog (
                        scan_run_id, tenant_id, account_id, provider, region,
                        resource_uid, resource_type, resource_name, service,
                        size_bytes, record_count, owner, tags, creation_date,
                        encryption_at_rest, is_public, versioning_enabled, backup_enabled,
                        last_scanned_at
                    ) VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s, %s::jsonb, %s,
                        %s, %s, %s, %s,
                        NOW()
                    )
                    ON CONFLICT (scan_run_id, resource_uid) DO UPDATE SET
                        resource_name = EXCLUDED.resource_name,
                        size_bytes = EXCLUDED.size_bytes,
                        record_count = EXCLUDED.record_count,
                        owner = EXCLUDED.owner,
                        tags = EXCLUDED.tags,
                        encryption_at_rest = EXCLUDED.encryption_at_rest,
                        is_public = EXCLUDED.is_public,
                        last_scanned_at = NOW()
                """, (
                    scan_run_id, tenant_id, account_id, provider,
                    meta.get("region", ""),
                    uid,
                    meta.get("service", ""),
                    meta.get("name", ""),
                    meta.get("service", ""),
                    meta.get("size_bytes", 0),
                    meta.get("record_count", 0),
                    meta.get("owner", ""),
                    json.dumps(meta.get("tags", {})),
                    meta.get("creation_date"),
                    meta.get("encryption_at_rest", False),
                    meta.get("is_public", False),
                    meta.get("versioning_enabled", False),
                    meta.get("backup_enabled", False),
                ))
                count += 1
        conn.commit()
        _logger.info("Saved %d data catalog entries", count)
        return count
    except Exception as e:
        conn.rollback()
        _logger.warning("Failed to save data catalog: %s", e)
        return 0
    finally:
        conn.close()


def save_lineage_records(lineage: list) -> int:
    """Save data lineage records from inventory relationships."""
    if not lineage:
        return 0

    conn = _get_datasec_db_connection()
    try:
        with conn.cursor() as cur:
            for rec in lineage:
                cur.execute("""
                    INSERT INTO datasec_lineage (
                        scan_run_id, tenant_id,
                        source_uid, source_type, source_region,
                        destination_uid, destination_type, destination_region,
                        transfer_type, is_cross_region, is_cross_account,
                        relationship_source
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    rec["scan_run_id"], rec["tenant_id"],
                    rec["source_uid"], rec.get("source_type", ""),
                    rec.get("source_region", ""),
                    rec["destination_uid"], rec.get("destination_type", ""),
                    rec.get("destination_region", ""),
                    rec.get("transfer_type", "unknown"),
                    rec.get("is_cross_region", False),
                    rec.get("is_cross_account", False),
                    rec.get("relationship_source", "inventory"),
                ))
        conn.commit()
        _logger.info("Saved %d lineage records", len(lineage))
        return len(lineage)
    except Exception as e:
        conn.rollback()
        _logger.warning("Failed to save lineage records: %s", e)
        return 0
    finally:
        conn.close()


def save_access_activity(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    access_patterns: list,
) -> int:
    """Save CIEM data access activity events."""
    if not access_patterns:
        return 0

    conn = _get_datasec_db_connection()
    try:
        with conn.cursor() as cur:
            count = 0
            for event in access_patterns[:1000]:  # cap at 1000 events per scan
                cur.execute("""
                    INSERT INTO datasec_access_activity (
                        scan_run_id, tenant_id, account_id,
                        resource_uid, resource_type, principal, action,
                        event_time, source_ip, is_anomaly, anomaly_reason
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    scan_run_id, tenant_id, account_id,
                    event.get("resource_uid", event.get("resource", "")),
                    event.get("resource_type", ""),
                    event.get("principal", event.get("user", "")),
                    event.get("action", event.get("event_type", "")),
                    event.get("event_time", event.get("timestamp")),
                    event.get("source_ip", event.get("location", "")),
                    event.get("is_anomaly", False),
                    event.get("anomaly_reason", ""),
                ))
                count += 1
        conn.commit()
        _logger.info("Saved %d access activity events", count)
        return count
    except Exception as e:
        conn.rollback()
        _logger.warning("Failed to save access activity: %s", e)
        return 0
    finally:
        conn.close()


def update_catalog_encryption(
    scan_run_id: str,
    tenant_id: str,
    enc_status: Dict[str, Dict],
) -> int:
    """Update data catalog with encryption engine cross-reference data."""
    if not enc_status:
        return 0

    conn = _get_datasec_db_connection()
    try:
        count = 0
        with conn.cursor() as cur:
            for resource_uid, enc in enc_status.items():
                key_type = enc.get("key_type", "unknown")
                cur.execute("""
                    UPDATE datasec_data_catalog SET
                        encryption_at_rest = TRUE,
                        kms_key_type = %s,
                        encryption_in_transit = %s
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND resource_uid = %s
                """, (
                    key_type,
                    enc.get("transit_enforced", False),
                    scan_run_id, tenant_id, resource_uid,
                ))
                if cur.rowcount > 0:
                    count += 1
        conn.commit()
        _logger.info("Updated encryption status for %d catalog entries", count)
        return count
    except Exception as e:
        conn.rollback()
        _logger.warning("Failed to update catalog encryption: %s", e)
        return 0
    finally:
        conn.close()
