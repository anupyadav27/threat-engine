"""
Control Assessor

Computes per-control assessment results from compliance_findings.
For each control in a framework, determines PASS/FAIL/PARTIAL/MANUAL_REVIEW/NOT_APPLICABLE.

Reads:  compliance_findings, compliance_controls, rule_control_mapping
Writes: control_assessment_results, compliance_assessments
"""

import os
import uuid
import json
import logging
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _get_conn():
    return psycopg2.connect(
        host=os.getenv("COMPLIANCE_DB_HOST", "localhost"),
        port=int(os.getenv("COMPLIANCE_DB_PORT", "5432")),
        database=os.getenv("COMPLIANCE_DB_NAME", "threat_engine_compliance"),
        user=os.getenv("COMPLIANCE_DB_USER", "postgres"),
        password=os.getenv("COMPLIANCE_DB_PASSWORD", ""),
    )


def compute_assessment(
    scan_run_id: str,
    tenant_id: str,
    framework_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Compute control-level assessment results from compliance findings.

    For each control in the framework(s):
      - Count failing resources from compliance_findings
      - Determine status: PASS / FAIL / PARTIAL / MANUAL_REVIEW / NOT_APPLICABLE
      - Write to control_assessment_results

    Args:
        scan_run_id: Compliance scan ID
        tenant_id: Tenant identifier
        framework_id: Optional framework filter (None = all frameworks)

    Returns:
        Summary dict with counts per status
    """
    conn = _get_conn()
    try:
        # 1. Get all controls (optionally filtered by framework)
        controls = _load_controls(conn, framework_id)
        if not controls:
            return {"status": "no_controls", "total": 0}

        # 2. Get failure counts per control from compliance_findings
        fail_counts = _get_fail_counts(conn, scan_run_id, tenant_id)

        # 3. Get total resource counts per rule from check DB (pass + fail)
        total_counts = _get_total_counts_from_check(scan_run_id, tenant_id)

        # 4. Build rule -> control mapping
        rule_to_controls = _load_rule_control_map(conn, framework_id)

        # 5. Compute per-control status
        assessment_id = str(uuid.uuid4())
        results = []
        summary = {"PASS": 0, "FAIL": 0, "PARTIAL": 0, "MANUAL_REVIEW": 0, "NOT_APPLICABLE": 0}

        for ctrl in controls:
            cid = ctrl["control_id"]
            fid = ctrl["framework_id"]
            atype = ctrl.get("assessment_type", "automated")

            if atype == "manual":
                status = "MANUAL_REVIEW"
                pass_count = 0
                fail_count = 0
                total = 0
            else:
                # Find rules mapped to this control
                mapped_rules = [r for r, cids in rule_to_controls.items() if cid in cids]

                fail_count = fail_counts.get(cid, 0)
                # Also check by rule -> count failures
                if fail_count == 0:
                    for rid in mapped_rules:
                        fail_count += fail_counts.get(rid, 0)

                # Total resources = sum of total checks for mapped rules
                total = 0
                for rid in mapped_rules:
                    total += total_counts.get(rid, 0)

                pass_count = max(0, total - fail_count)

                if total == 0:
                    status = "NOT_APPLICABLE"
                elif fail_count == 0:
                    status = "PASS"
                elif pass_count == 0:
                    status = "FAIL"
                else:
                    status = "PARTIAL"

            summary[status] = summary.get(status, 0) + 1

            results.append((
                str(uuid.uuid4()),  # result_id
                assessment_id,
                cid,
                tenant_id,
                status,                     # implementation_status
                None,                       # effectiveness
                "automated" if atype != "manual" else "manual",  # test_method
                json.dumps({
                    "pass_count": pass_count,
                    "fail_count": fail_count,
                    "total_resources": total,
                    "scan_run_id": scan_run_id,
                }),                         # test_results
                None,                       # deficiencies
                None,                       # recommendations
                None,                       # evidence_references
                None,                       # residual_risk
                None,                       # compensating_controls
                None,                       # target_remediation_date
                None,                       # actual_remediation_date
                "system",                   # assessed_by
                datetime.now(timezone.utc),  # assessed_at
            ))

        # 6. Write assessment header
        _write_assessment(conn, assessment_id, scan_run_id, tenant_id, framework_id, controls, summary)

        # 7. Write control results (batch)
        _write_results(conn, results)

        conn.commit()
        logger.info(
            f"Assessment computed: {assessment_id} | "
            f"{len(results)} controls | {summary}"
        )
        return {
            "assessment_id": assessment_id,
            "scan_run_id": scan_run_id,
            "tenant_id": tenant_id,
            "framework_id": framework_id or "all",
            "total_controls": len(results),
            "summary": summary,
        }

    except Exception as e:
        conn.rollback()
        logger.error(f"Assessment computation failed: {e}", exc_info=True)
        raise
    finally:
        conn.close()


def _load_controls(conn, framework_id: Optional[str]) -> List[Dict]:
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        if framework_id:
            cur.execute(
                "SELECT control_id, framework_id, control_name, assessment_type, severity "
                "FROM compliance_controls WHERE framework_id = %s AND is_active = true",
                (framework_id,),
            )
        else:
            cur.execute(
                "SELECT control_id, framework_id, control_name, assessment_type, severity "
                "FROM compliance_controls WHERE is_active = true"
            )
        return [dict(r) for r in cur.fetchall()]


def _get_fail_counts(conn, scan_run_id: str, tenant_id: str) -> Dict[str, int]:
    """Count failures per control_id and per rule_id from compliance_findings."""
    counts: Dict[str, int] = {}
    with conn.cursor() as cur:
        # By control_id
        cur.execute("""
            SELECT COALESCE(NULLIF(control_id, ''), finding_data->>'control_id') AS cid,
                   COUNT(*) AS cnt
            FROM compliance_findings
            WHERE scan_run_id = %s AND tenant_id = %s
            GROUP BY cid
        """, (scan_run_id, tenant_id))
        for row in cur.fetchall():
            if row[0]:
                counts[row[0]] = row[1]

        # By rule_id
        cur.execute("""
            SELECT rule_id, COUNT(*) AS cnt
            FROM compliance_findings
            WHERE scan_run_id = %s AND tenant_id = %s AND rule_id IS NOT NULL
            GROUP BY rule_id
        """, (scan_run_id, tenant_id))
        for row in cur.fetchall():
            if row[0]:
                counts[row[0]] = row[1]

    return counts


def _get_total_counts_from_check(scan_run_id: str, tenant_id: str) -> Dict[str, int]:
    """Get total resource counts per rule from check DB (pass + fail).

    Uses the latest check scan for this tenant since the compliance scan_run_id
    is different from the check scan_run_id.
    """
    counts: Dict[str, int] = {}
    try:
        check_conn = psycopg2.connect(
            host=os.getenv("CHECK_DB_HOST", "localhost"),
            port=int(os.getenv("CHECK_DB_PORT", "5432")),
            database=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
            user=os.getenv("CHECK_DB_USER", "postgres"),
            password=os.getenv("CHECK_DB_PASSWORD", ""),
        )
        with check_conn.cursor() as cur:
            # Find the latest check scan for this tenant
            cur.execute("""
                SELECT scan_run_id FROM check_report
                WHERE tenant_id = %s AND status = 'completed'
                ORDER BY first_seen_at DESC LIMIT 1
            """, (tenant_id,))
            row = cur.fetchone()
            check_scan_id = row[0] if row else scan_run_id

            # Count pass+fail per rule
            cur.execute("""
                SELECT rule_id, COUNT(*) AS cnt,
                       COUNT(CASE WHEN status = 'PASS' THEN 1 END) AS pass_cnt,
                       COUNT(CASE WHEN status = 'FAIL' THEN 1 END) AS fail_cnt
                FROM check_findings
                WHERE scan_run_id = %s AND tenant_id = %s
                GROUP BY rule_id
            """, (check_scan_id, tenant_id))
            for row in cur.fetchall():
                if row[0]:
                    counts[row[0]] = row[1]  # total
        check_conn.close()
    except Exception as e:
        logger.warning(f"Could not read check DB for total counts: {e}")
    return counts


def _load_rule_control_map(conn, framework_id: Optional[str]) -> Dict[str, List[str]]:
    """Load rule_id -> [control_ids] from rule_control_mapping."""
    mapping: Dict[str, List[str]] = {}
    with conn.cursor() as cur:
        if framework_id:
            cur.execute(
                "SELECT rule_id, control_id FROM rule_control_mapping "
                "WHERE framework_id = %s AND is_active = true",
                (framework_id,),
            )
        else:
            cur.execute(
                "SELECT rule_id, control_id FROM rule_control_mapping WHERE is_active = true"
            )
        for row in cur.fetchall():
            mapping.setdefault(row[0], []).append(row[1])
    return mapping


def _write_assessment(conn, assessment_id, scan_run_id, tenant_id, framework_id, controls, summary):
    total = len(controls)
    implemented = summary.get("PASS", 0) + summary.get("PARTIAL", 0)
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO compliance_assessments (
                assessment_id, tenant_id, framework_id,
                assessment_name, assessment_type, status,
                started_at, completed_at,
                total_controls, controls_implemented, controls_deficient,
                controls_not_applicable, overall_score, assessment_data
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            assessment_id,
            tenant_id,
            framework_id or "all",
            f"Automated assessment - {scan_run_id[:8]}",
            "automated",
            "completed",
            datetime.now(timezone.utc),
            datetime.now(timezone.utc),
            total,
            implemented,
            summary.get("FAIL", 0),
            summary.get("NOT_APPLICABLE", 0),
            round(100 * implemented / total, 1) if total > 0 else 0,
            json.dumps({"scan_run_id": scan_run_id, "summary": summary}),
        ))


def _write_results(conn, results):
    if not results:
        return
    with conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO control_assessment_results (
                result_id, assessment_id, control_id, tenant_id,
                implementation_status, effectiveness, test_method,
                test_results, deficiencies, recommendations,
                evidence_references, residual_risk, compensating_controls,
                target_remediation_date, actual_remediation_date,
                assessed_by, assessed_at
            ) VALUES %s
            ON CONFLICT (result_id) DO NOTHING
        """, results, page_size=500)
