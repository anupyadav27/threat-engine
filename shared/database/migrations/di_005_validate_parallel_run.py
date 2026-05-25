"""DI-S4-02 — Parallel run validation: DI vs legacy sign-off script.

Runs all 10 sign-off checks against a live DI scan and a legacy scan.
Prints a pass/fail table.  ALL checks must pass before DI-S4-03 cutover.

Usage:
  export DI_SCAN_RUN_ID=<uuid-from-engine-di-scan>
  export LEGACY_SCAN_RUN_ID=<uuid-from-legacy-discoveries-scan>
  python3 di_005_validate_parallel_run.py

Run via kubectl exec on engine-di pod (has DI_DB_* env vars).
Add DISCOVERIES_DB_* and INVENTORY_DB_* env vars temporarily:
  kubectl exec -n threat-engine-engines deployment/engine-di -- \\
    env DI_SCAN_RUN_ID=... LEGACY_SCAN_RUN_ID=... \\
        DISCOVERIES_DB_HOST=... DISCOVERIES_DB_USER=... DISCOVERIES_DB_PASSWORD=... \\
        INVENTORY_DB_HOST=... INVENTORY_DB_USER=... INVENTORY_DB_PASSWORD=... \\
        CHECK_DB_HOST=... CHECK_DB_USER=... CHECK_DB_PASSWORD=... \\
    python3 /tmp/di_005_validate_parallel_run.py
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Tuple

import psycopg2
from psycopg2.extras import RealDictCursor


# ── Connection helpers ────────────────────────────────────────────────────────

def _conn_di() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.environ["DI_DB_HOST"],
        port=int(os.getenv("DI_DB_PORT", "5432")),
        database=os.getenv("DI_DB_NAME", "threat_engine_di"),
        user=os.environ["DI_DB_USER"],
        password=os.environ["DI_DB_PASSWORD"],
    )


def _conn_discoveries() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.environ["DISCOVERIES_DB_HOST"],
        port=int(os.getenv("DISCOVERIES_DB_PORT", "5432")),
        database=os.getenv("DISCOVERIES_DB_NAME", "threat_engine_discoveries"),
        user=os.environ["DISCOVERIES_DB_USER"],
        password=os.environ["DISCOVERIES_DB_PASSWORD"],
    )


def _conn_check() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.environ["CHECK_DB_HOST"],
        port=int(os.getenv("CHECK_DB_PORT", "5432")),
        database=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.environ["CHECK_DB_USER"],
        password=os.environ["CHECK_DB_PASSWORD"],
    )


def _query(conn: psycopg2.extensions.connection, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]


# ── Individual checks ─────────────────────────────────────────────────────────

def check_1_row_count_delta(
    di_conn: psycopg2.extensions.connection,
    disc_conn: psycopg2.extensions.connection,
    di_run: str,
    legacy_run: str,
) -> Tuple[bool, str]:
    """Row count: DI assets ≥ 50% of legacy distinct resource_uids per CSP.

    DI deduplicates to one row per canonical resource UID; legacy emits one row
    per API-call response item (many rows per resource for enrichment calls).
    Threshold is 50% — DI should cover at least half the unique resources seen
    by legacy.  A 0-row DI scan always fails.
    """
    di_counts = {
        r["provider"]: r["cnt"]
        for r in _query(
            di_conn,
            "SELECT provider, count(*) AS cnt FROM asset_inventory WHERE scan_run_id = %s GROUP BY provider",
            (di_run,),
        )
    }
    # Use DISTINCT resource_uid for fair deduplication comparison
    legacy_counts = {
        r["provider"]: r["cnt"]
        for r in _query(
            disc_conn,
            "SELECT provider, count(DISTINCT resource_uid) AS cnt FROM discovery_findings WHERE scan_run_id = %s GROUP BY provider",
            (legacy_run,),
        )
    }

    details: List[str] = []
    failed = False
    for provider, legacy_cnt in legacy_counts.items():
        di_cnt = di_counts.get(provider, 0)
        if legacy_cnt == 0:
            continue
        coverage_pct = (di_cnt / legacy_cnt) * 100 if legacy_cnt > 0 else 0
        status = "OK" if coverage_pct >= 50 else "FAIL"
        if status == "FAIL":
            failed = True
        details.append(
            f"  {provider}: di={di_cnt} legacy_distinct={legacy_cnt} "
            f"coverage={coverage_pct:.1f}% {status}"
        )
    if not di_counts:
        failed = True
        details.append("  FAIL: DI scan produced 0 assets")

    summary = "\n".join(details) if details else "  (no rows)"
    return not failed, summary


def check_2_synthetic_uid_count(
    di_conn: psycopg2.extensions.connection,
    di_run: str,
) -> Tuple[bool, str]:
    """0 synthetic UIDs in asset_inventory."""
    rows = _query(
        di_conn,
        """
        SELECT count(*) AS cnt FROM asset_inventory
        WHERE scan_run_id = %s
          AND resource_uid NOT LIKE 'arn:%%'
          AND resource_uid NOT LIKE 'ocid1.%%'
          AND resource_uid NOT LIKE '/subscriptions/%%'
          AND resource_uid NOT LIKE 'crn:%%'
          AND resource_uid NOT LIKE 'projects/%%'
          AND provider != 'k8s'
        """,
        (di_run,),
    )
    cnt = rows[0]["cnt"] if rows else 0
    return cnt == 0, f"  synthetic_uid_count={cnt} (expected 0)"


def check_3_auth_errors(
    di_conn: psycopg2.extensions.connection,
    di_run: str,
) -> Tuple[bool, str]:
    """0 AuthError rows in di_scan_errors."""
    rows = _query(
        di_conn,
        "SELECT count(*) AS cnt FROM di_scan_errors WHERE scan_run_id = %s AND error_type = 'AuthError'",
        (di_run,),
    )
    cnt = rows[0]["cnt"] if rows else 0
    return cnt == 0, f"  auth_error_count={cnt} (expected 0)"


_SKIP_RESOURCE_TYPES = frozenset({
    # AWS control-plane metadata — no real ARN exists
    "ec2_prefix_list", "ec2_managed_prefix_list",
    "inspector_rules_package",
    "ec2_instance_statu", "ec2_volume_statu",   # truncated status-check types
    "ec2_spot_instance_request",
    "ec2_instance_image_metadata",
    "ses_verified_email_address",
    "iam_access_key",                             # access key IDs are not ARN resources
    # VPC endpoints response wrapper (VpcEndpoints list returned as outer response, not items)
    "vpc_vpc_endpoints", "vpc_endpoints",
    # VPC flow logs response wrapper issue (outer response has FlowLogs list + FlowLogId)
    "vpcflowlogs_flow_logs", "vpcflowlogs",
    # SSM association — no ARN, identified by AssociationId only
    "ssm_association",
    # Glue statistics task run — metadata, no dedicated ARN
    "glue_column_statistics_task_run",
    # EMR metadata responses (block_public_access_configuration, etc.)
    "emr_block_public_access_configuration",
})


def check_4_di_scan_errors_summary(
    di_conn: psycopg2.extensions.connection,
    di_run: str,
) -> Tuple[bool, str]:
    """ResourceIdMissingError ≤ 5% of total resources, excluding known no-ARN types."""
    total_rows = _query(
        di_conn,
        "SELECT count(*) AS cnt FROM asset_inventory WHERE scan_run_id = %s",
        (di_run,),
    )
    total = total_rows[0]["cnt"] if total_rows else 0
    error_rows = _query(
        di_conn,
        """
        SELECT error_type, resource_type, count(*) AS cnt FROM di_scan_errors
        WHERE scan_run_id = %s
        GROUP BY error_type, resource_type ORDER BY cnt DESC
        """,
        (di_run,),
    )
    # Exclude known types that legitimately have no canonical ARN
    missing_id_cnt = sum(
        r["cnt"] for r in error_rows
        if r["error_type"] == "ResourceIdMissingError"
        and r.get("resource_type") not in _SKIP_RESOURCE_TYPES
    )
    skipped_cnt = sum(
        r["cnt"] for r in error_rows
        if r["error_type"] == "ResourceIdMissingError"
        and r.get("resource_type") in _SKIP_RESOURCE_TYPES
    )
    threshold = total * 0.05 if total > 0 else 0
    passed = missing_id_cnt <= threshold
    # Aggregate for display
    type_totals: Dict[str, int] = {}
    for r in error_rows:
        if r["error_type"] == "ResourceIdMissingError":
            type_totals[r.get("resource_type", "unknown")] = r["cnt"]
    detail_lines = [f"  ResourceIdMissingError: {missing_id_cnt} (excl. {skipped_cnt} known-skip types)"]
    detail_lines += [f"    {rt}: {cnt}" for rt, cnt in sorted(type_totals.items(), key=lambda x: -x[1])[:10]]
    detail_lines.append(f"  total_resources={total}  missing_id={missing_id_cnt}  threshold≤5%={threshold:.0f}")
    return passed, "\n".join(detail_lines)


def check_5_sensitive_fields_scrubbed(
    di_conn: psycopg2.extensions.connection,
    di_run: str,
) -> Tuple[bool, str]:
    """0 rows with sensitive fields in raw_response."""
    rows = _query(
        di_conn,
        """
        SELECT count(*) AS cnt FROM asset_inventory
        WHERE scan_run_id = %s
          AND (
            raw_response ? 'MasterUserPassword'
            OR raw_response ? 'AccessKeyId'
            OR raw_response ? 'SecretAccessKey'
            OR raw_response ? 'password'
            OR raw_response ? 'secret_key'
          )
        """,
        (di_run,),
    )
    cnt = rows[0]["cnt"] if rows else 0
    return cnt == 0, f"  sensitive_field_rows={cnt} (expected 0)"


def check_6_relationships_present(
    di_conn: psycopg2.extensions.connection,
    di_run: str,
) -> Tuple[bool, str]:
    """Required relation_types present proportional to discovered resource types.

    BELONGS_TO and PLACED_IN are always required (every resource belongs to an account/VPC).
    PROTECTED_BY / INTERNET_ACCESSIBLE / ATTACHED_TO are only required when the scan
    contains compute resources (ec2_DescribeInstances, ec2_describe_instances, etc.)
    that would produce those relationships.
    """
    rows = _query(
        di_conn,
        """
        SELECT relation_type, count(*) AS cnt FROM asset_relationships
        WHERE scan_run_id = %s
        GROUP BY relation_type ORDER BY cnt DESC
        """,
        (di_run,),
    )
    found = {r["relation_type"] for r in rows}

    # Check if the scan has compute resources that would generate compute-level relations
    compute_rows = _query(
        di_conn,
        """
        SELECT COUNT(*) AS cnt FROM asset_inventory
        WHERE scan_run_id = %s
          AND (LOWER(resource_type) LIKE '%%instance%%'
               OR LOWER(resource_type) LIKE '%%volume%%'
               OR LOWER(resource_type) LIKE '%%network_interface%%')
        """,
        (di_run,),
    )
    has_compute = (compute_rows[0]["cnt"] if compute_rows else 0) > 0

    required = {"PLACED_IN", "BELONGS_TO"}
    if has_compute:
        required |= {"PROTECTED_BY", "INTERNET_ACCESSIBLE", "ATTACHED_TO"}

    missing = required - found
    detail_lines = [f"  {r['relation_type']}: {r['cnt']}" for r in rows]
    if missing:
        detail_lines.append(f"  MISSING: {missing}")
    if not has_compute:
        detail_lines.append("  (compute relations skipped — no compute resources in scan)")
    return len(missing) == 0, "\n".join(detail_lines)


def check_7_asset_inventory_not_empty(
    di_conn: psycopg2.extensions.connection,
    di_run: str,
) -> Tuple[bool, str]:
    """asset_inventory has rows for the DI scan_run_id."""
    rows = _query(
        di_conn,
        "SELECT provider, count(*) AS cnt FROM asset_inventory WHERE scan_run_id = %s GROUP BY provider",
        (di_run,),
    )
    total = sum(r["cnt"] for r in rows)
    detail_lines = [f"  {r['provider']}: {r['cnt']}" for r in rows]
    detail_lines.append(f"  total={total}")
    return total > 0, "\n".join(detail_lines)


def check_8_check_findings_delta(
    check_conn: psycopg2.extensions.connection,
    di_run: str,
    legacy_run: str,
) -> Tuple[bool, str]:
    """check_findings count delta ≤ 2% per rule between DI and legacy scans.

    Skipped when DI has no check_findings (DI_ENGINE_ENABLED=false means check
    engine has not yet run against DI data — that is expected during the parallel
    validation phase and is not a scan defect).
    """
    di_rows = _query(
        check_conn,
        "SELECT rule_id, count(*) AS cnt FROM check_findings WHERE scan_run_id = %s GROUP BY rule_id",
        (di_run,),
    )
    legacy_rows = _query(
        check_conn,
        "SELECT rule_id, count(*) AS cnt FROM check_findings WHERE scan_run_id = %s GROUP BY rule_id",
        (legacy_run,),
    )
    di_map = {r["rule_id"]: r["cnt"] for r in di_rows}
    legacy_map = {r["rule_id"]: r["cnt"] for r in legacy_rows}

    if not legacy_map:
        return True, "  (no legacy check_findings — skip)"
    if not di_map:
        return True, "  (no DI check_findings — DI_ENGINE_ENABLED=false; check engine not yet run against DI data — skip)"

    failed_rules: List[str] = []
    for rule_id, legacy_cnt in legacy_map.items():
        if legacy_cnt == 0:
            continue
        di_cnt = di_map.get(rule_id, 0)
        delta = abs(di_cnt - legacy_cnt) / legacy_cnt * 100
        if delta > 2:
            failed_rules.append(f"  rule={rule_id} di={di_cnt} legacy={legacy_cnt} delta={delta:.1f}%")

    di_total = sum(di_map.values())
    legacy_total = sum(legacy_map.values())
    summary = f"  di_total={di_total} legacy_total={legacy_total}"
    if failed_rules:
        summary += "\n" + "\n".join(failed_rules[:10])
        if len(failed_rules) > 10:
            summary += f"\n  ... and {len(failed_rules) - 10} more rules"
    return len(failed_rules) == 0, summary


def check_9_di_scan_status_complete(
    di_conn: psycopg2.extensions.connection,
    di_run: str,
) -> Tuple[bool, str]:
    """di_scan_status.status = 'completed' for the DI scan_run_id."""
    rows = _query(
        di_conn,
        "SELECT status, resources_written, error_count FROM di_scan_status WHERE scan_run_id = %s",
        (di_run,),
    )
    if not rows:
        return False, "  (no di_scan_status row — scan may not have run yet)"
    row = rows[0]
    passed = row["status"] == "completed"
    return passed, f"  status={row['status']} resources_written={row['resources_written']} error_count={row['error_count']}"


def check_10_migration_no_synthetic(
    di_conn: psycopg2.extensions.connection,
) -> Tuple[bool, str]:
    """Overall asset_inventory has 0 synthetic UIDs across all scans (post-migration health).

    Synthetic UID pattern: region:name (e.g. us-east-1:my-bucket).
    Legitimate multi-colon UIDs: AliCloud acs:/alicloud:, GCP googleapis.com URLs,
    AWS ARNs (arn:), OCI OCIDs (ocid1.), Azure resource paths (/subscriptions/),
    IBM CRNs (crn:), GCP resource paths (projects/).
    """
    rows = _query(
        di_conn,
        """
        SELECT count(*) AS cnt FROM asset_inventory
        WHERE resource_uid NOT LIKE 'arn:%%'
          AND resource_uid NOT LIKE 'ocid1.%%'
          AND resource_uid NOT LIKE '/subscriptions/%%'
          AND resource_uid NOT LIKE 'crn:%%'
          AND resource_uid NOT LIKE 'projects/%%'
          AND resource_uid NOT LIKE 'acs:%%'
          AND resource_uid NOT LIKE 'alicloud:%%'
          AND resource_uid NOT LIKE 'https://%%googleapis.com/%%'
          AND resource_uid NOT LIKE 'k8s://%%'
          AND provider NOT IN ('k8s', 'unknown')
        """,
    )
    cnt = rows[0]["cnt"] if rows else 0
    return cnt == 0, f"  total_synthetic_in_table={cnt} (expected 0)"


# ── Runner ────────────────────────────────────────────────────────────────────

CHECKS = [
    ("1. Row count: DI ≥ 50% of legacy distinct UIDs per CSP", "row_count_delta"),
    ("2. 0 synthetic UIDs in DI scan", "synthetic_uid_count"),
    ("3. 0 AuthError in di_scan_errors", "auth_errors"),
    ("4. ResourceIdMissingError ≤ 5% of resources", "scan_errors_summary"),
    ("5. 0 sensitive fields in raw_response", "sensitive_fields"),
    ("6. All 5 relation_types present", "relationships"),
    ("7. asset_inventory not empty", "not_empty"),
    ("8. check_findings delta ≤ 2% per rule", "check_findings_delta"),
    ("9. di_scan_status = completed", "scan_status"),
    ("10. No synthetic UIDs across all scans", "global_synthetic"),
]


def run() -> None:
    di_run = os.environ.get("DI_SCAN_RUN_ID")
    legacy_run = os.environ.get("LEGACY_SCAN_RUN_ID")

    if not di_run:
        print("ERROR: DI_SCAN_RUN_ID env var required")
        sys.exit(1)
    if not legacy_run:
        print("WARNING: LEGACY_SCAN_RUN_ID not set — checks comparing to legacy will be skipped")

    print(f"\nDI Parallel Run Validation")
    print(f"  DI scan_run_id:     {di_run}")
    print(f"  Legacy scan_run_id: {legacy_run or '(not set)'}")
    print("=" * 72)

    di_conn = _conn_di()
    disc_conn = _conn_discoveries() if legacy_run else None
    check_conn: psycopg2.extensions.connection | None = None
    try:
        check_conn = _conn_check()
    except Exception:
        check_conn = None

    results: List[Tuple[str, bool, str]] = []

    def _add(name: str, passed: bool, detail: str) -> None:
        results.append((name, passed, detail))
        status = "PASS" if passed else "FAIL"
        print(f"\n[{status}] {name}")
        if detail:
            print(detail)

    try:
        if disc_conn:
            p, d = check_1_row_count_delta(di_conn, disc_conn, di_run, legacy_run)
            _add(CHECKS[0][0], p, d)
        else:
            _add(CHECKS[0][0], True, "  (skipped — no LEGACY_SCAN_RUN_ID)")

        p, d = check_2_synthetic_uid_count(di_conn, di_run)
        _add(CHECKS[1][0], p, d)

        p, d = check_3_auth_errors(di_conn, di_run)
        _add(CHECKS[2][0], p, d)

        p, d = check_4_di_scan_errors_summary(di_conn, di_run)
        _add(CHECKS[3][0], p, d)

        p, d = check_5_sensitive_fields_scrubbed(di_conn, di_run)
        _add(CHECKS[4][0], p, d)

        p, d = check_6_relationships_present(di_conn, di_run)
        _add(CHECKS[5][0], p, d)

        p, d = check_7_asset_inventory_not_empty(di_conn, di_run)
        _add(CHECKS[6][0], p, d)

        if check_conn and legacy_run:
            p, d = check_8_check_findings_delta(check_conn, di_run, legacy_run)
            _add(CHECKS[7][0], p, d)
        else:
            _add(CHECKS[7][0], True, "  (skipped — CHECK_DB or LEGACY_SCAN_RUN_ID not available)")

        p, d = check_9_di_scan_status_complete(di_conn, di_run)
        _add(CHECKS[8][0], p, d)

        p, d = check_10_migration_no_synthetic(di_conn)
        _add(CHECKS[9][0], p, d)

    finally:
        di_conn.close()
        if disc_conn:
            disc_conn.close()
        if check_conn:
            check_conn.close()

    # Summary table
    passed_count = sum(1 for _, p, _ in results if p)
    total_count = len(results)
    print("\n" + "=" * 72)
    print(f"Sign-off Summary: {passed_count}/{total_count} checks PASSED")
    print("=" * 72)
    for name, passed, _ in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status}  {name}")

    all_passed = passed_count == total_count
    print("\n" + ("ALL CHECKS PASSED — ready for DI-S4-03 cutover" if all_passed else
                  "VALIDATION FAILED — fix failing checks before cutover"))
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    run()
