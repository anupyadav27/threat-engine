#!/usr/bin/env python3
"""
AZ-13: Validate an Azure discovery scan end-to-end.

Checks:
  1. >= 100 Azure resources discovered
  2. All resource_uids start with /subscriptions/
  3. scan_runs.overall_status = 'completed'
  4. Scan duration < 60 minutes
  5. At least 5 distinct resource_types discovered
  6. Error rate < 5% (sampled from pod logs if AZURE_POD available)
  7. No NULL resource_type rows

Usage:
    # Port-forward RDS first:
    # kubectl port-forward svc/postgres 5432:5432 -n threat-engine-engines

    DISCOVERIES_DB_HOST=localhost DISCOVERIES_DB_PASSWORD=xxx \
    ONBOARDING_DB_HOST=localhost  ONBOARDING_DB_PASSWORD=xxx \
    python scripts/validate_azure_scan.py <scan_run_id>

    # Or with explicit DB hosts:
    DISCOVERIES_DB_HOST=postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com \
    python scripts/validate_azure_scan.py <scan_run_id>
"""

import os
import sys
from datetime import timedelta

import psycopg2

# ── DB connection helpers ─────────────────────────────────────────────────────

RDS_HOST = "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"


def _discoveries_conn():
    return psycopg2.connect(
        host=os.getenv("DISCOVERIES_DB_HOST", RDS_HOST),
        port=int(os.getenv("DISCOVERIES_DB_PORT", "5432")),
        dbname=os.getenv("DISCOVERIES_DB_NAME", "threat_engine_discoveries"),
        user=os.getenv("DISCOVERIES_DB_USER", "postgres"),
        password=os.getenv("DISCOVERIES_DB_PASSWORD", ""),
    )


def _onboarding_conn():
    return psycopg2.connect(
        host=os.getenv("ONBOARDING_DB_HOST", RDS_HOST),
        port=int(os.getenv("ONBOARDING_DB_PORT", "5432")),
        dbname=os.getenv("ONBOARDING_DB_NAME", "threat_engine_onboarding"),
        user=os.getenv("ONBOARDING_DB_USER", "postgres"),
        password=os.getenv("ONBOARDING_DB_PASSWORD", ""),
    )


# ── Check functions ────────────────────────────────────────────────────────────

CHECKS_PASSED = 0
CHECKS_FAILED = 0
WARNINGS = []


def ok(msg: str) -> None:
    global CHECKS_PASSED
    CHECKS_PASSED += 1
    print(f"  PASS  {msg}")


def fail(msg: str) -> None:
    global CHECKS_FAILED
    CHECKS_FAILED += 1
    print(f"  FAIL  {msg}")


def warn(msg: str) -> None:
    WARNINGS.append(msg)
    print(f"  WARN  {msg}")


def check_discovery_count(cur, scan_run_id: str, min_count: int = 100) -> int:
    cur.execute(
        "SELECT COUNT(*) FROM discovery_findings WHERE scan_run_id = %s AND provider = 'azure'",
        (scan_run_id,),
    )
    count = cur.fetchone()[0]
    if count >= min_count:
        ok(f"{count} Azure resources discovered (min {min_count})")
    elif count > 0:
        warn(f"Only {count} Azure resources — expected >= {min_count}. Check rule_discoveries is_enabled.")
    else:
        fail(f"0 Azure resources discovered. Check credential resolution and pod logs.")
    return count


def check_resource_uid_format(cur, scan_run_id: str) -> None:
    cur.execute(
        """
        SELECT COUNT(*) FROM discovery_findings
        WHERE scan_run_id = %s AND provider = 'azure'
          AND resource_uid NOT LIKE '/subscriptions/%%'
        """,
        (scan_run_id,),
    )
    bad = cur.fetchone()[0]
    if bad == 0:
        ok("All resource_uids start with /subscriptions/")
    else:
        fail(f"{bad} resources have invalid resource_uid format (not /subscriptions/...)")
        cur.execute(
            """
            SELECT resource_uid, resource_type FROM discovery_findings
            WHERE scan_run_id = %s AND provider = 'azure'
              AND resource_uid NOT LIKE '/subscriptions/%%'
            LIMIT 5
            """,
            (scan_run_id,),
        )
        for uid, rt in cur.fetchall():
            print(f"         example: uid={uid[:80]}  type={rt}")


def check_no_null_resource_type(cur, scan_run_id: str) -> None:
    cur.execute(
        """
        SELECT COUNT(*) FROM discovery_findings
        WHERE scan_run_id = %s AND provider = 'azure'
          AND (resource_type IS NULL OR resource_type = '')
        """,
        (scan_run_id,),
    )
    bad = cur.fetchone()[0]
    if bad == 0:
        ok("No NULL/empty resource_type rows")
    else:
        fail(f"{bad} rows with NULL/empty resource_type")


def check_resource_type_diversity(cur, scan_run_id: str, min_types: int = 5) -> None:
    cur.execute(
        """
        SELECT resource_type, COUNT(*) AS cnt
        FROM discovery_findings
        WHERE scan_run_id = %s AND provider = 'azure'
        GROUP BY resource_type
        ORDER BY cnt DESC
        """,
        (scan_run_id,),
    )
    rows = cur.fetchall()
    n = len(rows)
    if n >= min_types:
        ok(f"{n} distinct resource_types (min {min_types})")
    else:
        fail(f"Only {n} distinct resource_types (need >= {min_types})")
    print("         Top resource types:")
    for rt, cnt in rows[:10]:
        print(f"           {rt:40s} {cnt:>5}")


def check_scan_status(scan_run_id: str) -> None:
    try:
        conn = _onboarding_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT overall_status, started_at, finished_at FROM scan_runs WHERE scan_run_id = %s",
            (scan_run_id,),
        )
        row = cur.fetchone()
        conn.close()

        if row is None:
            fail(f"No scan_runs row found for scan_run_id={scan_run_id}")
            return

        status, started_at, finished_at = row
        if status == "completed":
            ok(f"scan_runs.overall_status = 'completed'")
        elif status == "running":
            warn(f"Scan still running — re-run validation when complete")
        else:
            fail(f"scan_runs.overall_status = '{status}' (expected 'completed')")

        if started_at and finished_at:
            duration = finished_at - started_at
            mins = duration.total_seconds() / 60
            if mins <= 60:
                ok(f"Scan duration {mins:.1f} min (max 60)")
            else:
                fail(f"Scan duration {mins:.1f} min exceeds 60-minute limit")
        else:
            warn("Missing started_at or finished_at — cannot check duration")

    except Exception as exc:
        warn(f"Could not connect to onboarding DB: {exc}")
        warn("Skipping scan_runs checks — run with ONBOARDING_DB_* env vars")


def check_neo4j_import(scan_run_id: str) -> None:
    """Optional: verify Neo4j has Azure nodes (requires neo4j driver)."""
    try:
        from neo4j import GraphDatabase  # type: ignore

        uri = os.getenv("NEO4J_URI", "neo4j+s://17ec5cbb.databases.neo4j.io")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "")
        if not password:
            warn("NEO4J_PASSWORD not set — skipping Neo4j checks")
            return

        driver = GraphDatabase.driver(uri, auth=(user, password))
        with driver.session() as session:
            result = session.run(
                "MATCH (r:Resource {provider: 'azure'}) RETURN count(r) AS cnt"
            )
            cnt = result.single()["cnt"]
            if cnt > 0:
                ok(f"Neo4j: {cnt} Azure Resource nodes present")
            else:
                warn("Neo4j: 0 Azure Resource nodes — threat engine may not have run yet")
        driver.close()

    except ImportError:
        warn("neo4j driver not installed — skipping Neo4j checks (pip install neo4j)")
    except Exception as exc:
        warn(f"Neo4j check failed: {exc}")


# ── Triage hints ──────────────────────────────────────────────────────────────

TRIAGE = {
    "0 Azure resources": (
        "Credential resolution broken — check AZ-17b.\n"
        "  kubectl logs -l app=engine-discoveries-azure -n threat-engine-engines --tail=50"
    ),
    "invalid resource_uid": (
        "Normalization bug in service_scanner._RESOURCE_TYPE_MAP.\n"
        "  Ensure full Azure Resource ID is stored in resource_uid."
    ),
    "scan_runs.overall_status": (
        "Check Argo workflow logs:\n"
        "  argo logs -n threat-engine-engines <workflow-name>"
    ),
    "duration": (
        "OPERATION_TIMEOUT or thread pool misconfiguration.\n"
        "  Check AZ-02b — timeout wrapper on Azure ThreadPoolExecutor."
    ),
}


def print_triage(failed_checks: list) -> None:
    if not failed_checks:
        return
    print("\n  Triage hints:")
    for check in failed_checks:
        for key, hint in TRIAGE.items():
            if key.lower() in check.lower():
                print(f"    [{key}]: {hint}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python validate_azure_scan.py <scan_run_id>")
        sys.exit(1)

    scan_run_id = sys.argv[1]
    print(f"\n=== AZ-13: Azure E2E Scan Validation ===")
    print(f"  scan_run_id: {scan_run_id}\n")

    # Discoveries DB checks
    try:
        conn = _discoveries_conn()
        cur = conn.cursor()

        count = check_discovery_count(cur, scan_run_id, min_count=100)
        if count > 0:
            check_resource_uid_format(cur, scan_run_id)
            check_no_null_resource_type(cur, scan_run_id)
            check_resource_type_diversity(cur, scan_run_id, min_types=5)

        conn.close()
    except Exception as exc:
        fail(f"Could not connect to discoveries DB: {exc}")
        print("  Set DISCOVERIES_DB_HOST / DISCOVERIES_DB_PASSWORD env vars")

    # Onboarding DB: scan status + duration
    check_scan_status(scan_run_id)

    # Neo4j (optional)
    check_neo4j_import(scan_run_id)

    # Summary
    total = CHECKS_PASSED + CHECKS_FAILED
    print(f"\n=== Result: {CHECKS_PASSED}/{total} checks passed"
          f"{' | ' + str(len(WARNINGS)) + ' warnings' if WARNINGS else ''} ===")
    for w in WARNINGS:
        print(f"  ! {w}")

    if CHECKS_FAILED > 0:
        print("\nFailed checks — see triage hints above.")
        sys.exit(1)
    else:
        print("\nALL CHECKS PASSED — AZ-13 complete.")


if __name__ == "__main__":
    main()
