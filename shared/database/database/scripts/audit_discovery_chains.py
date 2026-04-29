#!/usr/bin/env python3
"""
audit_discovery_chains.py — Cross-CSP for_each chain validator.

Checks rule_discoveries DB for:
  1. Services with zero independent (root) discoveries → will produce 0 findings
  2. Broken for_each references → dependent resources silently skipped
  3. Self-referencing loops → discovery blocked indefinitely

Usage:
    export CHECK_DB_HOST=postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
    export CHECK_DB_NAME=threat_engine_check
    export CHECK_DB_USER=postgres
    export CHECK_DB_PASSWORD=<password>

    python3 audit_discovery_chains.py              # all CSPs
    python3 audit_discovery_chains.py --provider aws
    python3 audit_discovery_chains.py --exit-on-critical  # non-zero exit if critical issues found
"""
import argparse
import os
import sys

import psycopg2
import psycopg2.extras

ALL_CSPS = ["aws", "azure", "gcp", "oci", "alicloud", "k8s"]


def connect():
    return psycopg2.connect(
        host=os.getenv("CHECK_DB_HOST", "localhost"),
        port=int(os.getenv("CHECK_DB_PORT", "5432")),
        dbname=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", "postgres"),
        password=os.getenv("CHECK_DB_PASSWORD", ""),
    )


EXPAND_SQL = """
    CASE WHEN jsonb_typeof(discoveries_data) = 'array'
         THEN jsonb_build_object('discovery', discoveries_data) -> 'discovery'
         ELSE discoveries_data -> 'discovery' END
"""


def audit_provider(cur, provider: str) -> dict:
    """Return audit results for one CSP."""

    # All discovery items expanded
    cur.execute(f"""
        WITH expanded AS (
            SELECT service,
                jsonb_array_elements({EXPAND_SQL}) AS disc
            FROM rule_discoveries
            WHERE provider = %s AND is_active = TRUE
        ),
        disc_ids AS (
            SELECT service, disc->>'discovery_id' AS id
            FROM expanded
            WHERE disc->>'discovery_id' IS NOT NULL
        ),
        per_disc AS (
            SELECT
                e.service,
                e.disc->>'discovery_id' AS disc_id,
                e.disc->>'for_each'     AS for_each,
                CASE
                    WHEN e.disc->>'for_each' IS NULL THEN 'independent'
                    WHEN e.disc->>'for_each' = e.disc->>'discovery_id' THEN 'self_loop'
                    WHEN NOT EXISTS (
                        SELECT 1 FROM disc_ids d
                        WHERE d.service = e.service AND d.id = e.disc->>'for_each'
                    ) THEN 'broken'
                    ELSE 'ok'
                END AS chain_status
            FROM expanded e
        )
        SELECT
            service,
            COUNT(*) FILTER (WHERE chain_status = 'independent') AS independent,
            COUNT(*) FILTER (WHERE chain_status = 'ok')          AS ok_dependent,
            COUNT(*) FILTER (WHERE chain_status = 'broken')      AS broken,
            COUNT(*) FILTER (WHERE chain_status = 'self_loop')   AS self_loops,
            array_agg(disc_id ORDER BY disc_id)
                FILTER (WHERE chain_status = 'self_loop')        AS self_loop_ids,
            array_agg(disc_id || ' -> ' || for_each ORDER BY disc_id)
                FILTER (WHERE chain_status = 'broken')           AS broken_details
        FROM per_disc
        GROUP BY service
        ORDER BY service;
    """, (provider,))

    rows = cur.fetchall()
    columns = [d.name for d in cur.description]
    results = [dict(zip(columns, row)) for row in rows]

    zero_root   = [r for r in results if r["independent"] == 0]
    has_broken  = [r for r in results if r["broken"] > 0]
    has_loops   = [r for r in results if r["self_loops"] > 0]

    return {
        "total_services": len(results),
        "zero_root": zero_root,
        "has_broken": has_broken,
        "has_loops": has_loops,
        "all": results,
    }


def main():
    parser = argparse.ArgumentParser(description="Audit discovery chain health across CSPs")
    parser.add_argument("--provider", default="all", help="CSP to audit (or 'all')")
    parser.add_argument("--exit-on-critical", action="store_true",
                        help="Exit with code 1 if critical issues (zero-root or self-loops) found")
    parser.add_argument("--show-broken", action="store_true",
                        help="Print all broken for_each details (verbose)")
    args = parser.parse_args()

    providers = ALL_CSPS if args.provider == "all" else [args.provider]

    try:
        conn = connect()
    except Exception as e:
        print(f"ERROR: Cannot connect to check DB: {e}")
        sys.exit(2)

    cur = conn.cursor()
    total_critical = 0

    print("=" * 72)
    print("Discovery Chain Health Audit")
    print("=" * 72)
    print(f"{'CSP':<14} {'Services':>8} {'ZeroRoot':>9} {'SelfLoop':>9} {'BrokenFE':>9}")
    print(f"{'-'*14} {'-'*8} {'-'*9} {'-'*9} {'-'*9}")

    details = {}
    for provider in providers:
        result = audit_provider(cur, provider)
        details[provider] = result
        zero = len(result["zero_root"])
        loops = len(result["has_loops"])
        broken = sum(r["broken"] for r in result["all"])
        broken_svcs = len(result["has_broken"])
        crit_marker = " ◄ CRITICAL" if (zero > 0 or loops > 0) else ""
        print(f"{provider:<14} {result['total_services']:>8} {zero:>9} {loops:>9} "
              f"{broken:>6}({broken_svcs}sv){crit_marker}")
        total_critical += zero + loops

    print()

    # Detailed output for problems
    for provider, result in details.items():
        has_issues = result["zero_root"] or result["has_loops"] or result["has_broken"]
        if not has_issues:
            continue

        print(f"── {provider.upper()} ──────────────────────────────────────────")

        if result["has_loops"]:
            print("  CRITICAL — Self-referencing loops (0 findings, scan blocked):")
            for r in result["has_loops"]:
                for sid in (r["self_loop_ids"] or []):
                    print(f"    {r['service']}: {sid} references itself")

        if result["zero_root"]:
            print("  CRITICAL — Zero independent discoveries (service produces 0 findings):")
            for r in result["zero_root"]:
                total_items = r["broken"] + r["ok_dependent"]
                print(f"    {r['service']}: {total_items} dependent items, 0 root calls")

        if result["has_broken"] and args.show_broken:
            print("  WARNING — Broken for_each references (nested resources skipped):")
            for r in result["has_broken"]:
                print(f"    {r['service']}: {r['broken']} broken")
                for detail in (r["broken_details"] or [])[:3]:
                    print(f"      {detail}")
        elif result["has_broken"]:
            svc_names = [r["service"] for r in result["has_broken"]]
            total_broken = sum(r["broken"] for r in result["has_broken"])
            print(f"  WARNING — {total_broken} broken for_each refs in {len(svc_names)} services "
                  f"(nested resources skipped, root discoveries OK):")
            print(f"    {', '.join(svc_names[:10])}" +
                  (" ..." if len(svc_names) > 10 else ""))
            print("  Run with --show-broken to see all details")
        print()

    print("=" * 72)
    if total_critical == 0:
        print("PASS: No critical issues found (zero-root or self-loops)")
    else:
        print(f"FAIL: {total_critical} critical issues require immediate attention")

    conn.close()

    if args.exit_on_critical and total_critical > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
