"""
Discovery Gap Checker — find catalog rules with no matching asset_inventory data.

Run this after any scan to detect broken relationship rules before they waste
compute or silently produce 0 edges.

Usage (against live RDS via DI pod):
    kubectl exec -n threat-engine-engines deployment/engine-di -- python3 -c "
    import subprocess, sys
    subprocess.run([sys.executable, '/tmp/check_discovery_gaps.py'], check=True)
    "

    # Or copy and run:
    kubectl cp catalog/relationships/check_discovery_gaps.py \\
        threat-engine-engines/<pod>:/tmp/check_discovery_gaps.py
    kubectl exec -n threat-engine-engines <pod> -- python3 /tmp/check_discovery_gaps.py

Exit codes:
    0 — all rules have source data
    1 — one or more SOURCE MISSING gaps found (needs discovery fix)
"""
from __future__ import annotations

import os
import sys

import psycopg2
import psycopg2.extras


def _get_conn() -> "psycopg2.connection":
    return psycopg2.connect(
        host=os.environ.get("DI_DB_HOST") or os.environ.get("INVENTORY_DB_HOST", ""),
        port=int(os.environ.get("DI_DB_PORT") or os.environ.get("INVENTORY_DB_PORT", "5432")),
        dbname=os.environ.get("DI_DB_NAME") or os.environ.get("INVENTORY_DB_NAME", "threat_engine_di"),
        user=os.environ.get("DI_DB_USER") or os.environ.get("INVENTORY_DB_USER", ""),
        password=os.environ.get("DI_DB_PASSWORD") or os.environ.get("INVENTORY_DB_PASSWORD", ""),
    )


def run_gap_check() -> int:
    """
    Cross-reference resource_relationship_catalog against asset_inventory.

    For each catalog rule:
      - SOURCE MISSING  → source_resource_type has 0 rows → discovery YAML needs fix
      - target missing  → source exists but target has 0 rows → lower priority
      - ACTIVE          → both source and target have rows → rule will produce edges

    Returns number of SOURCE MISSING gaps (used as exit code).
    """
    conn = _get_conn()

    # Step 1: gap matrix
    gap_sql = """
        SELECT
            c.csp,
            c.source_resource_type,
            c.target_resource_type,
            c.relation_type,
            COALESCE(src.cnt, 0)  AS src_rows,
            COALESCE(tgt.cnt, 0)  AS tgt_rows
        FROM resource_relationship_catalog c
        LEFT JOIN (
            SELECT provider, resource_type, COUNT(*) AS cnt
            FROM asset_inventory
            GROUP BY provider, resource_type
        ) src ON src.provider = c.csp AND src.resource_type = c.source_resource_type
        LEFT JOIN (
            SELECT provider, resource_type, COUNT(*) AS cnt
            FROM asset_inventory
            GROUP BY provider, resource_type
        ) tgt ON tgt.provider = c.csp AND tgt.resource_type = c.target_resource_type
        ORDER BY c.csp, src_rows DESC, c.source_resource_type
    """

    with conn.cursor() as cur:
        cur.execute(gap_sql)
        rules = cur.fetchall()

    # Step 2: for SOURCE MISSING gaps, find similar types in asset_inventory
    # to distinguish "name mismatch" from "not discovered at all"
    similar_sql = """
        SELECT DISTINCT resource_type
        FROM asset_inventory
        WHERE provider = %s
          AND (
              resource_type ILIKE %s
              OR resource_type ILIKE %s
          )
        ORDER BY resource_type
        LIMIT 5
    """

    source_missing = 0
    active = 0
    target_only_missing = 0

    print()
    print("=" * 110)
    print("  DISCOVERY GAP REPORT")
    print("=" * 110)
    print(f"  {'CSP':8} {'SOURCE TYPE':42} {'TARGET TYPE':42} {'SRC':>5} {'TGT':>5}  STATUS")
    print("-" * 110)

    for csp, src_type, tgt_type, rel_type, src_rows, tgt_rows in rules:
        if src_rows == 0 and tgt_rows == 0:
            status = "BOTH MISSING"
            source_missing += 1
        elif src_rows == 0:
            status = "SOURCE MISSING"
            source_missing += 1
        elif tgt_rows == 0:
            status = "target missing"
            target_only_missing += 1
        else:
            status = "OK"
            active += 1

        print(f"  {csp:8} {src_type:42} {tgt_type:42} {src_rows:5} {tgt_rows:5}  {status}")

        # For missing sources, show similar types to distinguish mismatch vs absent
        if src_rows == 0:
            # Try the service prefix (e.g. "elbv2" from "elbv2_load_balancer")
            svc_prefix = src_type.split("_")[0] if "_" in src_type else src_type.split(".")[0]
            with conn.cursor() as cur:
                cur.execute(similar_sql, (csp, f"{svc_prefix}%", f"%.{svc_prefix.replace('_', '.')}%"))
                similar = [r[0] for r in cur.fetchall()]
            if similar:
                print(f"           └─ similar types in inventory: {', '.join(similar)}")
                print(f"              → likely NAME MISMATCH — update catalog YAML to use one of these")
            else:
                print(f"           └─ no similar types found → DISCOVERY GAP: add step6 YAML for {csp}/{svc_prefix}")

    print("-" * 110)
    print(f"  Active rules: {active}   Source-missing gaps: {source_missing}   Target-missing: {target_only_missing}")
    print("=" * 110)

    if source_missing:
        print()
        print("FIX GUIDE:")
        print("  NAME MISMATCH  → update catalog/relationships/{csp}/infrastructure_attachment.yaml")
        print("                   change source_resource_type to the 'similar types' value shown above")
        print("                   then re-run: upload_relationship_catalog.py")
        print()
        print("  DISCOVERY GAP  → add a step6_{service}.discovery.yaml under")
        print("                   catalog/discovery_generator_data/{csp}/{service}/")
        print("                   redeploy engine-discoveries, re-scan, then verify type appears")
        print("                   in asset_inventory before adding the catalog rule")
        print()

    conn.close()
    return source_missing


if __name__ == "__main__":
    gaps = run_gap_check()
    sys.exit(1 if gaps > 0 else 0)
