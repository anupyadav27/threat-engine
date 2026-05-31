#!/usr/bin/env python3
"""
Pre-Scan Coverage Diagnostic — Multi-CSP Verbose Mode

Reads DB state and reports coverage for all CSPs before triggering an actual scan.
Does NOT write any data — read-only diagnostic.

Usage:
    # Run inside a pod that has DB access:
    kubectl exec -n threat-engine-engines deployment/engine-attack-path -- \
        python3 /tmp/prescan_coverage_check.py --tenant-id <UUID>

    # Or copy first:
    kubectl cp .claude/scripts/prescan_coverage_check.py \
        threat-engine-engines/<pod>:/tmp/prescan_coverage_check.py

    # Local run (requires port-forward to RDS or env vars set):
    python3 .claude/scripts/prescan_coverage_check.py --tenant-id <UUID> --verbose
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from typing import Any, Dict, List


# ── DB connection helpers (mirrors engine_common pattern) ─────────────────────

def _pg_conn(host_env: str, db_env: str, user_env: str = "PGUSER", pw_env: str = "PGPASSWORD"):
    import psycopg2
    return psycopg2.connect(
        host=os.environ.get(host_env, "localhost"),
        dbname=os.environ.get(db_env, ""),
        user=os.environ.get(user_env, "postgres"),
        password=os.environ.get(pw_env, ""),
        port=int(os.environ.get("PGPORT", "5432")),
        connect_timeout=10,
    )


def get_di_conn():
    try:
        from engine_common.db_connections import get_di_conn as _g
        return _g()
    except ImportError:
        return _pg_conn("DI_DB_HOST", "DI_DB_NAME", "DI_DB_USER", "DI_DB_PASSWORD")


def get_iam_conn():
    try:
        from engine_common.db_connections import get_iam_conn as _g
        return _g()
    except ImportError:
        return _pg_conn("IAM_DB_HOST", "IAM_DB_NAME", "IAM_DB_USER", "IAM_DB_PASSWORD")


def get_discovery_conn():
    try:
        from engine_common.db_connections import get_discovery_conn as _g
        return _g()
    except ImportError:
        return _pg_conn("DISCOVERIES_DB_HOST", "DISCOVERIES_DB_NAME",
                        "DISCOVERIES_DB_USER", "DISCOVERIES_DB_PASSWORD")


# ── Section printers ──────────────────────────────────────────────────────────

def _section(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


def _ok(msg: str) -> None:  print(f"  [OK]  {msg}")
def _warn(msg: str) -> None: print(f"  [WARN] {msg}")
def _info(msg: str) -> None: print(f"  [INFO] {msg}")
def _fail(msg: str) -> None: print(f"  [FAIL] {msg}")


# ── Check 1: asset_inventory per CSP ─────────────────────────────────────────

def check_asset_inventory(di_conn, tenant_id: str, verbose: bool) -> Dict[str, int]:
    _section("1. asset_inventory — per-CSP resource counts")
    counts: Dict[str, int] = {}
    try:
        with di_conn.cursor() as cur:
            cur.execute(
                """
                SELECT provider, COUNT(*) as cnt
                FROM asset_inventory
                WHERE tenant_id = %s
                  AND resource_uid IS NOT NULL
                GROUP BY provider
                ORDER BY cnt DESC
                """,
                (tenant_id,),
            )
            rows = cur.fetchall()
        for provider, cnt in rows:
            counts[provider or "unknown"] = cnt
            if cnt > 0:
                _ok(f"{provider or 'unknown':15s}  {cnt:6d} resources")
            else:
                _warn(f"{provider or 'unknown':15s}  0 resources — discovery may not have run")
        if not rows:
            _warn("No asset_inventory rows for this tenant — run discovery first")
    except Exception as exc:
        _fail(f"asset_inventory query failed: {exc}")
    return counts


# ── Check 2: asset_relationships ─────────────────────────────────────────────

def check_relationships(di_conn, tenant_id: str, verbose: bool) -> Dict[str, int]:
    _section("2. asset_relationships — edge type distribution")
    counts: Dict[str, int] = {}
    try:
        with di_conn.cursor() as cur:
            cur.execute(
                """
                SELECT relation_type, COUNT(*) as cnt,
                       SUM(CASE WHEN is_attack_edge THEN 1 ELSE 0 END) as attack_edges
                FROM asset_relationships
                WHERE tenant_id = %s
                GROUP BY relation_type
                ORDER BY cnt DESC
                LIMIT 30
                """,
                (tenant_id,),
            )
            rows = cur.fetchall()
        for rel_type, cnt, atk in rows:
            counts[rel_type] = cnt
            atk_flag = f"  [{atk} attack edges]" if atk else ""
            _ok(f"{rel_type:40s}  {cnt:6d}{atk_flag}")
        if not rows:
            _warn("No asset_relationships — catalog relationships may not have run")
    except Exception as exc:
        _fail(f"asset_relationships query failed: {exc}")

    # Check attack-specific edges
    try:
        with di_conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*) FROM asset_relationships
                WHERE tenant_id = %s AND is_attack_edge = TRUE
                """,
                (tenant_id,),
            )
            atk_total = cur.fetchone()[0]
        if atk_total > 0:
            _ok(f"Total is_attack_edge=TRUE rows: {atk_total}")
        else:
            _warn("0 is_attack_edge=TRUE rows — validators haven't run yet")
    except Exception as exc:
        _fail(f"attack edge count failed: {exc}")
    return counts


# ── Check 3: resource_security_posture ───────────────────────────────────────

def check_posture(di_conn, tenant_id: str, verbose: bool) -> Dict[str, Any]:
    _section("3. resource_security_posture — signals")
    result: Dict[str, Any] = {}
    try:
        with di_conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN is_crown_jewel THEN 1 ELSE 0 END) as crown_jewels,
                    SUM(CASE WHEN is_internet_exposed THEN 1 ELSE 0 END) as internet_exposed,
                    SUM(CASE WHEN is_attack_entry_point THEN 1 ELSE 0 END) as entry_points,
                    SUM(CASE WHEN is_on_attack_path THEN 1 ELSE 0 END) as on_path,
                    SUM(CASE WHEN is_choke_point THEN 1 ELSE 0 END) as choke_points
                FROM resource_security_posture
                WHERE tenant_id = %s
                """,
                (tenant_id,),
            )
            row = cur.fetchone()
            if row:
                total, cj, ie, ep, op, cp = row
                result = {
                    "total": total, "crown_jewels": cj, "internet_exposed": ie,
                    "entry_points": ep, "on_path": op, "choke_points": cp,
                }
                _ok(f"Total posture rows:     {total}")
                if cj and cj > 0:
                    _ok(f"Crown jewels:           {cj}")
                else:
                    _warn("Crown jewels: 0 — CrownJewelClassifier hasn't run or no sensitive data")
                if ie and ie > 0:
                    _ok(f"Internet exposed:       {ie}")
                else:
                    _warn("Internet exposed: 0 — network engine IEDS may not have run")
                _info(f"Attack entry points:    {ep or 0}")
                _info(f"On attack path:         {op or 0}")
                _info(f"Choke points:           {cp or 0}")
    except Exception as exc:
        _fail(f"resource_security_posture query failed: {exc}")

    # Crown jewels by type
    try:
        with di_conn.cursor() as cur:
            cur.execute(
                """
                SELECT crown_jewel_type, provider, COUNT(*) as cnt
                FROM resource_security_posture
                WHERE tenant_id = %s AND is_crown_jewel = TRUE
                GROUP BY crown_jewel_type, provider
                ORDER BY cnt DESC
                """,
                (tenant_id,),
            )
            cj_rows = cur.fetchall()
        if cj_rows and verbose:
            print("\n  Crown jewels by type + CSP:")
            for cj_type, prov, cnt in cj_rows:
                print(f"    {prov or 'unknown':10s}  {cj_type or 'unknown':30s}  {cnt}")
    except Exception as exc:
        _fail(f"Crown jewel breakdown failed: {exc}")

    return result


# ── Check 4: iam_policy_statements ───────────────────────────────────────────

def check_iam_statements(iam_conn, tenant_id: str, verbose: bool) -> Dict[str, int]:
    _section("4. iam_policy_statements — per-CSP identity coverage")
    counts: Dict[str, int] = {}
    try:
        with iam_conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    COALESCE(provider, 'aws') as provider,
                    attached_to_type,
                    COUNT(*) as cnt,
                    SUM(CASE WHEN is_admin THEN 1 ELSE 0 END) as admin_count
                FROM iam_policy_statements
                WHERE tenant_id = %s
                  AND effect = 'Allow'
                GROUP BY provider, attached_to_type
                ORDER BY provider, cnt DESC
                """,
                (tenant_id,),
            )
            rows = cur.fetchall()
        for prov, att_type, cnt, admin_cnt in rows:
            key = f"{prov}:{att_type}"
            counts[key] = cnt
            admin_str = f"  ({admin_cnt} admin)" if admin_cnt else ""
            _ok(f"{prov:12s}  {att_type or 'unknown':25s}  {cnt:5d} statements{admin_str}")
        if not rows:
            _warn("0 iam_policy_statements — IAM engine has not run for this tenant")

        # Check which CSPs have coverage
        csps_covered = {r[0] for r in rows}
        expected_csps = {"aws", "gcp", "azure", "alicloud", "oci", "ibm", "k8s"}
        missing = expected_csps - csps_covered
        discovered: set = set()
        # Check what CSPs have assets to know which missing are real gaps
        if missing and verbose:
            print(f"\n  CSPs with 0 IAM statements (may be expected if not scanned):")
            for csp in sorted(missing):
                print(f"    {csp}")
    except Exception as exc:
        _fail(f"iam_policy_statements query failed: {exc}")
    return counts


# ── Check 5: resource_relationship_catalog ────────────────────────────────────

def check_catalog_rules(di_conn, tenant_id: str, verbose: bool) -> Dict[str, int]:
    _section("5. resource_relationship_catalog — rules per CSP")
    counts: Dict[str, int] = {}
    try:
        with di_conn.cursor() as cur:
            cur.execute(
                """
                SELECT csp, COUNT(*) as cnt
                FROM resource_relationship_catalog
                WHERE is_active = TRUE
                GROUP BY csp
                ORDER BY cnt DESC
                """,
                (),
            )
            rows = cur.fetchall()
        for csp, cnt in rows:
            counts[csp] = cnt
            _ok(f"{csp:12s}  {cnt:4d} active rules")
        total = sum(counts.values())
        _info(f"Total active catalog rules: {total}")
    except Exception as exc:
        _fail(f"resource_relationship_catalog query failed: {exc}")
    return counts


# ── Check 6: network_exposure_findings (IEDS) ────────────────────────────────

def check_network_exposure(di_conn, tenant_id: str, verbose: bool) -> int:
    _section("6. network_exposure_findings — internet exposure (IEDS)")
    count = 0
    try:
        from engine_common.db_connections import get_network_conn
        net_conn = get_network_conn()
        try:
            with net_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT origin_type, COUNT(*) as cnt
                    FROM network_exposure_findings
                    WHERE tenant_id = %s AND status = 'OPEN'
                    GROUP BY origin_type
                    ORDER BY cnt DESC
                    """,
                    (tenant_id,),
                )
                rows = cur.fetchall()
            for origin, cnt in rows:
                count += cnt
                _ok(f"{origin or 'unknown':20s}  {cnt:5d} findings")
            if not rows:
                _warn("0 OPEN network_exposure_findings — network engine may not have run")
        finally:
            net_conn.close()
    except Exception as exc:
        _warn(f"network_exposure_findings unavailable (non-fatal): {exc}")
    return count


# ── Check 7: attack_paths table ───────────────────────────────────────────────

def check_attack_paths(di_conn, tenant_id: str, verbose: bool) -> Dict[str, Any]:
    _section("7. attack_paths — existing path count")
    result: Dict[str, Any] = {}
    try:
        from engine_common.db_connections import get_attack_path_conn
        ap_conn = get_attack_path_conn()
        try:
            with ap_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        severity,
                        COUNT(*) as cnt,
                        AVG(path_score) as avg_score,
                        MAX(path_score) as max_score
                    FROM attack_paths
                    WHERE tenant_id = %s
                    GROUP BY severity
                    ORDER BY
                        CASE severity
                          WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                          WHEN 'medium' THEN 3 ELSE 4
                        END
                    """,
                    (tenant_id,),
                )
                rows = cur.fetchall()
            total = 0
            for sev, cnt, avg_s, max_s in rows:
                total += cnt
                _ok(f"{sev:10s}  {cnt:5d} paths  avg_score={float(avg_s or 0):.1f}  max={float(max_s or 0):.1f}")
            result["total"] = total
            if total == 0:
                _warn("0 attack_paths — attack-path engine hasn't run for this tenant")
        finally:
            ap_conn.close()
    except Exception as exc:
        _warn(f"attack_paths unavailable (non-fatal): {exc}")
    return result


# ── Check 8: entry point summary ─────────────────────────────────────────────

def check_entry_points(di_conn, tenant_id: str, verbose: bool) -> None:
    _section("8. Attack entry points — category breakdown")
    try:
        with di_conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    COALESCE(attack_entry_point_category, 'INTERNET_ENTRY') as category,
                    COUNT(*) as cnt
                FROM resource_security_posture
                WHERE tenant_id = %s
                  AND is_attack_entry_point = TRUE
                GROUP BY attack_entry_point_category
                ORDER BY cnt DESC
                """,
                (tenant_id,),
            )
            rows = cur.fetchall()
        if rows:
            for cat, cnt in rows:
                _ok(f"{cat:35s}  {cnt:4d}")
        else:
            _warn("No attack entry points marked — run network engine + attack-path validators first")
    except Exception as exc:
        _fail(f"Entry point check failed: {exc}")


# ── Readiness summary ─────────────────────────────────────────────────────────

def print_readiness(
    asset_counts: Dict[str, int],
    posture: Dict[str, Any],
    iam_counts: Dict[str, int],
    catalog_counts: Dict[str, int],
    path_result: Dict[str, Any],
) -> None:
    _section("READINESS SUMMARY — Is a scan viable?")

    total_assets = sum(asset_counts.values())
    crown_jewels = posture.get("crown_jewels") or 0
    internet_exposed = posture.get("internet_exposed") or 0
    iam_stmts = sum(iam_counts.values())
    catalog_rules = sum(catalog_counts.values())

    gates = [
        (total_assets > 0,    f"Assets discovered:       {total_assets} (need > 0)"),
        (catalog_rules > 0,   f"Catalog rules loaded:    {catalog_rules} (need > 0)"),
        (iam_stmts > 0,       f"IAM statements:          {iam_stmts} (need > 0)"),
        (crown_jewels > 0,    f"Crown jewels classified: {crown_jewels} (need > 0)"),
        (internet_exposed > 0,f"Internet-exposed marked: {internet_exposed} (need > 0 for BFS paths)"),
    ]

    all_pass = True
    for passed, msg in gates:
        if passed:
            _ok(msg)
        else:
            _warn(msg)
            all_pass = False

    print()
    if all_pass:
        print("  >>> READY: All gates pass — trigger attack-path scan now.")
    else:
        print("  >>> NOT READY: Fix warnings above before triggering scan.")
        print()
        print("  Scan trigger command (once ready):")
        print("    kubectl port-forward svc/engine-attack-path 8025:80 -n threat-engine-engines &")
        print("    curl -s -X POST http://localhost:8025/api/v1/run-scan \\")
        print("      -H 'X-Auth-Context: {\"tenant_id\":\"<TENANT_ID>\",\"scan_run_id\":\"<SCAN_RUN_ID>\"}' \\")
        print("      -H 'Content-Type: application/json' \\")
        print("      -d '{\"scan_run_id\":\"<SCAN_RUN_ID>\",\"tenant_id\":\"<TENANT_ID>\"}'")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Pre-scan coverage diagnostic (read-only)")
    parser.add_argument("--tenant-id", required=True, help="Tenant UUID to inspect")
    parser.add_argument("--verbose", action="store_true", help="Show per-resource detail")
    args = parser.parse_args()

    tenant_id = args.tenant_id
    verbose = args.verbose

    print(f"\nPRE-SCAN COVERAGE DIAGNOSTIC")
    print(f"Tenant: {tenant_id}")
    print(f"Mode:   {'verbose' if verbose else 'summary'}")

    try:
        di_conn = get_di_conn()
    except Exception as exc:
        print(f"\n[FATAL] Cannot connect to DI DB: {exc}")
        sys.exit(1)

    try:
        iam_conn = get_iam_conn()
        iam_ok = True
    except Exception as exc:
        print(f"\n[WARN] IAM DB unavailable: {exc}")
        iam_conn = None
        iam_ok = False

    asset_counts = check_asset_inventory(di_conn, tenant_id, verbose)
    rel_counts   = check_relationships(di_conn, tenant_id, verbose)
    posture      = check_posture(di_conn, tenant_id, verbose)
    iam_counts   = check_iam_statements(iam_conn, tenant_id, verbose) if iam_ok else {}
    catalog_counts = check_catalog_rules(di_conn, tenant_id, verbose)
    check_network_exposure(di_conn, tenant_id, verbose)
    path_result  = check_attack_paths(di_conn, tenant_id, verbose)
    check_entry_points(di_conn, tenant_id, verbose)

    print_readiness(asset_counts, posture, iam_counts, catalog_counts, path_result)

    try:
        di_conn.close()
    except Exception:
        pass
    if iam_conn:
        try:
            iam_conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()