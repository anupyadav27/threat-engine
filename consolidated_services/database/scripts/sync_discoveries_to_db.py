#!/usr/bin/env python3
"""
sync_discoveries_to_db.py — Sync local discovery YAMLs into rule_discoveries (check DB).

Target table:
  rule_discoveries (threat_engine_check)
    service           VARCHAR — service name (e.g. 'ec2', 's3', 'compute')
    provider          VARCHAR — 'aws' | 'azure' | 'gcp' | 'oci' | 'alicloud' | 'ibm'
    discoveries_data  JSONB   — parsed `discovery:` list from local YAML
    boto3_client_name VARCHAR — from YAML services.client
    filter_rules      JSONB   — {"api_filters": [...], "response_filters": [...]}
    is_active         BOOLEAN

  Read at runtime by:
    engine_check      → _load_discovery_cache() for validation
    engine_discoveries → config_loader.get_filter_rules() / database_feature_manager

Filter rules sourced from:
  consolidated_services/database/scripts/csp_filter_catalog.py
  (enterprise catalog covering AWS, Azure, GCP, OCI, AliCloud, IBM)

Local YAML sources per CSP (in priority order where multiple exist):
  aws:      A) engine_check/engine_check_aws/services/{svc}/discoveries/   (curated, 100 svcs)
            B) data_pythonsdk/aws/{svc}/step6_{svc}.discovery.yaml         (generated, 446 svcs)
  azure:       data_pythonsdk/azure/{svc}/step6_{svc}.discovery.yaml
  gcp:         data_pythonsdk/gcp/{svc}/step6_{svc}.discovery.yaml
  oci:         data_pythonsdk/oci/{svc}/step6_{svc}.discovery.yaml
  alicloud:    data_pythonsdk/alicloud/{svc}/step6_{svc}.discovery.yaml
  ibm:         data_pythonsdk/ibm/{svc}/step6_{svc}.discovery.yaml

Usage:
    # Dry-run — see what would change without touching RDS
    python3 sync_discoveries_to_db.py --dry-run

    # Sync AWS only (default)
    python3 sync_discoveries_to_db.py

    # Sync a specific CSP
    python3 sync_discoveries_to_db.py --provider azure
    python3 sync_discoveries_to_db.py --provider gcp

    # Sync ALL CSPs at once
    python3 sync_discoveries_to_db.py --provider all

    # Only add services missing from RDS
    python3 sync_discoveries_to_db.py --provider all --new-only

    # Refresh one service
    python3 sync_discoveries_to_db.py --provider aws --service ec2

    # Credentials (RDS)
    export CHECK_DB_HOST=postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
    export CHECK_DB_NAME=threat_engine_check
    export CHECK_DB_USER=postgres
    export CHECK_DB_PASSWORD=<password>
    python3 sync_discoveries_to_db.py --provider all
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional

import psycopg2
import psycopg2.extras
import yaml

# Import enterprise filter catalog (csp_filter_catalog.py lives in same directory)
_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))
from csp_filter_catalog import get_filter_rules, has_filters  # noqa: E402

# ── Project root ───────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parent.parent.parent.parent

# ── Local YAML source paths per CSP ───────────────────────────────────────────
# For AWS: two sources — curated engine_check (priority A) + generated catalog (priority B)
# For all other CSPs: only catalog/{csp}/

ENGINE_CHECK_SERVICES = ROOT / "engines" / "check" / "engine_check_aws" / "services"
PYTHONSDK_ROOT        = ROOT / "catalog"

ALL_CSPS = ["aws", "azure", "gcp", "oci", "alicloud", "ibm"]


# ── Database connection ────────────────────────────────────────────────────────

def _check_db_cfg() -> dict:
    return {
        "host":     os.getenv("CHECK_DB_HOST", "localhost"),
        "port":     int(os.getenv("CHECK_DB_PORT", "5432")),
        "dbname":   os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        "user":     os.getenv("CHECK_DB_USER", "postgres"),
        "password": os.getenv("CHECK_DB_PASSWORD", ""),
    }


def _connect(cfg: dict):
    try:
        conn = psycopg2.connect(**cfg)
        conn.autocommit = False
        return conn
    except Exception as e:
        print(f"  ERROR: Cannot connect to check DB ({cfg['host']}/{cfg['dbname']}): {e}")
        return None


# ── YAML helpers ───────────────────────────────────────────────────────────────

def _load_yaml(path: Path) -> Optional[dict]:
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"  WARN: Failed to parse {path.name}: {e}")
        return None


def _discovery_list(parsed: dict) -> list:
    return parsed.get("discovery", []) if parsed else []


def _boto3_client(parsed: dict) -> str:
    return (parsed or {}).get("services", {}).get("client", "")


# ── Source enumeration ─────────────────────────────────────────────────────────

def _aws_curated() -> dict[str, Path]:
    """Source A for AWS: curated engine_check YAMLs."""
    result = {}
    if not ENGINE_CHECK_SERVICES.exists():
        return result
    for svc_dir in sorted(ENGINE_CHECK_SERVICES.iterdir()):
        if not svc_dir.is_dir():
            continue
        disc_dir = svc_dir / "discoveries"
        if not disc_dir.exists():
            continue
        for yaml_path in disc_dir.glob("*.discoveries.yaml"):
            result[svc_dir.name] = yaml_path
            break
    return result


def _pythonsdk_services(csp: str) -> dict[str, Path]:
    """Generated step6 YAMLs from data_pythonsdk/{csp}/."""
    result = {}
    csp_dir = PYTHONSDK_ROOT / csp
    if not csp_dir.exists():
        return result
    for svc_dir in sorted(csp_dir.iterdir()):
        if not svc_dir.is_dir():
            continue
        svc = svc_dir.name
        # Skip utility files/dirs that aren't service directories
        if svc.endswith(".py") or svc.endswith(".json") or svc.endswith(".yaml"):
            continue
        step6 = svc_dir / f"step6_{svc}.discovery.yaml"
        if step6.exists():
            result[svc] = step6
    return result


def _build_service_map(csp: str) -> tuple[dict[str, Path], dict[str, str]]:
    """
    Returns (service_map, source_labels):
      service_map:   {service: yaml_path}  — curated beats generated for AWS
      source_labels: {service: "curated"|"generated"}
    """
    service_map: dict[str, Path] = {}
    labels:      dict[str, str]  = {}

    sdk = _pythonsdk_services(csp)
    for svc, path in sdk.items():
        service_map[svc] = path
        labels[svc] = "generated"

    if csp == "aws":
        curated = _aws_curated()
        for svc, path in curated.items():
            service_map[svc] = path
            labels[svc] = "curated"

    return service_map, labels


# ── RDS current state ──────────────────────────────────────────────────────────

def _fetch_rds_state(conn, provider: str) -> dict[str, dict]:
    result = {}
    if conn is None:
        return result
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT service, discoveries_data, filter_rules
            FROM   rule_discoveries
            WHERE  provider = %s
              AND  (customer_id IS NULL OR customer_id = '')
              AND  (tenant_id   IS NULL OR tenant_id   = '')
        """, (provider,))
        for row in cur.fetchall():
            data = row["discoveries_data"]
            if isinstance(data, str):
                data = json.loads(data)
            fr = row.get("filter_rules") or {}
            if isinstance(fr, str):
                fr = json.loads(fr)
            ops = data or []
            result[row["service"]] = {
                "n_ops":       len(ops),
                "field_count": sum(
                    len(d.get("emit", {}).get("item", {}))
                    for d in ops if isinstance(d, dict)
                ),
                "n_api_filters":      len(fr.get("api_filters",      [])),
                "n_response_filters": len(fr.get("response_filters", [])),
            }
        cur.close()
    except Exception as e:
        print(f"  WARN: Could not read rule_discoveries for {provider}: {e}")
    return result


# ── Upsert ─────────────────────────────────────────────────────────────────────

def _upsert(conn, csp: str, service: str, disc_list: list,
            boto3_client_name: str, dry_run: bool) -> str:
    if conn is None:
        return "no-conn"
    if dry_run:
        return "would-write"

    filters = get_filter_rules(csp, service)

    sql = """
    INSERT INTO rule_discoveries
        (service, provider, discoveries_data, boto3_client_name,
         filter_rules, source, generated_by, is_active, updated_at)
    VALUES
        (%s, %s, %s, %s, %s, 'default', 'sync_script', TRUE, NOW())
    ON CONFLICT (service, provider, customer_id, tenant_id)
    DO UPDATE SET
        discoveries_data  = EXCLUDED.discoveries_data,
        boto3_client_name = EXCLUDED.boto3_client_name,
        filter_rules      = EXCLUDED.filter_rules,
        is_active         = TRUE,
        updated_at        = NOW()
    """
    try:
        cur = conn.cursor()
        cur.execute(sql, (
            service, csp,
            json.dumps(disc_list),
            boto3_client_name or service,
            json.dumps(filters),
        ))
        cur.close()
        conn.commit()
        return "upserted"
    except Exception as e:
        conn.rollback()
        print(f"  ERROR upsert {csp}/{service}: {e}")
        return "error"


# ── Diff label ─────────────────────────────────────────────────────────────────

def _diff(svc: str, csp: str, local_ops: int, local_fields: int,
          rds: dict) -> str:
    flt = has_filters(csp, svc)
    flt_tag = " [+filters]" if flt else ""

    if svc not in rds:
        return f"NEW        ({local_ops} ops, {local_fields} fields){flt_tag}"

    r = rds[svc]
    if (local_ops == r["n_ops"] and local_fields == r["field_count"]
            and (not flt or r["n_api_filters"] + r["n_response_filters"] > 0)):
        return f"SAME       ({local_ops} ops, {local_fields} fields){flt_tag}"

    dops = local_ops - r["n_ops"]
    dfld = local_fields - r["field_count"]
    return (f"DIFF       ops {r['n_ops']}→{local_ops} ({dops:+d}), "
            f"fields {r['field_count']}→{local_fields} ({dfld:+d}){flt_tag}")


# ── Sync one CSP ───────────────────────────────────────────────────────────────

def sync_csp(csp: str, conn, args) -> dict:
    """Sync all services for one CSP. Returns stats dict."""
    stats = dict(new=0, updated=0, same=0, error=0, dry=0)

    service_map, labels = _build_service_map(csp)
    if not service_map:
        print(f"  [{csp}] No local YAML sources found — skipping")
        return stats

    rds = _fetch_rds_state(conn, csp)

    svcs = sorted(service_map.keys())
    if args.service:
        svcs = [s for s in svcs if s == args.service]
        if not svcs:
            print(f"  [{csp}] Service '{args.service}' not found in local sources")
            return stats

    new_svcs = [s for s in svcs if s not in rds]

    print(f"\n  [{csp.upper()}]  local={len(svcs)}  rds={len(rds)}"
          f"  new={len(new_svcs)}"
          f"  filtered_svcs={sum(1 for s in svcs if has_filters(csp, s))}")
    print(f"  {'Service':<42} {'Src':<10} {'Status'}")
    print(f"  {'-'*42} {'-'*10} {'-'*65}")

    for svc in svcs:
        yaml_path = service_map[svc]
        src_label = labels[svc]

        parsed = _load_yaml(yaml_path)
        if not parsed:
            stats["error"] += 1
            continue

        disc_list = _discovery_list(parsed)
        if not disc_list:
            continue

        local_ops    = len(disc_list)
        local_fields = sum(
            len(d.get("emit", {}).get("item", {}))
            for d in disc_list if isinstance(d, dict)
        )

        diff_label = _diff(svc, csp, local_ops, local_fields, rds)
        is_same = diff_label.startswith("SAME")
        is_new  = diff_label.startswith("NEW")

        if args.new_only and not is_new:
            stats["same"] += 1
            continue

        # Skip unchanged (unless single-service targeted or has newly added filters)
        if is_same and not args.service and not diff_label.endswith("[+filters]"):
            stats["same"] += 1
            continue

        result = _upsert(conn, csp, svc, disc_list,
                         _boto3_client(parsed), args.dry_run)
        print(f"  {svc:<42} {src_label:<10} {diff_label}  → {result}")

        if args.dry_run:
            stats["dry"] += 1
        elif result == "error":
            stats["error"] += 1
        elif is_new:
            stats["new"] += 1
        else:
            stats["updated"] += 1

    return stats


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Sync local discovery YAMLs → rule_discoveries (check DB) for all CSPs"
    )
    parser.add_argument("--dry-run",  action="store_true",
                        help="Show what would change without writing to RDS")
    parser.add_argument("--provider", default="aws",
                        choices=ALL_CSPS + ["all"],
                        help="CSP to sync: aws | azure | gcp | oci | alicloud | ibm | all")
    parser.add_argument("--new-only", action="store_true",
                        help="Only add services missing from RDS; skip existing")
    parser.add_argument("--service",  default=None,
                        help="Process one service only (e.g. --service ec2)")
    args = parser.parse_args()

    csps = ALL_CSPS if args.provider == "all" else [args.provider]
    mode = "DRY RUN" if args.dry_run else "WRITING"

    print(f"sync_discoveries_to_db ({mode})")
    print(f"  CSPs: {', '.join(csps)}"
          f"  |  new-only: {args.new_only}"
          f"  |  service: {args.service or 'all'}")

    # ── Connect ──
    cfg  = _check_db_cfg()
    conn = _connect(cfg)
    if conn:
        print(f"  DB: {cfg['host']}/{cfg['dbname']}")
    else:
        print("  Running offline — dry-run output only (no DB writes possible)")
    print()

    # ── Filter catalog summary ──
    print("  Filter catalog coverage:")
    for csp in csps:
        from csp_filter_catalog import all_filtered_services
        fsvcs = all_filtered_services(csp)
        if fsvcs:
            print(f"    {csp:<10} {len(fsvcs)} services with managed-resource filters: "
                  f"{', '.join(fsvcs)}")
        else:
            print(f"    {csp:<10} (no filter rules defined yet)")

    # ── Sync each CSP ──
    grand = dict(new=0, updated=0, same=0, error=0, dry=0)

    for csp in csps:
        stats = sync_csp(csp, conn, args)
        for k in grand:
            grand[k] += stats[k]

    # ── Grand summary ──
    print()
    print("=" * 70)
    if args.dry_run:
        print(f"DRY RUN complete — {grand['dry']} services would be written")
    else:
        print(f"Done across {len(csps)} CSP(s):")
        print(f"  {grand['new']:>5}  new services added")
        print(f"  {grand['updated']:>5}  existing services updated")
        print(f"  {grand['same']:>5}  services unchanged (skipped)")
        print(f"  {grand['error']:>5}  errors")

    if conn:
        conn.close()


if __name__ == "__main__":
    main()
