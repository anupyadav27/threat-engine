#!/usr/bin/env python3
"""
Load Python SDK discovery YAMLs into rule_discoveries table.

Source: /Users/apple/Desktop/threat-engine-main-5-feb-2026-backup/data_pythonsdk

For each CSP/service:
  1. Read *_discovery.yaml
  2. Filter to read-only operations only (list_*, get_*, Describe_*, List_*)
  3. Upsert into rule_discoveries (ON CONFLICT UPDATE)

Run:
  python3 scripts/load_pythonsdk_to_rule_discoveries.py [--dry-run] [--csp azure,gcp,oci,ibm,k8s,alicloud,aws]
"""

import os
import sys
import json
import yaml
import argparse
import psycopg2
import psycopg2.extras
from pathlib import Path
from typing import Dict, List, Any, Optional

# ── Config ────────────────────────────────────────────────────────────────────

SDK_ROOT = Path("/Users/apple/Desktop/threat-engine/data_pythonsdk")

DB_CONFIG = {
    "host":     os.getenv("CHECK_DB_HOST", "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"),
    "port":     int(os.getenv("CHECK_DB_PORT", "5432")),
    "dbname":   os.getenv("CHECK_DB_NAME", "threat_engine_check"),
    "user":     os.getenv("CHECK_DB_USER", "postgres"),
    "password": os.getenv("CHECK_DB_PASSWORD", "jtv2BkJF8qoFtAKP"),
}

ALL_CSPS = ["azure", "gcp", "oci", "ibm", "k8s", "alicloud", "aws"]

# ── Read-only action filter per CSP ───────────────────────────────────────────
# Actions that START WITH any of these prefixes are kept; all others dropped.

READ_ONLY_PREFIXES: Dict[str, List[str]] = {
    "azure":    ["list", "get"],
    "gcp":      ["list", "get"],
    "oci":      ["list", "get"],
    "ibm":      ["list", "get"],
    "k8s":      ["list", "get"],
    "alicloud": ["Describe", "List", "Get"],
    "aws":      ["list_", "describe_", "get_"],
}

# Actions that are explicitly NOT read-only even if they start with a valid prefix
BLOCKED_ACTIONS = {
    "azure": {"check_name_availability", "execute", "update", "create", "delete",
              "rotate", "flush", "trigger", "reset", "regenerate"},
}


def is_read_only(action: str, csp: str) -> bool:
    """Return True if action is a read-only SDK call."""
    action_lower = action.lower()
    blocked = BLOCKED_ACTIONS.get(csp, set())
    if action in blocked or action_lower in blocked:
        return False
    prefixes = READ_ONLY_PREFIXES.get(csp, ["list", "get"])
    return any(action.startswith(p) or action_lower.startswith(p.lower()) for p in prefixes)


def filter_discoveries(discoveries: List[Dict], csp: str) -> List[Dict]:
    """Keep only discovery entries whose calls are all read-only."""
    result = []
    for disc in discoveries:
        calls = disc.get("calls", [])
        if not calls:
            continue
        # Keep entry only if all calls are read-only
        all_readonly = all(is_read_only(c.get("action", ""), csp) for c in calls)
        if all_readonly:
            result.append(disc)
    return result


def load_yaml(path: Path) -> Optional[Dict]:
    try:
        with open(path) as fh:
            return yaml.safe_load(fh)
    except Exception as e:
        print(f"  WARN: cannot parse {path}: {e}")
        return None


def load_csp(csp: str) -> List[Dict]:
    """Load all discovery YAMLs for a CSP, return list of DB-ready dicts."""
    csp_dir = SDK_ROOT / csp
    if not csp_dir.exists():
        print(f"  WARN: {csp_dir} not found, skipping.")
        return []

    records = []
    for yaml_path in sorted(csp_dir.rglob("*_discovery.yaml")):
        data = load_yaml(yaml_path)
        if not data:
            continue

        service   = data.get("service", "")
        provider  = data.get("provider", csp)
        version   = data.get("version", "1.0")
        services  = data.get("services", {})
        raw_discs = data.get("discovery", [])

        if not service:
            print(f"  WARN: no service field in {yaml_path}, skipping.")
            continue

        # Filter to read-only operations
        filtered = filter_discoveries(raw_discs, csp)

        if not filtered:
            # Keep the record but with empty discovery list (don't discard service entirely)
            pass

        # Build the discoveries_data JSONB — same structure as original YAML
        discoveries_data = {
            "version":   version,
            "provider":  provider,
            "service":   service,
            "services":  services,
            "discovery": filtered,
            "checks":    data.get("checks", []),
        }

        records.append({
            "service":          service,
            "provider":         provider,
            "version":          version,
            "discoveries_data": json.dumps(discoveries_data),
            "boto3_client_name": services.get("client", ""),
            "source":           "pythonsdk_backup",
            "generated_by":     "load_pythonsdk_script",
            "is_active":        True,
        })

    return records


def upsert_records(conn, records: List[Dict], dry_run: bool) -> Dict[str, int]:
    """Upsert records into rule_discoveries. Returns {inserted, updated, skipped}."""
    stats = {"inserted": 0, "updated": 0, "skipped": 0}

    sql = """
        INSERT INTO rule_discoveries
            (service, provider, version, discoveries_data, boto3_client_name,
             source, generated_by, is_active, customer_id, tenant_id,
             created_at, updated_at)
        VALUES
            (%(service)s, %(provider)s, %(version)s, %(discoveries_data)s::jsonb,
             %(boto3_client_name)s, %(source)s, %(generated_by)s, %(is_active)s,
             NULL, NULL, NOW(), NOW())
        ON CONFLICT (service, provider, customer_id, tenant_id)
        DO UPDATE SET
            version          = EXCLUDED.version,
            discoveries_data = EXCLUDED.discoveries_data,
            boto3_client_name = EXCLUDED.boto3_client_name,
            source           = EXCLUDED.source,
            generated_by     = EXCLUDED.generated_by,
            is_active        = EXCLUDED.is_active,
            updated_at       = NOW()
        RETURNING (xmax = 0) AS inserted
    """

    if dry_run:
        for rec in records:
            disc_count = len(json.loads(rec["discoveries_data"]).get("discovery", []))
            print(f"    [DRY-RUN] {rec['provider']}.{rec['service']} — {disc_count} ops")
            stats["skipped"] += 1
        return stats

    with conn.cursor() as cur:
        for rec in records:
            try:
                cur.execute(sql, rec)
                row = cur.fetchone()
                if row and row[0]:
                    stats["inserted"] += 1
                else:
                    stats["updated"] += 1
            except Exception as e:
                print(f"  ERROR upserting {rec['provider']}.{rec['service']}: {e}")
                conn.rollback()
                stats["skipped"] += 1
                continue
        conn.commit()

    return stats


def main():
    parser = argparse.ArgumentParser(description="Load SDK discovery YAMLs → rule_discoveries")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be done, no DB writes")
    parser.add_argument("--csp", default=",".join(ALL_CSPS),
                        help="Comma-separated CSPs to load (default: all)")
    parser.add_argument("--skip-aws", action="store_true", help="Skip AWS (already correct in DB)")
    args = parser.parse_args()

    csps = [c.strip() for c in args.csp.split(",")]
    if args.skip_aws and "aws" in csps:
        csps.remove("aws")

    print(f"\n{'DRY RUN — ' if args.dry_run else ''}Loading SDK YAMLs for: {', '.join(csps)}")
    print(f"Source: {SDK_ROOT}")
    print(f"Target: {DB_CONFIG['host']}/{DB_CONFIG['dbname']}\n")

    if not args.dry_run:
        try:
            conn = psycopg2.connect(**DB_CONFIG)
        except Exception as e:
            print(f"ERROR: Cannot connect to DB: {e}")
            sys.exit(1)
    else:
        conn = None

    total_stats = {"inserted": 0, "updated": 0, "skipped": 0}

    for csp in csps:
        print(f"── {csp.upper()} ──")
        records = load_csp(csp)

        if not records:
            print(f"  No records found.")
            continue

        # Summary before upsert
        total_ops = sum(
            len(json.loads(r["discoveries_data"]).get("discovery", []))
            for r in records
        )
        print(f"  Services: {len(records)} | Read-only discovery ops: {total_ops}")

        stats = upsert_records(conn, records, args.dry_run)
        total_stats["inserted"] += stats["inserted"]
        total_stats["updated"]  += stats["updated"]
        total_stats["skipped"]  += stats["skipped"]

        if not args.dry_run:
            print(f"  → inserted={stats['inserted']} updated={stats['updated']} skipped={stats['skipped']}")
        print()

    if conn:
        conn.close()

    print("── TOTAL ──")
    print(f"  Inserted: {total_stats['inserted']}")
    print(f"  Updated:  {total_stats['updated']}")
    print(f"  Skipped:  {total_stats['skipped']}")
    print()


if __name__ == "__main__":
    main()
