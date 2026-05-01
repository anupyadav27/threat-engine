#!/usr/bin/env python3
"""
Sync resource_inventory_identifier.should_inventory to check rule coverage.

Logic:
  - For each CSP (aws, gcp, azure, k8s):
    * Scan catalog/rule/{csp}_rule_check/ for service directories
    * Any row in resource_inventory_identifier whose service IS in checks  → should_inventory = TRUE
    * Any row whose service is NOT in checks                               → should_inventory = FALSE
  - "resource means resource AND subresources": matching is done at the service
    level — all resource_types under an ec2 service flip together.

Usage:
    # Dry run (no DB changes, just print what would change):
    python sync_should_inventory_to_checks.py --dry-run

    # Apply to DB (uses env vars for connection):
    python sync_should_inventory_to_checks.py

    # Override catalog root:
    python sync_should_inventory_to_checks.py --catalog-root /path/to/catalog/rule

    # Explicit DB URL:
    python sync_should_inventory_to_checks.py --db-url postgresql://user:pass@host/db

    # Also update the CSV backup:
    python sync_should_inventory_to_checks.py --update-csv /path/to/resource_inventory_identifier.csv

    # Only specific CSPs:
    python sync_should_inventory_to_checks.py --csp aws gcp
"""

import argparse
import csv
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Optional, Set

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("psycopg2 not found. Install: pip install psycopg2-binary")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Repo root relative to this script: engines/inventory/scripts/ → repo root (3 levels up)
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CATALOG_ROOT = REPO_ROOT / "catalog" / "rule"

# CSP → directory suffix mapping
CSP_DIR_SUFFIX: Dict[str, str] = {
    "aws": "aws_rule_check",
    "gcp": "gcp_rule_check",
    "azure": "azure_rule_check",
    "k8s": "k8s_rule_check",
}

# Files/dirs to skip inside a check rule directory (not actual services)
SKIP_NAMES = {
    "generate_gcp_checks.py",
    "catalog_validation_report.json",
}
SKIP_EXTENSIONS = {".yaml", ".yml", ".json", ".py", ".txt", ".md"}


def get_services_with_checks(catalog_root: Path, csp: str) -> Set[str]:
    """Return set of service names that have check rules for the given CSP."""
    dir_suffix = CSP_DIR_SUFFIX.get(csp)
    if not dir_suffix:
        raise ValueError(f"Unknown CSP: {csp}")

    check_dir = catalog_root / dir_suffix
    if not check_dir.is_dir():
        logger.warning("Check rule directory not found: %s", check_dir)
        return set()

    services: Set[str] = set()
    for entry in check_dir.iterdir():
        if entry.name in SKIP_NAMES:
            continue
        if entry.suffix.lower() in SKIP_EXTENSIONS:
            continue
        if entry.is_dir():
            services.add(entry.name)

    logger.info("CSP %-6s → %d services with check rules", csp, len(services))
    return services


def build_db_url(args: argparse.Namespace) -> str:
    """Build PostgreSQL connection URL from args or env vars."""
    if args.db_url:
        return args.db_url
    host = os.getenv("INVENTORY_DB_HOST", "localhost")
    port = os.getenv("INVENTORY_DB_PORT", "5432")
    db = os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory")
    user = os.getenv("INVENTORY_DB_USER", "inventory_user")
    pw = os.getenv("INVENTORY_DB_PASSWORD", "inventory_password")
    return f"postgresql://{user}:{pw}@{host}:{port}/{db}"


def run_sync(
    conn,
    csp: str,
    services_with_checks: Set[str],
    dry_run: bool,
) -> Dict[str, int]:
    """
    Update should_inventory for one CSP.

    Returns: {"enabled": N, "disabled": N, "unchanged_enabled": N, "unchanged_disabled": N}
    """
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Fetch current state for this CSP
    cur.execute(
        "SELECT service, resource_type, should_inventory FROM resource_inventory_identifier WHERE csp = %s",
        (csp,),
    )
    rows = cur.fetchall()

    if not rows:
        logger.info("CSP %-6s → no rows in resource_inventory_identifier, skipping", csp)
        cur.close()
        return {"enabled": 0, "disabled": 0, "unchanged_enabled": 0, "unchanged_disabled": 0}

    to_enable: Set[str] = set()   # services that should become TRUE
    to_disable: Set[str] = set()  # services that should become FALSE
    unchanged_enabled: int = 0
    unchanged_disabled: int = 0

    # Group by service to count resource_types
    service_current: Dict[str, Dict] = {}
    for row in rows:
        svc = row["service"]
        if svc not in service_current:
            service_current[svc] = {"should_inventory": row["should_inventory"], "count": 0}
        service_current[svc]["count"] += 1

    for svc, info in service_current.items():
        currently_enabled = info["should_inventory"]
        has_checks = svc in services_with_checks

        if has_checks and not currently_enabled:
            to_enable.add(svc)
        elif not has_checks and currently_enabled:
            to_disable.add(svc)
        elif has_checks and currently_enabled:
            unchanged_enabled += info["count"]
        else:
            unchanged_disabled += info["count"]

    enabled_count = sum(service_current[s]["count"] for s in to_enable)
    disabled_count = sum(service_current[s]["count"] for s in to_disable)

    # Log services without any inventory rows (in checks but not in inventory table)
    inventory_services = set(service_current.keys())
    check_only = services_with_checks - inventory_services
    inventory_only_enabled = {s for s in (inventory_services - services_with_checks) if service_current[s]["should_inventory"]}

    if check_only:
        logger.info(
            "CSP %-6s → %d services in checks but NOT in inventory table (no action needed): %s",
            csp,
            len(check_only),
            ", ".join(sorted(check_only)[:20]) + ("…" if len(check_only) > 20 else ""),
        )

    logger.info(
        "CSP %-6s → will ENABLE %d rows (%d services), DISABLE %d rows (%d services)",
        csp,
        enabled_count,
        len(to_enable),
        disabled_count,
        len(to_disable),
    )

    if to_enable:
        logger.debug("Enabling: %s", sorted(to_enable))
    if to_disable:
        logger.debug("Disabling: %s", sorted(to_disable))

    if not dry_run:
        if to_enable:
            cur.execute(
                """
                UPDATE resource_inventory_identifier
                   SET should_inventory = TRUE, updated_at = NOW()
                 WHERE csp = %s AND service = ANY(%s)
                """,
                (csp, list(to_enable)),
            )
            logger.info("CSP %-6s → enabled %d rows (enable services: %s)", csp, cur.rowcount, sorted(to_enable))

        if to_disable:
            cur.execute(
                """
                UPDATE resource_inventory_identifier
                   SET should_inventory = FALSE, updated_at = NOW()
                 WHERE csp = %s AND service = ANY(%s)
                """,
                (csp, list(to_disable)),
            )
            logger.info("CSP %-6s → disabled %d rows (disable services: %s)", csp, cur.rowcount, sorted(to_disable))

    cur.close()
    return {
        "enabled": enabled_count,
        "disabled": disabled_count,
        "unchanged_enabled": unchanged_enabled,
        "unchanged_disabled": unchanged_disabled,
        "services_enabled": sorted(to_enable),
        "services_disabled": sorted(to_disable),
        "services_checks_only": sorted(check_only),
    }


def update_csv_backup(csv_path: str, csp_services: Dict[str, Set[str]]) -> None:
    """Update the should_inventory column in a CSV backup file."""
    path = Path(csv_path)
    if not path.exists():
        logger.warning("CSV path not found: %s — skipping CSV update", csv_path)
        return

    # Raise CSV field size limit to handle large JSONB fields
    csv.field_size_limit(10 * 1024 * 1024)  # 10 MB

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        rows = list(reader)

    if "should_inventory" not in fieldnames or "csp" not in fieldnames or "service" not in fieldnames:
        logger.error("CSV missing required columns (csp, service, should_inventory) — skipping")
        return

    changed = 0
    for row in rows:
        csp = row.get("csp", "")
        svc = row.get("service", "")
        if csp not in csp_services:
            continue
        services_with_checks = csp_services[csp]
        new_val = "t" if svc in services_with_checks else "f"
        if row["should_inventory"] != new_val:
            row["should_inventory"] = new_val
            changed += 1

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    logger.info("CSV backup updated: %d rows changed → %s", changed, csv_path)


def print_summary(results: Dict[str, Dict]) -> None:
    """Print a human-readable summary table."""
    print("\n" + "=" * 80)
    print("SYNC SUMMARY: resource_inventory_identifier.should_inventory → check coverage")
    print("=" * 80)
    print(f"{'CSP':<8} {'ENABLED rows':>14} {'DISABLED rows':>15} {'Already ON':>12} {'Already OFF':>13}")
    print("-" * 80)
    total_enabled = total_disabled = 0
    for csp, r in results.items():
        print(
            f"{csp:<8} {r['enabled']:>14,} {r['disabled']:>15,} "
            f"{r['unchanged_enabled']:>12,} {r['unchanged_disabled']:>13,}"
        )
        total_enabled += r["enabled"]
        total_disabled += r["disabled"]
    print("-" * 80)
    print(f"{'TOTAL':<8} {total_enabled:>14,} {total_disabled:>15,}")
    print("=" * 80)

    for csp, r in results.items():
        if r.get("services_enabled"):
            print(f"\n[{csp.upper()}] Services ENABLED (had checks, were disabled):")
            for s in r["services_enabled"]:
                print(f"    + {s}")
        if r.get("services_disabled"):
            print(f"\n[{csp.upper()}] Services DISABLED (no checks, were enabled):")
            for s in r["services_disabled"]:
                print(f"    - {s}")
        if r.get("services_checks_only"):
            print(f"\n[{csp.upper()}] Services in checks but not in inventory table (no action):")
            for s in r["services_checks_only"][:30]:
                print(f"    ? {s}")
            if len(r["services_checks_only"]) > 30:
                print(f"    … and {len(r['services_checks_only']) - 30} more")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sync resource_inventory_identifier.should_inventory to check rule coverage"
    )
    parser.add_argument(
        "--catalog-root",
        default=str(DEFAULT_CATALOG_ROOT),
        help=f"Path to catalog/rule directory (default: {DEFAULT_CATALOG_ROOT})",
    )
    parser.add_argument(
        "--db-url",
        default=None,
        help="PostgreSQL connection URL (overrides env vars)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without modifying the DB",
    )
    parser.add_argument(
        "--csp",
        nargs="+",
        default=list(CSP_DIR_SUFFIX.keys()),
        choices=list(CSP_DIR_SUFFIX.keys()),
        help="CSPs to process (default: all)",
    )
    parser.add_argument(
        "--update-csv",
        default=None,
        metavar="CSV_PATH",
        help="Also update should_inventory in a CSV backup file",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show DEBUG logs (lists of services being enabled/disabled)",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.dry_run:
        logger.info("DRY RUN mode — no DB changes will be made")

    catalog_root = Path(args.catalog_root)
    if not catalog_root.is_dir():
        logger.error("Catalog root not found: %s", catalog_root)
        sys.exit(1)

    # Build service sets for each CSP
    csp_services: Dict[str, Set[str]] = {}
    for csp in args.csp:
        csp_services[csp] = get_services_with_checks(catalog_root, csp)

    db_url = build_db_url(args)
    logger.info("Connecting to DB: %s", db_url.split("@")[-1])  # hide credentials

    try:
        conn = psycopg2.connect(db_url)
        conn.autocommit = False
    except Exception as exc:
        logger.error("DB connection failed: %s", exc)
        sys.exit(1)

    results: Dict[str, Dict] = {}
    try:
        for csp in args.csp:
            results[csp] = run_sync(conn, csp, csp_services[csp], dry_run=args.dry_run)

        if not args.dry_run:
            conn.commit()
            logger.info("Transaction committed.")
        else:
            conn.rollback()
            logger.info("Dry run — rolled back (nothing written).")
    except Exception as exc:
        conn.rollback()
        logger.error("Error during sync, rolled back: %s", exc)
        raise
    finally:
        conn.close()

    print_summary(results)

    if args.update_csv and not args.dry_run:
        update_csv_backup(args.update_csv, csp_services)
    elif args.update_csv and args.dry_run:
        logger.info("Dry run — CSV update skipped")


if __name__ == "__main__":
    main()
