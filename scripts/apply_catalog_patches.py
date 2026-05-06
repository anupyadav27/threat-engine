#!/usr/bin/env python3
"""DCAT-01 Phase A4 — Catalog Patch Applier + DB Sync.

Closes the loop on Phase A0.5 (catalog_gap_autogen.py). Reads the auto-generated
patches from catalog/_dcat_patches/{csp}/{svc}.patch.yaml and:

  1. Merges `additions` into the live `step6_*.discovery.yaml` per service —
     preserves existing fields, only ADDs new ones (skips leaf-name collisions
     so we don't overwrite a hand-curated template with the auto-generated form).
  2. Applies `renames` — rewrites templates whose path is broken to the
     SDK-correct path.
  3. Syncs the resulting catalog YAML to the `rule_discoveries` table in
     threat_engine_check DB so engines see the same shape at runtime as on disk.

Local catalog (file system) and DB row stay in lockstep — that is the contract.

Usage:
  # Dry-run for a single service
  python3 scripts/apply_catalog_patches.py --provider aws --service kms --dry-run

  # Apply local YAML edits but skip DB sync
  python3 scripts/apply_catalog_patches.py --provider aws --service kms --no-db

  # Apply local + DB sync for one service
  python3 scripts/apply_catalog_patches.py --provider aws --service kms

  # All AWS services (be careful — touches 372 files)
  python3 scripts/apply_catalog_patches.py --provider aws --all

DB connection:
  CHECK_DB_HOST / CHECK_DB_PORT / CHECK_DB_NAME / CHECK_DB_USER / CHECK_DB_PASSWORD
  Local laptop typically can't reach private RDS — run from inside an engine pod
  via `kubectl exec -n threat-engine-engines <pod> -- python3 ...` or set up a
  bastion port-forward.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections import defaultdict
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


ROOT = Path("/Users/apple/Desktop/threat-engine")
CATALOG_ROOT = ROOT / "catalog/discovery_generator_data"
PATCH_ROOT = ROOT / "catalog/_dcat_patches"

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("apply_patches")


# ── YAML helpers (preserve key order) ───────────────────────────────────────


class _OrderedDumper(yaml.SafeDumper):
    """Yaml dumper that keeps insertion order (Python 3.7+ dicts)."""


def _represent_dict(dumper, data):
    return dumper.represent_mapping("tag:yaml.org,2002:map", data.items())


_OrderedDumper.add_representer(dict, _represent_dict)


def load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open() as f:
        return yaml.safe_load(f) or {}


def write_yaml(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        yaml.dump(
            data,
            f,
            Dumper=_OrderedDumper,
            default_flow_style=False,
            sort_keys=False,
            width=200,
            allow_unicode=True,
        )


# ── Patch model ────────────────────────────────────────────────────────────


def load_patch(provider: str, service: str) -> Dict[str, Any]:
    p = PATCH_ROOT / provider / f"{service}.patch.yaml"
    if not p.exists():
        return {}
    with p.open() as f:
        return yaml.safe_load(f) or {}


def find_catalog_yaml(provider: str, service: str) -> Optional[Path]:
    """Prefer step6_<svc>.discovery.yaml; fall back to final_discovery_v1.yaml."""
    svc_dir = CATALOG_ROOT / provider / service
    if not svc_dir.is_dir():
        return None
    for pattern in (f"step6_*.discovery.yaml", "final_discovery_v1.yaml"):
        for candidate in sorted(svc_dir.glob(pattern)):
            # Skip backups
            if ".backup" in candidate.name or "_backup" in candidate.name:
                continue
            return candidate
    return None


# ── Merge + rename logic ───────────────────────────────────────────────────


def _leaf_name(path: str) -> str:
    """KeyMetadata.MultiRegionConfiguration.MultiRegionKeyType → MultiRegionKeyType.

    Strips list-index markers like [].
    """
    leaf = path.replace("[]", "").rsplit(".", 1)[-1]
    return leaf


def _existing_paths(item_block: Dict[str, str]) -> Dict[str, str]:
    """field_name -> jinja template, for fast lookup of leaf collisions."""
    return {k: v for k, v in (item_block or {}).items() if isinstance(v, str)}


def _strip_jinja_path(template_str: str) -> str:
    """{{ response.KeyMetadata.KeyId }} -> KeyMetadata.KeyId."""
    inner = template_str.strip()
    if inner.startswith("{{"):
        inner = inner[2:]
    if inner.endswith("}}"):
        inner = inner[:-2]
    inner = inner.strip()
    for prefix in ("response.", "item.", "context."):
        if inner.startswith(prefix):
            return inner[len(prefix):]
    return inner


def merge_additions(
    item_block: Dict[str, str],
    additions: Dict[str, str],
) -> Tuple[Dict[str, str], int, int]:
    """Add new fields to an emit.item block.

    Skip rules:
      - if the leaf name already exists with the SAME path, skip silently
      - if the leaf name exists with a DIFFERENT path, keep the existing
        and skip the new one (catalog hand-curation wins; auto-add is
        defensive only)
      - otherwise, add the new field with its leaf name as the key

    Returns: (new_block, added_count, skipped_count)
    """
    if not isinstance(item_block, dict):
        item_block = {}
    new_block = dict(item_block)
    existing = _existing_paths(new_block)
    existing_paths = {_strip_jinja_path(t) for t in existing.values()}

    added = 0
    skipped = 0
    for field_key, template in (additions or {}).items():
        if not isinstance(template, str):
            continue
        path = _strip_jinja_path(template)
        leaf = _leaf_name(path)
        # Skip overly nested list expansions for now — they need
        # a separate iterating discovery, not a flat field.
        if "[]" in path:
            skipped += 1
            continue
        # Skip if the path is already declared (under any name)
        if path in existing_paths:
            skipped += 1
            continue
        # Skip if leaf name collides with a hand-curated template
        if leaf in new_block:
            skipped += 1
            continue
        new_block[leaf] = template
        existing_paths.add(path)
        added += 1
    return new_block, added, skipped


def apply_renames(
    item_block: Dict[str, str],
    renames: Dict[str, str],
) -> Tuple[Dict[str, str], int]:
    """Rewrite templates whose path is broken.

    `renames` maps old_path → new_path. We find any field whose template
    references old_path and rewrite it to new_path, preserving the field key.
    """
    if not isinstance(item_block, dict):
        return item_block, 0
    new_block = dict(item_block)
    fixed = 0
    for old_path, new_path in (renames or {}).items():
        if not new_path:
            continue
        for field_key, template in list(new_block.items()):
            if not isinstance(template, str):
                continue
            current_path = _strip_jinja_path(template)
            if current_path == old_path:
                new_template = template.replace(old_path, new_path, 1)
                new_block[field_key] = new_template
                fixed += 1
    return new_block, fixed


def merge_into_catalog(
    catalog_data: Dict[str, Any],
    patch: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Tuple[int, int, int]]]:
    """Apply additions + renames to a catalog YAML's discovery list.

    Returns: (mutated_catalog, per_discovery_stats: {discovery_id: (added, skipped, renamed)})
    """
    stats: Dict[str, Tuple[int, int, int]] = {}
    additions = patch.get("additions") or {}
    renames = patch.get("renames") or {}

    discoveries = catalog_data.get("discovery") or []
    for disc in discoveries:
        did = disc.get("discovery_id", "")
        if not did:
            continue
        emit = disc.setdefault("emit", {})
        item_block = emit.get("item") or {}

        item_block, added, skipped = merge_additions(item_block, additions.get(did, {}))
        item_block, renamed = apply_renames(item_block, renames.get(did, {}))

        if item_block:
            emit["item"] = item_block
        stats[did] = (added, skipped, renamed)

    return catalog_data, stats


# ── DB sync ────────────────────────────────────────────────────────────────


def db_connect():
    """Connect to threat_engine_check using CHECK_DB_* env vars."""
    try:
        import psycopg2
    except ImportError:
        log.error("psycopg2 not installed — DB sync unavailable")
        return None

    host = os.getenv("CHECK_DB_HOST") or os.getenv("DB_HOST")
    if not host:
        log.error("CHECK_DB_HOST not set — DB sync unavailable")
        return None

    return psycopg2.connect(
        host=host,
        port=int(os.getenv("CHECK_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("CHECK_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        connect_timeout=10,
    )


def sync_to_db(
    conn,
    provider: str,
    service: str,
    catalog_data: Dict[str, Any],
    *,
    dry_run: bool = False,
) -> bool:
    """Upsert the catalog into rule_discoveries.

    The table column `discoveries_data` holds the discovery list as JSONB.
    Existing row is matched by (provider, service); we update discoveries_data
    and bump updated_at + version.

    The on-disk YAML is written first so failures here leave files consistent.
    """
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, version, source FROM rule_discoveries
        WHERE provider = %s AND service = %s AND is_active = true
        ORDER BY updated_at DESC LIMIT 1
        """,
        (provider, service),
    )
    row = cur.fetchone()

    # rule_discoveries.discoveries_data holds the discovery list directly
    # (not the full YAML envelope with 'version'/'provider'/'service' keys).
    discovery_list = (
        catalog_data.get("discovery", [])
        if isinstance(catalog_data, dict)
        else (catalog_data if isinstance(catalog_data, list) else [])
    )
    new_data = json.dumps(discovery_list, default=str)

    if dry_run:
        if row:
            log.info(
                f"  DRY: would UPDATE rule_discoveries id={row[0]} "
                f"({len(new_data)} bytes JSON)"
            )
        else:
            log.info(f"  DRY: would INSERT rule_discoveries for {provider}/{service}")
        return True

    # rule_discoveries.version is varchar — use timestamp-tagged string so we
    # can trace which run wrote each row.
    from datetime import datetime, timezone
    new_version = f"dcat01-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}"

    if row:
        rid, _version, _source = row
        cur.execute(
            """
            UPDATE rule_discoveries
               SET discoveries_data = %s,
                   version = %s,
                   updated_at = now(),
                   source = COALESCE(source, 'catalog'),
                   generated_by = 'apply_catalog_patches'
             WHERE id = %s
            """,
            (new_data, new_version, rid),
        )
        log.info(f"  ✓ DB UPDATE id={rid} -> {new_version}")
    else:
        cur.execute(
            """
            INSERT INTO rule_discoveries
                (service, provider, version, discoveries_data,
                 created_at, updated_at, source, generated_by, is_active)
            VALUES (%s, %s, %s, %s, now(), now(), 'catalog', 'apply_catalog_patches', true)
            """,
            (service, provider, new_version, new_data),
        )
        log.info(f"  ✓ DB INSERT new row for {provider}/{service} ({new_version})")

    conn.commit()
    return True


# ── Per-service driver ──────────────────────────────────────────────────────


def apply_one(
    provider: str,
    service: str,
    *,
    dry_run: bool,
    sync_db: bool,
    write_yaml_files: bool,
    db_conn=None,
) -> Tuple[int, int, int, bool]:
    """Apply patch for one (provider, service). Returns (added, skipped, renamed, ok)."""
    patch = load_patch(provider, service)
    if not patch:
        return (0, 0, 0, False)

    yaml_path = find_catalog_yaml(provider, service)
    if not yaml_path:
        log.warning(f"  {provider}/{service}: no catalog YAML found")
        return (0, 0, 0, False)

    catalog = load_yaml(yaml_path)
    catalog_copy = deepcopy(catalog)
    catalog_copy, stats = merge_into_catalog(catalog_copy, patch)

    total_added = sum(s[0] for s in stats.values())
    total_skipped = sum(s[1] for s in stats.values())
    total_renamed = sum(s[2] for s in stats.values())

    log.info(
        f"  {provider}/{service}: +{total_added} adds, {total_skipped} skipped (collision), "
        f"{total_renamed} renames across {len(stats)} discoveries"
    )

    if total_added == 0 and total_renamed == 0:
        # No real change; skip writes
        return (0, total_skipped, 0, True)

    # Phase 1: write YAML
    if write_yaml_files and not dry_run:
        # Backup the old YAML alongside the new one
        backup = yaml_path.with_suffix(yaml_path.suffix + ".pre_dcat01")
        if not backup.exists():
            backup.write_bytes(yaml_path.read_bytes())
        write_yaml(yaml_path, catalog_copy)
        log.info(f"  ✓ wrote YAML: {yaml_path.name}")
    elif dry_run:
        log.info(f"  DRY: would write YAML: {yaml_path}")

    # Phase 2: sync DB
    if sync_db and db_conn is not None:
        try:
            sync_to_db(db_conn, provider, service, catalog_copy, dry_run=dry_run)
        except Exception as exc:
            log.error(f"  ✗ DB sync failed for {provider}/{service}: {exc}")
            return (total_added, total_skipped, total_renamed, False)
    elif sync_db and db_conn is None:
        log.warning(f"  {provider}/{service}: DB sync requested but no connection — skipped")

    return (total_added, total_skipped, total_renamed, True)


# ── CLI ────────────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", help="csp slug (aws/gcp/azure/oci/alicloud/k8s/ibm)")
    ap.add_argument("--service")
    ap.add_argument("--all", action="store_true", help="every service for the given provider")
    ap.add_argument("--all-providers", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="preview without writing")
    ap.add_argument("--no-db", action="store_true", help="skip rule_discoveries DB sync")
    ap.add_argument("--no-yaml", action="store_true", help="skip local YAML rewrite")
    args = ap.parse_args()

    write_yaml_files = not args.no_yaml
    sync_db = not args.no_db

    db_conn = db_connect() if sync_db else None
    if sync_db and db_conn is None and not args.dry_run:
        log.error("DB sync requested but DB unreachable — abort. Use --no-db to skip, or set CHECK_DB_HOST.")
        return 2

    targets: List[Tuple[str, Optional[str]]] = []
    if args.all_providers:
        for p in ["aws", "gcp", "azure", "oci", "alicloud", "k8s", "ibm"]:
            if (PATCH_ROOT / p).is_dir():
                targets.append((p, None))
    elif args.provider and args.all:
        targets.append((args.provider, None))
    elif args.provider and args.service:
        targets.append((args.provider, args.service))
    else:
        ap.print_help()
        return 1

    grand_added = 0
    grand_skipped = 0
    grand_renamed = 0
    failed: List[Tuple[str, str]] = []

    for provider, single_service in targets:
        prov_dir = PATCH_ROOT / provider
        if not prov_dir.is_dir():
            log.warning(f"no patches for {provider}")
            continue
        if single_service:
            services = [single_service]
        else:
            services = [p.stem.replace(".patch", "") for p in prov_dir.glob("*.patch.yaml")]

        log.info(f"=== {provider} ({len(services)} services) ===")
        for svc in services:
            try:
                added, skipped, renamed, ok = apply_one(
                    provider,
                    svc,
                    dry_run=args.dry_run,
                    sync_db=sync_db,
                    write_yaml_files=write_yaml_files,
                    db_conn=db_conn,
                )
            except Exception as exc:
                log.error(f"  ✗ {provider}/{svc}: {exc}")
                failed.append((provider, svc))
                continue
            if ok:
                grand_added += added
                grand_skipped += skipped
                grand_renamed += renamed
            else:
                failed.append((provider, svc))

    log.info("")
    log.info("=" * 70)
    log.info(
        f"TOTAL: +{grand_added} adds, {grand_skipped} skipped (collision), "
        f"{grand_renamed} renames"
    )
    if failed:
        log.warning(f"FAILED: {len(failed)} services — first 10: {failed[:10]}")
    if args.dry_run:
        log.info("(dry-run — no files or DB rows changed)")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
