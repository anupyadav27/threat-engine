#!/usr/bin/env python3
"""
sync_gcp_to_db.py
=================
Sync all GCP services that have check rules into:
  1. rule_discoveries  (check DB)       — one row per service, discoveries_data from final_discovery_v1.yaml
  2. resource_inventory_identifier (inventory DB) — one row per identifier op, from inventory_resource_identifiers block

Covers all 42 active GCP check-rule services mapped to 41 final_discovery_v1.yaml files.

Usage (local):
    CHECK_DB_HOST=localhost CHECK_DB_PORT=5432 CHECK_DB_NAME=threat_engine_check \
    CHECK_DB_USER=apple CHECK_DB_PASSWORD="" \
    INV_DB_HOST=localhost INV_DB_PORT=5432 INV_DB_NAME=threat_engine_inventory \
    INV_DB_USER=apple INV_DB_PASSWORD="" \
    python sync_gcp_to_db.py [--dry-run]
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import psycopg2
import yaml

# ──────────────────────────────────────────────────────────────────────────────
ROOT       = Path('/Users/apple/Desktop/threat-engine')
CHECK_DIR  = ROOT / 'catalog/rule/gcp_rule_check'
GEN_DIR    = ROOT / 'catalog/discovery_generator/gcp'
# ──────────────────────────────────────────────────────────────────────────────

# check-rule service dir → generator service dir (when they differ)
SERVICE_ALIASES: Dict[str, str] = {
    'audit':                   'logging',
    'bigtable':                'bigtableadmin',
    'billing':                 'billingbudgets',
    'endpoints':               'servicemanagement',
    'filestore':               'file',
    'gke':                     'container',
    'kms':                     'cloudkms',
    'resourcemanager':         'cloudresourcemanager',
    'security_command_center': 'securitycenter',
    'sql':                     'sqladmin',
    # New: services with dedicated final_discovery yamls
    'datastudio':              'looker',
    'trace':                   'cloudtrace',
    'vertex_ai':               'vertex_ai',   # uses its own yaml (copy of aiplatform + extra)
    'cloudaudit':              'cloudaudit',
    'config_connector':        'config_connector',
    'os_config':               'osconfig',    # os_config has 0 vars but keep for rule_discoveries
}

# ──────────────────────────────────────────────────────────────────────────────
# DB connections
# ──────────────────────────────────────────────────────────────────────────────

def _check_conn():
    return psycopg2.connect(
        host=os.getenv("CHECK_DB_HOST", "localhost"),
        port=int(os.getenv("CHECK_DB_PORT", "5432")),
        dbname=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", "apple"),
        password=os.getenv("CHECK_DB_PASSWORD", ""),
    )


def _inv_conn():
    return psycopg2.connect(
        host=os.getenv("INV_DB_HOST", "localhost"),
        port=int(os.getenv("INV_DB_PORT", "5432")),
        dbname=os.getenv("INV_DB_NAME", "threat_engine_inventory"),
        user=os.getenv("INV_DB_USER", "apple"),
        password=os.getenv("INV_DB_PASSWORD", ""),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _load_yaml(path: Path) -> dict:
    try:
        return yaml.safe_load(path.read_text()) or {}
    except Exception as e:
        print(f"  WARN: could not parse {path}: {e}")
        return {}


def _derive_resource_type(op: str) -> str:
    """
    Derive a resource_type string from a GCP discovery op id.
    gcp.compute.instances.aggregatedList → instances
    gcp.storage.buckets.list             → buckets
    gcp.iam.projects.serviceAccounts.list → serviceAccounts
    """
    parts = op.split('.')
    # Skip 'gcp' (index 0) and service (index 1), then find the resource segment
    # (the segment before the method like list/get/aggregatedList)
    if len(parts) >= 4:
        # Last segment is the method; resource is second-to-last
        return parts[-2]
    if len(parts) == 3:
        return parts[2]
    return parts[-1]


def _build_root_ops(discovery: list) -> list:
    """Build root_ops list from discovery entries (independent ops)."""
    ops = []
    for entry in discovery:
        did = entry.get('discovery_id', '')
        if entry.get('for_each'):
            continue  # skip dependent ops
        calls = entry.get('calls', [{}])
        call  = calls[0] if calls else {}
        ops.append({
            'operation':       did,
            'kind':            'read_list',
            'independent':     True,
            'python_method':   call.get('action', ''),
            'required_params': [],
        })
    return ops


def _build_enrich_ops(discovery: list) -> list:
    """Build enrich_ops list from discovery entries (dependent ops)."""
    ops = []
    for entry in discovery:
        did = entry.get('discovery_id', '')
        if not entry.get('for_each'):
            continue  # skip independent ops
        calls = entry.get('calls', [{}])
        call  = calls[0] if calls else {}
        params = call.get('params', {})
        required = list(params.keys()) if params else []
        param_sources = {}
        for pk, pv in params.items():
            # '{{ item.name }}' → from_field='name'
            m = re.search(r'item\.(\S+?)\s*}}', str(pv))
            if m:
                param_sources[pk] = {'from_field': m.group(1)}
        ops.append({
            'operation':       did,
            'kind':            'read_get',
            'independent':     False,
            'python_method':   call.get('action', ''),
            'required_params': required,
            'param_sources':   param_sources,
        })
    return ops


# ──────────────────────────────────────────────────────────────────────────────
# Load final_discovery_v1.yaml for a service
# ──────────────────────────────────────────────────────────────────────────────

def load_final_discovery(check_svc: str) -> Optional[dict]:
    """Load the final_discovery_v1.yaml for the given check-rule service name."""
    gen_svc = SERVICE_ALIASES.get(check_svc, check_svc)
    path = GEN_DIR / gen_svc / 'final_discovery_v1.yaml'
    if not path.exists():
        return None
    data = _load_yaml(path)
    data['_gen_svc'] = gen_svc
    return data


# ──────────────────────────────────────────────────────────────────────────────
# rule_discoveries upsert
# ──────────────────────────────────────────────────────────────────────────────

def upsert_rule_discoveries(conn, check_svc: str, final: dict, dry_run: bool) -> str:
    """
    Upsert a row in rule_discoveries for this GCP service.
    discoveries_data stores the full discovery block from final_discovery_v1.yaml.
    """
    gen_svc  = final['_gen_svc']
    svc_block = final.get('services', {})
    discovery = final.get('discovery', [])

    discoveries_data = {
        'service':   gen_svc,
        'provider':  'gcp',
        'services':  svc_block,
        'discovery': discovery,
    }

    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, discoveries_data FROM rule_discoveries "
            "WHERE provider='gcp' AND service=%s",
            (check_svc,)
        )
        row = cur.fetchone()

        if row:
            rid, existing_data = row
            if isinstance(existing_data, str):
                existing_data = json.loads(existing_data)

            existing_dids = {
                d.get('discovery_id')
                for d in (existing_data or {}).get('discovery', [])
            }
            new_dids = {d.get('discovery_id') for d in discovery}

            if new_dids <= existing_dids:
                return 'unchanged'

            if dry_run:
                return 'would_update'

            # Merge: keep existing, add new
            existing_map = {
                d['discovery_id']: d
                for d in (existing_data or {}).get('discovery', [])
                if d.get('discovery_id')
            }
            for d in discovery:
                did = d.get('discovery_id')
                if did and did not in existing_map:
                    existing_map[did] = d
            merged = dict(existing_data or discoveries_data)
            merged['discovery'] = list(existing_map.values())

            cur.execute(
                "UPDATE rule_discoveries SET discoveries_data=%s, updated_at=now() WHERE id=%s",
                (json.dumps(merged), rid),
            )
            conn.commit()
            return 'updated'
        else:
            if dry_run:
                return 'would_create'
            cur.execute(
                """INSERT INTO rule_discoveries
                   (service, provider, is_active, discoveries_data)
                   VALUES (%s, 'gcp', true, %s)
                   ON CONFLICT DO NOTHING""",
                (check_svc, json.dumps(discoveries_data)),
            )
            conn.commit()
            return 'created'


# ──────────────────────────────────────────────────────────────────────────────
# resource_inventory_identifier upsert
# ──────────────────────────────────────────────────────────────────────────────

def upsert_inventory_identifiers(inv_conn, check_svc: str, final: dict, dry_run: bool) -> Tuple[int, int]:
    """
    Upsert rows in resource_inventory_identifier from the inventory_resource_identifiers block.
    Returns (created, existing) counts.
    """
    gen_svc   = final['_gen_svc']
    rii_rows  = final.get('inventory_resource_identifiers', [])
    discovery = final.get('discovery', [])

    root_ops   = _build_root_ops(discovery)
    enrich_ops = _build_enrich_ops(discovery)

    created  = 0
    existing = 0

    # Group rii rows by op to build one RII row per identifier op
    for row in rii_rows:
        op           = row.get('identifier_op', '')
        resource_type = row.get('resource_type', '').strip()
        arn_entity    = row.get('item_var_path', '').replace('item.', '', 1)  # e.g. item.name → name
        id_template   = row.get('identifier_template', '').strip()

        # Derive resource_type from op if missing or 'unknown'
        if not resource_type or resource_type in ('unknown', ''):
            resource_type = _derive_resource_type(op)

        # identifier_type: 'name' if template uses {name}, else 'id'
        id_type = 'name' if 'name' in arn_entity.lower() or 'name' in id_template.lower() else 'id'

        # root_ops for this specific op
        op_root_ops = [o for o in root_ops if o['operation'] == op]
        if not op_root_ops:
            # op might be dependent — still register it
            op_root_ops = [{
                'operation':       op,
                'kind':            'read_list',
                'independent':     True,
                'python_method':   '',
                'required_params': [],
            }]

        with inv_conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM resource_inventory_identifier WHERE csp='gcp' AND service=%s AND resource_type=%s",
                (gen_svc, resource_type),
            )
            if cur.fetchone():
                existing += 1
                continue

            if dry_run:
                created += 1
                continue

            cur.execute(
                """INSERT INTO resource_inventory_identifier
                   (csp, service, resource_type, classification, has_arn, arn_entity,
                    identifier_type, identifier_pattern,
                    can_inventory_from_roots, should_inventory,
                    root_ops, enrich_ops, raw_catalog)
                   VALUES ('gcp', %s, %s, 'PRIMARY_RESOURCE', false, %s,
                           %s, %s,
                           true, true,
                           %s::jsonb, %s::jsonb, %s::jsonb)
                   ON CONFLICT (csp, service, resource_type) DO NOTHING""",
                (
                    gen_svc,
                    resource_type,
                    arn_entity,
                    id_type,
                    id_template,
                    json.dumps(op_root_ops),
                    json.dumps(enrich_ops),
                    json.dumps({'identifier_op': op, 'identifier_field': row.get('identifier_field', '')}),
                ),
            )
            created += 1

    if not dry_run:
        inv_conn.commit()

    return created, existing


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser()
parser.add_argument('--dry-run', action='store_true', help='Show what would be done without writing')
parser.add_argument('--service', default=None, help='Process only this check-rule service')
args = parser.parse_args()

dry_run = args.dry_run

check_services = sorted(d.name for d in CHECK_DIR.iterdir() if d.is_dir())

# Load services and their final_discovery yamls
service_finals: List[Tuple[str, dict]] = []
skipped: List[str] = []

for svc in check_services:
    if args.service and svc != args.service:
        continue
    final = load_final_discovery(svc)
    if not final:
        skipped.append(svc)
        continue
    service_finals.append((svc, final))

print(f'Services to sync: {len(service_finals)}  |  Skipped (no yaml): {len(skipped)}')
if skipped:
    print(f'  Skipped: {skipped}')
if dry_run:
    print('  *** DRY RUN — no DB changes ***')
print()

if dry_run:
    # Just show what would happen without connecting to DB
    total_rii = 0
    for svc, final in service_finals:
        rii_rows = final.get('inventory_resource_identifiers', [])
        disc_ops = len(final.get('discovery', []))
        print(f'  [{svc:<30}] gen={final["_gen_svc"]:<25} disc_ops={disc_ops:2d}  identifiers={len(rii_rows):2d}')
        total_rii += len(rii_rows)
    print()
    print(f'Would upsert: {len(service_finals)} rule_discoveries rows, {total_rii} resource_inventory_identifier rows')
    sys.exit(0)

# Live run — connect to both DBs
try:
    check_conn = _check_conn()
    print('check DB connected ✓')
except Exception as e:
    print(f'ERROR: cannot connect to check DB: {e}')
    sys.exit(1)

try:
    inv_conn = _inv_conn()
    print('inventory DB connected ✓')
except Exception as e:
    print(f'ERROR: cannot connect to inventory DB: {e}')
    sys.exit(1)

print()

stats = {
    'rd_created': 0, 'rd_updated': 0, 'rd_unchanged': 0,
    'rii_created': 0, 'rii_existing': 0,
}

for svc, final in service_finals:
    gen_svc = final['_gen_svc']

    # 1. rule_discoveries
    rd_result = upsert_rule_discoveries(check_conn, svc, final, dry_run=False)
    stats[f'rd_{rd_result}'] = stats.get(f'rd_{rd_result}', 0) + 1

    # 2. resource_inventory_identifier
    rii_created, rii_existing = upsert_inventory_identifiers(inv_conn, svc, final, dry_run=False)
    stats['rii_created']  += rii_created
    stats['rii_existing'] += rii_existing

    rd_char  = {'created': '+', 'updated': '~', 'unchanged': '='}[rd_result]
    print(
        f'  [{rd_char}] {svc:<30} gen={gen_svc:<25} '
        f'rd={rd_result:<9} rii_new={rii_created:2d} rii_exist={rii_existing:2d}'
    )

check_conn.close()
inv_conn.close()

print()
print('═' * 70)
print(f'rule_discoveries:             {stats["rd_created"]} created, {stats["rd_updated"]} updated, {stats["rd_unchanged"]} unchanged')
print(f'resource_inventory_identifier: {stats["rii_created"]} created, {stats["rii_existing"]} already exist')
