#!/usr/bin/env python3
"""
sync_aws_to_db.py
=================
Sync all AWS services that have final_discovery_v1.yaml into:
  1. rule_discoveries  (check DB)       — discoveries_data as flat JSONB array
  2. resource_inventory_identifier (inventory DB) — from inventory_resource_identifiers block

Covers 157 check-rule services mapped to their gen service directories.

AWS DB format for discoveries_data: flat JSONB array of discovery entries
  [{discovery_id, calls, emit, [for_each]}, ...]
(different from GCP which uses {service, provider, services, discovery} dict)

Usage (local):
    CHECK_DB_HOST=localhost CHECK_DB_PORT=5432 CHECK_DB_NAME=threat_engine_check \\
    CHECK_DB_USER=apple CHECK_DB_PASSWORD="" \\
    INV_DB_HOST=localhost INV_DB_PORT=5432 INV_DB_NAME=threat_engine_inventory \\
    INV_DB_USER=apple INV_DB_PASSWORD="" \\
    python sync_aws_to_db.py [--dry-run] [--service SERVICE]
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import psycopg2
import yaml

# ──────────────────────────────────────────────────────────────────────────────
ROOT      = Path('/Users/apple/Desktop/threat-engine')
CHECK_DIR = ROOT / 'catalog/rule/aws_rule_check'
GEN_DIR   = ROOT / 'catalog/discovery_generator/aws'
# ──────────────────────────────────────────────────────────────────────────────

SERVICE_ALIASES: Dict[str, str] = {'acm_pca': 'acm-pca'}


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


def load_final_discovery(check_svc: str) -> Optional[dict]:
    gen_svc = SERVICE_ALIASES.get(check_svc, check_svc)
    path = GEN_DIR / gen_svc / 'final_discovery_v1.yaml'
    if not path.exists():
        return None
    data = _load_yaml(path)
    if not data:
        return None
    data['_gen_svc'] = gen_svc
    return data


def _disc_to_array_entry(disc: dict) -> dict:
    """Convert a discovery block to the flat array entry format used in AWS DB."""
    entry: dict = {'discovery_id': disc.get('discovery_id', '')}
    if disc.get('for_each'):
        entry['for_each'] = disc['for_each']
    entry['calls'] = disc.get('calls', [])
    entry['emit']  = disc.get('emit', {})
    return entry


def _derive_resource_type(op: str) -> str:
    """Derive resource_type from op id. aws.s3.list_buckets → bucket (singularized)"""
    parts = op.split('.')
    if len(parts) >= 3:
        # Last segment is the action: list_buckets → buckets → bucket
        action = parts[-1]
        # Extract noun: list_buckets → buckets, describe_instances → instances
        for prefix in ('list_', 'describe_', 'get_', 'batch_get_'):
            if action.startswith(prefix):
                noun = action[len(prefix):]
                # Singularize: buckets → bucket, instances → instance
                if noun.endswith('ies'):
                    return noun[:-3] + 'y'
                if noun.endswith('s') and not noun.endswith('ss'):
                    return noun[:-1]
                return noun
        return action
    return parts[-1]


def _build_root_ops(discovery: list) -> list:
    ops = []
    for entry in discovery:
        if entry.get('for_each'):
            continue
        calls = entry.get('calls', [])
        call  = calls[0] if calls else {}
        ops.append({
            'operation':       entry.get('discovery_id', ''),
            'kind':            'read_list',
            'independent':     True,
            'python_method':   call.get('action', ''),
            'required_params': [],
        })
    return ops


def _build_enrich_ops(discovery: list) -> list:
    ops = []
    for entry in discovery:
        if not entry.get('for_each'):
            continue
        calls = entry.get('calls', [])
        call  = calls[0] if calls else {}
        params = call.get('params', {})
        required = list(params.keys()) if params else []
        ops.append({
            'operation':       entry.get('discovery_id', ''),
            'kind':            'read_get',
            'independent':     False,
            'python_method':   call.get('action', ''),
            'required_params': required,
        })
    return ops


# ──────────────────────────────────────────────────────────────────────────────
# rule_discoveries upsert
# ──────────────────────────────────────────────────────────────────────────────

def upsert_rule_discoveries(conn, check_svc: str, final: dict, dry_run: bool) -> str:
    """
    Upsert a row in rule_discoveries for this AWS service.
    discoveries_data: flat JSONB array of discovery entries (AWS format).
    """
    discovery = final.get('discovery', [])
    disc_array = [_disc_to_array_entry(d) for d in discovery]

    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, discoveries_data FROM rule_discoveries "
            "WHERE provider='aws' AND service=%s",
            (check_svc,)
        )
        row = cur.fetchone()

        if row:
            rid, existing_data = row
            if isinstance(existing_data, str):
                existing_data = json.loads(existing_data)

            # existing_data could be list or dict (legacy)
            if isinstance(existing_data, list):
                existing_dids = {d.get('discovery_id') for d in existing_data}
            elif isinstance(existing_data, dict):
                existing_dids = {d.get('discovery_id') for d in existing_data.get('discovery', [])}
            else:
                existing_dids = set()

            new_dids = {d.get('discovery_id') for d in disc_array}

            if new_dids <= existing_dids:
                return 'unchanged'

            if dry_run:
                return 'would_update'

            # Merge: keep existing, add new entries
            if isinstance(existing_data, list):
                existing_map = {d['discovery_id']: d for d in existing_data if d.get('discovery_id')}
            else:
                existing_map = {}
            for d in disc_array:
                did = d.get('discovery_id')
                if did and did not in existing_map:
                    existing_map[did] = d
            merged = list(existing_map.values())

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
                   VALUES (%s, 'aws', true, %s)
                   ON CONFLICT DO NOTHING""",
                (check_svc, json.dumps(disc_array)),
            )
            conn.commit()
            return 'created'


# ──────────────────────────────────────────────────────────────────────────────
# resource_inventory_identifier upsert
# ──────────────────────────────────────────────────────────────────────────────

def upsert_inventory_identifiers(inv_conn, check_svc: str, final: dict, dry_run: bool) -> Tuple[int, int]:
    gen_svc   = final['_gen_svc']
    rii_rows  = final.get('inventory_resource_identifiers') or []
    discovery = final.get('discovery', [])

    root_ops   = _build_root_ops(discovery)
    enrich_ops = _build_enrich_ops(discovery)

    created  = 0
    existing = 0

    for row in rii_rows:
        op            = row.get('identifier_op', '')
        resource_type = row.get('resource_type', '').strip()
        arn_entity    = row.get('item_var_path', '').replace('item.', '', 1)
        id_template   = row.get('identifier_template', '').strip()

        if not resource_type or resource_type in ('unknown', ''):
            resource_type = _derive_resource_type(op)

        id_type = 'name' if 'name' in arn_entity.lower() or 'name' in id_template.lower() else 'id'

        op_root_ops = [o for o in root_ops if o['operation'] == op]
        if not op_root_ops:
            op_root_ops = [{
                'operation':       op,
                'kind':            'read_list',
                'independent':     True,
                'python_method':   '',
                'required_params': [],
            }]

        with inv_conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM resource_inventory_identifier WHERE csp='aws' AND service=%s AND resource_type=%s",
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
                   VALUES ('aws', %s, %s, 'PRIMARY_RESOURCE', false, %s,
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
parser.add_argument('--dry-run', action='store_true')
parser.add_argument('--service', default=None, help='Process only this check-rule service')
args = parser.parse_args()

dry_run = args.dry_run

check_services = sorted(d.name for d in CHECK_DIR.iterdir() if d.is_dir())

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
    total_rii = 0
    for svc, final in service_finals:
        rii_rows = final.get('inventory_resource_identifiers') or []
        disc_ops = len(final.get('discovery', []))
        print(f'  [{svc:<30}] gen={final["_gen_svc"]:<25} disc_ops={disc_ops:3d}  identifiers={len(rii_rows):2d}')
        total_rii += len(rii_rows)
    print()
    print(f'Would upsert: {len(service_finals)} rule_discoveries rows, {total_rii} resource_inventory_identifier rows')
    sys.exit(0)

# Live run
try:
    check_conn = _check_conn()
    print('check DB connected ✓')
except Exception as e:
    print(f'ERROR: cannot connect to check DB: {e}')
    sys.exit(1)

try:
    inventory_conn = _inv_conn()
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

    rd_result = upsert_rule_discoveries(check_conn, svc, final, dry_run=False)
    stats[f'rd_{rd_result}'] = stats.get(f'rd_{rd_result}', 0) + 1

    rii_created, rii_existing = upsert_inventory_identifiers(inventory_conn, svc, final, dry_run=False)
    stats['rii_created']  += rii_created
    stats['rii_existing'] += rii_existing

    rd_char = {'created': '+', 'updated': '~', 'unchanged': '='}[rd_result]
    print(
        f'  [{rd_char}] {svc:<30} gen={gen_svc:<25} '
        f'rd={rd_result:<9} rii_new={rii_created:2d} rii_exist={rii_existing:2d}'
    )

check_conn.close()
inventory_conn.close()

print()
print('═' * 70)
print(f'rule_discoveries:             {stats["rd_created"]} created, {stats["rd_updated"]} updated, {stats["rd_unchanged"]} unchanged')
print(f'resource_inventory_identifier: {stats["rii_created"]} created, {stats["rii_existing"]} already exist')
