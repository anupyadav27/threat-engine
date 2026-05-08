#!/usr/bin/env python3
"""
generate_aws_master_field_catalog.py
=====================================
Build aws_master_field_catalog.csv from ALL AWS read operations —
no scope filter, covers all 446 services.

Two source paths per service:
  PATH A — service has final_discovery_v1.yaml (166 services)
    Fields come from emit.item in the discovery yaml.
    Chain info (root_op, chain_ops_with_fields) fully resolved.

  PATH B — service has step2 + step4 only (280 services)
    Fields come from step4_fields_produced_index.json.
    Op metadata (kind, python_method) from step2_read_operation_registry.json.
    Chain info set to best-effort (independent ops get full chain; dependent
    ops get chain_ops = root -> op but no field-level detail).

Output columns (matches GCP/Azure gcp_master_field_catalog.csv):
  csp, service, field_path, item_var_path, field_type, is_id, producing_op,
  op_kind, is_independent, root_op, chain_ops, chain_length, hop_distance,
  chain_ops_with_fields, operators, operators_no_value, python_call, http_path

Usage:
    python generate_aws_master_field_catalog.py           # dry-run
    python generate_aws_master_field_catalog.py --apply   # write CSV
"""

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml

# ──────────────────────────────────────────────────────────────────────────────
ROOT       = Path('/Users/apple/Desktop/threat-engine')
CHECK_DIR  = ROOT / 'catalog/rule/aws_rule_check'
GEN_DIR    = ROOT / 'catalog/discovery_generator/aws'
OUTPUT_CSV = GEN_DIR / 'aws_master_field_catalog.csv'

SERVICE_ALIASES: Dict[str, str] = {'acm_pca': 'acm-pca'}

APPLY = '--apply' in sys.argv

COLUMNS = [
    'csp', 'service', 'field_path', 'item_var_path', 'field_type', 'is_id',
    'producing_op', 'op_kind', 'is_independent', 'root_op', 'chain_ops',
    'chain_length', 'hop_distance', 'chain_ops_with_fields',
    'operators', 'operators_no_value', 'python_call', 'http_path',
]

BLANK_ROW = {c: '' for c in COLUMNS}


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _load_yaml(p: Path) -> dict:
    try:
        return yaml.safe_load(p.read_text()) or {}
    except Exception:
        return {}


def _load_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def load_step2_ops(svc: str) -> Dict[str, dict]:
    """Returns {yaml_action → op_metadata} from step2 registry."""
    p = GEN_DIR / svc / 'step2_read_operation_registry.json'
    if not p.exists():
        return {}
    data = _load_json(p)
    result: Dict[str, dict] = {}
    for op_name, op_data in data.get('operations', {}).items():
        if not isinstance(op_data, dict):
            continue
        method = op_data.get('yaml_action', op_data.get('python_method', ''))
        if method:
            result[method] = op_data
    return result


def load_step4_fields(svc: str) -> Dict[str, dict]:
    """Returns {field_name → field_metadata} from step4 index."""
    p = GEN_DIR / svc / 'step4_fields_produced_index.json'
    if not p.exists():
        return {}
    data = _load_json(p)
    fields = data.get('fields', {})
    return {k: v for k, v in fields.items() if isinstance(v, dict)}


def load_step4a_operators_no_value(svc: str) -> Dict[str, str]:
    """Returns {field_name → operators_no_value} from step4a CSV."""
    p = GEN_DIR / svc / 'step4a_field_operator_value_table.csv'
    if not p.exists():
        return {}
    result: Dict[str, str] = {}
    try:
        with p.open() as f:
            for row in csv.DictReader(f):
                field = row.get('field_name', '').strip()
                onv   = row.get('operators_no_value', '').strip()
                if field:
                    result[field] = onv
    except Exception:
        pass
    return result


# ──────────────────────────────────────────────────────────────────────────────
# PATH A — collect from final_discovery_v1.yaml  (no scope filter)
# ──────────────────────────────────────────────────────────────────────────────

def _op_fields_tag(disc_entry: dict) -> str:
    did  = disc_entry.get('discovery_id', '')
    item = disc_entry.get('emit', {}).get('item', {})
    fields = sorted(item.keys()) if item else []
    return f"{did}[{'|'.join(fields)}]" if fields else did


def build_chain_info(disc_entry: dict,
                     disc_by_id: Dict[str, dict]) -> Tuple[str, str, int, int]:
    did      = disc_entry.get('discovery_id', '')
    for_each = disc_entry.get('for_each', '')
    if not for_each:
        return did, did, 1, 0
    root_entry = disc_by_id.get(for_each, {})
    if root_entry.get('for_each'):
        root_op = root_entry['for_each']
        return root_op, f'{root_op} -> {for_each} -> {did}', 3, 2
    return for_each, f'{for_each} -> {did}', 2, 1


def build_chain_ops_with_fields(disc_entry: dict,
                                 disc_by_id: Dict[str, dict]) -> str:
    did      = disc_entry.get('discovery_id', '')
    for_each = disc_entry.get('for_each', '')
    if not for_each:
        return _op_fields_tag(disc_entry)
    root_entry = disc_by_id.get(for_each, {})
    if root_entry.get('for_each'):
        root_root = root_entry['for_each']
        return (f"{_op_fields_tag(disc_by_id.get(root_root, {'discovery_id': root_root}))} -> "
                f"{_op_fields_tag(root_entry)} -> "
                f"{_op_fields_tag(disc_entry)}")
    return f"{_op_fields_tag(root_entry)} -> {_op_fields_tag(disc_entry)}"


def collect_from_yaml(svc: str) -> List[dict]:
    """
    PATH A: build rows from final_discovery_v1.yaml.
    Covers ALL ops in the yaml (no scope filter).
    """
    yaml_path = GEN_DIR / svc / 'final_discovery_v1.yaml'
    if not yaml_path.exists():
        return []

    final = _load_yaml(yaml_path)
    if not final:
        return []

    discovery = final.get('discovery', [])
    disc_by_id: Dict[str, dict] = {
        d['discovery_id']: d for d in discovery if d.get('discovery_id')
    }

    step4_fields = load_step4_fields(svc)
    step2_ops    = load_step2_ops(svc)
    ops_no_value = load_step4a_operators_no_value(svc)

    rii_rows  = final.get('inventory_resource_identifiers', []) or []
    id_fields: Set[str] = {
        rii.get('identifier_field', '').strip()
        for rii in rii_rows if rii.get('identifier_field', '').strip()
    }

    rows: List[dict] = []

    for disc in discovery:
        did      = disc.get('discovery_id', '')
        for_each = disc.get('for_each', '')
        calls    = disc.get('calls', [])
        emit     = disc.get('emit', {})
        item     = emit.get('item', {})

        if not did:
            continue

        action         = calls[0].get('action', '') if calls else ''
        op_meta        = step2_ops.get(action, {})
        op_kind        = op_meta.get('kind', 'read_get' if for_each else 'read_list')
        is_independent = not bool(for_each)
        python_call    = f"client.{action}()" if action else ''

        root_op, chain_ops, chain_length, hop_distance = build_chain_info(disc, disc_by_id)
        chain_with_fields = build_chain_ops_with_fields(disc, disc_by_id)

        if not item:
            rows.append({
                **BLANK_ROW,
                'csp': 'aws', 'service': svc,
                'producing_op': did, 'op_kind': op_kind,
                'is_independent': 'Yes' if is_independent else 'No',
                'root_op': root_op, 'chain_ops': chain_ops,
                'chain_length': chain_length, 'hop_distance': hop_distance,
                'chain_ops_with_fields': chain_with_fields,
                'python_call': python_call,
            })
            continue

        for field_name in sorted(item.keys()):
            f4 = step4_fields.get(field_name, {})
            rows.append({
                'csp':                   'aws',
                'service':               svc,
                'field_path':            field_name,
                'item_var_path':         f'item.{field_name}',
                'field_type':            f4.get('type', 'string'),
                'is_id':                 'Yes' if field_name in id_fields else 'No',
                'producing_op':          did,
                'op_kind':               op_kind,
                'is_independent':        'Yes' if is_independent else 'No',
                'root_op':               root_op,
                'chain_ops':             chain_ops,
                'chain_length':          chain_length,
                'hop_distance':          hop_distance,
                'chain_ops_with_fields': chain_with_fields,
                'operators':             ', '.join(f4.get('operators', [])) if f4.get('operators') else '',
                'operators_no_value':    ops_no_value.get(field_name, ''),
                'python_call':           python_call,
                'http_path':             '',
            })

    return rows


# ──────────────────────────────────────────────────────────────────────────────
# PATH B — collect from step2 + step4  (services without final_discovery yaml)
# ──────────────────────────────────────────────────────────────────────────────

def collect_from_step4(svc: str) -> List[dict]:
    """
    PATH B: build rows from step2_read_operation_registry.json +
    step4_fields_produced_index.json.
    Used for the 280 services that have no final_discovery_v1.yaml.
    """
    step2_ops    = load_step2_ops(svc)
    step4_fields = load_step4_fields(svc)
    ops_no_value = load_step4a_operators_no_value(svc)

    if not step2_ops:
        return []

    # Group step4 fields by their producing op (discovery_id)
    fields_by_op: Dict[str, List[Tuple[str, dict]]] = defaultdict(list)
    for field_name, fdata in step4_fields.items():
        did = fdata.get('discovery_id', '').strip()
        if did:
            fields_by_op[did].append((field_name, fdata))

    # Build a discovery_id → step2 action map
    # step2 uses yaml_action; discovery_id is aws.{svc}.{yaml_action}
    did_to_step2: Dict[str, dict] = {}
    for action, op_data in step2_ops.items():
        did = f'aws.{svc}.{action}'
        did_to_step2[did] = op_data

    # Collect all discovery_ids: union of step2 and step4
    all_dids: Set[str] = set(did_to_step2.keys()) | set(fields_by_op.keys())

    rows: List[dict] = []

    for did in sorted(all_dids):
        op_data    = did_to_step2.get(did, {})
        action     = did.split('.')[-1] if '.' in did else ''
        op_kind    = op_data.get('kind', 'read_list')
        is_indep   = op_data.get('independent', True)
        python_call = f"client.{op_data.get('python_method', action)}()" if (op_data or action) else ''

        # Chain info: step4-only services don't have dependency chain resolved.
        # Independent ops: trivial chain. Dependent: best-effort (no parent field detail).
        if is_indep:
            root_op          = did
            chain_ops        = did
            chain_length     = 1
            hop_distance     = 0
            chain_with_fields = did
        else:
            # We don't know the exact parent from step4-only data
            root_op          = did
            chain_ops        = did
            chain_length     = 2
            hop_distance     = 1
            chain_with_fields = did

        field_list = sorted(fields_by_op.get(did, []), key=lambda x: x[0])

        if not field_list:
            rows.append({
                **BLANK_ROW,
                'csp': 'aws', 'service': svc,
                'producing_op': did, 'op_kind': op_kind,
                'is_independent': 'Yes' if is_indep else 'No',
                'root_op': root_op, 'chain_ops': chain_ops,
                'chain_length': chain_length, 'hop_distance': hop_distance,
                'chain_ops_with_fields': chain_with_fields,
                'python_call': python_call,
            })
            continue

        for field_name, fdata in field_list:
            rows.append({
                'csp':                   'aws',
                'service':               svc,
                'field_path':            field_name,
                'item_var_path':         f'item.{field_name}',
                'field_type':            fdata.get('type', 'string') or 'string',
                'is_id':                 'No',
                'producing_op':          did,
                'op_kind':               op_kind,
                'is_independent':        'Yes' if is_indep else 'No',
                'root_op':               root_op,
                'chain_ops':             chain_ops,
                'chain_length':          chain_length,
                'hop_distance':          hop_distance,
                'chain_ops_with_fields': chain_with_fields,
                'operators':             ', '.join(fdata.get('operators', [])) if fdata.get('operators') else '',
                'operators_no_value':    ops_no_value.get(field_name, ''),
                'python_call':           python_call,
                'http_path':             '',
            })

    return rows


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

if not APPLY:
    print('*** DRY RUN — pass --apply to write CSV ***')
print()

# Discover all service directories that have any catalog data
all_svc_dirs = [
    d for d in sorted(GEN_DIR.iterdir())
    if d.is_dir()
    and (
        (d / 'final_discovery_v1.yaml').exists()
        or (d / 'step2_read_operation_registry.json').exists()
    )
]

yaml_svcs  = {d.name for d in all_svc_dirs if (d / 'final_discovery_v1.yaml').exists()}
step4_only = {d.name for d in all_svc_dirs if d.name not in yaml_svcs}

print(f'Services with final_discovery_v1.yaml : {len(yaml_svcs)}  (PATH A)')
print(f'Services with step2+step4 only        : {len(step4_only)}  (PATH B)')
print()

all_rows: List[dict] = []

for svc_dir in sorted(GEN_DIR.iterdir()):
    if not svc_dir.is_dir():
        continue
    svc = svc_dir.name

    if svc in yaml_svcs:
        rows = collect_from_yaml(svc)
    elif svc in step4_only:
        rows = collect_from_step4(svc)
    else:
        continue

    if rows:
        all_rows.extend(rows)

# Stats
total_ops = len(set(r['producing_op'] for r in all_rows))
print(f'Total field rows : {len(all_rows):,}')
print(f'Total unique ops : {total_ops:,}')

indep = len(set(r['producing_op'] for r in all_rows if r['is_independent'] == 'Yes'))
dep   = total_ops - indep
print(f'  independent    : {indep}')
print(f'  dependent      : {dep}')
print()

if not all_rows:
    print('ERROR: no rows — check paths')
    sys.exit(1)

if APPLY:
    with OUTPUT_CSV.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(all_rows)
    print(f'Wrote {len(all_rows):,} rows → {OUTPUT_CSV}')
else:
    print(f'Would write {len(all_rows):,} rows → {OUTPUT_CSV}')
