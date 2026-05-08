#!/usr/bin/env python3
"""
generate_oci_alicloud_rule_discoveries.py
=========================================
Generate {svc}.discovery.yaml for every OCI/AliCloud service that has check rules.

OCI:
  Reads:   catalog/rule/oci_rule_check/{svc}/{svc}.checks.yaml
  Master:  catalog/discovery_generator/oci/oci_master_field_catalog.csv
  Output:  catalog/rule/oci_rule_check/{svc}/{svc}.discovery.yaml

AliCloud:
  Reads:   catalog/rule/alicloud_rule_check/{svc}/{svc}.checks.yaml
  Master:  catalog/discovery_generator/alicloud/alicloud_master_read_ops.csv
  Output:  catalog/rule/alicloud_rule_check/{svc}/{svc}.discovery.yaml

Usage:
    python generate_oci_alicloud_rule_discoveries.py              # dry-run both
    python generate_oci_alicloud_rule_discoveries.py --apply      # write all
    python generate_oci_alicloud_rule_discoveries.py --csp oci    # dry-run OCI only
    python generate_oci_alicloud_rule_discoveries.py --csp alicloud --apply
"""

import csv
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

import yaml

ROOT = Path('/Users/apple/Desktop/threat-engine')

APPLY  = '--apply' in sys.argv
TARGET_CSP = None
if '--csp' in sys.argv:
    idx = sys.argv.index('--csp')
    if idx + 1 < len(sys.argv):
        TARGET_CSP = sys.argv[idx + 1].lower()

if not APPLY:
    print('*** DRY RUN — pass --apply to write files ***')
print()

csv.field_size_limit(10_000_000)


# ──────────────────────────────────────────────────────────────────────────────
# CSP config
# ──────────────────────────────────────────────────────────────────────────────

CSP_CONFIG = {
    'oci': {
        'gen_dir':    ROOT / 'catalog/discovery_generator/oci',
        'master_csv': ROOT / 'catalog/discovery_generator/oci/oci_master_field_catalog.csv',
        'rules_dir':  ROOT / 'catalog/rule/oci_rule_check',
        'step6_glob': 'step6*.yaml',
        'default_items_for': '{{ response.data }}',
        'get_items_for': '{{ response.data }}',
    },
    'alicloud': {
        'gen_dir':    ROOT / 'catalog/discovery_generator/alicloud',
        'master_csv': ROOT / 'catalog/discovery_generator/alicloud/alicloud_master_read_ops.csv',
        'rules_dir':  ROOT / 'catalog/rule/alicloud_rule_check',
        'step6_glob': 'step6*.yaml',
        'default_items_for': '{{ response.items }}',
        'get_items_for': '{{ response }}',
    },
}


def load_ops_table(csv_path: Path) -> Dict[str, dict]:
    """Load master CSV keyed by producing_op."""
    ops: Dict[str, dict] = {}
    for row in csv.DictReader(csv_path.open()):
        op = row.get('producing_op', '').strip()
        if op and op not in ops:
            ops[op] = row
    return ops


def preload_step6_hints(gen_dir: Path, step6_glob: str):
    """Pre-load items_for, action, params, for_each from existing step6 yamls."""
    op_items_for: Dict[str, str] = {}
    op_action:    Dict[str, str] = {}
    op_params:    Dict[str, dict] = {}
    op_for_each:  Dict[str, str] = {}

    for f in sorted(gen_dir.rglob(step6_glob)):
        if '.backup' in f.name:
            continue
        try:
            d = yaml.safe_load(f.read_text()) or {}
        except Exception:
            continue
        if not isinstance(d, dict):
            continue
        for disc in d.get('discovery', []) or []:
            did      = disc.get('discovery_id', '')
            emit     = disc.get('emit', {}) or {}
            calls    = disc.get('calls', [{}]) or [{}]
            for_each = disc.get('for_each', '')
            if not did:
                continue
            items_for = emit.get('items_for', '')
            action    = calls[0].get('action', '') if calls else ''
            params    = {k: v for k, v in (calls[0].get('params', {}) or {}).items()
                         if '{{' in str(v)}
            if items_for and did not in op_items_for:
                op_items_for[did] = items_for
            if action and did not in op_action:
                op_action[did] = action
            if params and did not in op_params:
                op_params[did] = params
            if for_each and for_each != did and did not in op_for_each:
                op_for_each[did] = for_each

    return op_items_for, op_action, op_params, op_for_each


# ──────────────────────────────────────────────────────────────────────────────
# OCI helpers
# ──────────────────────────────────────────────────────────────────────────────

def oci_action(op: str, row: dict, op_action: Dict[str, str]) -> str:
    """Last segment of op id is already the SDK method name."""
    if op in op_action:
        return op_action[op]
    return op.split('.')[-1]


def oci_items_for(op: str, row: dict, op_items_for: Dict[str, str],
                  default_items_for: str, get_items_for: str) -> str:
    if op in op_items_for:
        return op_items_for[op]
    op_kind = row.get('op_kind', '')
    if op_kind in ('read_get', 'get'):
        return get_items_for
    return default_items_for


def oci_emit_item(row: dict) -> dict:
    """OCI: standard fields always emitted."""
    return {
        'ocid':           '{{ item.ocid }}',
        'compartment_id': '{{ item.compartment_id }}',
        'name':           '{{ item.name }}',
        'status':         '{{ item.status }}',
        'time_created':   '{{ item.time_created }}',
        'freeform_tags':  '{{ item.freeform_tags }}',
        'defined_tags':   '{{ item.defined_tags }}',
    }


def oci_params(op: str, row: dict,
               ops_table: Dict[str, dict],
               op_params: Dict[str, dict]) -> Optional[dict]:
    if op in op_params:
        return op_params[op]
    root_op  = row.get('root_op', '').strip()
    id_param = row.get('resource_id_param', '').strip()
    if not id_param and root_op and root_op in ops_table:
        root_row = ops_table[root_op]
        id_param = root_row.get('resource_id_param', '').strip()
        if not id_param:
            id_param = root_row.get('resource_id_field', '').strip()
    if id_param:
        return {id_param: '{{ item.ocid }}'}
    # Default for dependent OCI ops
    return {'id': '{{ item.ocid }}'}


# ──────────────────────────────────────────────────────────────────────────────
# AliCloud helpers
# ──────────────────────────────────────────────────────────────────────────────

def alicloud_action(op: str, row: dict, op_action: Dict[str, str]) -> str:
    """Derive action from python_call or op last segment."""
    if op in op_action:
        return op_action[op]
    python_call = row.get('python_call', '')
    if python_call:
        m = re.search(r'\.Client\(\)\.(\w+)\(', python_call)
        if m:
            return m.group(1)
    return op.split('.')[-1]


def alicloud_items_for(op: str, row: dict, op_items_for: Dict[str, str],
                       default_items_for: str) -> str:
    if op in op_items_for:
        return op_items_for[op]
    # Check hint stored in check_rule_yaml field
    hint = row.get('check_rule_yaml', '')
    if hint.startswith('items_for='):
        return hint[len('items_for='):]
    op_kind = row.get('op_kind', '')
    if op_kind in ('read_get', 'get'):
        return '{{ response }}'
    return default_items_for


def alicloud_emit_item(produced_fields: str) -> dict:
    """Build emit.item from pipe-separated produced_fields."""
    fields = [f.strip() for f in produced_fields.split('|') if f.strip()]
    if not fields:
        return {}
    item: dict = {}
    seen: set = set()
    for field in fields:
        clean = re.sub(r'^\w+\[\]\.', '', field)
        top = clean.split('.')[0] if '.' in clean else clean
        if top and top not in seen:
            seen.add(top)
            item[top] = f'{{{{ item.{top} }}}}'
    return item


def alicloud_params(op: str, row: dict,
                    ops_table: Dict[str, dict],
                    op_params: Dict[str, dict]) -> Optional[dict]:
    if op in op_params:
        return op_params[op]
    id_param = row.get('resource_id_param', '').strip()
    root_op  = row.get('root_op', '').strip()
    if not id_param and root_op and root_op in ops_table:
        root_row = ops_table[root_op]
        id_param = root_row.get('resource_id_param', '').strip()
        if not id_param:
            id_param = root_row.get('resource_id_field', '').strip()
    id_field = ''
    if root_op and root_op in ops_table:
        id_field = ops_table[root_op].get('resource_id_field', '').strip()
    if id_param and id_field:
        return {id_param: f'{{{{ item.{id_field} }}}}'}
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Unified discovery builder
# ──────────────────────────────────────────────────────────────────────────────

def build_entry(csp: str, op: str, row: dict,
                ops_table: Dict[str, dict],
                op_items_for: Dict[str, str],
                op_action: Dict[str, str],
                op_params: Dict[str, dict],
                op_for_each: Dict[str, str],
                cfg: dict) -> dict:
    is_indep = row.get('is_independent', 'Yes').strip() != 'No'

    if csp == 'oci':
        action    = oci_action(op, row, op_action)
        items_for = oci_items_for(op, row, op_items_for,
                                  cfg['default_items_for'], cfg['get_items_for'])
        emit_item = oci_emit_item(row)
        params    = None if is_indep else oci_params(op, row, ops_table, op_params)
    else:
        action    = alicloud_action(op, row, op_action)
        items_for = alicloud_items_for(op, row, op_items_for, cfg['default_items_for'])
        emit_item = alicloud_emit_item(row.get('produced_fields', ''))
        params    = None if is_indep else alicloud_params(op, row, ops_table, op_params)

    call: dict = {'action': action, 'save_as': 'response', 'on_error': 'continue'}
    if not is_indep and params:
        call['params'] = params

    emit: dict = {'as': 'item', 'items_for': items_for}
    if emit_item:
        emit['item'] = emit_item

    entry: dict = {'discovery_id': op, 'calls': [call], 'emit': emit}
    if not is_indep:
        for_each_val = op_for_each.get(op) or row.get('root_op', '')
        entry['for_each'] = for_each_val

    return entry


def get_check_ops(rules_dir: Path, svc: str) -> Set[str]:
    p = rules_dir / svc / f'{svc}.checks.yaml'
    if not p.exists():
        return set()
    try:
        d = yaml.safe_load(p.read_text()) or {}
    except Exception:
        return set()
    return {c['for_each'] for c in d.get('checks', []) if c.get('for_each')}


def resolve_op_set(check_ops: Set[str], ops_table: Dict[str, dict]) -> List[str]:
    needed: Set[str] = set(check_ops)
    for op in list(check_ops):
        row = ops_table.get(op)
        if row and row.get('is_independent', '').strip() == 'No':
            root = row.get('root_op', '').strip()
            if root and root in ops_table and root != op:
                needed.add(root)
    independent = sorted(op for op in needed
                         if ops_table.get(op, {}).get('is_independent', '').strip() != 'No')
    dependent   = sorted(op for op in needed
                         if ops_table.get(op, {}).get('is_independent', '').strip() == 'No')
    return independent + dependent


def generate_for_service(csp: str, svc: str,
                         ops_table: Dict[str, dict],
                         op_items_for, op_action, op_params, op_for_each,
                         cfg: dict):
    check_ops = get_check_ops(cfg['rules_dir'], svc)
    if not check_ops:
        return None

    missing = check_ops - set(ops_table.keys())
    valid   = check_ops - missing
    if missing:
        print(f'  [{svc}] WARNING: {len(missing)} ops not in master: {sorted(missing)}')

    op_list = resolve_op_set(valid, ops_table)
    if not op_list:
        return None

    entries = [build_entry(csp, op, ops_table[op], ops_table,
                           op_items_for, op_action, op_params, op_for_each, cfg)
               for op in op_list]

    from_checks = len(valid)
    extra_roots = len(op_list) - from_checks

    return {
        '__meta__': {
            'comment': (
                f'Auto-generated: step6 discovery for {svc} check rules\n'
                f'{from_checks} ops from checks'
                + (f', +{extra_roots} root ops added' if extra_roots else '')
                + (f', {len(missing)} ops skipped (not in master)' if missing else '')
            )
        },
        'version':   '1.0',
        'provider':  csp,
        'service':   svc,
        'discovery': entries,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

csps = ['oci', 'alicloud'] if TARGET_CSP is None else [TARGET_CSP]

for csp in csps:
    cfg = CSP_CONFIG[csp]
    print(f'══ {csp.upper()} ══')

    print(f'  Loading master CSV ...')
    ops_table = load_ops_table(cfg['master_csv'])
    print(f'  {len(ops_table):,} ops loaded')

    print(f'  Loading step6 hints ...')
    op_items_for, op_action, op_params, op_for_each = preload_step6_hints(
        cfg['gen_dir'], cfg['step6_glob']
    )
    print(f'  {len(op_items_for)} items_for | {len(op_action)} actions | '
          f'{len(op_params)} params | {len(op_for_each)} for_each')

    rules_dir = cfg['rules_dir']
    check_svcs = sorted(
        d.name for d in rules_dir.iterdir()
        if d.is_dir() and (d / f'{d.name}.checks.yaml').exists()
    )
    print(f'  Services: {len(check_svcs)}')
    print()

    written = skipped = 0

    for svc in check_svcs:
        svc_out_dir = rules_dir / svc
        svc_out_dir.mkdir(parents=True, exist_ok=True)
        out_path = svc_out_dir / f'{svc}.discovery.yaml'

        doc = generate_for_service(csp, svc, ops_table,
                                   op_items_for, op_action, op_params, op_for_each,
                                   cfg)
        if not doc:
            print(f'  [{svc}] SKIP — no valid ops')
            skipped += 1
            continue

        entries  = doc['discovery']
        n_ops    = len(entries)
        n_indep  = sum(1 for e in entries if 'for_each' not in e)
        n_dep    = n_ops - n_indep
        n_fields = sum(len(e.get('emit', {}).get('item', {})) for e in entries)

        print(f'  [{svc:<40}] {n_ops} ops ({n_indep}i+{n_dep}d) | {n_fields} fields')

        if APPLY:
            comment = doc.pop('__meta__', {}).get('comment', '')
            with out_path.open('w') as f:
                if comment:
                    for line in comment.splitlines():
                        f.write(f'# {line}\n')
                yaml.dump(doc, f,
                          default_flow_style=False,
                          allow_unicode=True,
                          indent=2,
                          sort_keys=False)
            written += 1

    print()
    print('─' * 60)
    if APPLY:
        print(f'  {csp}: Written {written} | Skipped {skipped}')
    else:
        print(f'  {csp}: Would write {len(check_svcs) - skipped} | Would skip {skipped}')
    print()
