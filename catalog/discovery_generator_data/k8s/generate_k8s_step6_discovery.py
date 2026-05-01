#!/usr/bin/env python3
"""
generate_k8s_step6_discovery.py
================================
Generate {svc}.discovery.yaml for every K8s service that has check rules.

Source:  catalog/test-rulecheck_python_code/generated/k8s/{svc}/*.yaml
Output:  catalog/rule/k8s_rule_check/{svc}/{svc}.discovery.yaml

Usage:
    python generate_k8s_step6_discovery.py             # dry-run
    python generate_k8s_step6_discovery.py --apply     # write all
    python generate_k8s_step6_discovery.py --svc pod --apply
"""

import csv
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

import yaml

# ──────────────────────────────────────────────────────────────────────────────
ROOT      = Path('/Users/apple/Desktop/threat-engine')
GEN_DIR   = ROOT / 'catalog/discovery_generator/k8s'
TEST_DIR  = ROOT / 'catalog/test-rulecheck_python_code/generated/k8s'
CHECK_DIR = ROOT / 'catalog/rule/k8s_rule_check'
OPS_CSV   = GEN_DIR / 'k8s_master_read_ops.csv'

APPLY  = '--apply' in sys.argv
TARGET = None
if '--svc' in sys.argv:
    idx = sys.argv.index('--svc')
    if idx + 1 < len(sys.argv):
        TARGET = sys.argv[idx + 1].lower()

if not APPLY:
    print('*** DRY RUN — pass --apply to write files ***')
print()

# ──────────────────────────────────────────────────────────────────────────────
# Load master ops table
# ──────────────────────────────────────────────────────────────────────────────
csv.field_size_limit(10_000_000)
print('Loading k8s_master_read_ops.csv ...')
ops_table: Dict[str, dict] = {}
for row in csv.DictReader(OPS_CSV.open()):
    op = row['producing_op'].strip()
    if op:
        ops_table[op] = row
print(f'  {len(ops_table):,} ops loaded')


# ──────────────────────────────────────────────────────────────────────────────
# Pre-load items_for, action, for_each from existing step6 yamls
# ──────────────────────────────────────────────────────────────────────────────
print('Loading items_for + action + for_each from existing step6 yamls ...')
op_items_for: Dict[str, str] = {}
op_action:    Dict[str, str] = {}
op_params:    Dict[str, dict] = {}
op_for_each:  Dict[str, str] = {}

for f in sorted(GEN_DIR.rglob('step6_*.discovery.yaml')):
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

print(f'  {len(op_items_for)} ops with items_for')
print(f'  {len(op_action)} ops with action')
print(f'  {len(op_params)} ops with params')
print(f'  {len(op_for_each)} ops with for_each')
print()


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def action_from_python_call(python_call: str, svc: str) -> str:
    """
    K8s pattern: core_v1_api.list_pod_for_all_namespaces_pod(**params)
    → strip api class prefix and trailing _<service> suffix
    """
    if not python_call:
        return ''
    # Match: <api_class>.<method>(**params)
    m = re.match(r'\w+_api\.(\w+)\(\*\*params\)', python_call)
    if not m:
        # Try no-param variant
        m = re.match(r'\w+_api\.(\w+)\(\)', python_call)
    if not m:
        # custom_objects_api pattern: just use last segment of op
        return ''
    method = m.group(1)
    # Strip trailing _<service> suffix (e.g. _pod, _admission, _rbac)
    if svc and method.endswith(f'_{svc}'):
        method = method[:-(len(svc) + 1)]
    return method


def build_items_for(op: str, row: dict) -> str:
    """K8s list ops always use {{ response }} — the engine iterates .items."""
    if op in op_items_for:
        return op_items_for[op]
    op_kind = row.get('op_kind', '')
    if op_kind == 'read_get':
        return '{{ response }}'
    return '{{ response }}'


def build_params(op: str, row: dict) -> Optional[dict]:
    """Resolve call params for dependent ops."""
    if op in op_params:
        return op_params[op]
    id_param = row.get('resource_id_param', '').strip()
    root_op  = row.get('root_op', '')
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


def build_emit_item(produced_fields: str) -> dict:
    """Build emit.item from pipe-separated produced_fields."""
    fields = [f.strip() for f in produced_fields.split('|') if f.strip()]
    if not fields:
        return {}
    item: dict = {}
    seen: set = set()
    for field in fields:
        # Use the full field path as key (K8s has nested paths like spec.containers[])
        clean = re.sub(r'\[\]', '[]', field)
        key = clean
        if key and key not in seen:
            seen.add(key)
            item[key] = f'{{{{ item.{key} }}}}'
    return item


def build_discovery_entry(op: str, row: dict) -> dict:
    """Build a single discovery entry dict."""
    svc    = row.get('service', '')
    action = op_action.get(op) or action_from_python_call(row.get('python_call', ''), svc)
    if not action:
        # Fallback: last segment of op id
        action = op.split('.')[-1]

    is_indep = row.get('is_independent', 'Yes') == 'Yes'
    fields   = row.get('produced_fields', '')

    call: dict = {'action': action, 'save_as': 'response', 'on_error': 'continue'}
    if not is_indep:
        params = build_params(op, row)
        if params:
            call['params'] = params

    items_for = build_items_for(op, row)
    emit_item = build_emit_item(fields)

    emit: dict = {'as': 'item', 'items_for': items_for}
    if emit_item:
        emit['item'] = emit_item

    entry: dict = {'discovery_id': op, 'calls': [call], 'emit': emit}
    if not is_indep:
        for_each_val = op_for_each.get(op) or row.get('root_op', '')
        entry['for_each'] = for_each_val

    return entry


# ──────────────────────────────────────────────────────────────────────────────
# Per-service: collect for_each ops from individual rule yamls
# ──────────────────────────────────────────────────────────────────────────────

def get_check_ops(svc: str) -> Set[str]:
    """Collect all for_each values from individual rule yamls in test dir."""
    svc_dir = TEST_DIR / svc
    if not svc_dir.exists():
        return set()
    ops = set()
    for ck in svc_dir.glob('*.yaml'):
        try:
            d = yaml.safe_load(ck.read_text()) or {}
        except Exception:
            continue
        fe = d.get('for_each', '')
        if fe:
            ops.add(fe)
    return ops


def resolve_op_set(check_ops: Set[str]) -> List[str]:
    needed: Set[str] = set(check_ops)
    for op in list(check_ops):
        row = ops_table.get(op)
        if row and row.get('is_independent') == 'No':
            root = row.get('root_op', '')
            if root and root in ops_table and root != op:
                needed.add(root)
    independent = sorted(op for op in needed
                         if ops_table.get(op, {}).get('is_independent') != 'No')
    dependent   = sorted(op for op in needed
                         if ops_table.get(op, {}).get('is_independent') == 'No')
    return independent + dependent


def generate_for_service(svc: str):
    check_ops = get_check_ops(svc)
    if not check_ops:
        return None

    missing = check_ops - set(ops_table.keys())
    valid   = check_ops - missing
    if missing:
        print(f'  [{svc}] WARNING: {len(missing)} ops not in master: {sorted(missing)}')

    op_list = resolve_op_set(valid)
    if not op_list:
        return None

    entries = [build_discovery_entry(op, ops_table[op]) for op in op_list]

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
        'provider':  'k8s',
        'service':   svc,
        'discovery': entries,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

check_svcs = sorted(
    d.name for d in TEST_DIR.iterdir()
    if d.is_dir() and any(True for _ in d.glob('*.yaml'))
)
if TARGET:
    check_svcs = [s for s in check_svcs if s == TARGET]

print(f'Services to process: {len(check_svcs)}')
print()

written = skipped = 0

for svc in check_svcs:
    svc_out_dir = CHECK_DIR / svc
    svc_out_dir.mkdir(parents=True, exist_ok=True)
    out_path = svc_out_dir / f'{svc}.discovery.yaml'

    doc = generate_for_service(svc)
    if not doc:
        print(f'  [{svc}] SKIP — no valid ops')
        skipped += 1
        continue

    entries  = doc['discovery']
    n_ops    = len(entries)
    n_indep  = sum(1 for e in entries if 'for_each' not in e)
    n_dep    = n_ops - n_indep
    n_fields = sum(len(e.get('emit', {}).get('item', {})) for e in entries)

    print(f'  [{svc:<35}] {n_ops} ops ({n_indep} indep + {n_dep} dep) | {n_fields} fields → {out_path.name}')

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
print('═' * 60)
if APPLY:
    print(f'Written : {written} discovery yamls')
    print(f'Skipped : {skipped}')
else:
    print(f'Would write : {len(check_svcs) - skipped} files')
    print(f'Would skip  : {skipped}')
