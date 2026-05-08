#!/usr/bin/env python3
"""
generate_azure_step6_discovery.py
==================================
Generate {svc}.discovery.yaml for every Azure service that has check rules.

Output: catalog/rule/azure_rule_check/{svc}/{svc}.discovery.yaml

Usage:
    python generate_azure_step6_discovery.py             # dry-run
    python generate_azure_step6_discovery.py --apply     # write all
    python generate_azure_step6_discovery.py --svc aks --apply
"""

import csv
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

import yaml

# ──────────────────────────────────────────────────────────────────────────────
ROOT      = Path('/Users/apple/Desktop/threat-engine')
GEN_DIR   = ROOT / 'catalog/discovery_generator/azure'
CHECK_DIR = ROOT / 'catalog/rule/azure_rule_check'
OPS_CSV   = GEN_DIR / 'azure_master_read_ops.csv'
OUT_DIR   = CHECK_DIR   # discovery yamls live alongside check yamls

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
print('Loading azure_master_read_ops.csv ...')
ops_table: Dict[str, dict] = {}
for row in csv.DictReader(OPS_CSV.open()):
    op = row['producing_op'].strip()
    if op:
        ops_table[op] = row
print(f'  {len(ops_table):,} ops loaded')


# ──────────────────────────────────────────────────────────────────────────────
# Pre-load items_for, params, action, for_each from existing step6 yamls
# ──────────────────────────────────────────────────────────────────────────────
print('Loading items_for + params + for_each from existing step6 yamls ...')
op_items_for: Dict[str, str] = {}
op_params:    Dict[str, dict] = {}
op_action:    Dict[str, str]  = {}
op_for_each:  Dict[str, str]  = {}

for f in sorted(GEN_DIR.rglob('step6_*.discovery.yaml')):
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
        emit     = disc.get('emit', {})
        calls    = disc.get('calls', [{}])
        for_each = disc.get('for_each', '')
        if not did:
            continue
        items_for = emit.get('items_for', '')
        action    = calls[0].get('action', '') if calls else ''
        params    = {k: v for k, v in (calls[0].get('params', {}) or {}).items()
                     if '{{' in str(v)}
        if items_for:
            op_items_for[did] = items_for
        if action and did not in op_action:
            op_action[did] = action
        if params:
            op_params[did] = params
        # Only store for_each if it's not self-referential
        if for_each and for_each != did:
            op_for_each[did] = for_each

print(f'  {len(op_items_for)} ops with items_for')
print(f'  {len(op_action)} ops with action')
print(f'  {len(op_params)} ops with params')
print(f'  {len(op_for_each)} ops with for_each (non-self-referential)')
print()


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def action_from_python_call(python_call: str) -> str:
    """client.configurations.list_by_subscription(**params) → configurations.list_by_subscription"""
    m = re.match(r'client\.(.+?)\(\*\*params\)', python_call or '')
    if m:
        return m.group(1)
    m = re.match(r'client\.(.+?)\(\)', python_call or '')
    return m.group(1) if m else ''


def build_items_for(op: str, row: dict) -> str:
    """Resolve items_for. Azure list ops almost always use response.value."""
    if op in op_items_for:
        return op_items_for[op]
    op_kind = row.get('op_kind', '')
    if op_kind == 'read_get':
        return '{{ response }}'
    return '{{ response.value }}'


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


def build_emit_item(produced_fields: str, op_kind: str) -> dict:
    """
    Build emit.item from pipe-separated produced_fields.
    Azure fields are often 'value[].fieldname' — strip the value[] prefix.
    """
    fields = [f.strip() for f in produced_fields.split('|') if f.strip()]
    if not fields:
        return {}
    item: dict = {}
    seen: set = set()
    for field in fields:
        # Strip 'value[].' prefix common in Azure ARM list responses
        clean = re.sub(r'^value\[\]\.', '', field)
        # Use only top-level field (before first '.')
        top = clean.split('.')[0] if '.' in clean else clean
        if top and top not in seen:
            seen.add(top)
            item[top] = f'{{{{ item.{top} }}}}'
    return item


def build_discovery_entry(op: str, row: dict) -> dict:
    """Build a single discovery entry dict."""
    # Action: prefer pre-loaded from existing yaml, else derive from python_call
    action = op_action.get(op) or action_from_python_call(row.get('python_call', ''))
    if not action:
        # fallback: last two segments of op id
        parts = op.split('.')
        action = '.'.join(parts[-2:]) if len(parts) >= 2 else parts[-1]

    is_indep = row.get('is_independent', 'Yes') == 'Yes'
    op_kind  = row.get('op_kind', 'read_list')
    fields   = row.get('produced_fields', '')

    call: dict = {'action': action, 'save_as': 'response', 'on_error': 'continue'}
    if not is_indep:
        params = build_params(op, row)
        if params:
            call['params'] = params

    items_for = build_items_for(op, row)
    emit_item = build_emit_item(fields, op_kind)

    emit: dict = {'as': 'item', 'items_for': items_for}
    if emit_item:
        emit['item'] = emit_item

    entry: dict = {'discovery_id': op, 'calls': [call], 'emit': emit}
    if not is_indep:
        # Prefer pre-loaded for_each (correct chain) over master CSV root_op (may be self-referential)
        for_each_val = op_for_each.get(op) or row.get('root_op', '')
        entry['for_each'] = for_each_val

    return entry


# ──────────────────────────────────────────────────────────────────────────────
# Per-service generation
# ──────────────────────────────────────────────────────────────────────────────

def get_check_ops(svc: str) -> Set[str]:
    p = CHECK_DIR / svc / f'{svc}.checks.yaml'
    if not p.exists():
        return set()
    try:
        d = yaml.safe_load(p.read_text()) or {}
    except Exception:
        return set()
    return {c['for_each'] for c in d.get('checks', []) if c.get('for_each')}


def resolve_op_set(check_ops: Set[str]) -> List[str]:
    needed: Set[str] = set(check_ops)
    for op in list(check_ops):
        row = ops_table.get(op)
        if row and row.get('is_independent') == 'No':
            root = row.get('root_op', '')
            if root and root in ops_table and root != op:
                needed.add(root)
    independent = sorted(op for op in needed
                         if ops_table.get(op, {}).get('is_independent') == 'Yes')
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
        print(f'  [{svc}] WARNING: {len(missing)} ops not in master: {sorted(missing)[:2]}')

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
        'provider':  'azure',
        'service':   svc,
        'discovery': entries,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

check_svcs = sorted(
    d.name for d in CHECK_DIR.iterdir()
    if d.is_dir() and (d / f'{d.name}.checks.yaml').exists()
)
if TARGET:
    check_svcs = [s for s in check_svcs if s == TARGET]

print(f'Services to process: {len(check_svcs)}')
print()

written = skipped = 0

for svc in check_svcs:
    svc_out_dir = OUT_DIR / svc
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
