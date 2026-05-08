#!/usr/bin/env python3
"""
generate_aws_step6_discovery.py
================================
Generate step6_{service}.discovery.yaml for every AWS service that has check rules.

Source:
  aws_master_read_ops.csv  → op metadata, produced fields, chain info
  {svc}.checks.yaml        → which for_each ops are needed per service
  existing step6 yamls     → items_for response key + params (pre-resolved)

Logic per service:
  1. Collect all for_each ops from check rules
  2. For dependent ops → also include their root_op
  3. Deduplicate → ordered set (independent first, then dependent)
  4. Build discovery entry per op from CSV data
  5. Write step6_{service}.discovery.yaml

Usage:
    python generate_aws_step6_discovery.py             # dry-run, all services
    python generate_aws_step6_discovery.py --apply     # write all
    python generate_aws_step6_discovery.py --svc acm --apply  # single service
"""

import csv
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set

import yaml

# ──────────────────────────────────────────────────────────────────────────────
ROOT      = Path('/Users/apple/Desktop/threat-engine')
GEN_DIR   = ROOT / 'catalog/discovery_generator/aws'
CHECK_DIR = ROOT / 'catalog/rule/aws_rule_check'
OPS_CSV   = GEN_DIR / 'aws_master_read_ops.csv'
OUT_DIR   = CHECK_DIR  # discovery yamls live alongside check yamls

APPLY     = '--apply' in sys.argv
TARGET    = None
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
print('Loading aws_master_read_ops.csv ...')
ops_table: Dict[str, dict] = {}
for row in csv.DictReader(OPS_CSV.open()):
    op = row['producing_op'].strip()
    if op:
        ops_table[op] = row
print(f'  {len(ops_table):,} ops loaded')


# ──────────────────────────────────────────────────────────────────────────────
# Pre-load items_for and params from existing step6 yamls
# ──────────────────────────────────────────────────────────────────────────────

print('Loading items_for + params from existing step6 yamls ...')
op_items_for: Dict[str, str]  = {}
op_params: Dict[str, dict]    = {}

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
        did   = disc.get('discovery_id', '')
        emit  = disc.get('emit', {})
        calls = disc.get('calls', [{}])
        items_for = emit.get('items_for', '')
        params    = {k: v for k, v in (calls[0].get('params', {}) or {}).items()
                     if '{{' in str(v)}      # keep only dynamic params
        if did:
            if items_for:
                op_items_for[did] = items_for
            if params:
                op_params[did] = params

print(f'  {len(op_items_for)} ops with items_for')
print(f'  {len(op_params)} ops with params')
print()


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def action_from_op(op: str) -> str:
    """aws.acm.describe_certificate → describe_certificate"""
    parts = op.split('.')
    return parts[-1] if parts else op


def action_from_python_call(python_call: str) -> str:
    """client.describe_certificate() → describe_certificate"""
    m = re.match(r'client\.(\w+)\(\)', python_call or '')
    return m.group(1) if m else ''


def build_items_for(op: str, row: dict) -> str:
    """Resolve items_for for an op."""
    # 1. From existing step6
    if op in op_items_for:
        return op_items_for[op]
    # 2. Heuristic based on op_kind
    op_kind = row.get('op_kind', '')
    if op_kind == 'read_get':
        return '{{ response }}'
    # 3. Default for list/describe
    return '{{ response.items }}'


def build_params(op: str, row: dict) -> Optional[dict]:
    """Resolve call params for a dependent op."""
    # 1. From existing step6 (most accurate)
    if op in op_params:
        return op_params[op]
    # 2. Derive from resource_id_param + resource_id_field of ROOT op
    root_op = row.get('root_op', '')
    id_param = row.get('resource_id_param', '').strip()
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


def build_emit_item(produced_fields: str, is_get: bool, op: str) -> dict:
    """Build emit.item dict from pipe-separated field names."""
    fields = [f.strip() for f in produced_fields.split('|') if f.strip()]
    if not fields:
        return {}

    item: dict = {}
    for field in fields:
        # Fields like 'Certificate.CertificateAuthorityArn' → response path for get ops
        if is_get and '.' not in field:
            item[field] = f'{{{{ response.{field} }}}}'
        else:
            item[field] = f'{{{{ item.{field} }}}}'
    return item


def build_discovery_entry(op: str, row: dict) -> dict:
    """Build a single discovery entry dict."""
    action   = action_from_python_call(row.get('python_call', '')) or action_from_op(op)
    is_indep = row.get('is_independent', 'Yes') == 'Yes'
    op_kind  = row.get('op_kind', 'read_list')
    is_get   = op_kind == 'read_get'
    fields   = row.get('produced_fields', '')

    # Call block
    call: dict = {
        'action':   action,
        'save_as':  'response',
        'on_error': 'continue',
    }
    if not is_indep:
        params = build_params(op, row)
        if params:
            call['params'] = params

    # Emit block
    items_for  = build_items_for(op, row)
    emit_item  = build_emit_item(fields, is_get, op)

    emit: dict = {
        'as':       'item',
        'items_for': items_for,
    }
    if emit_item:
        emit['item'] = emit_item

    entry: dict = {
        'discovery_id': op,
        'calls':        [call],
        'emit':         emit,
    }
    if not is_indep:
        entry['for_each'] = row.get('root_op', '')

    return entry


# ──────────────────────────────────────────────────────────────────────────────
# Per-service generation
# ──────────────────────────────────────────────────────────────────────────────

def get_check_ops(svc: str) -> Set[str]:
    """Return all for_each ops used in check rules for this service."""
    p = CHECK_DIR / svc / f'{svc}.checks.yaml'
    if not p.exists():
        return set()
    try:
        d = yaml.safe_load(p.read_text()) or {}
    except Exception:
        return set()
    return {c['for_each'] for c in d.get('checks', []) if c.get('for_each')}


def resolve_op_set(check_ops: Set[str]) -> List[str]:
    """
    Expand check ops to full required op set:
    - Keep check ops
    - Add root_op for any dependent check op whose root isn't already included
    Return ordered: independent ops first, then dependent ops.
    """
    needed: Set[str] = set(check_ops)

    for op in list(check_ops):
        row = ops_table.get(op)
        if row and row.get('is_independent') == 'No':
            root = row.get('root_op', '')
            if root:
                needed.add(root)

    independent = sorted(op for op in needed
                         if ops_table.get(op, {}).get('is_independent') == 'Yes')
    dependent   = sorted(op for op in needed
                         if ops_table.get(op, {}).get('is_independent') == 'No')

    return independent + dependent


def generate_for_service(svc: str) -> Optional[dict]:
    check_ops = get_check_ops(svc)
    if not check_ops:
        return None

    # Validate ops exist in table
    missing = check_ops - set(ops_table.keys())
    if missing:
        print(f'  [{svc}] WARNING: {len(missing)} ops not in master table: {sorted(missing)[:3]}')

    op_list = resolve_op_set(check_ops - missing)
    if not op_list:
        return None

    entries = [build_discovery_entry(op, ops_table[op]) for op in op_list]

    from_checks  = len(check_ops - missing)
    extra_roots  = len(op_list) - from_checks

    doc = {
        '__meta__': {
            'comment': (
                f'Auto-generated: step6 discovery for {svc} check rules\n'
                f'{from_checks} ops from checks'
                + (f', +{extra_roots} root ops added' if extra_roots else '')
            )
        },
        'version':   '1.0',
        'provider':  'aws',
        'service':   svc,
        'discovery': entries,
    }

    return doc


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

written = skipped = missing_ops = 0

for svc in check_svcs:
    # Output goes to catalog/rule/aws_rule_check/{svc}/
    svc_out_dir = OUT_DIR / svc
    svc_out_dir.mkdir(parents=True, exist_ok=True)

    out_path = svc_out_dir / f'{svc}.discovery.yaml'

    doc = generate_for_service(svc)
    if not doc:
        print(f'  [{svc}] SKIP — no valid ops')
        skipped += 1
        continue

    entries   = doc['discovery']
    n_ops     = len(entries)
    n_indep   = sum(1 for e in entries if 'for_each' not in e)
    n_dep     = n_ops - n_indep
    n_fields  = sum(len(e.get('emit', {}).get('item', {})) for e in entries)

    verb = 'Write' if APPLY else 'Would write'
    print(f'  [{svc:<30}] {n_ops} ops ({n_indep} indep + {n_dep} dep) | {n_fields} total fields → {out_path.name}')

    if APPLY:
        # Remove __meta__ before writing
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
    print(f'Written : {written} step6 discovery yamls')
    print(f'Skipped : {skipped}')
else:
    print(f'Would write : {len(check_svcs) - skipped} files')
