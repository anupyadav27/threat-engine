#!/usr/bin/env python3
"""
generate_aws_master_read_ops.py
================================
Build aws_master_read_ops.csv — one row per unique AWS read operation.

Sources:
  1. aws_master_field_catalog.csv   → op metadata, produced fields (deduped),
                                      field types, operators, chain_ops_with_fields
  2. {service}/final_discovery_v1.yaml  → resource_type + resource_id_param (RII block)
  3. aws_rule_check/{service}/{svc}.checks.yaml  → rule_count + check_rule_yaml

Output columns (23):
  csp, service, producing_op, op_kind, is_independent,
  root_op, chain_ops, chain_length, hop_distance,
  chain_ops_with_fields,        ← chain showing fields emitted at each step
  python_call, http_path,
  produced_fields,              ← pipe-separated unique field names
  fields_types,                 ← pipe-sep: FieldName:type pairs
  fields_operators,             ← pipe-sep: FieldName:op1,op2,op3 pairs
  resource_type,                ← from RII block
  resource_id_field,            ← field where is_id=Yes in master CSV
  resource_id_param,            ← from RII block
  rule_count,                   ← count of check rules using this op
  check_rule_yaml,              ← full YAML blob for all rules on this op
  is_active,
  updated_at

Usage:
    python generate_aws_master_read_ops.py             # dry-run
    python generate_aws_master_read_ops.py --apply     # write CSV
"""

import csv
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, OrderedDict

import yaml

# ──────────────────────────────────────────────────────────────────────────────
ROOT       = Path('/Users/apple/Desktop/threat-engine')
GEN_DIR    = ROOT / 'catalog/discovery_generator/aws'
CHECK_DIR  = ROOT / 'catalog/rule/aws_rule_check'
MASTER_CSV = GEN_DIR / 'aws_master_field_catalog.csv'
OUTPUT_CSV = GEN_DIR / 'aws_master_read_ops.csv'

COLUMNS = [
    'csp', 'service', 'producing_op', 'op_kind', 'is_independent',
    'root_op', 'chain_ops', 'chain_length', 'hop_distance',
    'chain_ops_with_fields',
    'python_call', 'http_path',
    'produced_fields',
    'fields_types',
    'fields_operators',
    'resource_type', 'resource_id_field', 'resource_id_param',
    'rule_count', 'check_rule_yaml',
    'is_active', 'updated_at',
]

META_COLS = [
    'csp', 'service', 'op_kind', 'is_independent',
    'root_op', 'chain_ops', 'chain_length', 'hop_distance',
    'chain_ops_with_fields',
    'python_call', 'http_path',
]

APPLY = '--apply' in sys.argv

if not APPLY:
    print('*** DRY RUN — pass --apply to write CSV ***')
print()


# ──────────────────────────────────────────────────────────────────────────────
# SOURCE 1: aws_master_field_catalog.csv → GROUP BY producing_op
#   - meta cols: first row for op (all rows identical for same op)
#   - produced_fields: ordered-unique list (preserve first-seen order)
#   - fields_types: FieldName:type (deduped, ordered)
#   - fields_operators: FieldName:op1,op2,op3 (deduped, ordered)
#   - resource_id_field: field where is_id=Yes
# ──────────────────────────────────────────────────────────────────────────────

print('Loading aws_master_field_catalog.csv ...')
master_rows = list(csv.DictReader(MASTER_CSV.open()))
print(f'  {len(master_rows):,} field rows')
unique_ops = len(set(r['producing_op'] for r in master_rows))
print(f'  {unique_ops} unique ops')
print()

ops: Dict[str, dict] = {}   # producing_op → aggregated row

for row in master_rows:
    op = row['producing_op'].strip()
    if not op:
        continue

    if op not in ops:
        ops[op] = {col: row[col] for col in META_COLS}
        ops[op]['producing_op']     = op
        ops[op]['_fields_seen']     = {}   # OrderedDict[field_name → {type, operators}]
        ops[op]['resource_id_field'] = ''

    field = row['field_path'].strip()
    if not field:
        continue

    # First time we see this field on this op, record its type + operators
    if field not in ops[op]['_fields_seen']:
        ops[op]['_fields_seen'][field] = {
            'type':      row.get('field_type', '').strip(),
            'operators': row.get('operators', '').strip(),
        }

    # id field: prefer the actual identifier field (is_id=Yes)
    if row.get('is_id', '').strip().lower() == 'yes':
        ops[op]['resource_id_field'] = field


# Flatten the _fields_seen dict into produced_fields / fields_types / fields_operators
for op, d in ops.items():
    seen = d.pop('_fields_seen')
    d['produced_fields']  = '|'.join(seen.keys())
    d['fields_types']     = '|'.join(
        f"{f}:{meta['type']}" for f, meta in seen.items() if meta['type']
    )
    d['fields_operators'] = '|'.join(
        f"{f}:{meta['operators']}" for f, meta in seen.items() if meta['operators']
    )


# ──────────────────────────────────────────────────────────────────────────────
# SOURCE 2: final_discovery_v1.yaml → resource_type + resource_id_param
# ──────────────────────────────────────────────────────────────────────────────

rii_map: Dict[str, dict] = {}

print('Loading RII from final_discovery_v1.yaml files ...')
rii_count = 0

for svc_dir in sorted(GEN_DIR.iterdir()):
    if not svc_dir.is_dir():
        continue
    yaml_path = svc_dir / 'final_discovery_v1.yaml'
    if not yaml_path.exists():
        continue
    try:
        data = yaml.safe_load(yaml_path.read_text()) or {}
    except Exception:
        continue

    for rii in data.get('inventory_resource_identifiers') or []:
        id_op    = (rii.get('identifier_op') or '').strip()
        res_type = (rii.get('resource_type') or '').strip()
        id_param = (rii.get('resource_id_param') or '').strip()
        if id_op and res_type:
            rii_map[id_op] = {
                'resource_type':    res_type,
                'resource_id_param': id_param,
            }
            rii_count += 1

print(f'  {rii_count} RII entries across {len(rii_map)} ops')
print()


# ──────────────────────────────────────────────────────────────────────────────
# SOURCE 3: *.checks.yaml → rule_count + check_rule_yaml (grouped by for_each)
# ──────────────────────────────────────────────────────────────────────────────

rules_by_op: Dict[str, List[dict]] = defaultdict(list)

print('Loading check rules from *.checks.yaml files ...')
total_rules = 0

for svc_dir in sorted(CHECK_DIR.iterdir()):
    if not svc_dir.is_dir():
        continue
    checks_path = svc_dir / f'{svc_dir.name}.checks.yaml'
    if not checks_path.exists():
        continue
    try:
        data = yaml.safe_load(checks_path.read_text()) or {}
    except Exception:
        continue

    for rule in data.get('checks', []):
        fe = (rule.get('for_each') or '').strip()
        if fe:
            rules_by_op[fe].append(rule)
            total_rules += 1

print(f'  {total_rules} rules across {len(rules_by_op)} ops')
print()


# ──────────────────────────────────────────────────────────────────────────────
# ASSEMBLE final op rows
# ──────────────────────────────────────────────────────────────────────────────

now_ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
output_rows: List[dict] = []

for op, d in sorted(ops.items()):
    rii   = rii_map.get(op, {})
    rules = rules_by_op.get(op, [])
    rule_count = len(rules)

    check_rule_yaml = ''
    if rules:
        try:
            check_rule_yaml = yaml.dump(
                rules,
                default_flow_style=False,
                allow_unicode=True,
                indent=2,
                sort_keys=True,
            ).strip()
        except Exception:
            check_rule_yaml = ''

    output_rows.append({
        'csp':                   d['csp'],
        'service':               d['service'],
        'producing_op':          op,
        'op_kind':               d['op_kind'],
        'is_independent':        d['is_independent'],
        'root_op':               d['root_op'],
        'chain_ops':             d['chain_ops'],
        'chain_length':          d['chain_length'],
        'hop_distance':          d['hop_distance'],
        'chain_ops_with_fields': d['chain_ops_with_fields'],
        'python_call':           d['python_call'],
        'http_path':             d['http_path'],
        'produced_fields':       d['produced_fields'],
        'fields_types':          d['fields_types'],
        'fields_operators':      d['fields_operators'],
        'resource_type':         rii.get('resource_type', ''),
        'resource_id_field':     d['resource_id_field'],
        'resource_id_param':     rii.get('resource_id_param', ''),
        'rule_count':            rule_count,
        'check_rule_yaml':       check_rule_yaml,
        'is_active':             'true',
        'updated_at':            now_ts,
    })


# ──────────────────────────────────────────────────────────────────────────────
# STATS
# ──────────────────────────────────────────────────────────────────────────────

total_ops  = len(output_rows)
with_rules = sum(1 for r in output_rows if r['rule_count'] > 0)
with_rii   = sum(1 for r in output_rows if r['resource_type'])
indep      = sum(1 for r in output_rows if r['is_independent'] == 'Yes')
dep        = total_ops - indep
max_r      = max(output_rows, key=lambda r: r['rule_count'])
max_f      = max(output_rows, key=lambda r: r['produced_fields'].count('|'))

print('═' * 60)
print(f'Total ops:              {total_ops}')
print(f'  independent:          {indep}')
print(f'  dependent:            {dep}')
print(f'Ops with rules:         {with_rules}')
print(f'Ops with RII:           {with_rii}')
print(f'Max rules on one op:    {max_r["rule_count"]:>3}  ({max_r["producing_op"]})')
print(f'Max fields on one op:   {max_f["produced_fields"].count("|")+1:>3}  ({max_f["producing_op"]})')
print()

# Sample: a dependent op with rules, RII, and operators
sample = next(
    (r for r in output_rows
     if r['is_independent'] == 'No' and r['rule_count'] > 0 and r['resource_type']),
    output_rows[0]
)
print('Sample row (dependent, has rules + RII):')
for k, v in sample.items():
    sv = str(v)
    if k == 'check_rule_yaml':
        lines = sv.split('\n')
        sv = f'[{len(lines)} lines] {lines[0]}...'
    elif k in ('produced_fields', 'fields_types', 'fields_operators', 'chain_ops_with_fields'):
        sv = sv[:100] + '...' if len(sv) > 100 else sv
    print(f'  {k}: {sv}')

print()


# ──────────────────────────────────────────────────────────────────────────────
# WRITE
# ──────────────────────────────────────────────────────────────────────────────

if APPLY:
    with OUTPUT_CSV.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(output_rows)
    print(f'Wrote {len(output_rows):,} rows → {OUTPUT_CSV}')
else:
    print(f'Would write {len(output_rows):,} rows → {OUTPUT_CSV}')
