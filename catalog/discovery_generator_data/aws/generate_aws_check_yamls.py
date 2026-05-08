#!/usr/bin/env python3
"""
generate_aws_check_yamls.py
============================
Regenerate catalog/rule/aws_rule_check/{service}/{service}.checks.yaml
from aws_field_rule_catalog.csv (single source of truth).

Actions:
  1. Read all rule rows from aws_field_rule_catalog.csv
  2. Group by service
  3. Rebuild each {service}.checks.yaml from scratch
  4. Remove any stale rule files for services no longer in catalog

Condition logic:
  - If check_conditions_json is present → use it directly (multi-condition)
  - Else use check_condition JSON (single condition)

Usage:
    python generate_aws_check_yamls.py             # dry-run
    python generate_aws_check_yamls.py --apply     # write files
"""

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

import yaml

# ──────────────────────────────────────────────────────────────────────────────
ROOT        = Path('/Users/apple/Desktop/threat-engine')
CATALOG_CSV = ROOT / 'catalog/discovery_generator/aws/aws_field_rule_catalog.csv'
CHECK_DIR   = ROOT / 'catalog/rule/aws_rule_check'

APPLY = '--apply' in sys.argv

if not APPLY:
    print('*** DRY RUN — pass --apply to write files ***')
print()

# ──────────────────────────────────────────────────────────────────────────────
# Load catalog
# ──────────────────────────────────────────────────────────────────────────────

csv.field_size_limit(10_000_000)
print(f'Loading {CATALOG_CSV.name} ...')
all_rows = list(csv.DictReader(CATALOG_CSV.open()))
rule_rows = [r for r in all_rows if r.get('check_rule_id', '').strip()]
print(f'  {len(rule_rows)} rule rows across catalog')

# Group by service, then by rule_id (dedup)
rules_by_svc: Dict[str, Dict[str, dict]] = defaultdict(dict)
for r in rule_rows:
    svc     = r['service'].strip()
    rule_id = r['check_rule_id'].strip()
    if not svc or not rule_id:
        continue
    # Keep first occurrence per rule_id (rows can repeat for multi-field rules)
    if rule_id not in rules_by_svc[svc]:
        rules_by_svc[svc][rule_id] = r

print(f'  {sum(len(v) for v in rules_by_svc.values())} unique rules across {len(rules_by_svc)} services')
print()


# ──────────────────────────────────────────────────────────────────────────────
# Build condition block from catalog row
# ──────────────────────────────────────────────────────────────────────────────

def build_conditions(r: dict) -> object:
    """
    Returns the conditions object to embed in the YAML.
    Priority:
      1. check_conditions_json  → multi-condition (all/any/single)
      2. check_condition        → single condition JSON
      3. Fallback: build from check_var + check_condition_op + check_condition_value
    """
    # Multi-condition
    cj = r.get('check_conditions_json', '').strip()
    if cj:
        try:
            return json.loads(cj)
        except Exception:
            pass

    # Single condition JSON
    cc = r.get('check_condition', '').strip()
    if cc:
        try:
            return json.loads(cc)
        except Exception:
            pass

    # Fallback: build from individual columns
    var = r.get('check_var', '').strip()
    op  = r.get('check_condition_op', '').strip()
    val = r.get('check_condition_value', '').strip()
    if var and op:
        cond: dict = {'var': var, 'op': op}
        cond['value'] = None if not val or val.lower() == 'null' else val
        return cond

    return {}


# ──────────────────────────────────────────────────────────────────────────────
# Compare against existing yamls
# ──────────────────────────────────────────────────────────────────────────────

existing_rule_ids: set = set()
existing_svcs: set = set()
for p in sorted(CHECK_DIR.rglob('*.checks.yaml')):
    d = yaml.safe_load(p.read_text()) or {}
    for c in d.get('checks', []):
        rid = c.get('rule_id', '')
        if rid:
            existing_rule_ids.add(rid)
    existing_svcs.add(p.parent.name)

catalog_rule_ids = {
    r['check_rule_id'] for svc_rules in rules_by_svc.values()
    for r in svc_rules.values()
}

new_rules   = catalog_rule_ids - existing_rule_ids
stale_rules = existing_rule_ids - catalog_rule_ids

print(f'Existing yaml rules : {len(existing_rule_ids)} across {len(existing_svcs)} services')
print(f'Catalog rules       : {len(catalog_rule_ids)} across {len(rules_by_svc)} services')
print(f'New (to add)        : {len(new_rules)}')
print(f'Stale (to remove)   : {len(stale_rules)}')
if stale_rules:
    print(f'  Stale rule_ids: {sorted(stale_rules)}')
print()


# ──────────────────────────────────────────────────────────────────────────────
# Generate / overwrite check yamls
# ──────────────────────────────────────────────────────────────────────────────

written  = 0
skipped  = 0
created  = 0

for svc in sorted(rules_by_svc.keys()):
    svc_rules = rules_by_svc[svc]
    svc_dir   = CHECK_DIR / svc
    out_path  = svc_dir / f'{svc}.checks.yaml'

    checks_list: List[dict] = []
    for rule_id in sorted(svc_rules.keys()):
        r = svc_rules[rule_id]
        check_entry: dict = {
            'rule_id':    rule_id,
            'for_each':   r.get('check_for_each', '').strip(),
            'severity':   r.get('check_severity', 'MEDIUM').strip() or 'MEDIUM',
            'conditions': build_conditions(r),
        }
        checks_list.append(check_entry)

    doc = {
        'version':  '1.0',
        'provider': 'aws',
        'service':  svc,
        'checks':   checks_list,
    }

    is_new = not out_path.exists()

    if APPLY:
        svc_dir.mkdir(parents=True, exist_ok=True)
        with out_path.open('w') as f:
            yaml.dump(doc, f,
                      default_flow_style=False,
                      allow_unicode=True,
                      indent=2,
                      sort_keys=False)
        written += 1
        if is_new:
            created += 1
    else:
        skipped += 1

    verb = 'Write' if APPLY else 'Would write'
    marker = ' [NEW]' if is_new else ''
    print(f'  {verb} {svc}/{svc}.checks.yaml — {len(checks_list)} rules{marker}')


print()
print('═' * 60)
if APPLY:
    print(f'Written  : {written} files  ({created} new, {written-created} updated)')
    print(f'New rules added  : {len(new_rules)}')
    print(f'Stale rules gone : {len(stale_rules)}')
else:
    print(f'Would write {skipped} files')
    print(f'New rules to add  : {len(new_rules)}')
    print(f'Stale rules to drop: {len(stale_rules)}')
