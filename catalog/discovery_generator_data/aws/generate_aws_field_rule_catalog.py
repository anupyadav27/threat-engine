#!/usr/bin/env python3
"""
generate_aws_field_rule_catalog.py
====================================
Merge aws_master_field_catalog.csv (discovery fields) with AWS check rules
into a single unified aws_field_rule_catalog.csv following the OCI template schema.

Schema (35 columns — same as oci_field_rule_catalog.csv):
  Discovery columns (1-18):  csp, service, field_path, item_var_path, field_type,
                              is_id, producing_op, op_kind, is_independent, root_op,
                              chain_ops, chain_length, hop_distance, chain_ops_with_fields,
                              operators, operators_no_value, python_call, http_path
  Resource columns (19-21):  resource_type, resource_id_field, resource_id_param
  Check rule columns (22-35): check_rule_id, check_for_each, check_var,
                               check_condition_op, check_condition_value,
                               check_condition, check_conditions_json,
                               check_severity, check_frameworks, check_description,
                               is_system_rule, is_active, needs_review, review_reason

Row granularity: ONE ROW PER RULE (check_rule_id).
  - Discovery-only rows: check columns empty, check_rule_id = ""
  - Multi-condition rules: check_var = primary var; check_conditions_json = full JSON
  - needs_review flags quality issues for manual review

Usage:
    python generate_aws_field_rule_catalog.py           # dry-run (counts only)
    python generate_aws_field_rule_catalog.py --apply   # write CSV
"""

import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml

# ──────────────────────────────────────────────────────────────────────────────
ROOT      = Path('/Users/apple/Desktop/threat-engine')
CHECK_DIR = ROOT / 'catalog/rule/aws_rule_check'
GEN_DIR   = ROOT / 'catalog/discovery_generator/aws'
MASTER_CSV = GEN_DIR / 'aws_master_field_catalog.csv'
OUTPUT_CSV = GEN_DIR / 'aws_field_rule_catalog.csv'

SERVICE_ALIASES: Dict[str, str] = {'acm_pca': 'acm-pca'}
META_DIR = ROOT / 'catalog/rule/aws_rule_metadata'

VALID_OPERATORS = {
    'equals', 'not_equals', 'contains', 'not_contains', 'in', 'not_in',
    'exists', 'not_exists', 'starts_with', 'ends_with',
    'greater_than', 'less_than',
    'greater_than_or_equal', 'less_than_or_equal',
    'greater_than_or_equal_to', 'less_than_or_equal_to',   # aliases
    'is_empty', 'not_empty', 'matches', 'not_matches',
}
VALID_SEVERITIES = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}

COLUMNS = [
    # Discovery
    'csp', 'service', 'field_path', 'item_var_path', 'field_type', 'is_id',
    'producing_op', 'op_kind', 'is_independent', 'root_op', 'chain_ops',
    'chain_length', 'hop_distance', 'chain_ops_with_fields',
    'operators', 'operators_no_value', 'python_call', 'http_path',
    # Resource identity
    'resource_type', 'resource_id_field', 'resource_id_param',
    # Check rule
    'check_rule_id', 'check_for_each', 'check_var',
    'check_condition_op', 'check_condition_value',
    'check_condition', 'check_conditions_json',
    'check_severity', 'check_frameworks', 'check_description',
    'is_system_rule', 'is_active', 'needs_review', 'review_reason',
]

APPLY = '--apply' in sys.argv


# ──────────────────────────────────────────────────────────────────────────────
def _load_yaml(p: Path) -> dict:
    try:
        return yaml.safe_load(p.read_text()) or {}
    except Exception:
        return {}


# ── 1. Load master field catalog ──────────────────────────────────────────────

def load_master() -> List[dict]:
    rows = []
    with MASTER_CSV.open() as f:
        for r in csv.DictReader(f):
            rows.append(dict(r))
    return rows


# ── 2. Build global discovery index: op → set(emit field keys) ───────────────

def build_global_emit_index() -> Dict[str, Set[str]]:
    index: Dict[str, Set[str]] = {}
    for yf in GEN_DIR.glob('*/final_discovery_v1.yaml'):
        data = _load_yaml(yf)
        for disc in data.get('discovery', []):
            did  = disc.get('discovery_id', '')
            emit = disc.get('emit', {})
            item = emit.get('item', {})
            if item:
                keys = set()
                for k in item.keys():
                    keys.add(k.split('.')[0].split('[')[0])
                    keys.add(k)
                index[did] = keys
            else:
                index[did] = {'__stub__'}
    return index


# ── 3. Build resource identity map: (gen_svc, op) → (resource_type, id_field) ─

def build_resource_map() -> Dict[Tuple[str, str], Tuple[str, str]]:
    rmap: Dict[Tuple[str, str], Tuple[str, str]] = {}
    for yf in GEN_DIR.glob('*/final_discovery_v1.yaml'):
        gen_svc = yf.parent.name
        data    = _load_yaml(yf)
        for rii in (data.get('inventory_resource_identifiers') or []):
            op      = rii.get('identifier_op', '')
            rt      = rii.get('resource_type', '')
            id_fld  = rii.get('identifier_field', '')
            if op and rt:
                rmap[(gen_svc, op)] = (rt, id_fld)
    return rmap


# ── 4. Extract vars and conditions from a conditions block ────────────────────

def _extract_primary_var(cond) -> Optional[str]:
    """Return the first var found in conditions."""
    if not cond:
        return None
    if isinstance(cond, dict):
        if 'var' in cond:
            return cond['var']
        for k in ('all', 'any', 'not'):
            sub = cond.get(k)
            if isinstance(sub, list):
                for c in sub:
                    v = _extract_primary_var(c)
                    if v:
                        return v
            elif isinstance(sub, dict):
                v = _extract_primary_var(sub)
                if v:
                    return v
    if isinstance(cond, list):
        for c in cond:
            v = _extract_primary_var(c)
            if v:
                return v
    return None


def _extract_all_condition_leaves(cond) -> List[dict]:
    """Flatten all leaf conditions ({var, op, value}) from a conditions block."""
    leaves = []
    if not cond:
        return leaves
    if isinstance(cond, dict):
        if 'var' in cond:
            return [cond]
        for k in ('all', 'any', 'not'):
            sub = cond.get(k)
            if isinstance(sub, list):
                for c in sub:
                    leaves.extend(_extract_all_condition_leaves(c))
            elif isinstance(sub, dict):
                leaves.extend(_extract_all_condition_leaves(sub))
    elif isinstance(cond, list):
        for c in cond:
            leaves.extend(_extract_all_condition_leaves(c))
    return leaves


def _is_complex(cond) -> bool:
    """True if conditions contain all/any/not nesting."""
    if isinstance(cond, dict):
        return any(k in cond for k in ('all', 'any', 'not'))
    return False


# ── 5. Load rule metadata: {rule_id → {severity, title, description, compliance}} ──

def load_rule_metadata() -> Dict[str, dict]:
    meta: Dict[str, dict] = {}
    if not META_DIR.exists():
        return meta
    for f in META_DIR.glob('**/*.yaml'):
        try:
            data = yaml.safe_load(f.read_text()) or {}
        except Exception:
            continue
        rid = data.get('rule_id', '')
        if rid:
            meta[rid] = {
                'severity':    data.get('severity', '').upper(),
                'title':       data.get('title', ''),
                'description': data.get('description', data.get('rationale', '')),
                'frameworks':  ', '.join(data.get('compliance', [])),
            }
    return meta


# ── 6. Load check rules: {check_svc → [rule_dict, ...]} ─────────────────────

def load_all_check_rules() -> Dict[str, List[dict]]:
    result: Dict[str, List[dict]] = {}
    if not CHECK_DIR.exists():
        return result
    for svc_dir in sorted(CHECK_DIR.iterdir()):
        if not svc_dir.is_dir():
            continue
        cf = svc_dir / f'{svc_dir.name}.checks.yaml'
        if not cf.exists():
            continue
        data = _load_yaml(cf)
        rules = data.get('checks', [])
        if rules:
            result[svc_dir.name] = rules
    return result


# ── 6. Build (producing_op, item_var_path) → master row index ─────────────────

def build_master_index(master: List[dict]) -> Dict[Tuple[str, str], dict]:
    """Index master rows by (producing_op, item_var_path) for fast lookup."""
    idx: Dict[Tuple[str, str], dict] = {}
    for row in master:
        key = (row['producing_op'], row['item_var_path'])
        idx[key] = row
    return idx


# ── 7. Quality check a rule row ───────────────────────────────────────────────

def quality_check(
    check_for_each: str,
    check_var: str,
    check_condition_op: str,
    check_severity: str,
    emit_index: Dict[str, Set[str]],
) -> Tuple[bool, str]:
    """
    Returns (needs_review, reason).
    Runs all checks and collects all issues.
    """
    issues = []

    # 1. for_each op in discovery
    keys = emit_index.get(check_for_each)
    if keys is None:
        # Try dash↔underscore normalisation
        alt = check_for_each.replace('-', '_') if '-' in check_for_each else check_for_each.replace('_', '-', 1)
        keys = emit_index.get(alt)
        if keys is None:
            issues.append('op_not_in_discovery')

    # 2. var field in emit
    if keys and '__stub__' not in keys and check_var and check_var.strip() != 'item':
        path = check_var.removeprefix('item.').strip()
        top  = path.split('.')[0].split('[')[0]
        if top not in keys and path not in keys:
            issues.append('var_not_in_emit')

    # 3. condition_op valid
    if check_condition_op and check_condition_op.lower() not in VALID_OPERATORS:
        issues.append(f'unknown_op:{check_condition_op}')

    # 4. severity valid
    if not check_severity or check_severity.upper() not in VALID_SEVERITIES:
        issues.append(f'invalid_severity:{check_severity}')

    if issues:
        return True, '; '.join(issues)
    return False, ''


# ──────────────────────────────────────────────────────────────────────────────
# MAIN BUILD
# ──────────────────────────────────────────────────────────────────────────────

print('Loading master catalog …', end=' ', flush=True)
master_rows = load_master()
print(f'{len(master_rows)} rows')

print('Building discovery emit index …', end=' ', flush=True)
emit_index = build_global_emit_index()
print(f'{len(emit_index)} ops')

print('Building resource identity map …', end=' ', flush=True)
resource_map = build_resource_map()
print(f'{len(resource_map)} (svc,op) mappings')

print('Loading rule metadata …', end=' ', flush=True)
rule_metadata = load_rule_metadata()
print(f'{len(rule_metadata)} entries')

print('Loading check rules …', end=' ', flush=True)
all_rules = load_all_check_rules()
total_rules = sum(len(v) for v in all_rules.values())
print(f'{total_rules} rules across {len(all_rules)} services')

print()
if not APPLY:
    print('*** DRY RUN — pass --apply to write CSV ***')
print()

# Build master index by (producing_op, item_var_path)
master_idx = build_master_index(master_rows)
# Track which master rows have been claimed by a rule
claimed_keys: Set[Tuple[str, str]] = set()

# ── Enrich master rows with resource identity ─────────────────────────────────
for row in master_rows:
    gen_svc = SERVICE_ALIASES.get(row['service'], row['service'])
    op      = row['producing_op']
    rt, idf = resource_map.get((gen_svc, op), ('', ''))
    # also try exact service match
    if not rt:
        rt, idf = resource_map.get((row['service'], op), ('', ''))
    row['resource_type']     = rt
    row['resource_id_field'] = idf
    row['resource_id_param'] = ''
    # empty check columns
    for col in ['check_rule_id', 'check_for_each', 'check_var',
                'check_condition_op', 'check_condition_value',
                'check_condition', 'check_conditions_json',
                'check_severity', 'check_frameworks', 'check_description',
                'is_system_rule', 'is_active', 'needs_review', 'review_reason']:
        row[col] = ''

# ── Process check rules ───────────────────────────────────────────────────────

rule_rows:    List[dict] = []  # rows with check rule data
orphan_rows:  List[dict] = []  # rules with no matching master field row

stats = {
    'matched': 0,       # rule matched exact master row
    'new_field': 0,     # rule references field not in master emit, new row created
    'op_missing': 0,    # rule's for_each op not in any discovery yaml
    'needs_review': 0,
    'total_rules': 0,
}

for check_svc, rules in sorted(all_rules.items()):
    gen_svc = SERVICE_ALIASES.get(check_svc, check_svc)

    for rule in rules:
        rule_id    = rule.get('rule_id', '')
        for_each   = rule.get('for_each', '')
        conditions = rule.get('conditions')

        # Pull from metadata (canonical source for AWS rules)
        meta        = rule_metadata.get(rule_id, {})
        severity    = meta.get('severity') or rule.get('severity', '').upper() or 'MEDIUM'
        description = meta.get('description') or rule.get('description', '')
        frameworks  = meta.get('frameworks', '')
        rule_title  = meta.get('title', '')

        if not rule_id or not for_each:
            continue

        stats['total_rules'] += 1

        # Extract primary var + condition leaf
        primary_var = _extract_primary_var(conditions) or ''
        leaves      = _extract_all_condition_leaves(conditions)
        primary     = leaves[0] if leaves else {}

        cond_op    = str(primary.get('op', '')).lower() if primary else ''
        cond_val   = str(primary.get('value', '')) if primary and primary.get('value') is not None else ''
        cond_json_single = json.dumps({
            'var':   primary_var,
            'op':    cond_op,
            'value': primary.get('value') if primary else None,
        }) if primary_var else ''

        # Full conditions JSON (for multi-condition rules)
        is_complex = _is_complex(conditions)
        cond_json_full = json.dumps(conditions) if is_complex else ''

        # Quality check
        nr, reason = quality_check(for_each, primary_var, cond_op, severity, emit_index)
        if nr:
            stats['needs_review'] += 1

        # Derive description from rule_id if still missing
        if not description:
            description = rule_title or rule_id.split('.')[-1].replace('_', ' ').title()

        # Build check columns dict
        check_cols = {
            'check_rule_id':         rule_id,
            'check_for_each':        for_each,
            'check_var':             primary_var,
            'check_condition_op':    cond_op,
            'check_condition_value': cond_val,
            'check_condition':       cond_json_single,
            'check_conditions_json': cond_json_full,
            'check_severity':        severity,
            'check_frameworks':      frameworks,
            'check_description':     description,
            'is_system_rule':        'true',
            'is_active':             'true',
            'needs_review':          str(nr).lower(),
            'review_reason':         reason,
        }

        # Try to find matching master row: (for_each, primary_var)
        key = (for_each, primary_var)
        if key in master_idx:
            # Clone the master row and add check columns
            base = dict(master_idx[key])
            base.update(check_cols)
            rule_rows.append(base)
            claimed_keys.add(key)
            stats['matched'] += 1
        else:
            # No exact match — find closest: same producing_op, any field
            # or create minimal new row
            # Check if op exists in discovery
            op_keys = emit_index.get(for_each, emit_index.get(
                for_each.replace('-', '_') if '-' in for_each else for_each.replace('_', '-', 1),
                None
            ))

            if op_keys is None:
                stats['op_missing'] += 1
            else:
                stats['new_field'] += 1

            # Build a minimal discovery row for this rule
            # Find any master row for same op to inherit discovery columns
            op_base_row = next(
                (r for r in master_rows if r['producing_op'] == for_each),
                None
            )

            if op_base_row:
                new_row = dict(op_base_row)
                # Override field-specific columns
                new_row['field_path']    = primary_var.removeprefix('item.').strip()
                new_row['item_var_path'] = primary_var
                new_row['field_type']    = ''
                new_row['is_id']         = 'No'
            else:
                # Completely new row
                new_row = {c: '' for c in COLUMNS}
                new_row['csp']           = 'aws'
                new_row['service']       = gen_svc
                new_row['field_path']    = primary_var.removeprefix('item.').strip()
                new_row['item_var_path'] = primary_var
                new_row['producing_op']  = for_each
                new_row['check_for_each'] = for_each
                # Resource identity
                rt, idf = resource_map.get((gen_svc, for_each), ('', ''))
                new_row['resource_type']     = rt
                new_row['resource_id_field'] = idf
                new_row['resource_id_param'] = ''

            new_row.update(check_cols)
            # Ensure review flag is set for unmatched rows
            if not new_row['needs_review'] or new_row['needs_review'] == 'false':
                new_row['needs_review']  = 'true'
                new_row['review_reason'] = (new_row.get('review_reason') or '') + \
                    ('; ' if new_row.get('review_reason') else '') + 'field_not_in_master'

            rule_rows.append(new_row)

# ── Combine: discovery-only rows + rule rows ──────────────────────────────────
# Discovery-only rows: master rows that were NOT claimed by any rule
discovery_only = [r for r in master_rows
                  if (r['producing_op'], r['item_var_path']) not in claimed_keys]

# Final output: discovery-only first, then rule rows (sorted by service)
all_output_rows = (
    sorted(discovery_only, key=lambda r: (r['service'], r['producing_op'], r['field_path'])) +
    sorted(rule_rows,      key=lambda r: (r['service'], r.get('check_rule_id', ''), r['field_path']))
)

# ── Stats ──────────────────────────────────────────────────────────────────────
print(f'Master rows:           {len(master_rows):>6,}')
print(f'  → claimed by rules:  {len(claimed_keys):>6,}')
print(f'  → discovery-only:    {len(discovery_only):>6,}')
print()
print(f'Rules processed:       {stats["total_rules"]:>6,}')
print(f'  → matched master:    {stats["matched"]:>6,}')
print(f'  → new field rows:    {stats["new_field"]:>6,}')
print(f'  → op missing:        {stats["op_missing"]:>6,}')
print(f'  → needs_review:      {stats["needs_review"]:>6,}')
print()
print(f'Output rows total:     {len(all_output_rows):>6,}')
print(f'  → discovery-only:    {len(discovery_only):>6,}')
print(f'  → with rules:        {len(rule_rows):>6,}')

if APPLY:
    # Ensure all rows have all columns
    clean_rows = []
    for row in all_output_rows:
        clean = {c: row.get(c, '') for c in COLUMNS}
        clean_rows.append(clean)

    with OUTPUT_CSV.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(clean_rows)
    print()
    print(f'Wrote {len(clean_rows):,} rows → {OUTPUT_CSV}')
else:
    print()
    print(f'Would write {len(all_output_rows):,} rows → {OUTPUT_CSV}')
