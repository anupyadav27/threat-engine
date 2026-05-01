#!/usr/bin/env python3
"""
generate_yamls_from_catalog.py
================================
Regenerate both final_discovery_v1.yaml and *.checks.yaml for every AWS
service from aws_field_rule_catalog.csv — the single source of truth.

Outputs:
  catalog/discovery_generator/aws/{service}/final_discovery_v1.yaml
  catalog/rule/aws_rule_check/{service}/{service}.checks.yaml

Usage:
    python generate_yamls_from_catalog.py             # dry-run (show counts)
    python generate_yamls_from_catalog.py --apply     # write files
    python generate_yamls_from_catalog.py --apply --service s3   # one service
    python generate_yamls_from_catalog.py --apply --only-checks  # checks only
    python generate_yamls_from_catalog.py --apply --only-discovery # discovery only
"""

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

# ──────────────────────────────────────────────────────────────────────────────
ROOT        = Path('/Users/apple/Desktop/threat-engine')
GEN_DIR     = ROOT / 'catalog/discovery_generator/aws'
CHECK_DIR   = ROOT / 'catalog/rule/aws_rule_check'
CATALOG_CSV = GEN_DIR / 'aws_field_rule_catalog.csv'
# ──────────────────────────────────────────────────────────────────────────────

APPLY          = '--apply' in sys.argv
ONLY_CHECKS    = '--only-checks' in sys.argv
ONLY_DISCOVERY = '--only-discovery' in sys.argv
TARGET_SVC     = next((sys.argv[i+1] for i, a in enumerate(sys.argv)
                        if a == '--service' and i+1 < len(sys.argv)), None)


# ──────────────────────────────────────────────────────────────────────────────
# Load catalog
# ──────────────────────────────────────────────────────────────────────────────

def load_catalog() -> List[dict]:
    with CATALOG_CSV.open() as f:
        return list(csv.DictReader(f))


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _clean(v: str) -> str:
    return (v or '').strip()


def _bool_str(v: str) -> bool:
    return _clean(v).lower() in ('yes', 'true', '1')


# ──────────────────────────────────────────────────────────────────────────────
# GROUP ROWS BY SERVICE
# ──────────────────────────────────────────────────────────────────────────────

def group_by_service(rows: List[dict]) -> Dict[str, List[dict]]:
    """
    Group by the op's own service (aws.{svc}.{action} → svc), not catalog row service.
    This ensures cross-service ops (e.g. vpc rules using aws.ec2.* ops) go into the
    correct ec2/ discovery directory, not a vpc/ one that would shadow it.
    """
    svc_rows: Dict[str, List[dict]] = defaultdict(list)
    for row in rows:
        op = _clean(row.get('producing_op', ''))
        if op:
            parts = op.split('.')
            # aws.{service}.{action...}  → service = parts[1]
            disc_svc = parts[1] if len(parts) >= 3 else _clean(row['service'])
        else:
            disc_svc = _clean(row['service'])
        if disc_svc:
            svc_rows[disc_svc].append(row)
    return dict(svc_rows)


# ──────────────────────────────────────────────────────────────────────────────
# GENERATE final_discovery_v1.yaml for a service
# ──────────────────────────────────────────────────────────────────────────────

def _extract_condition_vars(conditions_json: str) -> List[str]:
    """
    Extract all 'var' values from a check_conditions_json string.
    Returns a list of item_var_path strings like 'item.OwnerId'.
    """
    if not conditions_json:
        return []
    try:
        data = json.loads(conditions_json)
    except Exception:
        return []
    vars_found: List[str] = []

    def _walk(obj: object) -> None:
        if isinstance(obj, dict):
            if 'var' in obj:
                v = obj['var']
                if isinstance(v, str) and v.startswith('item.'):
                    vars_found.append(v)
            for val in obj.values():
                _walk(val)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(data)
    return vars_found


def _build_discovery_yaml(service: str, rows: List[dict]) -> str:
    """
    Build final_discovery_v1.yaml content from catalog rows for one service.
    Groups rows by producing_op to reconstruct emit.item blocks.
    Reconstructs for_each chains from chain_ops / root_op columns.
    Also adds secondary condition vars from check_conditions_json so all
    multi-condition rule fields appear in emit.item.
    """
    # Collect unique ops in order (independent first, then dependent)
    ops_seen:  Dict[str, dict] = {}   # discovery_id → op_meta
    emit_items: Dict[str, Dict[str, str]] = defaultdict(dict)  # discovery_id → {field: template}

    for row in rows:
        op   = _clean(row['producing_op'])
        fld  = _clean(row['field_path'])
        var  = _clean(row['item_var_path'])
        if not op:
            continue

        if op not in ops_seen:
            root  = _clean(row['root_op'])
            is_indep = _bool_str(row['is_independent'])
            for_each = '' if is_indep else root

            # python_call → action (last part before '()')
            pcall  = _clean(row['python_call'])
            action = ''
            if '.(' in pcall or '(' in pcall:
                # "client.list_buckets()" → "list_buckets"
                import re
                m = re.search(r'\.(\w+)\(', pcall)
                if m:
                    action = m.group(1)

            ops_seen[op] = {
                'discovery_id': op,
                'for_each':     for_each,
                'action':       action,
                'op_kind':      _clean(row['op_kind']),
                'is_independent': is_indep,
            }

        # Collect primary emit field
        if fld and var:
            emit_items[op][fld] = f'{{{{ {var} }}}}'

        # Also collect secondary vars from check_conditions_json
        cond_json = _clean(row.get('check_conditions_json', ''))
        if cond_json:
            for cvar in _extract_condition_vars(cond_json):
                # cvar = 'item.SomeField' or 'item.Nested.Path'
                top = cvar[len('item.'):].split('.')[0]   # top-level field name
                if top and top not in emit_items[op]:
                    emit_items[op][top] = f'{{{{ {cvar} }}}}'

    # Build RII from rows with resource_type + is_id
    rii_map: Dict[str, dict] = {}   # op → rii entry
    for row in rows:
        op     = _clean(row['producing_op'])
        rt     = _clean(row['resource_type'])
        id_fld = _clean(row['resource_id_field'])
        if rt and id_fld and op and op not in rii_map:
            rii_map[op] = {
                'resource_type':      rt,
                'identifier_op':      op,
                'identifier_field':   id_fld,
                'item_var_path':      f'item.{id_fld}',
                'identifier_template': f'{{{id_fld.lower()}}}',
            }

    # Sort ops: independent first, then dependent
    indep_ops = [o for o in ops_seen.values() if o['is_independent']]
    dep_ops   = [o for o in ops_seen.values() if not o['is_independent']]

    # Detect client from python_call
    client_name = service
    for row in rows:
        pcall = _clean(row['python_call'])
        if pcall:
            import re
            m = re.search(r'client\.(\w+)', pcall)
            if not m:
                m = re.search(r"boto3\.client\(['\"](\S+?)['\"]\)", pcall)
            if m:
                client_name = service
            break

    # Infer params for dependent ops from chain_ops column
    # chain_ops: "root_op -> dep_op"  — params come from original step6 yaml (best effort)
    # We'll reconstruct minimal params from the check_var references in catalog rows
    def _infer_params(op: str) -> dict:
        """Infer call params for dependent ops from original final_discovery yaml."""
        params = {}
        for row in rows:
            if _clean(row['producing_op']) != op:
                continue
            # Try to get from original final_discovery yaml
            existing = GEN_DIR / service / 'final_discovery_v1.yaml'
            if existing.exists():
                try:
                    import yaml
                    data = yaml.safe_load(existing.read_text()) or {}
                    for disc in data.get('discovery', []):
                        if disc.get('discovery_id') == op:
                            calls = disc.get('calls', [])
                            if calls:
                                return calls[0].get('params', {})
                except Exception:
                    pass
            break
        return params

    # ── Render YAML ──────────────────────────────────────────────────────────
    lines = []
    svc_display = service
    total_rules  = len([r for r in rows if _clean(r.get('check_rule_id',''))])
    n_indep = len(indep_ops)
    n_dep   = len(dep_ops)
    lines.append(f'# ==========================================================')
    lines.append(f'# Discovery YAML — {svc_display} (final_discovery v1)')
    lines.append(f'# Generated from: aws_field_rule_catalog.csv')
    lines.append(f'# Check rules: {total_rules} | ops: {n_indep} independent, {n_dep} dependent')
    lines.append(f'# ==========================================================')
    lines.append(f"version: '1.0'")
    lines.append(f"provider: aws")
    lines.append(f"service: {service}")
    lines.append('')
    lines.append('services:')
    lines.append(f"  client: {client_name}")
    lines.append(f"  module: \"boto3.client('{client_name}')\"")
    lines.append('')

    lines.append('# Resource identifiers — used by inventory engine for asset dedup/linking')
    lines.append('inventory_resource_identifiers:')
    if rii_map:
        for rii in rii_map.values():
            lines.append(f"  - resource_type: {rii['resource_type']}")
            lines.append(f"    identifier_op: {rii['identifier_op']}")
            lines.append(f"    identifier_field: {rii['identifier_field']}")
            lines.append(f"    item_var_path: {rii['item_var_path']}")
            lines.append(f"    identifier_template: '{rii['identifier_template']}'")
    else:
        lines.append('  []')
    lines.append('')
    lines.append('checks: []')
    lines.append('')
    lines.append('discovery:')
    lines.append('')

    for group_label, op_group in [('INDEPENDENT', indep_ops), ('DEPENDENT', dep_ops)]:
        for op_meta in op_group:
            op       = op_meta['discovery_id']
            for_each = op_meta['for_each']
            action   = op_meta['action']
            items    = emit_items.get(op, {})

            label = '[dependent]' if for_each else ''
            lines.append(f'  # ════ {group_label} ({"enrich" if for_each else "root"}) operations ════')
            lines.append(f'  # ── {op} {label} ──')
            lines.append(f'  - discovery_id: {op}')
            if for_each:
                lines.append(f'    for_each: {for_each}')
            lines.append('    calls:')
            lines.append(f"      - action: {action}")

            params = _infer_params(op) if for_each else {}
            if params:
                lines.append('        params:')
                for pk, pv in params.items():
                    pv_s = str(pv)
                    if "'" in pv_s or pv_s.startswith('[') or pv_s.startswith('{'):
                        lines.append(f'          {pk}: "{pv_s}"')
                    else:
                        lines.append(f"          {pk}: '{pv_s}'")
            lines.append("        save_as: response")
            lines.append("        on_error: continue")

            lines.append('    emit:')
            lines.append('      as: item')
            if items:
                # Determine items_for
                existing_if = None
                existing_yaml = GEN_DIR / service / 'final_discovery_v1.yaml'
                if existing_yaml.exists():
                    try:
                        import yaml as _yaml
                        data = _yaml.safe_load(existing_yaml.read_text()) or {}
                        for disc in data.get('discovery', []):
                            if disc.get('discovery_id') == op:
                                existing_if = disc.get('emit', {}).get('items_for', '')
                                break
                    except Exception:
                        pass

                items_for = existing_if or '{{ response.items }}'
                lines.append(f"      items_for: '{items_for}'")
                lines.append('      item:')
                for fld, tpl in sorted(items.items()):
                    # Use double quotes if key or value contains single quotes
                    if "'" in fld:
                        safe_key = f'"{fld}"'
                    else:
                        safe_key = fld
                    if "'" in tpl:
                        safe_val = f'"{tpl}"'
                    else:
                        safe_val = f"'{tpl}'"
                    lines.append(f"        {safe_key}: {safe_val}")
            lines.append('')

    return '\n'.join(lines) + '\n'


# ──────────────────────────────────────────────────────────────────────────────
# GENERATE *.checks.yaml for a service
# ──────────────────────────────────────────────────────────────────────────────

def _parse_condition_from_row(row: dict) -> Optional[dict]:
    """
    Reconstruct condition dict from catalog columns.
    Priority: check_conditions_json (complex) → check_condition (single JSON) → columns
    """
    cj = _clean(row.get('check_conditions_json', ''))
    if cj:
        try:
            return json.loads(cj)
        except Exception:
            pass

    cj2 = _clean(row.get('check_condition', ''))
    if cj2:
        try:
            return json.loads(cj2)
        except Exception:
            pass

    # Reconstruct from individual columns
    var = _clean(row.get('check_var', ''))
    op  = _clean(row.get('check_condition_op', ''))
    val_raw = _clean(row.get('check_condition_value', ''))

    if not var or not op:
        return None

    # Type-coerce value
    if val_raw == '' or val_raw.lower() == 'null':
        val = None
    elif val_raw.lower() in ('true', 'false'):
        val = val_raw.lower() == 'true'
    else:
        # Try numeric
        try:
            val = int(val_raw)
        except ValueError:
            try:
                val = float(val_raw)
            except ValueError:
                val = val_raw

    return {'var': var, 'op': op, 'value': val}


def _build_checks_yaml(check_svc: str, rule_rows: List[dict]) -> str:
    """Build {service}.checks.yaml from catalog rows that have check_rule_id."""
    lines = []
    lines.append(f"version: '1.0'")
    lines.append(f"provider: aws")
    lines.append(f"service: {check_svc}")
    lines.append('checks:')

    for row in sorted(rule_rows, key=lambda r: _clean(r.get('check_rule_id', ''))):
        rule_id  = _clean(row.get('check_rule_id', ''))
        for_each = _clean(row.get('check_for_each', ''))
        severity = _clean(row.get('check_severity', 'MEDIUM'))

        if not rule_id or not for_each:
            continue

        cond = _parse_condition_from_row(row)
        if cond is None:
            continue

        lines.append(f'- rule_id: {rule_id}')
        lines.append(f'  for_each: {for_each}')
        lines.append(f'  severity: {severity}')

        # Render conditions
        def _yaml_scalar(v) -> str:
            """Safely render a scalar value for YAML output."""
            if v is None:
                return 'null'
            if isinstance(v, bool):
                return str(v).lower()
            if isinstance(v, (int, float)):
                return str(v)
            s = str(v)
            # If value contains single quotes or looks like a list/dict, use double quotes
            if "'" in s or s.startswith('[') or s.startswith('{'):
                escaped = s.replace('"', '\\"')
                return f'"{escaped}"'
            return f"'{s}'"

        def _render_cond(c, indent=2) -> List[str]:
            pad = '  ' * indent
            if isinstance(c, dict):
                if 'var' in c:
                    clines = []
                    clines.append(f'{pad}var: {c["var"]}')
                    clines.append(f'{pad}op: {c["op"]}')
                    clines.append(f'{pad}value: {_yaml_scalar(c.get("value"))}')
                    return clines
                for key in ('all', 'any', 'not'):
                    if key in c:
                        sub = c[key]
                        result = [f'{pad}{key}:']
                        if isinstance(sub, list):
                            for item in sub:
                                sub_lines = _render_cond(item, indent + 1)
                                if sub_lines:
                                    result.append(f'{pad}- ' + sub_lines[0].lstrip())
                                    result.extend(sub_lines[1:])
                        elif isinstance(sub, dict):
                            sub_lines = _render_cond(sub, indent + 1)
                            result.extend(sub_lines)
                        return result
            return []

        cond_lines = _render_cond(cond, indent=2)
        lines.append('  conditions:')
        for cl in cond_lines:
            lines.append(cl)

    return '\n'.join(lines) + '\n'


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

if not APPLY:
    print('*** DRY RUN — pass --apply to write files ***')
print()

print(f'Loading catalog: {CATALOG_CSV}')
rows = load_catalog()
print(f'  {len(rows):,} rows loaded')
print()

# Group by service (use check_for_each's service for check rows; producing_op's service for discovery)
svc_rows = group_by_service(rows)

# For check rules: group by the check service (service column of the rule row)
# The 'service' column in catalog rows for rule rows = gen_svc (the generator dir)
# But check rules are keyed by check_svc (the rule dir name, e.g. acm_pca vs acm-pca)
# We can derive check_svc from check_rule_id: rule_id[1] is the service component
def _check_svc_from_rule_id(rule_id: str) -> str:
    parts = rule_id.split('.')
    return parts[1] if len(parts) >= 2 else ''

# Build check_svc → rule rows
check_svc_rows: Dict[str, List[dict]] = defaultdict(list)
for row in rows:
    rid = _clean(row.get('check_rule_id', ''))
    if not rid:
        continue
    cs = _check_svc_from_rule_id(rid)
    if cs:
        check_svc_rows[cs].append(row)

# Stats
disc_written  = 0
disc_skipped  = 0
check_written = 0
check_skipped = 0

# ── Discovery YAMLs ───────────────────────────────────────────────────────────
if not ONLY_CHECKS:
    print('── Discovery YAMLs ──────────────────────────────────────────────────')
    for service, svc_row_list in sorted(svc_rows.items()):
        if TARGET_SVC and service != TARGET_SVC:
            continue

        out_path = GEN_DIR / service / 'final_discovery_v1.yaml'
        content  = _build_discovery_yaml(service, svc_row_list)

        n_ops   = len(set(r['producing_op'] for r in svc_row_list if r['producing_op']))
        n_rules = len([r for r in svc_row_list if r.get('check_rule_id','').strip()])

        if APPLY:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(content)
            disc_written += 1
            print(f'  [w] {service:<28} ops={n_ops:3d}  rules={n_rules:4d}')
        else:
            disc_skipped += 1
            print(f'  [d] {service:<28} ops={n_ops:3d}  rules={n_rules:4d}')
    print()

# ── Check rule YAMLs ──────────────────────────────────────────────────────────
if not ONLY_DISCOVERY:
    print('── Check rule YAMLs ─────────────────────────────────────────────────')
    for check_svc, rule_row_list in sorted(check_svc_rows.items()):
        if TARGET_SVC and check_svc != TARGET_SVC:
            continue

        out_path = CHECK_DIR / check_svc / f'{check_svc}.checks.yaml'
        content  = _build_checks_yaml(check_svc, rule_row_list)
        n_rules  = len([r for r in rule_row_list if r.get('check_rule_id','').strip()])

        if APPLY:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(content)
            check_written += 1
            print(f'  [w] {check_svc:<28} rules={n_rules:4d}')
        else:
            check_skipped += 1
            print(f'  [d] {check_svc:<28} rules={n_rules:4d}')
    print()

# ── Summary ───────────────────────────────────────────────────────────────────
print('═' * 60)
if APPLY:
    if not ONLY_CHECKS:
        print(f'Discovery YAMLs written:   {disc_written}')
    if not ONLY_DISCOVERY:
        print(f'Check rule YAMLs written:  {check_written}')
else:
    if not ONLY_CHECKS:
        print(f'Discovery YAMLs (would write): {disc_skipped}')
    if not ONLY_DISCOVERY:
        print(f'Check rule YAMLs (would write): {check_skipped}')
print()
print('Round-trip complete: aws_field_rule_catalog.csv → YAML files')
