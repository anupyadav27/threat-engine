#!/usr/bin/env python3
"""
generate_aws_final_discovery.py
================================
Generate final_discovery_v1.yaml for every AWS check-rule service.

Sources (per service):
  - step6_{svc}.discovery.yaml → discovery entries (action, for_each, params, emit.item)
  - step5_resource_catalog_inventory_enrich.json → inventory_resource_identifiers
  - step2_read_operation_registry.json → op metadata (kind, independent)

Scope: only discovery ops referenced in check rules' for_each (same as GCP).

Usage:
    python generate_aws_final_discovery.py           # dry-run
    python generate_aws_final_discovery.py --apply   # write files
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml

# ──────────────────────────────────────────────────────────────────────────────
ROOT      = Path('/Users/apple/Desktop/threat-engine')
CHECK_DIR = ROOT / 'catalog/rule/aws_rule_check'
GEN_DIR   = ROOT / 'catalog/discovery_generator/aws'
# ──────────────────────────────────────────────────────────────────────────────

DRY_RUN = '--apply' not in sys.argv
NOW = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

# check-rule service dir → generator service dir (when they differ)
SERVICE_ALIASES: Dict[str, str] = {
    'acm_pca': 'acm-pca',
}

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
        return json.loads(p.read_text()) or {}
    except Exception:
        return {}


def _pascal_to_snake(name: str) -> str:
    """Convert PascalCase to snake_case. DescribeInstances → describe_instances"""
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


# ──────────────────────────────────────────────────────────────────────────────
# 1. Build global check-rule op scope
# ──────────────────────────────────────────────────────────────────────────────

def build_check_rule_scope() -> Dict[str, Set[str]]:
    """Returns {check_svc → set(for_each_ops)}"""
    scope: Dict[str, Set[str]] = {}
    for svc_dir in CHECK_DIR.iterdir():
        if not svc_dir.is_dir():
            continue
        cf = svc_dir / f'{svc_dir.name}.checks.yaml'
        if not cf.exists():
            continue
        data = _load_yaml(cf)
        ops = set()
        for rule in data.get('checks', []):
            fe = rule.get('for_each', '')
            if fe:
                ops.add(fe)
        if ops:
            scope[svc_dir.name] = ops
    return scope


# ──────────────────────────────────────────────────────────────────────────────
# 2. Load step6 yaml → discovery entries indexed by discovery_id
# ──────────────────────────────────────────────────────────────────────────────

def load_step6_entries(gen_svc: str) -> Dict[str, dict]:
    """Returns {discovery_id → full disc entry dict}"""
    # Find the step6 yaml
    step6_files = list(GEN_DIR.glob(f'{gen_svc}/step6_*.discovery.yaml'))
    if not step6_files:
        return {}
    data = _load_yaml(step6_files[0])
    entries = {}
    for disc in data.get('discovery', []):
        did = disc.get('discovery_id', '')
        if did:
            entries[did] = disc
    return entries


# ──────────────────────────────────────────────────────────────────────────────
# 3. Load step2 → op metadata
# ──────────────────────────────────────────────────────────────────────────────

def load_step2_ops(gen_svc: str) -> Dict[str, dict]:
    """Returns {yaml_action → op_metadata} from step2"""
    p = GEN_DIR / gen_svc / 'step2_read_operation_registry.json'
    if not p.exists():
        return {}
    data = _load_json(p)
    result = {}
    for op_name, op_data in data.get('operations', {}).items():
        action = op_data.get('yaml_action', _pascal_to_snake(op_name))
        result[action] = op_data
        result[op_name] = op_data  # also index by PascalCase
    return result


# ──────────────────────────────────────────────────────────────────────────────
# 4. Build inventory_resource_identifiers from step5
# ──────────────────────────────────────────────────────────────────────────────

def _pick_id_field(emit_item: dict) -> Tuple[str, str]:
    """
    Pick the best identifier field from emit.item.
    Returns (field_name, template_type): 'arn', 'id', 'name'
    """
    fields = list(emit_item.keys())

    # Prefer ARN
    arn_fields = [f for f in fields if f.lower().endswith('arn')]
    if arn_fields:
        return arn_fields[0], 'arn'

    # Then ID
    id_fields = [f for f in fields if f.lower().endswith('id') and 'filter' not in f.lower()]
    if id_fields:
        return id_fields[0], 'id'

    # Then Name
    name_fields = [f for f in fields
                   if f.lower() in ('name', 'bucketname', 'functionname', 'rolename',
                                    'username', 'groupname', 'policyname', 'topicname',
                                    'queuename', 'clustername', 'dbname', 'reponame')
                   or f.lower().endswith('name')]
    if name_fields:
        return name_fields[0], 'name'

    # Fallback: first field
    return (fields[0], 'id') if fields else ('', 'id')


def build_inventory_resource_identifiers(
    gen_svc: str,
    check_svc: str,
    scoped_ops: Set[str],
    step6_entries: Dict[str, dict],
) -> List[dict]:
    """
    Build inventory_resource_identifiers from step5 PRIMARY_RESOURCE entries.
    Only for ops that are in scoped_ops and are independent (no for_each).
    """
    p = GEN_DIR / gen_svc / 'step5_resource_catalog_inventory_enrich.json'
    if not p.exists():
        # Fallback: build from step6 root ops
        return _build_rii_from_step6(gen_svc, check_svc, scoped_ops, step6_entries)

    step5 = _load_json(p)
    resources = step5.get('resources', {})

    rii_rows = []
    seen_ops = set()

    for rname, r in resources.items():
        if r.get('classification') != 'PRIMARY_RESOURCE':
            continue
        if not r.get('can_inventory_from_roots', True):
            continue

        inv_ops = r.get('inventory', {}).get('ops', [])
        for op_meta in inv_ops:
            op_pascal = op_meta.get('operation', '')
            if not op_pascal:
                continue

            # Convert to discovery_id format
            svc_part = op_meta.get('service', gen_svc)
            snake   = _pascal_to_snake(op_pascal)
            did     = f'aws.{svc_part}.{snake}'

            # Only include if this op is in check-rule scope
            if did not in scoped_ops:
                continue
            if did in seen_ops:
                continue

            seen_ops.add(did)

            # Get emit.item for this op to find identifier field
            disc_entry = step6_entries.get(did, {})
            emit_item  = disc_entry.get('emit', {}).get('item', {})
            id_field, id_type = _pick_id_field(emit_item)
            if not id_field:
                continue

            # Build resource_type from resource name
            resource_type = rname.split('_')[0] if '_' in rname else rname

            # Identifier template
            if id_type == 'arn':
                template = '{arn}'
            elif id_type == 'name':
                field_lower = id_field.lower().replace('name', '').rstrip('_')
                template = f'{{{field_lower}name}}' if field_lower else '{name}'
            else:
                field_lower = id_field.lower()
                template = f'{{{field_lower}}}'

            rii_rows.append({
                'resource_type':       resource_type,
                'identifier_op':       did,
                'identifier_field':    id_field,
                'item_var_path':       f'item.{id_field}',
                'identifier_template': template,
            })

    # Deduplicate by identifier_op (keep first)
    seen = set()
    deduped = []
    for r in rii_rows:
        op = r['identifier_op']
        if op not in seen:
            seen.add(op)
            deduped.append(r)

    if not deduped:
        deduped = _build_rii_from_step6(gen_svc, check_svc, scoped_ops, step6_entries)

    return deduped


def _build_rii_from_step6(
    gen_svc: str,
    check_svc: str,
    scoped_ops: Set[str],
    step6_entries: Dict[str, dict],
) -> List[dict]:
    """Fallback: build RII rows from step6 root ops."""
    rows = []
    for did, disc in step6_entries.items():
        if did not in scoped_ops:
            continue
        if disc.get('for_each'):
            continue  # dependent op
        emit_item = disc.get('emit', {}).get('item', {})
        id_field, id_type = _pick_id_field(emit_item)
        if not id_field:
            continue

        svc_part = did.split('.')[1]
        action   = did.split('.')[-1]
        resource_type = action.replace('describe_', '').replace('list_', '').rstrip('s')

        if id_type == 'arn':
            template = '{arn}'
        elif id_type == 'name':
            template = '{name}'
        else:
            template = f'{{{id_field.lower()}}}'

        rows.append({
            'resource_type':       resource_type,
            'identifier_op':       did,
            'identifier_field':    id_field,
            'item_var_path':       f'item.{id_field}',
            'identifier_template': template,
        })
    return rows


# ──────────────────────────────────────────────────────────────────────────────
# 5. Render final_discovery_v1.yaml
# ──────────────────────────────────────────────────────────────────────────────

def render_final_discovery(
    check_svc: str,
    gen_svc: str,
    scoped_ops: Set[str],
    step6_entries: Dict[str, dict],
    rii_rows: List[dict],
    total_check_rules: int,
) -> str:
    """Render the final_discovery_v1.yaml content."""
    # Filter and order discovery entries: root ops first, then dependent
    root_entries = []
    dep_entries  = []
    for did in sorted(scoped_ops):
        if did not in step6_entries:
            continue
        disc = step6_entries[did]
        if disc.get('for_each'):
            dep_entries.append(disc)
        else:
            root_entries.append(disc)

    all_entries = root_entries + dep_entries
    n_ind = len(root_entries)
    n_dep = len(dep_entries)

    lines = []
    lines.append(f'# {"=" * 58}')
    lines.append(f'# Discovery YAML — {check_svc} (final_discovery v1)')
    lines.append(f'# Generated: {NOW}')
    lines.append(f'# Check rules: {total_check_rules} | ops in scope: {len(all_entries)} ({n_ind} independent, {n_dep} dependent)')
    lines.append(f'# {"=" * 58}')
    lines.append(f"version: '1.0'")
    lines.append(f'provider: aws')
    lines.append(f'service: {check_svc}')
    lines.append('')
    lines.append('services:')
    lines.append(f"  client: {gen_svc}")
    lines.append(f"  module: \"boto3.client('{gen_svc}')\"")
    lines.append('')
    lines.append('# Resource identifiers — used by inventory engine for asset dedup/linking')
    lines.append('inventory_resource_identifiers:')

    if rii_rows:
        for r in rii_rows:
            lines.append(f"  - resource_type: {r['resource_type']}")
            lines.append(f"    identifier_op: {r['identifier_op']}")
            lines.append(f"    identifier_field: {r['identifier_field']}")
            lines.append(f"    item_var_path: {r['item_var_path']}")
            lines.append(f"    identifier_template: '{r['identifier_template']}'")
    else:
        lines.append('  []')

    lines.append('')
    lines.append('checks: []')
    lines.append('')
    lines.append('discovery:')
    lines.append('')

    for disc in all_entries:
        did      = disc.get('discovery_id', '')
        for_each = disc.get('for_each', '')
        calls    = disc.get('calls', [])
        emit     = disc.get('emit', {})
        is_dep   = bool(for_each)

        if is_dep:
            lines.append('  # ════ DEPENDENT (enrich) operations ════')
            lines.append(f'  # ── {did} [dependent] ──')
        else:
            lines.append('  # ════ INDEPENDENT (root) operations ════')
            lines.append(f'  # ── {did} ──')

        lines.append(f'  - discovery_id: {did}')
        if for_each:
            lines.append(f'    for_each: {for_each}')
        lines.append('    calls:')

        for call in calls:
            lines.append(f"      - action: {call.get('action', '')}")
            params = call.get('params', {})
            if params:
                lines.append('        params:')
                for pk, pv in params.items():
                    lines.append(f"          {pk}: '{pv}'")
            lines.append("        save_as: response")
            lines.append("        on_error: continue")

        lines.append('    emit:')
        lines.append('      as: item')

        items_for  = emit.get('items_for', '')
        item_dict  = emit.get('item', {})

        if items_for:
            items_for_str = items_for if items_for.startswith('{{') else f'{{{{ {items_for} }}}}'
            lines.append(f"      items_for: '{items_for_str}'")

        if item_dict:
            lines.append('      item:')
            for field, tpl in sorted(item_dict.items()):
                tpl_str = str(tpl)
                # Normalize template format
                if not tpl_str.startswith('{{'):
                    tpl_str = f'{{{{ item.{field} }}}}'
                lines.append(f"        {field}: '{tpl_str}'")

        lines.append('')

    return '\n'.join(lines) + '\n'


# ──────────────────────────────────────────────────────────────────────────────
# 6. Main processing loop
# ──────────────────────────────────────────────────────────────────────────────

def process_service(check_svc: str, scoped_ops: Set[str]) -> Optional[str]:
    """
    Generate final_discovery_v1.yaml content for a check-rule service.
    Returns rendered content string or None if nothing to generate.
    """
    gen_svc = SERVICE_ALIASES.get(check_svc, check_svc)

    # Load step6 entries (ALL ops in the yaml, not just check-rule scoped ones)
    step6_entries = load_step6_entries(gen_svc)
    if not step6_entries:
        # Try hyphenated variant
        gen_svc_hyph = check_svc.replace('_', '-')
        step6_entries = load_step6_entries(gen_svc_hyph)
        if step6_entries:
            gen_svc = gen_svc_hyph

    # How many check rules in this service
    cf = CHECK_DIR / check_svc / f'{check_svc}.checks.yaml'
    check_data = _load_yaml(cf) if cf.exists() else {}
    total_checks = len(check_data.get('checks', []))

    # Filter scoped_ops to those that exist in step6
    covered = scoped_ops & set(step6_entries.keys())
    missing = scoped_ops - covered

    if not covered and not missing:
        return None

    # For missing ops (not in step6), create minimal stub entries
    for did in sorted(missing):
        action = did.split('.')[-1]  # last segment is the action
        # Check if any check rule uses this as a dependent op
        step6_entries[did] = {
            'discovery_id': did,
            'for_each':    '',
            'calls': [{'action': action, 'params': {}, 'save_as': 'response', 'on_error': 'continue'}],
            'emit': {'as': 'item', 'items_for': '{{ response.items }}', 'item': {}},
        }

    # Build identifier rows
    rii_rows = build_inventory_resource_identifiers(gen_svc, check_svc, scoped_ops, step6_entries)

    # Render
    content = render_final_discovery(
        check_svc    = check_svc,
        gen_svc      = gen_svc,
        scoped_ops   = scoped_ops,
        step6_entries= step6_entries,
        rii_rows     = rii_rows,
        total_check_rules = total_checks,
    )
    return content, gen_svc, len(covered), len(missing), len(rii_rows)


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

if DRY_RUN:
    print('*** DRY RUN — pass --apply to write files ***\n')

print('Building check-rule scope …', end=' ', flush=True)
scope = build_check_rule_scope()
print(f'done ({len(scope)} services)')
print()

total_files    = 0
total_ops      = 0
total_missing  = 0
total_rii      = 0

for check_svc, check_ops in sorted(scope.items()):
    result = process_service(check_svc, check_ops)
    if result is None:
        print(f'  SKIP {check_svc} (no step6 data)')
        continue

    content, gen_svc, n_covered, n_missing, n_rii = result

    # Determine output path
    gen_svc_dir = SERVICE_ALIASES.get(check_svc, check_svc)
    out_dir  = GEN_DIR / gen_svc_dir
    out_path = out_dir / 'final_discovery_v1.yaml'

    total_files   += 1
    total_ops     += n_covered + n_missing
    total_missing += n_missing
    total_rii     += n_rii

    miss_str = f'  [{n_missing} STUB]' if n_missing else ''
    status_str = f'ops={n_covered}{miss_str}  rii={n_rii}'

    if DRY_RUN:
        print(f'  [DRY] {check_svc:<30} gen={gen_svc:<25} {status_str}')
    else:
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path.write_text(content)
        print(f'  [+] {check_svc:<30} gen={gen_svc:<25} {status_str}')

print()
print('─' * 60)
action = 'Would write' if DRY_RUN else 'Wrote'
print(f'{action} {total_files} final_discovery_v1.yaml files')
print(f'Total ops: {total_ops} ({total_missing} stubs for missing step6 entries)')
print(f'Total RII rows: {total_rii}')

if not DRY_RUN:
    print()
    print('Next steps:')
    print('  1. python generate_aws_master_field_catalog.py --apply')
    print('  2. python validate_aws_check_vars_vs_discovery.py')
    print('  3. python sync_aws_to_db.py --dry-run')
