#!/usr/bin/env python3
"""
enrich_final_discovery_from_checks.py  (AWS)
=============================================
For each AWS final_discovery_v1.yaml, scan the check rules that reference
each discovery op and add any missing top-level fields to emit.item.

Ensures every `var: item.FIELD` in a check rule has FIELD in the
corresponding emit.item block so the check engine can traverse to it.

Usage:
    python enrich_final_discovery_from_checks.py          # dry-run
    python enrich_final_discovery_from_checks.py --apply  # write files
"""

import re
import sys
from pathlib import Path
from typing import Dict, List, Set

import yaml

# ──────────────────────────────────────────────────────────────────────────────
ROOT      = Path('/Users/apple/Desktop/threat-engine')
CHECK_DIR = ROOT / 'catalog/rule/aws_rule_check'
GEN_DIR   = ROOT / 'catalog/discovery_generator/aws'

SERVICE_ALIASES: Dict[str, str] = {'acm_pca': 'acm-pca'}
# ──────────────────────────────────────────────────────────────────────────────

DRY_RUN = '--apply' not in sys.argv


def _load_yaml(p: Path) -> dict:
    try:
        return yaml.safe_load(p.read_text()) or {}
    except Exception:
        return {}


def extract_vars(cond) -> List[str]:
    if not cond:
        return []
    if isinstance(cond, dict):
        if 'var' in cond:
            return [cond['var']]
        result = []
        for k in ('all', 'any', 'not'):
            sub = cond.get(k)
            if isinstance(sub, list):
                for c in sub:
                    result.extend(extract_vars(c))
            elif isinstance(sub, dict):
                result.extend(extract_vars(sub))
        return result
    if isinstance(cond, list):
        result = []
        for c in cond:
            result.extend(extract_vars(c))
        return result
    return []


# ── Build global map: op → set of required top-level fields from check rules ──

def build_required_fields() -> Dict[str, Set[str]]:
    """Returns {discovery_op → set(top_level_fields)} from all AWS check rules."""
    required: Dict[str, Set[str]] = {}
    for svc_dir in CHECK_DIR.iterdir():
        if not svc_dir.is_dir():
            continue
        checks_f = svc_dir / f'{svc_dir.name}.checks.yaml'
        if not checks_f.exists():
            continue
        data = _load_yaml(checks_f)
        for rule in data.get('checks', []):
            fe = rule.get('for_each', '')
            if not fe:
                continue
            for var in extract_vars(rule.get('conditions')):
                # Skip bare "item" references — no specific field needed
                if not var or var.strip() == 'item':
                    continue
                path = var.removeprefix('item.').strip()
                top  = path.split('.')[0].split('[')[0]
                if top:
                    required.setdefault(fe, set()).add(top)
    return required


# ── Render final_discovery_v1.yaml back to YAML ───────────────────────────────

def _render_final_discovery(data: dict) -> List[str]:
    """Render a final_discovery dict back to YAML lines."""
    lines = []
    lines.append(f"version: '{data.get('version', '1.0')}'")
    lines.append(f"provider: {data.get('provider', 'aws')}")
    lines.append(f"service: {data.get('service', '')}")
    lines.append('')

    svc = data.get('services', {})
    lines.append('services:')
    lines.append(f"  client: {svc.get('client', '')}")
    lines.append(f"  module: \"{svc.get('module', '')}\"")
    lines.append('')

    lines.append('# Resource identifiers — used by inventory engine for asset dedup/linking')
    lines.append('inventory_resource_identifiers:')
    for r in data.get('inventory_resource_identifiers', []):
        lines.append(f"  - resource_type: {r.get('resource_type', '')}")
        lines.append(f"    identifier_op: {r.get('identifier_op', '')}")
        lines.append(f"    identifier_field: {r.get('identifier_field', '')}")
        lines.append(f"    item_var_path: {r.get('item_var_path', '')}")
        if r.get('identifier_template'):
            lines.append(f"    identifier_template: '{r['identifier_template']}'")
    lines.append('')
    lines.append('checks: []')
    lines.append('')
    lines.append('discovery:')
    lines.append('')

    for disc in data.get('discovery', []):
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

        items_for = emit.get('items_for', '')
        item_dict = emit.get('item', {})

        if items_for:
            lines.append(f"      items_for: '{items_for}'")
            if item_dict:
                lines.append('      item:')
                for field, tpl in sorted(item_dict.items()):
                    tpl_str = str(tpl)
                    lines.append(f"        {field}: '{tpl_str}'")
        elif item_dict:
            lines.append('      item:')
            for field, tpl in sorted(item_dict.items()):
                tpl_str = str(tpl)
                lines.append(f"        {field}: '{tpl_str}'")
        else:
            pass  # stub — no item block

        lines.append('')

    return lines


def _rewrite_file(yaml_path: Path, data: dict):
    """Rewrite the final_discovery_v1.yaml preserving header comment."""
    original = yaml_path.read_text()
    header_lines = []
    for line in original.splitlines():
        if line.startswith('#'):
            header_lines.append(line)
        else:
            break

    body_lines = _render_final_discovery(data)
    new_text   = '\n'.join(header_lines) + '\n' + '\n'.join(body_lines) + '\n'
    yaml_path.write_text(new_text)


# ── Patch a final_discovery_v1.yaml file ──────────────────────────────────────

def patch_file(yaml_path: Path, required: Dict[str, Set[str]]) -> int:
    """
    Add missing fields to emit.item blocks.
    Returns number of fields added.
    """
    data    = _load_yaml(yaml_path)
    added   = 0
    patched = False

    for disc in data.get('discovery', []):
        did  = disc.get('discovery_id', '')
        emit = disc.get('emit', {})
        item = emit.get('item')

        if item is None:
            continue  # stub — no emit.item block to patch

        # Current top-level keys
        current_tops: Set[str] = set()
        for k in item.keys():
            top = k.split('.')[0].split('[')[0]
            current_tops.add(top)

        needed  = required.get(did, set())
        missing = needed - current_tops

        if not missing:
            continue

        # Add missing fields to item dict
        for field in sorted(missing):
            item[field] = f'{{{{ item.{field} }}}}'
            added += 1

        patched = True

    if patched and not DRY_RUN:
        _rewrite_file(yaml_path, data)

    return added


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

print('Building required fields from check rules …', end=' ', flush=True)
required = build_required_fields()
total_ops    = len(required)
total_fields = sum(len(v) for v in required.values())
print(f'done ({total_ops} ops, {total_fields} unique fields)')

if DRY_RUN:
    print('*** DRY RUN — pass --apply to write files ***')
print()

yaml_files  = sorted(GEN_DIR.glob('*/final_discovery_v1.yaml'))
grand_total = 0

for yf in yaml_files:
    svc = yf.parent.name
    n   = patch_file(yf, required)
    grand_total += n
    if n > 0:
        action = 'would add' if DRY_RUN else 'added'
        print(f'  [{svc:<25}] {action} {n:3d} missing fields')

print()
print('─' * 50)
action = 'Would add' if DRY_RUN else 'Added'
print(f'{action} {grand_total} fields across {len(yaml_files)} files')
