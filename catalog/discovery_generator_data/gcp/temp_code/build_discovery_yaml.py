#!/usr/bin/env python3
"""
Step-8: Discovery YAML Generator
Build <service>.discovery.yaml for each GCP service from the step6 resource catalog.

INPUT (per service directory):
  step5_resource_catalog_inventory_enrich.json
  step3_read_operation_dependency_chain_independent.json  (for chain details)

OUTPUT (per service directory):
  step6_<service>.discovery.yaml

CLI:
  python build_discovery_yaml.py --service abusiveexperiencereport
  python build_discovery_yaml.py --all
  python build_discovery_yaml.py \\
      --catalog /path/to/step5_resource_catalog_inventory_enrich.json \\
      --chains  /path/to/step3_read_operation_dependency_chain_independent.json \\
      --out     /path/to/output.discovery.yaml
"""

import json
import argparse
import sys
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

# ─────────────────────────────────────────────────────────────────────────────
# YAML WRITER  (hand-rolled — no PyYAML dependency; preserves comments & order)
# ─────────────────────────────────────────────────────────────────────────────

def _indent(text: str, n: int) -> str:
    pad = ' ' * n
    return '\n'.join(pad + line if line.strip() else line for line in text.splitlines())


def _scalar(value) -> str:
    """Render a Python value as a YAML scalar (inline)."""
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (int, float)):
        return str(value)
    s = str(value)
    # Quote if it contains special chars or looks like a bool/null/number
    need_quote = (
        not s
        or s[0] in ('{', '[', '!', '&', '*', '#', '?', '|', '-', '<', '>', '=',
                     '`', ',', '"', "'", '%', '@')
        or ':' in s
        or '#' in s
        or s in ('true', 'false', 'null', 'yes', 'no', 'on', 'off')
        or s[0].isdigit()
        or s.startswith('- ')
        or '\n' in s
    )
    if need_quote:
        escaped = s.replace('\\', '\\\\').replace('"', '\\"')
        return f'"{escaped}"'
    return s


def _yaml_dict(d: dict, indent: int = 0) -> str:
    """Recursively render a dict as YAML block."""
    lines = []
    pad = ' ' * indent
    for k, v in d.items():
        key = _scalar(k) if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', str(k)) else str(k)
        if isinstance(v, dict):
            if v:
                lines.append(f'{pad}{key}:')
                lines.append(_yaml_dict(v, indent + 2))
            else:
                lines.append(f'{pad}{key}: {{}}')
        elif isinstance(v, list):
            if v:
                lines.append(f'{pad}{key}:')
                lines.append(_yaml_list(v, indent + 2))
            else:
                lines.append(f'{pad}{key}: []')
        else:
            lines.append(f'{pad}{key}: {_scalar(v)}')
    return '\n'.join(lines)


def _yaml_list(lst: list, indent: int = 0) -> str:
    """Recursively render a list as YAML block."""
    lines = []
    pad = ' ' * indent
    for item in lst:
        if isinstance(item, dict):
            items_str = _yaml_dict(item, indent + 2)
            first_line = items_str.lstrip()
            rest = '\n'.join(items_str.splitlines()[1:]) if '\n' in items_str else ''
            lines.append(f'{pad}- {first_line.split(chr(10))[0]}')
            for extra in items_str.splitlines()[1:]:
                lines.append(extra)
        elif isinstance(item, list):
            lines.append(f'{pad}-')
            lines.append(_yaml_list(item, indent + 2))
        else:
            lines.append(f'{pad}- {_scalar(item)}')
    return '\n'.join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _op_short(op_key: str) -> str:
    """gcp.abusiveexperiencereport.violatingSites.list → violatingSites.list"""
    parts = op_key.split('.')
    return '.'.join(parts[2:]) if len(parts) > 2 else op_key


def _resource_from_op(op_key: str) -> str:
    parts = op_key.split('.')
    return parts[-2] if len(parts) >= 3 else parts[-1]


def _verb_from_op(op_key: str) -> str:
    return op_key.split('.')[-1]


def _build_var_name(resource_type: str, suffix: str = 'list') -> str:
    """Build a clean variable name: sites_list, instances_result, etc."""
    return f'{resource_type}_{suffix}'


def _jinja(expr: str) -> str:
    return '{{ ' + expr + ' }}'


_ANCHOR_VAR_PREFIXES = {
    # Leading template variable → literal prefix to prepend to canonical path
    'project':      'projects/',
    'projectid':    'projects/',
    'projectname':  'projects/',
    'organization': 'organizations/',
    'org':          'organizations/',
    'folder':       'folders/',
}


def _canonicalize_full_name_template(tmpl: str) -> str:
    """
    Prepend the standard GCP hierarchy prefix when the template starts with
    a bare anchor variable like {project}/zones/...
    Returns the canonicalized template string.
    """
    t = tmpl.strip().lstrip('/')
    # Normalize {+var}/{*var} → {var}
    t = re.sub(r'\{[+*]?(\w+)\}', r'{\1}', t)
    segments = t.split('/')
    if not segments:
        return t
    m = re.match(r'^\{(\w+)\}$', segments[0])
    if m:
        var_lower = m.group(1).lower()
        prefix = _ANCHOR_VAR_PREFIXES.get(var_lower)
        if prefix:
            return prefix + t
    return t


def _url_encode_expr(field_expr: str) -> str:
    return f'url_encode({field_expr})'


def _apply_transforms(transforms: list, item_var: str) -> tuple[list, str]:
    """
    Process the transforms list and return:
      (vars_block_list, final_name_expr)
    vars_block_list = list of {name: expr} dicts for the YAML vars: block
    final_name_expr = the Jinja expression for the final identifier param
    """
    vars_block = []
    expr_map = {}  # to_var → jinja expression

    for t in transforms:
        if 'build' in t:
            continue  # full_id template — handled separately
        from_field = t.get('from', '')
        fn = t.get('fn', '')
        to_var = t.get('to', '')

        # Convert from_field to a Jinja expression
        if '[].' in from_field:
            # e.g. "violatingSites[].reviewedSite" → item_var.reviewedSite
            field_name = from_field.split('[].')[-1]
            from_expr = f'{item_var}.{field_name}'
        elif from_field in expr_map:
            from_expr = expr_map[from_field]
        else:
            from_expr = f'{item_var}.{from_field}'

        if fn == 'url_encode':
            out_expr = _url_encode_expr(from_expr)
        elif fn.startswith('prefix:'):
            prefix_val = fn[len('prefix:'):]
            out_expr = f'"{prefix_val}" ~ {from_expr}'
        elif fn.startswith('join_with:'):
            sep = fn[len('join_with:'):]
            out_expr = f'{from_expr} | join("{sep}")'
        else:
            out_expr = from_expr  # identity

        expr_map[to_var] = out_expr
        vars_block.append({to_var: _jinja(out_expr)})

    # The final identifier is the last transform's 'to' variable
    last_to = transforms[-1].get('to') if transforms and 'to' in transforms[-1] else None
    if last_to and last_to in expr_map:
        final_expr = _jinja(expr_map[last_to])
    elif transforms:
        # Find the 'to' in the last non-build transform
        for t in reversed(transforms):
            if 'to' in t and t['to'] in expr_map:
                final_expr = _jinja(expr_map[t['to']])
                break
        else:
            final_expr = _jinja(last_to or 'name')
    else:
        final_expr = _jinja('name')

    return vars_block, final_expr


# ─────────────────────────────────────────────────────────────────────────────
# SELECTIVE RULES GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

_SELECTIVE_RULES_DEFAULTS = {
    # service → list of (condition_expr, field_hint) tuples
    # Use {item} as placeholder; it will be replaced with the actual item_var
    'abusiveexperiencereport': [
        ("{item}.abusiveStatus != 'PASSING'",  'abusiveStatus not passing'),
        ('{item}.underReview == true',          'currently under review'),
        ("{item}.filterStatus not in ('OFF', 'UNKNOWN_FILTER')",
         'active filtering in place'),
    ],
}

_GENERIC_SELECTIVE_RULES = [
    ('{item}.status not in ("ACTIVE", "RUNNING")', 'non-healthy status'),
    ('{item}.get("error") is not none',             'item has error field'),
]


def _selective_rules(service: str, item_var: str, resource_type: str) -> list:
    """Generate selective enrichment rules for the given service/resource."""
    service_rules = _SELECTIVE_RULES_DEFAULTS.get(service)
    if service_rules:
        rules = []
        for expr, comment in service_rules:
            # Replace {item} placeholder with the actual item_var
            actual_expr = expr.replace('{item}', item_var)
            rules.append({'when': _jinja(actual_expr), 'do': 'enrich'})
        rules.append({'default': 'skip'})
        return rules

    # Generic fallback
    rules = []
    for expr, _ in _GENERIC_SELECTIVE_RULES:
        actual_expr = expr.replace('{item}', item_var)
        rules.append({'when': _jinja(actual_expr), 'do': 'enrich'})
    rules.append({'default': 'skip'})
    return rules


# ─────────────────────────────────────────────────────────────────────────────
# DISCOVERY BLOCK BUILDER  (one per resource_type)
#
# Canonical block structure (per GPT spec):
#
# INVENTORY stage:
#   - discovery_id: <svc>.<resource>.inventory
#     calls:   [list/search op]
#     emit:
#       as: <resource>_inventory_item
#       items_for: "{{ <list_var>.<list_field> }}"
#       item:
#         <field>: "{{ item.<field> }}"        ← "item" is the loop var (built-in)
#         url_encoded_*: "{{ url_encode(item.<src>) }}"   ← constructed-id helpers
#         name: "{{ '<prefix>/' ~ url_encoded_* }}"
#         _full_id: "{{ name }}"
#
# ENRICH stage (when enrich ops exist):
#   - discovery_id: <svc>.<resource>.enrich
#     foreach:
#       from: "{{ <list_var>.<list_field> }}"
#       as: <singular>_item                    ← named var for decision rules
#     decision:
#       mode: selective | always | never
#       rules: [...]
#     vars:
#       url_encoded_*: "{{ url_encode(<singular>_item.<src>) }}"
#       name: "{{ '<prefix>/' ~ url_encoded_* }}"
#       _full_id: "{{ name }}"
#     calls:   [get op, params reference vars]
#     emit:
#       as: <resource>_enriched_item
#       items_for: "{{ [<detail_var>] }}"      ← wrap single get result in list
#       item:
#         _full_id: "{{ _full_id }}"
#         <field>: "{{ item.<field> }}"        ← from get response via items_for loop
# ─────────────────────────────────────────────────────────────────────────────

def _build_discovery_block(
    service: str,
    resource_type: str,
    rdata: dict,
    chains: dict,
    enrichment_mode: str = 'selective',
) -> str:
    """
    Build YAML for one resource_type (inventory + optional enrich stage).
    Returns the YAML text block (caller will prepend to discovery: list).
    """
    identifier = rdata.get('identifier', {})
    inv_ops    = rdata.get('inventory', {}).get('ops', [])
    enrich_ops = rdata.get('inventory_enrich', {}).get('ops', [])
    pattern    = rdata.get('pattern_type', 'CONSTRUCTED')
    confidence = rdata.get('confidence', 0.0)
    id_kind    = identifier.get('kind', 'tuple')
    transforms = identifier.get('transforms', [])

    if not inv_ops:
        return ''

    # ── Primary inventory op ──────────────────────────────────────────────
    inv_op     = inv_ops[0]
    inv_op_key = inv_op['op']
    inv_res    = _resource_from_op(inv_op_key)
    produces   = inv_op.get('produces', {})

    # Detect list_field from produces paths (e.g. 'violatingSites[].reviewedSite' → 'violatingSites')
    list_field: Optional[str] = None
    for logical, fp in produces.items():
        if '[].' in fp:
            list_field = fp.split('[].')[0]
            break

    # Variable names
    list_var     = _build_var_name(resource_type, 'list')       # sites_list
    detail_var   = _build_var_name(resource_type, 'detail')     # sites_detail
    # Named item variable for foreach / decision rules (singular of resource_type)
    _rt_singular = resource_type[:-1] if resource_type.endswith('s') else resource_type
    item_var     = f'{_rt_singular}_item'                       # site_item

    # items_for expression
    items_for_expr = (
        f'"{_jinja(list_var + "." + list_field)}"'
        if list_field
        else f'"{_jinja(list_var)}"'
    )

    # ── Compute identifier transform vars ─────────────────────────────────
    # For constructed IDs: build a list of (var_name, jinja_expr) tuples.
    # These go into emit.item (inventory stage, using "item.") and
    # into vars: (enrich stage, using item_var.).
    transform_vars: list[tuple[str, str]] = []   # [(var_name, jinja_expr_with_item_dot)]
    enrich_transform_vars: list[tuple[str, str]] = []  # [(var_name, jinja_expr_with_item_var_dot)]

    # Also track final 'name' var name (the enrich param)
    final_id_var = 'name'

    if id_kind == 'constructed' and transforms:
        expr_map_item    = {}  # to_var → raw expr using "item."
        expr_map_itemvar = {}  # to_var → raw expr using item_var (e.g. "site_item.")

        for t in transforms:
            if 'build' in t:
                continue
            from_field = t.get('from', '')
            fn         = t.get('fn', '')
            to_var     = t.get('to', '')
            if not to_var:
                continue

            # Source expression using "item." (for inventory emit.item context)
            if '[].' in from_field:
                src_field = from_field.split('[].')[-1]
                from_item    = f'item.{src_field}'
                from_itemvar = f'{item_var}.{src_field}'
            elif from_field in expr_map_item:
                from_item    = expr_map_item[from_field]
                from_itemvar = expr_map_itemvar[from_field]
            else:
                from_item    = f'item.{from_field}'
                from_itemvar = f'{item_var}.{from_field}'

            # Apply function
            if fn == 'url_encode':
                out_item    = f'url_encode({from_item})'
                out_itemvar = f'url_encode({from_itemvar})'
            elif fn.startswith('prefix:'):
                prefix = fn[len('prefix:'):]
                out_item    = f"'{prefix}' ~ {from_item}"
                out_itemvar = f"'{prefix}' ~ {from_itemvar}"
            elif fn.startswith('join_with:'):
                sep = fn[len('join_with:'):]
                out_item    = f'{from_item} | join("{sep}")'
                out_itemvar = f'{from_itemvar} | join("{sep}")'
            else:
                out_item    = from_item
                out_itemvar = from_itemvar

            expr_map_item[to_var]    = out_item
            expr_map_itemvar[to_var] = out_itemvar
            transform_vars.append((to_var, out_item))
            enrich_transform_vars.append((to_var, out_itemvar))
            final_id_var = to_var  # last 'to' is the final identifier var

        # Add _full_id alias pointing to final_id_var (for clarity)
        transform_vars.append(('_full_id', final_id_var))
        enrich_transform_vars.append(('_full_id', final_id_var))

    elif id_kind == 'full_name':
        # Build _full_id from HTTP path template (canonicalized to include projects/ prefix)
        raw_tmpl = identifier.get('full_identifier', {}).get('template', '')
        # Filter bare single-var templates like "{name}" — handled below
        bare_name_tmpl = re.match(r'^\{[+*]?\w+\}$', raw_tmpl.strip())
        if raw_tmpl and not bare_name_tmpl:
            # Canonicalize: prepend projects/ etc. if template starts with {project}
            tmpl = _canonicalize_full_name_template(raw_tmpl)

            def _resolve_full_name_part(m):
                part = m.group(1)
                if part in ('project', 'projectId', 'project_id'):
                    return _jinja('project_id')
                elif part == 'zone':
                    return _jinja('zone')
                elif part == 'region':
                    return _jinja('region')
                elif part in ('location', 'locationsId'):
                    return _jinja('location')
                elif part in ('organization', 'org'):
                    return _jinja('org_id')
                elif part == 'folder':
                    return _jinja('folder_id')
                else:
                    return _jinja(f'item.{part}')
            full_id_val = re.sub(r'\{(\w+)\}', _resolve_full_name_part, tmpl)
            transform_vars.append(('_full_id', full_id_val))

            def _resolve_full_name_part_var(m):
                part = m.group(1)
                if part in ('project', 'projectId', 'project_id'):
                    return _jinja('project_id')
                elif part == 'zone':
                    return _jinja('zone')
                elif part == 'region':
                    return _jinja('region')
                elif part in ('location', 'locationsId'):
                    return _jinja('location')
                elif part in ('organization', 'org'):
                    return _jinja('org_id')
                elif part == 'folder':
                    return _jinja('folder_id')
                else:
                    return _jinja(f'{item_var}.{part}')
            full_id_val_var = re.sub(r'\{(\w+)\}', _resolve_full_name_part_var, tmpl)
            enrich_transform_vars.append(('_full_id', full_id_val_var))
        else:
            # Template is bare "{name}" — the item.name IS the full path at runtime
            # (e.g. cloudkms resources where name = projects/.../keyRings/...)
            transform_vars.append(('_full_id', _jinja('item.name')))
            enrich_transform_vars.append(('_full_id', _jinja(f'{item_var}.name')))

    else:
        # tuple kind — construct _full_id from available anchor + id parts
        # Determine best id field from produces
        id_field_name = None
        for field in ('name', 'id', 'selfLink', 'resourceName', 'fullResourceName'):
            if field in produces:
                id_field_name = field
                break
        if id_field_name is None and produces:
            id_field_name = sorted(produces.keys())[0]

        # Build composite _full_id: gcp:{service}:{resource}:{project_id}/{zone?}/{region?}/{id}
        # Use a tuple representation for resources without a canonical path
        id_expr_parts = [f'"{service}:{resource_type}:"']
        if inv_op and 'project' in (inv_op.get('http', {}).get('path', '') or '').lower():
            id_expr_parts.append(_jinja('project_id'))
            id_expr_parts.append('"/"')
        if inv_op and '/zones/' in (inv_op.get('http', {}).get('path', '') or ''):
            id_expr_parts.append(_jinja('zone'))
            id_expr_parts.append('"/"')
        elif inv_op and '/regions/' in (inv_op.get('http', {}).get('path', '') or ''):
            id_expr_parts.append(_jinja('region'))
            id_expr_parts.append('"/"')
        if id_field_name:
            id_expr_parts.append(_jinja(f'item.{id_field_name}'))

        if len(id_expr_parts) > 1:
            full_id_item_val = '{{ ' + ' ~ '.join(
                e[3:-3] if e.startswith('{{ ') else e.strip('"')
                for e in id_expr_parts
            ) + ' }}'
            # Simpler: just build inline
            segs = []
            for e in id_expr_parts:
                if e.startswith('{{'):
                    segs.append(e[3:-3].strip())
                else:
                    segs.append(e)
            full_id_item_expr = ' ~ '.join(segs)
            transform_vars.append(('_full_id', _jinja(full_id_item_expr)))

            # For enrich: same but use item_var
            segs_var = []
            for e in id_expr_parts:
                if e.startswith('{{') and 'item.' in e:
                    segs_var.append(e[3:-3].strip().replace('item.', f'{item_var}.'))
                elif e.startswith('{{'):
                    segs_var.append(e[3:-3].strip())
                else:
                    segs_var.append(e)
            full_id_var_expr = ' ~ '.join(segs_var)
            enrich_transform_vars.append(('_full_id', _jinja(full_id_var_expr)))
        else:
            # Fallback: use the resource type as a label
            fallback = f'"{service}/{resource_type}/" ~ ' + _jinja('item.name')[3:-3] if id_field_name == 'name' else f'"{service}/{resource_type}/unknown"'
            transform_vars.append(('_full_id', _jinja(fallback)))
            enrich_transform_vars.append(('_full_id', _jinja(fallback)))

    # ── Inventory emit fields (all produces fields; exclude enrich-only like reportUrl) ──
    # Use "item." as the loop variable (items_for loop context)
    # Exclude fields that only the enrich op can provide (heuristic: any field
    # not in produces is enrich-only).
    inv_produces_keys = set(produces.keys())
    inv_emit_fields: list[tuple[str, str]] = []
    for logical in sorted(inv_produces_keys):
        fp = produces[logical]
        if '[].' in fp:
            field_name = fp.split('[].')[-1]
            inv_emit_fields.append((logical, f'item.{field_name}'))
        else:
            inv_emit_fields.append((logical, f'item.{fp}'))

    # ── Enrich op analysis ────────────────────────────────────────────────
    enrich_op_key    = None
    enrich_res       = None
    enrich_action    = None
    enrich_params_map: dict = {}

    if enrich_ops:
        enrich_op     = enrich_ops[0]
        enrich_op_key = enrich_op['op']
        enrich_res    = _resource_from_op(enrich_op_key)
        enrich_action = _verb_from_op(enrich_op_key)
        enrich_req    = enrich_op.get('required_params', {})

        for pname, pinfo in enrich_req.items():
            from_id = pinfo.get('from_identifier', '')
            if from_id in ('full_id',) or from_id.startswith('transforms'):
                enrich_params_map[pname] = _jinja(final_id_var)
            elif from_id == pname:
                # Check if it's a known anchor
                if pname in ('project', 'projectId'):
                    enrich_params_map[pname] = _jinja('project_id')
                elif pname in ('zone',):
                    enrich_params_map[pname] = _jinja('zone')
                elif pname in ('region',):
                    enrich_params_map[pname] = _jinja('region')
                elif pname in ('location',):
                    enrich_params_map[pname] = _jinja('location')
                else:
                    enrich_params_map[pname] = _jinja(pname)
            elif from_id in inv_produces_keys:
                enrich_params_map[pname] = _jinja(f'{item_var}.{pname}')
            else:
                enrich_params_map[pname] = _jinja(pname)

    # ── All enrich emit fields: identity from detail_var via item loop ────
    # In the enrich emit, items_for = "{{ [detail_var] }}" so "item" = detail object
    # Emit all inventory fields (re-emitted) + enrich-only fields
    # Enrich-only fields: anything producible by the get op not in inv_produces
    # For simplicity: emit _full_id + all inv fields + reportUrl if it's
    # a known enrich-only field (not in inventory produces)
    enrich_emit_fields: list[tuple[str, str]] = []
    if enrich_ops:
        enrich_op = enrich_ops[0]
        # Re-emit _full_id from vars
        enrich_emit_fields.append(('_full_id', _jinja('_full_id')))
        # All inventory fields (re-emitted from get response when available)
        for logical in sorted(inv_produces_keys):
            # reportUrl is special: it's in both but only reliable from enrich
            enrich_emit_fields.append((logical, _jinja(f'item.{logical}')))
        # Add any enrich-specific fields not in inventory
        # (heuristic: scan produces of enrich op if present)
        for fk in sorted(enrich_op.get('produces', {}).keys()):
            if fk not in inv_produces_keys and fk != '_full_id':
                enrich_emit_fields.append((fk, _jinja(f'item.{fk}')))

    # ── Build YAML lines ──────────────────────────────────────────────────
    lines: list[str] = []

    # ── INVENTORY STAGE ───────────────────────────────────────────────────
    lines.append(
        f'  # ── INVENTORY: {resource_type} '
        f'(pattern: {pattern}, id: {id_kind}, confidence: {confidence}) ──'
    )
    lines.append(f'  - discovery_id: {inv_op_key}')

    lines.append('    calls:')
    lines.append(f'      - action: {_verb_from_op(inv_op_key)}')
    lines.append(f'        resource: {inv_res}')
    lines.append('        params: {}')
    lines.append(f'        save_as: {list_var}')
    lines.append('        on_error: continue')

    lines.append('    emit:')
    lines.append(f'      as: {resource_type}_inventory_item')
    lines.append(f'      items_for: {items_for_expr}')
    lines.append('      item:')

    # Transform vars inline in emit.item (using "item." loop var)
    for var_name, expr in transform_vars:
        if var_name == '_full_id' and expr == final_id_var:
            # _full_id = name var (reference to already-defined var)
            lines.append(f'        {var_name}: "{_jinja(expr)}"')
        elif '{{' in expr:
            # Already a Jinja expression (e.g. full_name style)
            lines.append(f'        {var_name}: "{expr}"')
        else:
            lines.append(f'        {var_name}: "{_jinja(expr)}"')

    # Regular inventory fields
    for logical, expr in inv_emit_fields:
        lines.append(f'        {logical}: "{_jinja(expr)}"')

    # ── ENRICH STAGE ──────────────────────────────────────────────────────
    if enrich_ops and enrich_op_key:
        lines.append('')
        lines.append(
            f'  # ── ENRICH: {resource_type} via {_op_short(enrich_op_key)} ──'
        )
        lines.append('  # Enrichment modes:')
        lines.append('  #   always   → enrich every inventory item (complete fields)')
        lines.append('  #   never    → skip (fastest scan, lowest API cost)')
        lines.append('  #   selective→ enrich only if decision rules match')
        lines.append(f'  - discovery_id: {enrich_op_key}')

        # foreach: (named item_var for use in decision rules)
        lines.append('    foreach:')
        lines.append(f'      from: {items_for_expr}')
        lines.append(f'      as: {item_var}')

        # decision:
        rules = _selective_rules(service, item_var, resource_type)
        lines.append('    decision:')
        lines.append(f'      # Use this to override enrichment_config.default_mode for this step.')
        lines.append(f'      mode: {enrichment_mode}')
        lines.append('      rules:')
        for rule in rules:
            if 'when' in rule:
                lines.append(f'        - when: "{rule["when"]}"')
                lines.append(f'          do: {rule["do"]}')
            else:
                lines.append(f'        - default: {rule.get("default", "skip")}')

        # vars: (transform intermediates, using item_var.)
        if enrich_transform_vars:
            lines.append('    vars:')
            for var_name, expr in enrich_transform_vars:
                if var_name == '_full_id' and expr == final_id_var:
                    lines.append(f'      {var_name}: "{_jinja(expr)}"')
                elif '{{' in expr:
                    lines.append(f'      {var_name}: "{expr}"')
                else:
                    lines.append(f'      {var_name}: "{_jinja(expr)}"')

        # calls:
        lines.append('    calls:')
        lines.append(f'      - action: {enrich_action}')
        lines.append(f'        resource: {enrich_res}')
        lines.append('        params:')
        for pname, pval in enrich_params_map.items():
            lines.append(f'          {pname}: "{pval}"')
        lines.append(f'        save_as: {detail_var}')
        lines.append('        on_error: continue')

        # emit:  items_for wraps single get result in a list → "item" = detail object
        lines.append('    emit:')
        lines.append(f'      as: {resource_type}_enriched_item')
        lines.append(f'      items_for: "{_jinja("[" + detail_var + "]")}"')
        lines.append('      item:')
        for logical, expr in enrich_emit_fields:
            lines.append(f'        {logical}: "{expr}"')

    return '\n'.join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# TOP-LEVEL YAML BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_discovery_yaml(
    catalog_path: Path,
    chains_path: Optional[Path],
    enrichment_mode: str = 'selective',
) -> Optional[str]:
    """Build the full discovery YAML for a service from its step6 catalog."""
    if not catalog_path.exists():
        return None

    catalog = json.load(open(catalog_path))
    services = catalog.get('services', {})
    if not services:
        return None

    service_name = list(services.keys())[0]
    svc_data     = services[service_name]
    version      = svc_data.get('version', 'v1')
    resources    = svc_data.get('resources', {})

    chains: dict = {}
    if chains_path and chains_path.exists():
        chains = json.load(open(chains_path)).get('chains', {})

    # ── YAML header ───────────────────────────────────────────────────────
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    lines = []
    lines.append(f'# ============================================================')
    lines.append(f'# Discovery YAML — {service_name} ({version})')
    lines.append(f'# Generated: {now}')
    lines.append(f'# ============================================================')
    lines.append(f'# Enrichment mode options:')
    lines.append(f'#   always    → enrich every inventory item')
    lines.append(f'#   never     → list only (fastest / lowest cost)')
    lines.append(f'#   selective → enrich only items matching decision rules')
    lines.append(f'# Set enrichment_mode below to switch globally.')
    lines.append(f'# ============================================================')
    lines.append('')
    lines.append("version: '1.0'")
    lines.append('provider: gcp')
    lines.append(f'service: {service_name}')
    lines.append('')

    # ── service: block ─────────────────────────────────────────────────────
    lines.append('services:')
    lines.append(f'  client: {service_name}')
    lines.append(f"  module: \"googleapiclient.discovery.build('{service_name}', '{version}')\"")
    lines.append('')

    # ── enrichment_config: global default ─────────────────────────────────
    lines.append('# Global enrichment policy — override per discovery block via decision.mode')
    lines.append('enrichment_config:')
    lines.append(f'  default_mode: {enrichment_mode}')
    lines.append('  # always   → run inventory_enrich for every item')
    lines.append('  # never    → skip all enrich calls')
    lines.append('  # selective→ apply per-step decision rules')
    lines.append('')

    # ── anchors ───────────────────────────────────────────────────────────
    lines.append('# Anchors: fixed service-level parameters (user-provided)')
    lines.append('anchors:')
    for anchor in catalog.get('anchors', {}).get('fixed', []):
        lines.append(f'  {anchor}: null  # set by caller')
    lines.append('')

    # ── checks ────────────────────────────────────────────────────────────
    lines.append('checks: []')
    lines.append('')

    # ── discovery blocks per resource ──────────────────────────────────────
    lines.append('discovery:')

    for rtype in sorted(resources.keys()):
        rdata = resources[rtype]
        block = _build_discovery_block(
            service=service_name,
            resource_type=rtype,
            rdata=rdata,
            chains=chains,
            enrichment_mode=enrichment_mode,
        )
        if block:
            lines.append('')
            lines.append(block)

    lines.append('')
    return '\n'.join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# RUN ALL SERVICES
# ─────────────────────────────────────────────────────────────────────────────

def run_all(enrichment_mode: str = 'selective'):
    print('=' * 70)
    print('Building step8 discovery YAMLs for all GCP services')
    print('=' * 70)

    all_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir()
        and not d.name.startswith('.')
        and (d / 'step5_resource_catalog_inventory_enrich.json').exists()
    )

    built = skipped = 0
    for svc_dir in all_dirs:
        catalog_path = svc_dir / 'step5_resource_catalog_inventory_enrich.json'
        chains_path  = svc_dir / 'step3_read_operation_dependency_chain_independent.json'

        yaml_text = build_discovery_yaml(catalog_path, chains_path, enrichment_mode)
        if not yaml_text:
            print(f'  ⏭  {svc_dir.name}: nothing to emit')
            skipped += 1
            continue

        # Infer service name from catalog
        catalog = json.load(open(catalog_path))
        svc_name = list(catalog.get('services', {}).keys())[0]
        out_path = svc_dir / f'step6_{svc_name}.discovery.yaml'
        out_path.write_text(yaml_text, encoding='utf-8')
        built += 1
        print(f'  ✓ {svc_dir.name:42s} → {out_path.name}')

    print()
    print('=' * 70)
    print(f'Built  : {built}')
    print(f'Skipped: {skipped}')
    print('=' * 70)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Build Step-8 Discovery YAML from step6 resource catalog'
    )
    parser.add_argument('--service',  help='Service name (e.g. abusiveexperiencereport)')
    parser.add_argument('--catalog',  type=Path,
                        help='Path to step5_resource_catalog_inventory_enrich.json')
    parser.add_argument('--chains',   type=Path,
                        help='Path to step3 chains JSON')
    parser.add_argument('--out',      type=Path,
                        help='Output YAML path')
    parser.add_argument('--mode',     default='selective',
                        choices=['always', 'never', 'selective'],
                        help='Enrichment mode (default: selective)')
    parser.add_argument('--all',      action='store_true',
                        help='Run for all services under BASE_DIR')

    args = parser.parse_args()

    if args.all or (not args.service and not args.catalog):
        run_all(args.mode)
        return

    # Single service by name
    if args.service and not args.catalog:
        svc_dir      = BASE_DIR / args.service
        catalog_path = svc_dir / 'step5_resource_catalog_inventory_enrich.json'
        chains_path  = svc_dir / 'step3_read_operation_dependency_chain_independent.json'
        out_path     = args.out or svc_dir / f'step6_{args.service}.discovery.yaml'
    else:
        catalog_path = args.catalog
        chains_path  = args.chains
        out_path     = args.out

    if not catalog_path or not catalog_path.exists():
        print(f'ERROR: catalog not found: {catalog_path}')
        sys.exit(1)

    yaml_text = build_discovery_yaml(catalog_path, chains_path, args.mode)
    if not yaml_text:
        print('ERROR: no YAML generated — check catalog file')
        sys.exit(1)

    out_path.write_text(yaml_text, encoding='utf-8')
    print(f'Written: {out_path}')
    print(yaml_text[:3000])


if __name__ == '__main__':
    main()
