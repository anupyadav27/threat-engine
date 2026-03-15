#!/usr/bin/env python3
"""
generate_missing_azure_steps.py
---------------------------------
Generates missing pipeline steps for the 106 Azure services that have
step1 (api_driven_registry) but are missing step1b, step2, step2b, step4,
and step6.

Also generates step6 for any Azure service that has step5b but no step6.

Steps generated per partial service (derived purely from step1):
  step1b  - Operation registry (kind_rules + operation classification)
  step2   - Operation adjacency registry (op_consumes / op_produces)
  step2b  - Resource operations registry (root ops + yaml_discovery ops)
  step4   - Fields produced index (seed_from_list of unique fields)
  step6   - Discovery YAML

step1, step3, step5, step5b are already present — not overwritten.

Run:
    python3 generate_missing_azure_steps.py
"""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

AZURE_BASE = Path('/Users/apple/Desktop/data_pythonsdk/azure')

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def to_snake_case(name: str) -> str:
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def classify_kind(op_name: str) -> str:
    """Classify operation into a kind based on its name."""
    n = op_name.lower()
    # Check category.method pattern (e.g. "virtualMachines_listAll")
    method = n.split('_', 1)[-1] if '_' in n else n
    # Also handle dot-separated (e.g. "availabilitysets.list")
    method = method.split('.')[-1] if '.' in method else method

    if re.search(r'\bdelete\b', method):
        return 'write_delete'
    elif re.search(r'\bcreate_or_update\b|\bcreate\b', method):
        return 'write_create'
    elif re.search(r'\bupdate\b|\bpatch\b', method):
        return 'write_update'
    elif re.search(r'\battach\b|\bassociate\b|\badd\b|\bput\b|\benable\b', method):
        return 'write_apply'
    elif re.search(r'\blist_by\b|\blist_all\b|\blist\b', method):
        return 'read_list'
    elif re.search(r'\bget\b', method):
        return 'read_get'
    return 'other'

def is_read_op(op_name: str) -> bool:
    kind = classify_kind(op_name)
    return kind.startswith('read_')

def entity_from_field(svc: str, field_name: str) -> str:
    return f"{svc}.{to_snake_case(field_name)}"

def entity_from_op_output(svc: str, op_name: str) -> list[str]:
    """Guess entity names produced by an op from its name."""
    # e.g. "virtualMachines_list" → svc.virtual_machine__name, svc.virtual_machine_id
    base = op_name.split('_')[0] if '_' in op_name else op_name.split('.')[0]
    snake = to_snake_case(base)
    return [f"{svc}.{snake}__name", f"{svc}.{snake}_id"]

# ─────────────────────────────────────────────────────────────────────────────
# Step builders
# ─────────────────────────────────────────────────────────────────────────────

KIND_RULES = {
    'read_list':    ['list', 'list_by_', 'list_all', 'list_'],
    'read_get':     ['get', 'get_'],
    'write_create': ['create', 'create_or_update', 'begin_create', 'begin_create_or_update'],
    'write_update': ['update', 'patch', 'begin_update', 'begin_patch'],
    'write_delete': ['delete', 'begin_delete', '_delete'],
    'write_apply':  ['attach', 'associate', 'add', 'put', 'enable', 'start', 'begin_start'],
    'other':        ['default'],
}

def build_step1b(svc: str, step1_data: dict) -> dict:
    """step1b_operation_registry.json — kind classification + consumes/produces."""
    ops_out = {}
    entity_aliases: dict[str, str] = {}

    all_ops = step1_data.get('independent', []) + step1_data.get('dependent', [])

    for op in all_ops:
        op_name = op['operation']
        method  = op.get('python_method', to_snake_case(op_name))
        action  = op.get('yaml_action', method)
        req     = op.get('required_params', [])
        opt     = op.get('optional_params', [])
        kind    = classify_kind(op_name)

        # Parse category from "category_method" or "category.method"
        if '_' in op_name:
            category = op_name.split('_')[0].lower()
        elif '.' in op_name:
            category = op_name.split('.')[0].lower()
        else:
            category = svc

        # Derive consumes from required_params
        consumes = []
        for p in req:
            ent = entity_from_field(svc, p)
            consumes.append({
                'entity': ent,
                'param':  p,
                'required': True,
                'source': 'param',
            })

        # Derive produces from item_fields or output_fields
        produces = []
        item_fields = op.get('item_fields', {})
        output_fields = op.get('output_fields', {})
        fields_src = item_fields if item_fields else output_fields
        for fn in list(fields_src.keys())[:20]:   # cap at 20 fields
            ent = entity_from_field(svc, fn)
            produces.append({
                'entity': ent,
                'source': 'item' if item_fields else 'output',
                'path':   fn,
            })

        op_id = f"azure.{svc}.{category}.{op_name.lower()}"

        ops_out[op_id] = {
            'operation_id':    op_id,
            'operation_key':   f"{category}::{op_name}",
            'operation':       op_name,
            'python_method':   method,
            'yaml_action':     action,
            'category':        category,
            'kind':            kind,
            'required_params': req,
            'optional_params': opt,
            'output_fields':   op.get('output_fields', {}),
            'main_output_field': op.get('main_output_field'),
            'consumes':        consumes,
            'produces':        produces,
            'side_effect':     not kind.startswith('read_'),
        }

    return {
        'service':        svc,
        'version':        '1.0',
        'module':         f'azure.mgmt.{svc}',
        'kind_rules':     KIND_RULES,
        'entity_aliases': entity_aliases,
        'overrides':      {'param_aliases': {}, 'consumes': {}, 'produces': {}},
        'operations':     ops_out,
        '_metadata':      {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'source':       'step1_api_driven_registry',
            'data_quality': 'basic',
        },
    }

def build_step2(svc: str, step1b: dict) -> dict:
    """step2_operation_adjacency_registry.json — op/entity consumption graph."""
    op_consumes: dict[str, list] = {}
    op_produces: dict[str, list] = {}
    entity_consumers: dict[str, list] = {}
    entity_producers: dict[str, list] = {}

    for op_id, op in step1b['operations'].items():
        consumed_ents = [c['entity'] for c in op.get('consumes', [])]
        produced_ents = [p['entity'] for p in op.get('produces', [])]

        op_consumes[op_id] = consumed_ents
        op_produces[op_id] = produced_ents

        for ent in consumed_ents:
            entity_consumers.setdefault(ent, []).append(op_id)
        for ent in produced_ents:
            entity_producers.setdefault(ent, []).append(op_id)

    return {
        'service':          svc,
        'op_consumes':      op_consumes,
        'op_produces':      op_produces,
        'entity_consumers': entity_consumers,
        'entity_producers': entity_producers,
        'external_entities': [],
    }

def build_step2b(svc: str, step1_data: dict) -> dict:
    """step2b_resource_operations_registry.json — root + yaml_discovery ops."""
    now = datetime.now(timezone.utc).isoformat()
    root_ops = [op['operation'] for op in step1_data.get('independent', [])]

    yaml_disc = list(root_ops)
    for op in step1_data.get('dependent', []):
        if is_read_op(op['operation']):
            yaml_disc.append(op['operation'])

    return {
        'service':                  svc,
        'generated_at':             now,
        'root_operations':          root_ops,
        'yaml_discovery_operations': yaml_disc,
    }

def build_step4(svc: str, step1_data: dict) -> dict:
    """step4_fields_produced_index.json — seed field names from step1."""
    seen: set[str] = set()
    all_ops = step1_data.get('independent', []) + step1_data.get('dependent', [])
    for op in all_ops:
        for fn in op.get('item_fields', {}):
            seen.add(fn)
        for fn in op.get('output_fields', {}):
            seen.add(fn)

    sorted_fields = sorted(seen)
    return {
        'service':                  svc,
        'seed_from_list':           sorted_fields,
        'enriched_from_get_describe': [],
        'final_union':              sorted_fields,
        'fields':                   {},
    }

def build_step6_yaml(svc: str, step1_data: dict, step5b: dict | None) -> str:
    """step6_{svc}.discovery.yaml — discovery YAML from step5b (or step1 roots)."""
    lines = [
        f"version: '1.0'",
        f"provider: azure",
        f"service: {svc}",
        f"services:",
        f"  client: {svc}",
        f"  module: azure.mgmt.{svc}",
        f"discovery:",
    ]

    # Build op lookup from step1
    op_lookup: dict[str, dict] = {}
    for op in step1_data.get('independent', []) + step1_data.get('dependent', []):
        op_lookup[op['operation']] = op

    # Use step5b selected operations if available, else fall back to independent ops
    if step5b:
        selected = step5b.get('minimal_operations', {}).get('selected_operations', [])
        ops_to_emit = [(s['operation'], s['type'], s.get('dependencies', []))
                       for s in selected]
    else:
        ops_to_emit = [(op['operation'], 'INDEPENDENT', [])
                       for op in step1_data.get('independent', [])]

    for op_name, op_type, deps in ops_to_emit:
        op_info = op_lookup.get(op_name, {})
        action  = op_info.get('python_method', to_snake_case(op_name))
        main_out = op_info.get('main_output_field') or 'value'

        # Parse category
        if '_' in op_name:
            category = op_name.split('_')[0].lower()
        elif '.' in op_name:
            category = op_name.split('.')[0].lower()
        else:
            category = svc

        disc_id = f"azure.{svc}.{category}.{op_name.lower()}"
        lines.append(f"  - discovery_id: {disc_id}")

        if op_type == 'DEPENDENT' and deps:
            dep_ent = deps[0]
            dep_svc = dep_ent.split('.')[0]
            dep_field = dep_ent.split('.', 1)[1] if '.' in dep_ent else dep_ent
            for_each_op_name_guess = f"{dep_field.replace('__name', '').replace('_id', '')}.list"
            lines.append(f"    for_each: azure.{dep_svc}.{for_each_op_name_guess}")

        lines.append(f"    calls:")
        lines.append(f"      - action: {action}")
        lines.append(f"        save_as: response")
        lines.append(f"        on_error: continue")

        req = op_info.get('required_params', [])
        if op_type == 'DEPENDENT' and req:
            lines.append(f"        params:")
            for p in req:
                field_guess = to_snake_case(p)
                lines.append(f"          {p}: \"{{{{ item.{field_guess} }}}}\"")

        lines.append(f"    emit:")
        lines.append(f"      as: item")
        lines.append(f"      items_for: \"{{{{ response.{main_out} }}}}\"")

    lines.append("checks: []")
    lines.append("")
    return '\n'.join(lines)

# ─────────────────────────────────────────────────────────────────────────────
# Per-service processing
# ─────────────────────────────────────────────────────────────────────────────

def load_json(path: Path) -> dict | None:
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None

def write_json(path: Path, obj: dict, label: str):
    if path.exists():
        print(f"    SKIP (exists): {label}")
        return
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    print(f"    WROTE: {label}")

def write_text(path: Path, text: str, label: str):
    if path.exists():
        print(f"    SKIP (exists): {label}")
        return
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)
    print(f"    WROTE: {label}")

def process_service(svc_dir: Path) -> str:
    svc = svc_dir.name

    # Load step1
    step1_path = svc_dir / 'step1_api_driven_registry.json'
    if not step1_path.exists():
        return 'no_step1'

    raw = load_json(step1_path)
    if raw is None:
        return 'load_error'

    # step1 is keyed by service name
    step1_data = raw.get(svc, raw)

    need_1b  = not (svc_dir / 'step1b_operation_registry.json').exists()
    need_2   = not (svc_dir / 'step2_operation_adjacency_registry.json').exists()
    need_2b  = not (svc_dir / 'step2b_resource_operations_registry.json').exists()
    need_4   = not (svc_dir / 'step4_fields_produced_index.json').exists()
    need_6   = not (svc_dir / f'step6_{svc}.discovery.yaml').exists()

    if not any([need_1b, need_2, need_2b, need_4, need_6]):
        return 'complete'

    print(f"\n  [{svc}]")
    step1b = None

    if need_1b:
        step1b = build_step1b(svc, step1_data)
        write_json(svc_dir / 'step1b_operation_registry.json', step1b, 'step1b_operation_registry.json')
    else:
        step1b = load_json(svc_dir / 'step1b_operation_registry.json') or build_step1b(svc, step1_data)

    if need_2:
        step2 = build_step2(svc, step1b)
        write_json(svc_dir / 'step2_operation_adjacency_registry.json', step2, 'step2_operation_adjacency_registry.json')

    if need_2b:
        step2b = build_step2b(svc, step1_data)
        write_json(svc_dir / 'step2b_resource_operations_registry.json', step2b, 'step2b_resource_operations_registry.json')

    if need_4:
        step4 = build_step4(svc, step1_data)
        write_json(svc_dir / 'step4_fields_produced_index.json', step4, 'step4_fields_produced_index.json')

    if need_6:
        step5b_data = load_json(svc_dir / 'step5b_minimal_operations_catalog.json')
        yaml_text = build_step6_yaml(svc, step1_data, step5b_data)
        write_text(svc_dir / f'step6_{svc}.discovery.yaml', yaml_text, f'step6_{svc}.discovery.yaml')

    return 'generated'

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    counts = {'generated': 0, 'complete': 0, 'no_step1': 0,
              'load_error': 0, 'skipped': 0}

    svc_dirs = sorted(
        [e.path for e in os.scandir(AZURE_BASE)
         if e.is_dir() and e.name not in ('temp_code', 'tools')],
        key=lambda p: Path(p).name
    )

    print('=' * 65)
    print('Azure Missing Steps Generator')
    print(f'Scanning {len(svc_dirs)} service folders...')
    print('=' * 65)

    for svc_path in svc_dirs:
        result = process_service(Path(svc_path))
        counts[result] = counts.get(result, 0) + 1

    print()
    print('=' * 65)
    print('SUMMARY')
    print('=' * 65)
    print(f"  Generated (new steps written) : {counts['generated']}")
    print(f"  Already complete              : {counts['complete']}")
    print(f"  Skipped (no step1)            : {counts['no_step1']}")
    print(f"  Load errors                   : {counts['load_error']}")
    print('=' * 65)
