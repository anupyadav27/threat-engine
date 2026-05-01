#!/usr/bin/env python3
"""
generate_missing_aws_steps.py
------------------------------
Generates step1 → step6 pipeline files for the 17 AWS services that have
only step5 but map to a valid boto3 service name.

Steps generated per service:
  step1  - API-driven registry (from boto3 service model)
  step2  - Resource operations registry (root ops + yaml_discovery ops)
  step3  - Read operation dependency chain (roots + entity_paths)
  step4  - Fields produced index (seed_from_list of unique output fields)
  step5b - Minimal operations catalog (minimal op set covering all entities)
  step6  - Discovery YAML (Jinja2 inventory file)

step5 (ARN identifier catalog) already exists — not overwritten.

Run:
    python3 generate_missing_aws_steps.py
"""

import boto3
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

AWS_BASE = Path('/Users/apple/Desktop/data_pythonsdk/aws')

# Folder name -> boto3 service name
FOLDER_TO_BOTO3 = {
    'access-analyzer':    'accessanalyzer',
    'aoss':               'opensearchserverless',
    'app-integrations':   'appintegrations',
    'aps':                'amp',
    'cassandra':          'keyspaces',
    'connect-campaigns':  'connectcampaigns',
    'elasticfilesystem':  'efs',
    'elasticloadbalancing': 'elb',
    'elasticmapreduce':   'emr',
    'execute-api':        'apigatewaymanagementapi',
    'iotmanagedintegrations': 'iot-managed-integrations',
    'kafka-cluster':      'kafka',
    'mobiletargeting':    'pinpoint',
    'neptune-db':         'neptunedata',
    's3-object-lambda':   's3control',
    'states':             'stepfunctions',
    'voiceid':            'voice-id',
}

# ─────────────────────────────────────────────────────────────────────────────
# Boto3 extraction (reused from regenerate_boto3_dependencies.py)
# ─────────────────────────────────────────────────────────────────────────────

def to_snake_case(name: str) -> str:
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def extract_enum_values(shape):
    if hasattr(shape, 'enum') and shape.enum:
        return list(shape.enum)
    return None

def detect_compliance_category(field_name: str) -> str:
    fl = field_name.lower()
    if any(k in fl for k in ['arn', 'id', 'name', 'principal', 'role', 'user', 'account']):
        return 'identity'
    elif any(k in fl for k in ['status', 'state', 'enabled', 'public', 'encrypted', 'secure', 'policy']):
        return 'security'
    elif any(k in fl for k in ['cost', 'price', 'billing', 'charge']):
        return 'cost'
    return 'general'

def get_operators_for_type(field_type: str, is_enum: bool) -> list:
    if is_enum:
        return ['equals', 'not_equals', 'in', 'not_in']
    elif field_type == 'boolean':
        return ['equals', 'not_equals']
    elif field_type in ['integer', 'long', 'float', 'double']:
        return ['equals', 'not_equals', 'greater_than', 'less_than',
                'greater_than_or_equal', 'less_than_or_equal']
    elif field_type == 'string':
        return ['equals', 'not_equals', 'contains', 'in', 'exists']
    elif field_type == 'timestamp':
        return ['equals', 'not_equals', 'greater_than', 'less_than',
                'greater_than_or_equal', 'less_than_or_equal']
    return ['equals', 'not_equals']

def extract_field_metadata(shape, field_name: str) -> dict:
    field_type = shape.type_name if hasattr(shape, 'type_name') else 'unknown'
    enum_values = extract_enum_values(shape)
    meta = {
        'type': field_type,
        'description': getattr(shape, 'documentation', '') or f'{field_name} field',
        'enum': bool(enum_values),
        'operators': get_operators_for_type(field_type, bool(enum_values)),
        'compliance_category': detect_compliance_category(field_name),
    }
    if enum_values:
        meta['possible_values'] = enum_values
    if field_type == 'boolean':
        meta['possible_values'] = [True, False]
    return meta

def extract_item_fields(shape, op_name: str, depth=0, max_depth=3) -> dict:
    fields = {}
    if not shape or depth >= max_depth:
        return fields
    if shape.type_name == 'list' and hasattr(shape, 'member'):
        member = shape.member
        if member.type_name == 'structure' and hasattr(member, 'members'):
            for fn, fs in member.members.items():
                fields[fn] = extract_field_metadata(fs, fn)
    elif shape.type_name == 'structure' and hasattr(shape, 'members'):
        for fn, fs in shape.members.items():
            fields[fn] = extract_field_metadata(fs, fn)
    return fields

def extract_output_fields(op_model) -> dict:
    fields = {}
    if not op_model.output_shape:
        return fields
    s = op_model.output_shape
    if s.type_name == 'structure' and hasattr(s, 'members'):
        for fn, fs in s.members.items():
            fields[fn] = extract_field_metadata(fs, fn)
    return fields

def find_main_output_field(op_model) -> str | None:
    if not op_model.output_shape:
        return None
    s = op_model.output_shape
    if s.type_name == 'structure' and hasattr(s, 'members'):
        list_fields = [(fn, fs) for fn, fs in s.members.items() if fs.type_name == 'list']
        if list_fields:
            for fn, _ in list_fields:
                if any(kw in fn.lower() for kw in
                       ['list', 'items', 'resources', 'summary', 'buckets',
                        'keys', 'apis', 'functions', 'pools', 'groups',
                        'results', 'findings', 'analyzers']):
                    return fn
            return list_fields[0][0]
        for fn, fs in s.members.items():
            if fs.type_name == 'structure':
                return fn
        if s.members:
            return list(s.members.keys())[0]
    return None

def extract_service_from_boto3(boto3_name: str) -> dict:
    """Extract full operation metadata from boto3 for one service."""
    try:
        client = boto3.client(boto3_name, region_name='us-east-1')
        model = client._service_model
        independent, dependent = [], []

        for op_name in model.operation_names:
            op_model = model.operation_model(op_name)
            req = list(op_model.input_shape.required_members) if op_model.input_shape else []
            all_p = list(op_model.input_shape.members.keys()) if op_model.input_shape else []
            opt = [p for p in all_p if p not in req]
            output_fields = extract_output_fields(op_model)
            main_out = find_main_output_field(op_model)
            item_fields = {}
            if op_model.output_shape and main_out:
                mf_shape = op_model.output_shape.members.get(main_out)
                if mf_shape:
                    item_fields = extract_item_fields(mf_shape, op_name)
            info = {
                'operation': op_name,
                'python_method': to_snake_case(op_name),
                'yaml_action': to_snake_case(op_name),
                'required_params': req,
                'optional_params': opt,
                'total_optional': len(opt),
                'output_fields': output_fields,
                'main_output_field': main_out,
                'item_fields': item_fields,
            }
            (independent if not req else dependent).append(info)

        return {
            'service': boto3_name,
            'total_operations': len(model.operation_names),
            'independent': independent,
            'dependent': dependent,
            'independent_count': len(independent),
            'dependent_count': len(dependent),
        }
    except Exception as e:
        print(f'  ERROR extracting {boto3_name}: {e}')
        return None

# ─────────────────────────────────────────────────────────────────────────────
# Step generators — each takes the boto3 data dict and folder_name
# ─────────────────────────────────────────────────────────────────────────────

def _entity_name(service_key: str, field_name: str) -> str:
    """Build entity name: service.resource_field (snake_case)."""
    return f"{service_key}.{to_snake_case(field_name)}"

def build_step1(folder_name: str, boto3_name: str, data: dict) -> dict:
    """step1_api_driven_registry.json — wrap boto3 data keyed by folder_name."""
    # Store keyed by the FOLDER name so it matches the directory convention
    return {folder_name: data}

def build_step2(folder_name: str, data: dict) -> dict:
    """step2_resource_operations_registry.json — root ops + yaml_discovery ops."""
    now = datetime.now(timezone.utc).isoformat()
    root_ops = [op['operation'] for op in data['independent']]

    # yaml_discovery = root ops + read dependent ops that look like Get/List/Describe
    yaml_disc = list(root_ops)
    read_prefixes = ('Get', 'List', 'Describe', 'Search', 'Lookup', 'Fetch',
                     'Query', 'Scan', 'Check', 'Validate', 'Show', 'Find')
    for op in data['dependent']:
        if op['operation'].startswith(read_prefixes):
            yaml_disc.append(op['operation'])

    return {
        'service': folder_name,
        'generated_at': now,
        'root_operations': root_ops,
        'yaml_discovery_operations': yaml_disc,
        'primary_resources': [],
        'other_resources': [],
        'summary': {
            'total_resources': 0,
            'primary_resources_count': 0,
            'other_resources_count': 0,
            'resources_with_arn': 0,
            'resources_from_root_ops': len(root_ops),
        },
    }

def build_step3(folder_name: str, data: dict) -> dict:
    """step3_read_operation_dependency_chain.json — roots + entity_paths."""
    roots = []
    entity_paths: dict[str, list] = {}

    for op in data['independent']:
        # Collect all item_fields as entities produced
        produced = []
        for fn in op.get('item_fields', {}):
            ent = _entity_name(folder_name, fn)
            produced.append(ent)
        # Also top-level output fields
        for fn in op.get('output_fields', {}):
            ent = _entity_name(folder_name, fn)
            if ent not in produced:
                produced.append(ent)

        roots.append({'op': op['operation'], 'produces': produced})

        for ent in produced:
            if ent not in entity_paths:
                entity_paths[ent] = [{
                    'operations': [op['operation']],
                    'produces': {op['operation']: produced},
                    'consumes': {op['operation']: []},
                    'external_inputs': [],
                }]

    # Dependent read ops — build chains
    read_prefixes = ('Get', 'List', 'Describe', 'Search', 'Lookup', 'Fetch',
                     'Query', 'Scan', 'Check', 'Validate', 'Show', 'Find')
    for op in data['dependent']:
        if not op['operation'].startswith(read_prefixes):
            continue
        produced = []
        for fn in op.get('item_fields', {}):
            produced.append(_entity_name(folder_name, fn))
        consumes = [_entity_name(folder_name, p) for p in op.get('required_params', [])]
        for ent in produced:
            if ent not in entity_paths:
                entity_paths[ent] = []
            entity_paths[ent].append({
                'operations': [op['operation']],
                'produces': {op['operation']: produced},
                'consumes': {op['operation']: consumes},
                'external_inputs': [],
            })

    return {
        'service': folder_name,
        'read_only': True,
        'roots': roots,
        'entity_paths': entity_paths,
    }

def build_step4(folder_name: str, data: dict) -> dict:
    """step4_fields_produced_index.json — unique field names from all ops."""
    seen: set[str] = set()
    for op in data['independent'] + data['dependent']:
        for fn in op.get('item_fields', {}):
            seen.add(fn)
        for fn in op.get('output_fields', {}):
            seen.add(fn)

    return {
        'service': folder_name,
        'seed_from_list': sorted(seen),
        'enriched_from_get_describe': [],
        'final_union': sorted(seen),
        'fields': {},
        'field_mappings': {},
    }

def build_step5b(folder_name: str, data: dict, step3: dict) -> dict:
    """step5b_minimal_operations_catalog.json — minimal op set (greedy)."""
    now = datetime.now(timezone.utc).isoformat()
    root_op_names = [r['op'] for r in step3['roots']]

    # Collect all entities that need to be covered
    all_entities: set[str] = set()
    for root in step3['roots']:
        all_entities.update(root['produces'])
    for ent, paths in step3['entity_paths'].items():
        all_entities.add(ent)

    covered: set[str] = set()
    selected = []

    # Phase 1 — root (independent) ops
    for root in step3['roots']:
        new_ents = [e for e in root['produces'] if e not in covered]
        if new_ents:
            covered.update(new_ents)
            selected.append({
                'operation': root['op'],
                'type': 'INDEPENDENT',
                'entities_covered': new_ents,
                'dependencies': [],
                'coverage_count': len(new_ents),
            })

    # Phase 2 — dependent read ops
    read_prefixes = ('Get', 'List', 'Describe', 'Search', 'Lookup', 'Fetch',
                     'Query', 'Scan', 'Check', 'Validate', 'Show', 'Find')
    for op in data['dependent']:
        if not op['operation'].startswith(read_prefixes):
            continue
        produced = [_entity_name(folder_name, fn)
                    for fn in op.get('item_fields', {})]
        new_ents = [e for e in produced if e not in covered]
        deps = [_entity_name(folder_name, p) for p in op.get('required_params', [])]
        if new_ents:
            covered.update(new_ents)
            selected.append({
                'operation': op['operation'],
                'type': 'DEPENDENT',
                'entities_covered': new_ents,
                'dependencies': deps,
                'coverage_count': len(new_ents),
            })

    total = len(all_entities)
    cov = len(covered)
    pct = round(cov / total * 100, 1) if total else 0.0
    ind_cnt = sum(1 for s in selected if s['type'] == 'INDEPENDENT')

    return {
        'service': folder_name,
        'generated_at': now,
        'total_fields': total,
        'root_operations_available': root_op_names,
        'minimal_operations': {
            'selected_operations': selected,
            'total_entities_needed': total,
            'entities_covered': cov,
            'entities_remaining': total - cov,
            'coverage_percentage': pct,
        },
        'summary': {
            'total_operations_needed': len(selected),
            'independent_operations': ind_cnt,
            'dependent_operations': len(selected) - ind_cnt,
            'coverage_percentage': pct,
        },
    }

def build_step6_yaml(folder_name: str, boto3_name: str,
                     data: dict, step5b: dict) -> str:
    """step6_{folder}.discovery.yaml — Jinja2 discovery YAML."""
    lines = [
        f"version: '1.0'",
        f"provider: aws",
        f"service: {folder_name}",
        f"services:",
        f"  client: {boto3_name}",
        f"  module: boto3.client",
        f"discovery:",
    ]

    selected = step5b['minimal_operations']['selected_operations']
    # Build a lookup: operation -> op_info from step1 data
    op_lookup = {}
    for op in data['independent'] + data['dependent']:
        op_lookup[op['operation']] = op

    for sel in selected:
        op_name = sel['operation']
        op_info = op_lookup.get(op_name, {})
        action = op_info.get('yaml_action', to_snake_case(op_name))
        main_out = op_info.get('main_output_field') or 'items'
        disc_id = f"aws.{folder_name}.{action}"

        lines.append(f"  - discovery_id: {disc_id}")

        if sel['type'] == 'DEPENDENT' and sel.get('dependencies'):
            # pick the first dependency as for_each source
            dep_ent = sel['dependencies'][0]
            dep_service = dep_ent.split('.')[0] if '.' in dep_ent else folder_name
            dep_field = dep_ent.split('.', 1)[1] if '.' in dep_ent else dep_ent
            dep_action_guess = f"aws.{dep_service}.list_{dep_field.replace('_', '_')}"
            lines.append(f"    for_each: {dep_action_guess}")

        lines.append(f"    calls:")
        lines.append(f"      - action: {action}")
        lines.append(f"        save_as: response")
        lines.append(f"        on_error: continue")

        if sel['type'] == 'DEPENDENT':
            params = op_info.get('required_params', [])
            if params:
                lines.append(f"        params:")
                for p in params:
                    field_guess = to_snake_case(p)
                    lines.append(f"          {p}: \"{{{{ item.{field_guess} }}}}\"")

        lines.append(f"    emit:")
        lines.append(f"      as: item")
        lines.append(f"      items_for: \"{{{{ response.{main_out} }}}}\"")

    lines.append("checks: []")
    lines.append("")
    return '\n'.join(lines)

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def process_service(folder_name: str, boto3_name: str) -> bool:
    svc_dir = AWS_BASE / folder_name
    print(f"\n  [{folder_name}] -> boto3:{boto3_name}")

    # 1. Extract from boto3
    print(f"    Extracting from boto3...", end=' ', flush=True)
    data = extract_service_from_boto3(boto3_name)
    if not data:
        print("FAILED")
        return False
    print(f"{data['total_operations']} ops ({data['independent_count']} independent)")

    # 2. Build each step
    step1  = build_step1(folder_name, boto3_name, data)
    step2  = build_step2(folder_name, data)
    step3  = build_step3(folder_name, data)
    step4  = build_step4(folder_name, data)
    step5b = build_step5b(folder_name, data, step3)
    step6  = build_step6_yaml(folder_name, boto3_name, data, step5b)

    # 3. Write files (never overwrite existing step5)
    def write_json(fname, obj):
        p = svc_dir / fname
        if p.exists():
            print(f"    SKIP (exists): {fname}")
            return
        with open(p, 'w', encoding='utf-8') as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
        print(f"    WROTE: {fname}")

    def write_text(fname, text):
        p = svc_dir / fname
        if p.exists():
            print(f"    SKIP (exists): {fname}")
            return
        with open(p, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f"    WROTE: {fname}")

    write_json('step1_api_driven_registry.json',          step1)
    write_json('step2_resource_operations_registry.json', step2)
    write_json('step3_read_operation_dependency_chain.json', step3)
    write_json('step4_fields_produced_index.json',        step4)
    write_json('step5b_minimal_operations_catalog.json',  step5b)
    write_text(f'step6_{folder_name}.discovery.yaml',     step6)
    return True


if __name__ == '__main__':
    print('=' * 65)
    print('AWS Missing Steps Generator')
    print(f'Generating step1→step6 for {len(FOLDER_TO_BOTO3)} services')
    print('=' * 65)

    ok, fail = 0, 0
    for folder, boto3_nm in sorted(FOLDER_TO_BOTO3.items()):
        if process_service(folder, boto3_nm):
            ok += 1
        else:
            fail += 1

    print()
    print('=' * 65)
    print(f'DONE — success: {ok}  failed: {fail}')
    print('=' * 65)
