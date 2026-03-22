#!/usr/bin/env python3
"""
Generate field_operator_value_table.csv for all GCP services.

Data sources (in priority order):
1. operation_registry.json  — produces[].path/type/enum from live Discovery API
2. gcp_dependencies_with_python_names_fully_enriched.json — item_fields with types
3. direct_vars.json  — fallback for operators/possible_values (legacy enriched fields)

The existing CSVs had placeholder enum values (OFF/ON/PAUSED/PENDING/UNKNOWN) from
generic templates. This script replaces them with real field data from the enriched
JSON files produced by the live GCP Discovery API run.
"""

import json
import csv
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

# ─────────────────────────────────────────────────────────────────────────────
# Operator sets
# ─────────────────────────────────────────────────────────────────────────────
OPERATORS_NO_VALUE    = {'exists', 'not_empty', 'not_exists'}
OPERATORS_WITH_VALUE  = {
    'equals', 'not_equals', 'contains', 'not_contains',
    'in', 'not_in', 'greater_than', 'less_than',
    'greater_than_or_equal', 'less_than_or_equal',
    'gt', 'lt', 'gte', 'lte', 'in_range',
}

# Operators by GCP field type
TYPE_OPERATORS = {
    'string':    ['contains', 'equals', 'in', 'not_equals', 'not_in'],
    'boolean':   ['equals', 'not_equals'],
    'integer':   ['equals', 'greater_than', 'in_range', 'less_than', 'not_equals'],
    'number':    ['equals', 'greater_than', 'in_range', 'less_than', 'not_equals'],
    'object':    ['contains', 'equals', 'exists', 'in', 'not_equals', 'not_exists', 'not_in'],
    'array':     ['contains', 'equals', 'exists', 'in', 'not_equals', 'not_exists', 'not_in'],
    'timestamp': ['equals', 'greater_than', 'greater_than_or_equal',
                  'less_than', 'less_than_or_equal', 'not_equals'],
    'any':       ['equals', 'exists', 'not_equals'],
}

# Fields that get exists/not_exists by name hint
NAME_HINTS_FOR_EXISTS = {
    'id', 'selflink', 'name', 'arn', 'url', 'uri', 'link',
    'fingerprint', 'etag', 'checksum', 'hash', 'token',
    'nextpagetoken', 'pagetoken', 'continuationtoken',
}

# object-type field name hints
OBJECT_HINTS = {'labels', 'metadata', 'annotations', 'tags', 'properties',
                'config', 'configuration', 'settings', 'policy', 'binding',
                'condition', 'spec', 'status', 'selector', 'template'}

# array-type field name hints
ARRAY_HINTS = {'items', 'entries', 'list', 'records', 'results',
               'permissions', 'members', 'roles', 'zones', 'regions',
               'scopes', 'services', 'targets', 'resources', 'networks',
               'routes', 'rules', 'paths', 'fields', 'values', 'keys',
               'ranges', 'ports', 'subnets', 'clusters', 'nodes'}

# GCP timestamp field name hints
TIMESTAMP_HINTS = {'createtime', 'creationtime', 'creationtimestamp',
                   'updatetime', 'updatetimestamp', 'deletetime',
                   'expiretime', 'expireat', 'starttime', 'endtime',
                   'lastmodified', 'lastchangetime', 'enforcementtime',
                   'timestamp', 'time', 'date', 'deadline', 'expiration'}

# Placeholder values the old system used — treat as no real enum data
PLACEHOLDER_VALUES = {'OFF', 'ON', 'PAUSED', 'PENDING', 'UNKNOWN'}

# Generic GCP resource fields that should NEVER have enum values — they are
# identifiers, timestamps, or descriptors that can hold arbitrary strings.
# The old pipeline mistakenly assigned cross-service enum values to these.
NON_ENUM_FIELD_NAMES = {
    'creationtimestamp', 'description', 'etag', 'id', 'kind',
    'labels', 'name', 'selflink', 'updatetimestamp', 'fingerprint',
    'createdby', 'updateby', 'lastupdated', 'createtime', 'updatetime',
}

# Values that indicate cross-service KMS/crypto contamination from old pipeline
# These should NEVER appear as enum values for generic field names like
# creationTimestamp, description, etag, kind, selfLink
CROSS_CONTAMINATION_PREFIXES = (
    'RSA_', 'AES_', 'EC_', 'HMAC_', 'ML_', 'PQ_', 'KEM_',
    'RSA_SIGN_', 'RSA_DECRYPT_',
)
CROSS_CONTAMINATION_VALUES = {
    'CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED', 'EXTERNAL_SYMMETRIC_ENCRYPTION',
    'GOOGLE_SYMMETRIC_ENCRYPTION',
}

def is_cross_contaminated(values: Optional[List]) -> bool:
    """Return True if the values list looks like cross-service KMS contamination."""
    if not values:
        return False
    contaminated = sum(
        1 for v in values
        if any(str(v).startswith(p) for p in CROSS_CONTAMINATION_PREFIXES)
        or str(v) in CROSS_CONTAMINATION_VALUES
    )
    return contaminated >= 3  # if 3+ contamination markers, flag it


# ─────────────────────────────────────────────────────────────────────────────
# Data loading helpers
# ─────────────────────────────────────────────────────────────────────────────

def load_json(path: Path) -> Optional[dict]:
    if path.exists():
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"  Warning: could not load {path}: {e}")
    return None


def is_placeholder(values: Optional[List]) -> bool:
    """Return True if the possible_values list is the old generic placeholder set."""
    if not values:
        return True
    return set(values) == PLACEHOLDER_VALUES or set(values).issubset(PLACEHOLDER_VALUES)

def is_bad_enum(values: Optional[List]) -> bool:
    """Return True if values are unusable (placeholder OR cross-contaminated)."""
    return is_placeholder(values) or is_cross_contaminated(values)


# ─────────────────────────────────────────────────────────────────────────────
# Field extraction from operation_registry.json
# ─────────────────────────────────────────────────────────────────────────────

def extract_fields_from_registry(registry: dict) -> Dict[str, dict]:
    """
    Walk all operations in operation_registry.json.
    For each operation, collect produces[] entries with source='item'.
    Returns {field_path: {type, enum, possible_values, description}}
    """
    fields: Dict[str, dict] = {}
    operations = registry.get('operations', {})

    for op_key, op_data in operations.items():
        produces = op_data.get('produces', [])
        for p in produces:
            if p.get('source') != 'item':
                continue
            field_path = p.get('path', '')
            if not field_path:
                continue
            # Take the leaf name as field key
            leaf = field_path.split('.')[-1] if '.' in field_path else field_path
            if leaf and leaf not in fields:
                fields[leaf] = {
                    'field_name': leaf,
                    'type': p.get('type', 'string'),
                    'enum': p.get('enum', False),
                    'possible_values': p.get('possible_values') or [],
                    'description': p.get('description', ''),
                    'source': 'operation_registry',
                }
    return fields


# ─────────────────────────────────────────────────────────────────────────────
# Field extraction from gcp_dependencies JSON
# ─────────────────────────────────────────────────────────────────────────────

def extract_fields_from_deps(deps: dict, service_name: str) -> Dict[str, dict]:
    """
    Walk independent + dependent operations in gcp_dependencies JSON.
    Returns {field_name: {type, enum, possible_values}}
    """
    fields: Dict[str, dict] = {}
    svc_data = deps.get(service_name, deps)  # handle both wrapped and unwrapped

    for kind in ('independent', 'dependent'):
        for op in svc_data.get(kind, []):
            item_fields = op.get('item_fields', {})
            if not isinstance(item_fields, dict):
                continue
            for fname, fdata in item_fields.items():
                if fname not in fields and isinstance(fdata, dict):
                    pv = fdata.get('possible_values') or []
                    fields[fname] = {
                        'field_name': fname,
                        'type': fdata.get('type', 'string'),
                        'enum': bool(fdata.get('enum', False)) and not is_bad_enum(pv),
                        'possible_values': pv if not is_bad_enum(pv) else [],
                        'description': fdata.get('description', ''),
                        'source': 'gcp_deps',
                    }
    return fields


# ─────────────────────────────────────────────────────────────────────────────
# Field extraction from direct_vars.json
# ─────────────────────────────────────────────────────────────────────────────

def extract_fields_from_direct_vars(dv: dict) -> Dict[str, dict]:
    """
    Extract fields from direct_vars.json.

    Two-pass strategy:
    1. First identify which fields have source=='discovery_response_schema'
       (real Live-API data). Those get full trust including enum/values.
    2. Legacy seeded fields (no source or generic source) get operators only —
       their possible_values are NEVER trusted because the old pipeline cross-
       contaminated fields (e.g. creationTimestamp got KMS crypto enum values).
    """
    fields: Dict[str, dict] = {}
    raw_fields = dv.get('fields', {})

    # Pass 1: collect all discovery_response_schema field names
    discovery_schema_fields: Set[str] = {
        fname for fname, fd in raw_fields.items()
        if isinstance(fd, dict) and fd.get('source') == 'discovery_response_schema'
    }

    for fname, fdata in raw_fields.items():
        if not isinstance(fdata, dict):
            continue
        source = fdata.get('source', '')

        if source == 'discovery_response_schema':
            # Real type+enum data from live Discovery API
            pv = fdata.get('possible_values') or []
            fields[fname] = {
                'field_name': fname,
                'type': fdata.get('type', 'string'),
                'enum': fdata.get('enum', False) and bool(pv) and not is_bad_enum(pv),
                'possible_values': pv if not is_bad_enum(pv) else [],
                'description': fdata.get('description', ''),
                'source': 'direct_vars_discovery',
                '_operators': fdata.get('operators') or [],
            }
        else:
            # Legacy seeded field.
            # Trust possible_values ONLY if they look like real service-specific
            # enum values (not the OFF/ON/PAUSED placeholder set and not cross-
            # service KMS contamination from the old enrichment pipeline).
            ops = fdata.get('operators') or []
            pv = fdata.get('possible_values') or []
            is_real = (
                bool(pv)
                and not is_bad_enum(pv)
                and fname.lower() not in NON_ENUM_FIELD_NAMES
            )
            fields[fname] = {
                'field_name': fname,
                'type': fdata.get('type', 'string'),
                'enum': is_real and fdata.get('enum', False),
                'possible_values': pv if is_real else [],
                'description': fdata.get('description', ''),
                'source': 'direct_vars_legacy',
                '_operators': ops,
            }

    return fields


# ─────────────────────────────────────────────────────────────────────────────
# Operator determination
# ─────────────────────────────────────────────────────────────────────────────

def normalise_type(raw_type: str) -> str:
    """Collapse complex GCP type strings into simple categories."""
    t = (raw_type or 'string').lower()
    if t.startswith('array') or t in ('array', 'list'):
        return 'array'
    if t in ('object', 'map', 'dict', 'structure', 'struct'):
        return 'object'
    if t in ('integer', 'int32', 'int64', 'long', 'uint32', 'uint64'):
        return 'integer'
    if t in ('number', 'float', 'double'):
        return 'number'
    if t == 'boolean':
        return 'boolean'
    if 'timestamp' in t or 'datetime' in t or t == 'date':
        return 'timestamp'
    return 'string'


def field_type_by_name_hints(field_name: str, base_type: str) -> str:
    """Override inferred type using name patterns."""
    lower = field_name.lower()
    if base_type in ('string', 'any'):
        if lower in TIMESTAMP_HINTS or any(lower.endswith(h) for h in ('time', 'timestamp', 'at', 'date')):
            return 'timestamp'
        if lower in OBJECT_HINTS:
            return 'object'
        if lower in ARRAY_HINTS or lower.endswith('list') or lower.endswith('items'):
            return 'array'
    return base_type


def get_operators_for_field(field_name: str, field_type: str,
                             is_enum: bool, has_values: bool,
                             legacy_operators: List[str]) -> List[str]:
    """
    Determine the sorted list of operators for this field.
    Priority:
      1. Use legacy operators if they're real (not empty and not just placeholders)
      2. Infer from type + enum status
    """
    lower = field_name.lower()
    ops: Set[str] = set()

    # Start from type defaults
    ops.update(TYPE_OPERATORS.get(field_type, TYPE_OPERATORS['string']))

    # Add exists for certain field names
    if lower in NAME_HINTS_FOR_EXISTS or lower.endswith('id') or lower.endswith('arn'):
        ops.add('exists')

    # Objects and arrays always get exists/not_exists
    if field_type in ('object', 'array'):
        ops.add('exists')
        ops.add('not_exists')
        if field_type == 'object':
            ops.add('not_empty')

    # Booleans only get equals/not_equals
    if field_type == 'boolean':
        ops = {'equals', 'not_equals'}

    # Enums: drop range/contains, keep equals/in/not_equals/not_in
    if is_enum or has_values:
        for drop in ('contains', 'in_range', 'greater_than', 'less_than',
                     'greater_than_or_equal', 'less_than_or_equal', 'gt', 'gte', 'lt', 'lte'):
            ops.discard(drop)
        ops.update(['equals', 'in', 'not_equals', 'not_in'])

    # Merge real legacy operators (non-placeholder)
    clean_legacy = [o.strip() for o in (legacy_operators or []) if o.strip()]
    if clean_legacy:
        ops.update(clean_legacy)

    return sorted(ops)


# ─────────────────────────────────────────────────────────────────────────────
# CSV row builder
# ─────────────────────────────────────────────────────────────────────────────

def build_row(service_name: str, field_name: str, merged: dict) -> dict:
    raw_type = merged.get('type', 'string')
    norm_type = normalise_type(raw_type)
    norm_type = field_type_by_name_hints(field_name, norm_type)

    # Use a simplified type for the CSV (matches existing CSV style)
    csv_type = norm_type  # keep as-is: string/boolean/integer/object/array/timestamp/number

    is_enum = merged.get('enum', False)
    possible_values = merged.get('possible_values') or []
    has_values = bool(possible_values) and not is_bad_enum(possible_values)
    if not has_values:
        possible_values = []
        is_enum = False

    legacy_ops = merged.get('_operators') or []
    operators = get_operators_for_field(field_name, norm_type, is_enum, has_values, legacy_ops)

    # Split operators into categories
    ops_no_value: List[str] = []
    ops_select_list: List[str] = []
    ops_manual: List[str] = []

    for op in operators:
        if op in OPERATORS_NO_VALUE:
            ops_no_value.append(op)
        elif has_values and op in OPERATORS_WITH_VALUE:
            ops_select_list.append(op)
        elif op in OPERATORS_WITH_VALUE:
            ops_manual.append(op)
        # skip any unknown operators

    ops_no_value.sort()
    ops_select_list.sort()
    ops_manual.sort()

    # Determine value_requirement_type
    has_nv = bool(ops_no_value)
    has_sl = bool(ops_select_list)
    has_mi = bool(ops_manual)

    if has_nv and not has_sl and not has_mi:
        vrt = 'No value required'
    elif has_sl and not has_mi and not has_nv:
        vrt = 'Select from list only'
    elif has_mi and not has_sl and not has_nv:
        vrt = 'Manual input only'
    elif has_nv and has_sl and not has_mi:
        vrt = 'No value or select from list'
    elif has_nv and has_mi and not has_sl:
        vrt = 'No value or manual input'
    elif has_sl and has_mi and not has_nv:
        vrt = 'Select from list or manual input'
    else:
        vrt = 'Mixed (no value, select, or manual)'

    values_source = ''
    if has_values:
        src = merged.get('source', '')
        if 'registry' in src:
            values_source = 'direct_vars'
        elif 'deps' in src:
            values_source = 'direct_vars'
        else:
            values_source = 'direct_vars'

    return {
        'service':              service_name,
        'field_name':           field_name,
        'field_type':           csv_type,
        'is_enum':              'Yes' if is_enum or has_values else 'No',
        'operators':            ', '.join(operators),
        'operators_no_value':   ', '.join(ops_no_value),
        'operators_select_list': ', '.join(ops_select_list),
        'operators_manual_input': ', '.join(ops_manual),
        'value_requirement_type': vrt,
        'possible_values':      ', '.join(str(v) for v in possible_values),
        'values_source':        values_source,
        'num_possible_values':  len(possible_values),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Per-service generation
# ─────────────────────────────────────────────────────────────────────────────

def merge_field_sources(sources: List[Dict[str, dict]], priority_order: List[str]) -> Dict[str, dict]:
    """
    Merge multiple {field_name: field_info} dicts.
    Priority: if a field already has real possible_values, keep them.
    Otherwise overlay with later sources.
    """
    merged: Dict[str, dict] = {}
    for src in sources:
        for fname, fdata in src.items():
            # Skip dotted names (nested) — keep only leaf fields
            if '.' in fname:
                continue
            if fname not in merged:
                merged[fname] = dict(fdata)
            else:
                existing = merged[fname]
                incoming = fdata

                # Update type if existing is generic 'string' and incoming is more specific
                if existing.get('type', 'string') == 'string' and incoming.get('type', 'string') != 'string':
                    existing['type'] = incoming['type']

                # Merge possible_values — prefer non-placeholder
                ex_pv = existing.get('possible_values') or []
                in_pv = incoming.get('possible_values') or []
                if (not ex_pv or is_bad_enum(ex_pv)) and in_pv and not is_bad_enum(in_pv):
                    existing['possible_values'] = in_pv
                    existing['enum'] = incoming.get('enum', True)
                    existing['source'] = incoming.get('source', existing.get('source'))

                # Merge legacy operators
                ex_ops = existing.get('_operators') or []
                in_ops = incoming.get('_operators') or []
                all_ops = list(set(ex_ops) | set(in_ops))
                existing['_operators'] = all_ops

                # description fallback
                if not existing.get('description') and incoming.get('description'):
                    existing['description'] = incoming['description']

    return merged


def generate_service(service_name: str, service_dir: Path) -> List[dict]:
    """Generate CSV rows for a single GCP service."""
    registry  = load_json(service_dir / 'operation_registry.json')
    deps      = load_json(service_dir / 'gcp_dependencies_with_python_names_fully_enriched.json')
    dv        = load_json(service_dir / 'direct_vars.json')

    sources: List[Dict[str, dict]] = []

    # Source 1: operation_registry (highest confidence — live API)
    if registry:
        sources.append(extract_fields_from_registry(registry))

    # Source 2: gcp_dependencies
    if deps:
        sources.append(extract_fields_from_deps(deps, service_name))

    # Source 3: direct_vars (legacy fallback)
    if dv:
        sources.append(extract_fields_from_direct_vars(dv))

    if not sources:
        return []

    merged = merge_field_sources(sources, [])

    if not merged:
        return []

    rows = []
    for fname in sorted(merged.keys()):
        row = build_row(service_name, fname, merged[fname])
        rows.append(row)

    return rows


def save_csv(rows: List[dict], output_path: Path):
    fieldnames = [
        'service', 'field_name', 'field_type', 'is_enum',
        'operators', 'operators_no_value', 'operators_select_list',
        'operators_manual_input', 'value_requirement_type',
        'possible_values', 'values_source', 'num_possible_values',
    ]
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


# ─────────────────────────────────────────────────────────────────────────────
# Main runner
# ─────────────────────────────────────────────────────────────────────────────

def run_all(base_dir: Path, single_service: Optional[str] = None, dry_run: bool = False):
    print("=" * 80)
    print("GCP field_operator_value_table.csv GENERATOR v2")
    print("=" * 80)

    if single_service:
        service_dirs = [base_dir / single_service]
    else:
        service_dirs = sorted(
            d for d in base_dir.iterdir()
            if d.is_dir() and not d.name.startswith('.')
            and not d.name.endswith('.py')
            and not d.name.endswith('.md')
        )

    total = len(service_dirs)
    processed = 0
    skipped = 0
    errors = []

    for sdir in service_dirs:
        service_name = sdir.name
        # Skip non-service dirs
        if not (sdir / 'operation_registry.json').exists() and \
           not (sdir / 'direct_vars.json').exists():
            skipped += 1
            continue

        try:
            rows = generate_service(service_name, sdir)
            if not rows:
                skipped += 1
                print(f"  ⚠  {service_name}: no fields found — skipping")
                continue

            output_path = sdir / 'field_operator_value_table.csv'
            if not dry_run:
                save_csv(rows, output_path)

            processed += 1
            enum_count = sum(1 for r in rows if r['is_enum'] == 'Yes')
            if processed <= 10 or processed % 50 == 0:
                print(f"  ✓ {service_name}: {len(rows)} fields ({enum_count} enum)")

        except Exception as e:
            errors.append((service_name, str(e)))
            print(f"  ✗ {service_name}: ERROR — {e}")

    print()
    print("=" * 80)
    print("DONE")
    print(f"  Total dirs scanned : {total}")
    print(f"  Services processed : {processed}")
    print(f"  Skipped            : {skipped}")
    print(f"  Errors             : {len(errors)}")
    if errors:
        print("\nErrors:")
        for svc, err in errors:
            print(f"  {svc}: {err}")
    print("=" * 80)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Generate field_operator_value_table.csv for GCP services')
    parser.add_argument('--service', help='Run for a single service only')
    parser.add_argument('--dry-run', action='store_true', help='Do not write files')
    parser.add_argument('--all', dest='run_all', action='store_true', help='Run for all services')
    args = parser.parse_args()

    if args.service:
        run_all(BASE_DIR, single_service=args.service, dry_run=args.dry_run)
    else:
        run_all(BASE_DIR, dry_run=args.dry_run)
