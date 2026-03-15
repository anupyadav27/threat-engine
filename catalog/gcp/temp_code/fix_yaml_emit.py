#!/usr/bin/env python3
"""
Fix GCP discovery YAML emit blocks to properly emit all item fields.

Two problems to fix:
  1. EMPTY item: block  → find item fields from operation_registry
  2. WRAPPER keys       → items_for points to {{ response }} emitting wrapper
                          keys (datasets, nextPageToken, kind...) instead of
                          the actual items. Fix: find the real list key, update
                          items_for to {{ response.<key> }}, pull item fields
                          from the paired .get operation.

Source of truth for real item fields: step1_operation_registry.json produces[]
"""

import json
import re
import os
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Tuple

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

# Keys that are list-wrapper fields — NOT real item fields
WRAPPER_KEYS = {
    'nextPageToken', 'pageToken', 'kind', 'etag', 'selfLink',
    'id', 'warning', 'warnings', 'unreachables', 'unreachable',
    'totalItems', 'pageInfo', 'regions', 'zones',
}

# Keys that signal "this IS the real list inside the wrapper"
LIST_SIGNAL_KEYS = {
    'items', 'datasets', 'jobs', 'tables', 'models', 'routines',
    'policies', 'accounts', 'rules', 'entries', 'resources',
    'operations', 'locations', 'networks', 'instances', 'clusters',
    'buckets', 'objects', 'files', 'topics', 'subscriptions',
    'messages', 'records', 'results', 'nodes', 'namespaces',
    'services', 'endpoints', 'routes', 'secrets', 'versions',
    'snapshots', 'backups', 'replicas', 'disks', 'images',
    'firewalls', 'zones', 'regions', 'projects', 'folders',
    'organizations', 'groups', 'members', 'users', 'roles',
    'permissions', 'keys', 'certificates', 'deployments', 'configs',
    'environments', 'functions', 'triggers', 'connectors', 'pipelines',
    'workflows', 'executions', 'tasks', 'queues', 'jobs', 'batches',
    'artifacts', 'repositories', 'packages', 'tags', 'builds',
    'targets', 'releases', 'rollouts', 'pages', 'sites', 'apps',
    'spaces', 'channels', 'memberships', 'reactions', 'attachments',
    'queries', 'reports', 'metrics', 'alerts', 'incidents', 'events',
    'logs', 'sinks', 'exclusions', 'views', 'buckets', 'datasets',
    'schemas', 'subjects', 'consumerGroups', 'connectors', 'acl',
    'rows', 'columns', 'fields', 'tables', 'indexes', 'constraints',
    'sessions', 'transactions', 'backups', 'restores',
    'annotationSets', 'annotations', 'callSets', 'readGroupSets',
    'readGroups', 'reads', 'variants', 'variantSets', 'referenceBindings',
    'references', 'referenceSets',
}


# ── YAML custom dumper (preserve Jinja2 single-quoted strings) ────────────────
class LiteralStr(str):
    pass

def literal_representer(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style="'")

yaml.add_representer(LiteralStr, literal_representer)

class IndentDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow=flow, indentless=False)

yaml.add_representer(LiteralStr, literal_representer, Dumper=IndentDumper)


# ── Registry helpers ──────────────────────────────────────────────────────────

def load_registry(svc_dir: Path) -> Dict:
    reg_path = svc_dir / 'step1_operation_registry.json'
    if reg_path.exists():
        return json.load(open(reg_path)).get('operations', {})
    return {}


def get_item_fields_from_registry(discovery_id: str, operations: Dict) -> List[str]:
    """Get produces[source=item] field paths for a discovery_id."""
    op = operations.get(discovery_id)
    if not op:
        # Try suffix match for nested resource paths
        suffix = '.' + '.'.join(discovery_id.split('.')[2:])
        for k, v in operations.items():
            if k.endswith(suffix) or k.lower().endswith(suffix.lower()):
                op = v
                break
    if not op:
        return []
    return [p['path'] for p in op.get('produces', []) if p.get('source') == 'item']


def get_output_path_from_registry(discovery_id: str, operations: Dict) -> Optional[str]:
    """Get produces[source=output] path (the list key) for a discovery_id."""
    op = operations.get(discovery_id)
    if not op:
        suffix = '.' + '.'.join(discovery_id.split('.')[2:])
        for k, v in operations.items():
            if k.endswith(suffix) or k.lower().endswith(suffix.lower()):
                op = v
                break
    if not op:
        return None
    return next((p['path'] for p in op.get('produces', [])
                 if p.get('source') == 'output'), None)


def find_paired_get_fields(discovery_id: str, operations: Dict) -> Tuple[Optional[str], List[str]]:
    """
    For a .list discovery_id, find the paired .get operation and return
    (output_path, item_fields_from_get).
    e.g. gcp.bigquery.datasets.list → gcp.bigquery.datasets.get
         output_path='datasets', item_fields=[access, creationTime, ...]
    """
    # Replace last segment (list/aggregatedList) with 'get'
    parts = discovery_id.split('.')
    for get_suffix in ['get', 'describe']:
        get_did = '.'.join(parts[:-1] + [get_suffix])
        item_fields = get_item_fields_from_registry(get_did, operations)
        output_path = get_output_path_from_registry(get_did, operations)
        if item_fields:
            return output_path, item_fields

    return None, []


def detect_real_list_key(item_keys: List[str]) -> Optional[str]:
    """
    Given wrapper keys like ['datasets','etag','kind','nextPageToken'],
    find which one is the real list payload.
    """
    # Prefer keys that are in LIST_SIGNAL_KEYS
    for k in item_keys:
        if k in LIST_SIGNAL_KEYS and k not in WRAPPER_KEYS:
            return k
    # Any key not in WRAPPER_KEYS
    for k in item_keys:
        if k not in WRAPPER_KEYS:
            return k
    return None


# ── Fix single YAML entry ─────────────────────────────────────────────────────

def fix_entry(entry: dict, operations: Dict) -> Tuple[bool, str]:
    """
    Fix a single discovery entry's emit block.
    Returns (was_changed, reason).
    """
    emit = entry.get('emit', {})
    item = emit.get('item') or {}
    items_for = emit.get('items_for', '')
    discovery_id = entry.get('discovery_id', '')
    item_keys = list(item.keys()) if item else []

    # ── Case 1: EMPTY item block ──────────────────────────────────────────────
    if not item:
        # Get item fields from registry
        item_fields = get_item_fields_from_registry(discovery_id, operations)

        # If still empty, try paired .get
        if not item_fields:
            output_path, item_fields = find_paired_get_fields(discovery_id, operations)
            if output_path and items_for == '{{ response }}':
                emit['items_for'] = LiteralStr(f'{{{{ response.{output_path} }}}}')

        if item_fields:
            emit['item'] = {f: LiteralStr(f'{{{{ item.{f} }}}}') for f in item_fields}
            return True, f'EMPTY→filled {len(item_fields)} fields'
        return False, 'EMPTY→no fields found in registry'

    # ── Case 2: WRAPPER keys with {{ response }} ──────────────────────────────
    is_wrapper = (
        items_for == '{{ response }}'
        and item_keys
        and all(k in WRAPPER_KEYS | LIST_SIGNAL_KEYS for k in item_keys)
    )
    if not is_wrapper:
        return False, 'OK'

    # Detect which key is the real list
    real_list_key = detect_real_list_key(item_keys)

    if not real_list_key:
        return False, 'WRAPPER→could not detect list key'

    # Get real item fields — first from paired .get, then from list op itself
    output_path, item_fields = find_paired_get_fields(discovery_id, operations)

    if not item_fields:
        # Try from the list op's own registry entry (some list ops have full fields)
        item_fields = get_item_fields_from_registry(discovery_id, operations)
        # Filter out wrapper keys from these
        item_fields = [f for f in item_fields if f not in WRAPPER_KEYS]
        if real_list_key in item_fields:
            item_fields.remove(real_list_key)

    if item_fields:
        emit['items_for'] = LiteralStr(f'{{{{ response.{real_list_key} }}}}')
        emit['item'] = {f: LiteralStr(f'{{{{ item.{f} }}}}') for f in item_fields}
        return True, f'WRAPPER→fixed items_for=response.{real_list_key} + {len(item_fields)} fields'

    # Fallback: at least fix items_for even if we can't fill item fields
    emit['items_for'] = LiteralStr(f'{{{{ response.{real_list_key} }}}}')
    return True, f'WRAPPER→fixed items_for=response.{real_list_key} (no item fields)'


# ── YAML write helpers ────────────────────────────────────────────────────────

def wrap_jinja(val):
    """Wrap string values that look like Jinja2 templates."""
    if isinstance(val, str) and val.startswith('{{'):
        return LiteralStr(val)
    return val


def wrap_jinja_recursive(obj):
    if isinstance(obj, dict):
        return {k: wrap_jinja_recursive(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [wrap_jinja_recursive(v) for v in obj]
    if isinstance(obj, str) and ('{{' in obj or '{%' in obj):
        return LiteralStr(obj)
    return obj


def write_yaml(doc: dict, path: Path):
    wrapped = wrap_jinja_recursive(doc)
    with open(path, 'w', encoding='utf-8') as f:
        yaml.dump(wrapped, f, Dumper=IndentDumper,
                  default_flow_style=False, allow_unicode=True,
                  sort_keys=False, width=120)


# ── Service processor ─────────────────────────────────────────────────────────

def fix_service(svc_dir: Path) -> Tuple[int, int, int]:
    """Returns (entries_checked, fixed, errors)."""
    yaml_files = list(svc_dir.glob('step2_*_discovery.yaml'))
    if not yaml_files:
        return 0, 0, 0

    yaml_path = yaml_files[0]
    try:
        doc = yaml.safe_load(open(yaml_path))
    except Exception:
        return 0, 0, 1

    if not doc:
        return 0, 0, 0

    operations = load_registry(svc_dir)
    entries = doc.get('discovery') or []
    fixed_count = 0

    for entry in entries:
        changed, reason = fix_entry(entry, operations)
        if changed:
            fixed_count += 1

    if fixed_count > 0:
        write_yaml(doc, yaml_path)

    return len(entries), fixed_count, 0


# ── Main ──────────────────────────────────────────────────────────────────────

def run_all(base_dir: Path):
    print('=' * 70)
    print('Fixing GCP discovery YAML emit blocks')
    print('=' * 70)

    service_dirs = sorted(
        d for d in base_dir.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and not d.name.endswith('.py') and not d.name.endswith('.md')
    )

    total_entries = total_fixed = total_errors = svcs_changed = 0

    for sdir in service_dirs:
        checked, fixed, errors = fix_service(sdir)
        total_entries += checked
        total_fixed   += fixed
        total_errors  += errors
        if fixed:
            svcs_changed += 1
            print(f'  ✓ {sdir.name}: fixed {fixed}/{checked} entries')

    print()
    print(f'Services changed : {svcs_changed}')
    print(f'Entries fixed    : {total_fixed} / {total_entries}')
    print(f'YAML errors      : {total_errors}')
    print('=' * 70)


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        fix_service(BASE_DIR / sys.argv[1])
        print('Done')
    else:
        run_all(BASE_DIR)
