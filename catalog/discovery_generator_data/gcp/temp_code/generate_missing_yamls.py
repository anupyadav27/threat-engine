#!/usr/bin/env python3
"""
Generate step2_{service}_discovery.yaml for services that have
step1_operation_registry.json and step3_gcp_dependencies but no YAML.

Uses GCP Discovery API to get real field schemas for list operations.
Falls back to operation_registry produces[] fields if API unavailable.
"""

import json
import re
import time
import urllib.request
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Tuple

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

# ── YAML custom dumper ──────────────────────────────────────────────────────
class LiteralStr(str): pass

def literal_representer(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style="'")

yaml.add_representer(LiteralStr, literal_representer)

class IndentDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow=flow, indentless=False)

yaml.add_representer(LiteralStr, literal_representer, Dumper=IndentDumper)

def wrap_jinja_recursive(obj):
    if isinstance(obj, dict): return {k: wrap_jinja_recursive(v) for k, v in obj.items()}
    if isinstance(obj, list): return [wrap_jinja_recursive(v) for v in obj]
    if isinstance(obj, str) and '{{' in obj: return LiteralStr(obj)
    return obj

def write_yaml(doc: dict, path: Path):
    wrapped = wrap_jinja_recursive(doc)
    with open(path, 'w', encoding='utf-8') as f:
        yaml.dump(wrapped, f, Dumper=IndentDumper,
                  default_flow_style=False, allow_unicode=True,
                  sort_keys=False, width=120)

# ── GCP Discovery API ───────────────────────────────────────────────────────
_discovery_index = None
_schema_cache: Dict[str, dict] = {}

def get_discovery_index():
    global _discovery_index
    if _discovery_index is None:
        try:
            url = "https://www.googleapis.com/discovery/v1/apis"
            with urllib.request.urlopen(url, timeout=15) as r:
                data = json.load(r)
            _discovery_index = {}
            for item in data.get('items', []):
                svc = item.get('name', '')
                ver = item.get('version', '')
                preferred = item.get('preferred', False)
                if svc not in _discovery_index or preferred:
                    _discovery_index[svc] = {'version': ver, 'discoveryRestUrl': item.get('discoveryRestUrl', '')}
        except Exception as e:
            print(f"  Warning: could not fetch discovery index: {e}")
            _discovery_index = {}
    return _discovery_index

def fetch_service_schemas(service: str) -> dict:
    """Fetch schemas for a service from GCP Discovery API."""
    if service in _schema_cache:
        return _schema_cache[service]
    
    index = get_discovery_index()
    entry = index.get(service)
    if not entry:
        _schema_cache[service] = {}
        return {}
    
    url = entry.get('discoveryRestUrl', '')
    if not url:
        _schema_cache[service] = {}
        return {}
    
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            data = json.load(r)
        schemas = data.get('schemas', {})
        _schema_cache[service] = schemas
        return schemas
    except Exception as e:
        print(f"  Warning: could not fetch schemas for {service}: {e}")
        _schema_cache[service] = {}
        return {}

def find_list_fields_from_schemas(schemas: dict, resource: str, method: str) -> Tuple[Optional[str], List[str]]:
    """Find (list_key, item_fields) for a list operation using Discovery API schemas."""
    resource_lower = resource.lower()
    
    # Common naming patterns for list response schemas
    candidates = []
    for name in schemas:
        name_lower = name.lower()
        if resource_lower in name_lower and ('list' in name_lower or 'response' in name_lower):
            candidates.append(name)
    
    # Also try direct resource name + List/Response suffix
    resource_cap = resource[0].upper() + resource[1:] if resource else ''
    for suffix in ['ListResponse', 'List', 'AggregatedList', 'ListResult']:
        candidates.insert(0, f"{resource_cap}{suffix}")
    
    for candidate in candidates:
        if candidate not in schemas:
            continue
        schema = schemas[candidate]
        props = schema.get('properties', {})
        # Find array property = the actual list
        for prop_k, prop_v in props.items():
            if prop_v.get('type') == 'array':
                item_ref = prop_v.get('items', {}).get('$ref', '')
                if item_ref and item_ref in schemas:
                    item_props = schemas[item_ref].get('properties', {})
                    if item_props:
                        return prop_k, list(item_props.keys())
    
    return None, []

# ── Registry helpers ────────────────────────────────────────────────────────
def load_registry(svc_dir: Path) -> Dict:
    reg_path = svc_dir / 'step1_operation_registry.json'
    if reg_path.exists():
        return json.load(open(reg_path)).get('operations', {})
    return {}

def get_item_fields_from_registry(discovery_id: str, operations: Dict) -> List[str]:
    op = operations.get(discovery_id)
    if not op:
        suffix = '.' + '.'.join(discovery_id.split('.')[2:])
        for k, v in operations.items():
            if k.lower().endswith(suffix.lower()):
                op = v
                break
    if not op:
        return []
    return [p['path'] for p in op.get('produces', []) if p.get('source') == 'item']

def get_output_path_from_registry(discovery_id: str, operations: Dict) -> Optional[str]:
    op = operations.get(discovery_id)
    if not op:
        suffix = '.' + '.'.join(discovery_id.split('.')[2:])
        for k, v in operations.items():
            if k.lower().endswith(suffix.lower()):
                op = v
                break
    if not op:
        return None
    return next((p['path'] for p in op.get('produces', [])
                 if p.get('source') == 'output'), None)

# ── Dependencies helper ─────────────────────────────────────────────────────
def load_all_ops(svc_dir: Path, service: str) -> Tuple[List[str], List[str]]:
    """Return (independent_ops, dependent_ops) as operation short names."""
    dep_files = list(svc_dir.glob('step3_*.json'))
    if not dep_files:
        return [], []
    try:
        dep = json.load(open(dep_files[0]))
    except:
        return [], []
    svc_data = dep.get(service, dep)
    indep = [op.get('operation', '') for op in svc_data.get('independent', []) if op.get('operation')]
    dependent = [op.get('operation', '') for op in svc_data.get('dependent', []) if op.get('operation')]
    return indep, dependent

# ── Build YAML entry ────────────────────────────────────────────────────────
LIST_METHODS = {'list', 'aggregatedlist', 'listinstances', 'listhidden', 'search', 'query'}
READ_METHODS = {'get', 'describe', 'getbyname', 'getbyid', 'fetch'}

def op_to_action(operation: str) -> str:
    """Convert 'datasets.list' → 'list', 'datasets.aggregatedList' → 'aggregatedList'."""
    return operation.split('.')[-1] if '.' in operation else operation

def build_entry(discovery_id: str, operation: str, service: str,
                operations: Dict, schemas: dict) -> dict:
    """Build a single YAML discovery entry."""
    action = op_to_action(operation)
    resource = operation.split('.')[-2] if '.' in operation else service
    method_lower = action.lower()
    
    entry = {
        'discovery_id': discovery_id,
        'calls': [{
            'action': action,
            'save_as': 'response',
            'on_error': 'continue',
        }],
        'emit': {
            'as': 'item',
            'items_for': LiteralStr('{{ response }}'),
        }
    }
    
    # Try to get item fields
    item_fields = []
    list_key = None
    
    if method_lower in LIST_METHODS or method_lower.startswith('list'):
        # First try Discovery API schemas
        list_key, item_fields = find_list_fields_from_schemas(schemas, resource, action)
        
        # Fall back to registry produces[]
        if not item_fields:
            item_fields = get_item_fields_from_registry(discovery_id, operations)
            if not item_fields:
                # Try paired get operation
                parts = discovery_id.split('.')
                get_did = '.'.join(parts[:-1] + ['get'])
                item_fields = get_item_fields_from_registry(get_did, operations)
            list_key = get_output_path_from_registry(discovery_id, operations)
    
    elif method_lower in READ_METHODS:
        # Single-item read
        item_fields = get_item_fields_from_registry(discovery_id, operations)
        if item_fields:
            list_key = None  # no list key, response IS the item
    
    if item_fields:
        if list_key:
            entry['emit']['items_for'] = LiteralStr(f'{{{{ response.{list_key} }}}}')
        entry['emit']['item'] = {f: LiteralStr(f'{{{{ item.{f} }}}}') for f in item_fields}
    
    return entry

# ── Main ────────────────────────────────────────────────────────────────────
def generate_yaml_for_service(svc_dir: Path) -> bool:
    service = svc_dir.name
    yaml_files = list(svc_dir.glob('step2_*_discovery.yaml'))
    if yaml_files:
        return False  # already exists
    
    operations = load_registry(svc_dir)
    if not operations:
        return False
    
    indep_ops, dep_ops = load_all_ops(svc_dir, service)
    if not indep_ops and not dep_ops:
        # Fall back: use all list/get ops from registry
        for k, v in operations.items():
            kind = v.get('kind', '')
            short = '.'.join(k.split('.')[2:])  # strip gcp.service prefix
            if kind == 'read_list':
                indep_ops.append(short)
            elif kind == 'read_get':
                dep_ops.append(short)
    
    if not indep_ops and not dep_ops:
        return False
    
    # Fetch schemas from Discovery API
    schemas = fetch_service_schemas(service)
    time.sleep(0.05)
    
    all_ops = list(dict.fromkeys(indep_ops + dep_ops))  # dedup, preserve order
    entries = []
    
    for operation in all_ops:
        discovery_id = f"gcp.{service}.{operation}"
        entry = build_entry(discovery_id, operation, service, operations, schemas)
        entries.append(entry)
    
    if not entries:
        return False
    
    doc = {'discovery': entries}
    yaml_path = svc_dir / f'step2_{service}_discovery.yaml'
    write_yaml(doc, yaml_path)
    return True

def run(base_dir: Path):
    print('=' * 70)
    print('Generating missing step2 discovery YAMLs')
    print('=' * 70)
    
    service_dirs = sorted(
        d for d in base_dir.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and not d.name.endswith('.py') and not d.name.endswith('.md')
    )
    
    generated = skipped = 0
    for sdir in service_dirs:
        yaml_files = list(sdir.glob('step2_*_discovery.yaml'))
        if yaml_files:
            continue  # already has YAML
        
        ok = generate_yaml_for_service(sdir)
        if ok:
            generated += 1
            print(f'  ✓ {sdir.name}')
        else:
            skipped += 1
    
    print()
    print(f'Generated: {generated}')
    print(f'Skipped:   {skipped}  (no registry or no operations)')
    print('=' * 70)

if __name__ == '__main__':
    run(BASE_DIR)
