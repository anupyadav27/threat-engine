#!/usr/bin/env python3
"""
Rebuild step1_api_driven_registry.json for all GCP services
by fetching directly from the GCP Discovery API.

This replaces the self-overwrite loop where build_api_driven_registry.py
was reading its own stale output. Now we go back to the authoritative source:
the GCP Discovery REST API.

For each service, we:
  1. Fetch https://{service}.googleapis.com/$discovery/rest?version={v}
  2. Parse all methods → extract required_params, response_fields, path, etc.
  3. Build step1_api_driven_registry.json with correct required_params,
     response_fields, dependency_hints (tiered resolver), independence, etc.

The discovery URL list is read from existing step1_api_driven_registry.json
(which has title, version, base_url) — only the ops data was corrupted.
"""

import json
import re
import time
import urllib.request
import urllib.error
from pathlib import Path
from collections import defaultdict

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS (same as build_api_driven_registry.py)
# ─────────────────────────────────────────────────────────────────────────────

ALWAYS_AVAILABLE = {
    'projectId', 'project', 'parent',
    'location', 'region', 'zone',
    'organizationId', 'folderId', 'billingAccountId',
    'customerId', 'accountId',
}

SEGMENT_TO_ALWAYS = {
    'projects':       'project',
    'locations':      'location',
    'regions':        'region',
    'zones':          'zone',
    'organizations':  'organizationId',
    'folders':        'folderId',
    'billingAccounts':'billingAccountId',
    'customers':      'customerId',
    'accounts':       'accountId',
}

SKIP_FIELDS = {'nextPageToken', 'kind', 'etag', 'unreachable', 'warnings'}

READ_METHOD_NAMES = {
    'get', 'list', 'aggregatedList', 'search', 'fetch',
    'query', 'describe', 'read', 'lookup',
}

WRITE_METHOD_NAMES = {
    'create', 'insert', 'update', 'patch', 'delete', 'remove',
    'apply', 'set', 'add', 'move', 'copy', 'resize', 'start',
    'stop', 'restart', 'enable', 'disable', 'activate', 'deactivate',
}


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def singularize(word: str) -> str:
    if word.endswith('ies'):
        return word[:-3] + 'y'
    if word.endswith('sses'):
        return word[:-2]
    if word.endswith('ses'):
        return word[:-2]
    if word.endswith('s') and not word.endswith('ss'):
        return word[:-1]
    return word


def _is_var_segment(seg: str) -> bool:
    return seg in ('[^/]+', '[^/]*', '.*', '.+', '__VAR__')


def parse_pattern(pattern: str) -> tuple[str, list[dict]]:
    """Parse ^projects/[^/]+/locations/[^/]+/clusters/[^/]+$ → template + slots."""
    if not pattern:
        return '', []
    clean = pattern.lstrip('^').rstrip('$')
    clean = re.sub(r'\[\^/\]\+', '__VAR__', clean)
    clean = re.sub(r'\[\^/\]\*', '__VAR__', clean)
    clean = re.sub(r'\.\*',      '__VAR__', clean)
    clean = re.sub(r'\.\+',      '__VAR__', clean)
    raw_parts = clean.split('/')

    template_parts = []
    slots = []
    prev_literal = None

    for part in raw_parts:
        if _is_var_segment(part):
            if prev_literal and prev_literal in SEGMENT_TO_ALWAYS:
                slot_name = SEGMENT_TO_ALWAYS[prev_literal]
                source = 'always_available'
            elif prev_literal:
                slot_name = singularize(prev_literal) + 'Id'
                source = 'from_list_op'
            else:
                slot_name = 'resourceId'
                source = 'unknown'
            template_parts.append('{' + slot_name + '}')
            slots.append({
                'slot': slot_name,
                'source': source,
                'after_segment': prev_literal or '',
            })
        else:
            template_parts.append(part)
            prev_literal = part

    return '/'.join(template_parts), slots


def compute_independence(required_params: dict) -> bool:
    """True if ALL required param slots are always_available."""
    if not required_params:
        return True
    for pname, pinfo in required_params.items():
        pattern = pinfo.get('pattern', '')
        is_composite = bool(re.search(r'(?<!\[)[^[]*/', pattern))
        if pname in ALWAYS_AVAILABLE:
            pass
        elif pattern and is_composite:
            _, slots = parse_pattern(pattern)
            for slot in slots:
                if slot['source'] != 'always_available':
                    return False
        else:
            return False
    return True


def classify_kind(http_method: str, method_name: str) -> str:
    m = method_name.lower()
    if m in ('list', 'aggregatedlist', 'listsites', 'listviolatingsites',
             'search', 'query', 'listinstances'):
        return 'read_list'
    if m in ('get', 'describe', 'fetch', 'read', 'lookup', 'getconfig',
             'getserverconfig', 'getstatus', 'gethealth'):
        return 'read_get'
    if http_method.upper() == 'GET':
        if m.startswith('list'):
            return 'read_list'
        return 'read_get'
    if http_method.upper() in ('POST', 'PUT', 'PATCH'):
        if m in ('create', 'insert', 'update', 'patch', 'set', 'add'):
            return 'write_create' if m in ('create', 'insert') else 'write_update'
    if http_method.upper() == 'DELETE':
        return 'write_delete'
    return 'other'


# ─────────────────────────────────────────────────────────────────────────────
# DISCOVERY API FETCHER
# ─────────────────────────────────────────────────────────────────────────────

def fetch_discovery(service: str, version: str, base_url: str) -> dict | None:
    """Fetch discovery document. Try standard patterns."""
    urls_to_try = []

    # Standard GCP discovery URL
    urls_to_try.append(f'https://{service}.googleapis.com/$discovery/rest?version={version}')

    # Some services use different base URLs
    if base_url and 'googleapis.com' in base_url:
        host = base_url.rstrip('/').replace('https://', '').rstrip('/')
        urls_to_try.append(f'https://{host}/$discovery/rest?version={version}')

    # Global discovery API
    urls_to_try.append(
        f'https://www.googleapis.com/discovery/v1/apis/{service}/{version}/rest'
    )

    for url in urls_to_try:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Python/3'})
            with urllib.request.urlopen(req, timeout=15) as r:
                d = json.loads(r.read())
                if 'resources' in d or 'methods' in d:
                    return d
        except Exception:
            pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# SCHEMA RESOLVER
# ─────────────────────────────────────────────────────────────────────────────

def resolve_schema(schema_ref: str, schemas: dict, depth: int = 0) -> dict:
    """Resolve a $ref schema to its properties."""
    if depth > 5:
        return {}
    if not schema_ref or schema_ref not in schemas:
        return {}
    schema = schemas[schema_ref]
    if schema.get('type') == 'object' or 'properties' in schema:
        return schema.get('properties', {})
    return {}


def get_response_fields(method: dict, schemas: dict) -> dict:
    """Extract response_fields from a discovery method."""
    resp_ref = method.get('response', {}).get('$ref', '')
    if not resp_ref:
        return {}

    props = resolve_schema(resp_ref, schemas)
    result = {}

    for fname, finfo in props.items():
        ftype = finfo.get('type', 'string')
        if ftype == 'array':
            item_ref = finfo.get('items', {}).get('$ref', '')
            item_props = resolve_schema(item_ref, schemas)
            item_fields = list(item_props.keys())

            # Find best id field: 'name' > 'selfLink' > 'id' > first string
            id_field = None
            for candidate in ('name', 'selfLink', 'id', 'reviewedSite',
                              'resourceId', 'siteUrl', 'url'):
                if candidate in item_props:
                    id_field = candidate
                    break
            if not id_field and item_fields:
                # Pick first string field
                for f in item_fields:
                    if item_props[f].get('type', 'string') == 'string':
                        id_field = f
                        break
                if not id_field:
                    id_field = item_fields[0]

            result[fname] = {
                'type':        'array',
                'items':       item_ref or 'object',
                'item_fields': item_fields,
                'id_field':    id_field,
                'description': finfo.get('description', ''),
            }
        else:
            result[fname] = {
                'type':        ftype,
                'description': finfo.get('description', ''),
            }
            if 'enum' in finfo:
                result[fname]['enum'] = finfo['enum']

    return result


# ─────────────────────────────────────────────────────────────────────────────
# METHOD EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

def extract_methods(
    resources: dict,
    schemas: dict,
    service: str,
    prefix: str = '',
) -> list[dict]:
    """Recursively extract all methods from a discovery document's resources."""
    ops = []

    for rname, rdata in resources.items():
        if not isinstance(rdata, dict):
            continue

        # Methods at this level
        methods = rdata.get('methods', {})
        for mname, mdata in methods.items():
            if not isinstance(mdata, dict):
                continue

            http_method = mdata.get('httpMethod', 'GET')
            path        = mdata.get('path', mdata.get('flatPath', ''))
            description = mdata.get('description', '')

            # Build op_key: gcp.{service}.{resource_chain}.{method}
            resource_chain = (prefix + '.' + rname).lstrip('.') if prefix else rname
            op_key = f'gcp.{service}.{resource_chain}.{mname}'

            # Parameters (path + required query)
            all_params  = mdata.get('parameters', {})
            param_order = mdata.get('parameterOrder', [])

            required_params = {}
            optional_params = {}
            for pname, pinfo in all_params.items():
                entry = {
                    'type':        pinfo.get('type', 'string'),
                    'location':    pinfo.get('location', 'query'),
                    'description': pinfo.get('description', '')[:200],
                }
                if 'pattern' in pinfo:
                    entry['pattern'] = pinfo['pattern']
                if pinfo.get('required') or pname in param_order:
                    required_params[pname] = entry
                else:
                    optional_params[pname] = entry

            # Response fields
            response_fields  = get_response_fields(mdata, schemas)
            response_schema  = mdata.get('response', {}).get('$ref', '')

            kind = classify_kind(http_method, mname)

            # Python call
            parts = resource_chain.split('.')
            svc_call = '.'.join(f'{p}()' for p in parts)
            python_call = f'svc.{svc_call}.{mname}(**params).execute()'

            # Paginated?
            paginated = 'pageToken' in optional_params or 'pageSize' in optional_params

            ops.append({
                'op':              op_key,
                'kind':            kind,
                'http_method':     http_method,
                'path':            path,
                'description':     description[:300],
                'resource_chain':  resource_chain.split('.'),
                'method':          mname,
                'python_call':     python_call,
                'required_params': required_params,
                'optional_params': optional_params,
                'response_schema': response_schema,
                'response_fields': response_fields,
                'paginated':       paginated,
                'scopes':          mdata.get('scopes', []),
            })

        # Recurse into sub-resources
        sub = rdata.get('resources', {})
        if sub:
            new_prefix = (prefix + '.' + rname).lstrip('.')
            ops.extend(extract_methods(sub, schemas, service, new_prefix))

    return ops


# ─────────────────────────────────────────────────────────────────────────────
# TIERED SLOT RESOLVER (same as build_api_driven_registry.py)
# ─────────────────────────────────────────────────────────────────────────────

def build_list_ops_info(ops_dict: dict) -> dict:
    result = {}
    for lk, lop in ops_dict.items():
        if lop.get('kind') != 'read_list':
            continue
        parts    = lk.split('.')
        resource = parts[-2] if len(parts) >= 2 else ''
        rf       = lop.get('response_fields', {})
        list_field = id_field = None
        item_fields = []
        for fname, finfo in rf.items():
            if finfo.get('type') == 'array' and finfo.get('id_field'):
                list_field  = fname
                id_field    = finfo['id_field']
                item_fields = finfo.get('item_fields', [])
                break
        if not list_field:
            for fname, finfo in rf.items():
                if finfo.get('type') == 'array' and fname not in ('unreachable',):
                    list_field  = fname
                    id_field    = finfo.get('id_field', 'name')
                    item_fields = finfo.get('item_fields', [])
                    break
        result[lk] = {
            'resource':    resource,
            'list_field':  list_field,
            'id_field':    id_field,
            'item_fields': item_fields,
        }
    return result


def resolve_list_op_for_slot(after_segment, slot_name, list_ops_info):
    if not after_segment and not slot_name:
        return None, None, 5

    after_lower    = after_segment.lower() if after_segment else ''
    slot_base      = slot_name.replace('Id', '').lower() if slot_name else ''
    after_singular = singularize(after_lower)

    # Tier 1: exact
    for lk, li in list_ops_info.items():
        if li['resource'] == after_segment:
            return lk, li, 1

    # Tier 2: suffix/plural
    for lk, li in list_ops_info.items():
        res_lower    = li['resource'].lower()
        res_singular = singularize(res_lower)
        if (res_lower.endswith(after_lower) and after_lower
                or after_lower.endswith(res_lower) and res_lower
                or res_singular == after_singular and after_singular):
            return lk, li, 2

    # Tier 3: slot_base in item_fields
    for lk, li in list_ops_info.items():
        for f in li.get('item_fields', []):
            if slot_base and slot_base in f.lower():
                return lk, li, 3

    # Tier 4: id_field base matches slot base
    for lk, li in list_ops_info.items():
        id_base = (li.get('id_field') or '').lower()
        if slot_base and (id_base.endswith(slot_base) or slot_base.endswith(id_base)):
            return lk, li, 4
        if slot_base and singularize(id_base) == singularize(slot_base):
            return lk, li, 4

    return None, None, 5


TIER_CONF = {1:'exact', 2:'suffix_match', 3:'field_match', 4:'id_base_match', 5:'external_input'}


# ─────────────────────────────────────────────────────────────────────────────
# BUILD inputs / outputs / dependency_hints sections
# ─────────────────────────────────────────────────────────────────────────────

def build_inputs(op: dict) -> dict:
    req      = op.get('required_params', {})
    optional = list(op.get('optional_params', {}).keys())
    required_list = []

    for pname, pinfo in req.items():
        pattern  = pinfo.get('pattern', '')
        is_comp  = bool(re.search(r'(?<!\[)[^[]*/', pattern))

        if pname in ALWAYS_AVAILABLE:
            template = '{' + pname + '}'
            slots    = [{'slot': pname, 'source': 'always_available', 'after_segment': ''}]
        elif pattern and is_comp:
            template, slots = parse_pattern(pattern)
        else:
            template = '{' + pname + '}'
            slots    = [{'slot': pname, 'source': 'from_list_op',
                         'after_segment': pname.replace('Id', '')}]

        required_list.append({
            'param':       pname,
            'type':        pinfo.get('type', 'string'),
            'location':    pinfo.get('location', 'path'),
            'template':    template,
            'slots':       slots,
            'pattern':     pattern,
            'description': pinfo.get('description', '')[:120],
        })

    return {'required': required_list, 'optional': optional}


def build_outputs(op: dict) -> dict:
    kind = op.get('kind', '')
    rf   = op.get('response_fields', {})

    result = {
        'response_schema':          op.get('response_schema', ''),
        'list_field':               None,
        'id_field':                 None,
        'id_is_full_resource_name': False,
        'produces_fields':          [],
    }

    if kind == 'read_list':
        list_field = id_field = None
        for fname, finfo in rf.items():
            if finfo.get('type') == 'array' and finfo.get('id_field'):
                list_field = fname
                id_field   = finfo['id_field']
                break
        if not list_field:
            for fname, finfo in rf.items():
                if finfo.get('type') == 'array' and fname not in ('unreachable',):
                    list_field = fname
                    id_field   = finfo.get('id_field', 'name')
                    break

        result['list_field'] = list_field
        result['id_field']   = id_field
        result['id_is_full_resource_name'] = id_field in ('name', 'selfLink')

        if list_field:
            finfo     = rf.get(list_field, {})
            item_flds = finfo.get('item_fields', [])
            if id_field:
                result['produces_fields'].append({
                    'path': f'{list_field}[].{id_field}', 'type': 'string',
                    'is_id': True,
                    'note': 'resource identity — use as name/parent param for .get()',
                })
            for f in item_flds:
                if f == id_field or f in SKIP_FIELDS:
                    continue
                result['produces_fields'].append({
                    'path': f'{list_field}[].{f}', 'type': 'string', 'is_id': False,
                })

        for fname, finfo in rf.items():
            if finfo.get('type') != 'array' and fname not in SKIP_FIELDS:
                result['produces_fields'].append({
                    'path': fname, 'type': finfo.get('type', 'string'), 'is_id': False,
                })

    elif kind == 'read_get':
        for fname, finfo in rf.items():
            if fname in SKIP_FIELDS:
                continue
            result['produces_fields'].append({
                'path':  fname, 'type': finfo.get('type', 'string'),
                'is_id': fname in ('name', 'selfLink', 'id'),
            })

    return result


def build_dependency_hints(op: dict, op_key: str, all_ops: dict, list_ops_info: dict) -> list[dict]:
    hints = []
    req   = op.get('required_params', {})

    for pname, pinfo in req.items():
        pattern  = pinfo.get('pattern', '')
        can_come_from = []
        is_comp  = bool(re.search(r'(?<!\[)[^[]*/', pattern))

        if pname in ALWAYS_AVAILABLE:
            can_come_from.append({'kind': 'always_available', 'param': pname})

        if pattern and is_comp and pname not in ALWAYS_AVAILABLE:
            template, slots = parse_pattern(pattern)
            can_come_from.append({'kind': 'known_format', 'template': template, 'slots': slots})

            for slot in slots:
                if slot['source'] != 'from_list_op':
                    continue
                lk, li, tier = resolve_list_op_for_slot(
                    slot['after_segment'], slot['slot'], list_ops_info
                )
                if tier < 5 and lk:
                    can_come_from.append({
                        'kind':             'from_list_op',
                        'op':               lk,
                        'match_tier':       tier,
                        'match_confidence': TIER_CONF[tier],
                        'list_field':       li['list_field'],
                        'id_field':         li['id_field'],
                        'produces_slot':    slot['slot'],
                        'note': (
                            f'[tier {tier}/{TIER_CONF[tier]}] call {lk}, '
                            f'iterate response["{li["list_field"]}"][], '
                            f'extract item["{li["id_field"]}"] → fill {{{slot["slot"]}}}'
                        ),
                    })
                else:
                    can_come_from.append({
                        'kind': 'external_input', 'slot': slot['slot'],
                        'after_segment': slot['after_segment'],
                        'note': f'No list op found for {{{slot["slot"]}}} — supply externally',
                    })

        elif pname not in ALWAYS_AVAILABLE:
            after_seg = pname.replace('Id', '')
            lk, li, tier = resolve_list_op_for_slot(after_seg, pname, list_ops_info)
            if tier < 5 and lk:
                can_come_from.append({
                    'kind':             'from_list_op',
                    'op':               lk,
                    'match_tier':       tier,
                    'match_confidence': TIER_CONF[tier],
                    'list_field':       li['list_field'],
                    'id_field':         li['id_field'],
                    'produces_slot':    pname,
                    'note': (
                        f'[tier {tier}/{TIER_CONF[tier]}] call {lk}, '
                        f'iterate response["{li["list_field"]}"][], '
                        f'extract item["{li["id_field"]}"] → use as "{pname}"'
                    ),
                })
            else:
                # Try get ops
                for gk, gop in all_ops.items():
                    if gk == op_key:
                        continue
                    if gop.get('kind') == 'read_get':
                        rf = gop.get('response_fields', {})
                        if pname in rf:
                            can_come_from.append({
                                'kind': 'from_get_op', 'op': gk, 'field': pname,
                                'note': f'response field "{pname}" from {gk}',
                            })
                if not can_come_from:
                    can_come_from.append({
                        'kind': 'external_input', 'slot': pname,
                        'note': f'No producer found for "{pname}" — supply externally',
                    })

        if can_come_from:
            hints.append({'param': pname, 'can_come_from': can_come_from})

    return hints


# ─────────────────────────────────────────────────────────────────────────────
# MAIN BUILDER PER SERVICE
# ─────────────────────────────────────────────────────────────────────────────

def build_for_service(svc_dir: Path) -> dict | None:
    """Fetch discovery, build step1_api_driven_registry.json."""
    # Read existing step1 for metadata (service, version, base_url, title)
    s1_path = svc_dir / 'step1_api_driven_registry.json'
    if not s1_path.exists():
        return None

    meta = json.load(open(s1_path))
    service = meta.get('service', svc_dir.name)
    version = meta.get('version', 'v1')
    base_url = meta.get('base_url', f'https://{service}.googleapis.com/')
    title   = meta.get('title', '')

    # Fetch discovery
    disc = fetch_discovery(service, version, base_url)
    if not disc:
        return None

    schemas   = disc.get('schemas', {})
    resources = disc.get('resources', {})

    # Also check top-level methods
    top_methods = disc.get('methods', {})
    if top_methods:
        resources['_root'] = {'methods': top_methods}

    ops_list = extract_methods(resources, schemas, service)
    if not ops_list:
        return None

    ops_dict = {op['op']: op for op in ops_list}

    # Pre-compute list_ops_info for tiered resolver
    list_ops_info = build_list_ops_info(ops_dict)

    registry_ops = {}
    for op_key, op in ops_dict.items():
        req = op.get('required_params', {})
        independent = compute_independence(req)

        inputs   = build_inputs(op)
        outputs  = build_outputs(op)
        dep_hints = build_dependency_hints(op, op_key, ops_dict, list_ops_info)

        registry_ops[op_key] = {
            'op':          op_key,
            'service':     service,
            'kind':        op['kind'],
            'http': {
                'verb': op.get('http_method', 'GET'),
                'path': '/' + op.get('path', '').lstrip('/'),
            },
            'python_call':     op.get('python_call', ''),
            'description':     op.get('description', '')[:200],
            'inputs':          inputs,
            'outputs':         outputs,
            'independent':     independent,
            'dependency_hints': dep_hints,
            'scopes':          op.get('scopes', []),
            'paginated':       op.get('paginated', False),
        }

    n_list  = sum(1 for o in registry_ops.values() if o['kind'] == 'read_list')
    n_get   = sum(1 for o in registry_ops.values() if o['kind'] == 'read_get')
    n_write = sum(1 for o in registry_ops.values() if o['kind'].startswith('write_'))
    n_other = len(registry_ops) - n_list - n_get - n_write
    n_ind   = sum(1 for o in registry_ops.values() if o['independent'])

    return {
        'service':  service,
        'version':  version,
        'csp':      'gcp',
        'title':    title,
        'base_url': base_url,
        'stats': {
            'total_ops':   len(registry_ops),
            'read_list':   n_list,
            'read_get':    n_get,
            'write':       n_write,
            'other':       n_other,
            'independent': n_ind,
            'dependent':   len(registry_ops) - n_ind,
        },
        'operations': registry_ops,
    }


# ─────────────────────────────────────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────────────────────────────────────

def run(service_filter: str | None = None, dry_run: bool = False):
    print('=' * 70)
    print('Rebuilding step1_api_driven_registry.json from GCP Discovery API')
    print('=' * 70)

    all_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and (d / 'step1_api_driven_registry.json').exists()
    )

    if service_filter:
        all_dirs = [d for d in all_dirs if d.name == service_filter]

    built = failed = skipped = 0
    total_ops = total_ind = total_dep = 0

    for svc_dir in all_dirs:
        svc = svc_dir.name
        try:
            result = build_for_service(svc_dir)
            if not result:
                print(f'  ✗ {svc:40s}  no discovery data — skipping')
                failed += 1
                continue

            if not dry_run:
                with open(svc_dir / 'step1_api_driven_registry.json', 'w') as f:
                    json.dump(result, f, indent=2)

            stats = result['stats']
            built     += 1
            total_ops += stats['total_ops']
            total_ind += stats['independent']
            total_dep += stats['dependent']

            print(f'  ✓ {svc:40s}  '
                  f'{stats["total_ops"]:4d} ops  '
                  f'ind={stats["independent"]:3d}  '
                  f'dep={stats["dependent"]:3d}  '
                  f'list={stats["read_list"]:3d}  '
                  f'get={stats["read_get"]:3d}')

            time.sleep(0.05)  # be nice to discovery API

        except Exception as e:
            print(f'  ✗ {svc:40s}  ERROR: {e}')
            failed += 1

    print()
    print('=' * 70)
    print(f'Built   : {built}')
    print(f'Failed  : {failed}')
    print(f'Total ops: {total_ops}')
    print(f'Independent: {total_ind}')
    print(f'Dependent:   {total_dep}')
    print('=' * 70)


if __name__ == '__main__':
    import sys
    svc = sys.argv[1] if len(sys.argv) > 1 else None
    dry = '--dry-run' in sys.argv
    run(svc, dry)
