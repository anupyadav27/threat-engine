#!/usr/bin/env python3
"""
Rebuild step1_operation_registry.json for the 155 skipped GCP services
that require auth for the live Discovery API.

Uses the static Discovery doc cache from:
  https://raw.githubusercontent.com/googleapis/google-api-python-client/main/
  googleapiclient/discovery_cache/documents/{service}.{version}.json

Same output format as build_step1_from_python_client.py
"""

import json
import re
import time
import urllib.request
from pathlib import Path
from collections import defaultdict

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')
GITHUB_CACHE = (
    'https://raw.githubusercontent.com/googleapis/google-api-python-client'
    '/main/googleapiclient/discovery_cache/documents/'
)

# ── Kind classification ────────────────────────────────────────────────────────
READ_LIST_METHODS  = {'list', 'aggregatedlist', 'aggregated'}
READ_GET_METHODS   = {'get', 'describe', 'fetch'}

WRITE_CREATE_RE = re.compile(r'^(create|insert|provision|enable|register|add|import|upload|batch_create|batchcreate)$', re.I)
WRITE_UPDATE_RE = re.compile(r'^(update|patch|modify|set|change|reset|replace|move|rename)$', re.I)
WRITE_DELETE_RE = re.compile(r'^(delete|remove|terminate|destroy|disable|undelete|purge|cancel|dismiss|invalidate|reject|abandon)$', re.I)
WRITE_APPLY_RE  = re.compile(r'^(attach|associate|grant|revoke|authorize|tag|bind|assign|link|addons|approve)$', re.I)

READ_OTHER_RE = re.compile(
    r'^(get|list|describe|fetch|read|search|query|aggregate|find|lookup|count|'
    r'check|validate|preview|diagnose|inspect|analyze|analyse|explain|summary|'
    r'report|discover|suggest|autocomplete|recommend|export|generate|view|show|'
    r'batchget|batch_get|testiam|getiampolicy|stream|poll|watch|listen|verify|'
    r'troubleshoot|evaluateuserconsents|decodeintegritytoken|runquery|'
    r'partitionquery|partitionread|runaggregationquery|findneighbors|'
    r'readindexdatapoints|streamingreadfeaturevalues|readfeaturevalues|'
    r'batchreadfeaturevalues|counttokens|executegraphqlread|executequery).*$',
    re.I
)

def classify_kind(method_name: str, http_method: str) -> str:
    m = method_name.lower().replace('_', '').replace('-', '')
    if m in READ_LIST_METHODS:          return 'read_list'
    if m in READ_GET_METHODS:           return 'read_get'
    if WRITE_CREATE_RE.match(m):        return 'write_create'
    if WRITE_UPDATE_RE.match(m):        return 'write_update'
    if WRITE_DELETE_RE.match(m):        return 'write_delete'
    if WRITE_APPLY_RE.match(m):         return 'write_apply'
    if http_method == 'GET':            return 'read_get'
    if READ_OTHER_RE.match(m):          return 'other'
    return 'other'

def has_side_effect(kind: str, http_method: str) -> bool:
    return http_method != 'GET'

# ── Schema expansion ──────────────────────────────────────────────────────────
def expand_schema(ref: str, schemas: dict, depth: int = 0) -> dict:
    if depth > 1 or not ref or ref not in schemas:
        return {}
    result = {}
    for pname, pdesc in schemas[ref].get('properties', {}).items():
        ptype  = pdesc.get('type', '')
        pref   = pdesc.get('$ref', '')
        items  = pdesc.get('items', {})
        desc   = pdesc.get('description', '')[:120]
        enum   = pdesc.get('enum', [])

        if ptype == 'array':
            item_ref  = items.get('$ref', '')
            item_type = items.get('type', 'string')
            if item_ref and item_ref in schemas and depth == 0:
                item_fields = list(schemas[item_ref].get('properties', {}).keys())
            else:
                item_fields = []
            entry = {
                'type':        'array',
                'items':       item_ref or item_type,
                'item_fields': item_fields,
            }
        elif pref:
            entry = {'type': 'object', 'ref': pref}
        elif ptype == 'object':
            entry = {'type': 'object'}
        else:
            entry = {'type': ptype or 'string'}

        if desc:
            entry['description'] = desc
        if enum:
            entry['enum'] = enum
        result[pname] = entry
    return result


def build_param_entry(pdesc: dict) -> dict:
    entry = {
        'type':     pdesc.get('type', 'string'),
        'location': pdesc.get('location', 'query'),
    }
    desc = pdesc.get('description', '')[:120]
    if desc:
        entry['description'] = desc
    if pdesc.get('enum'):
        entry['enum'] = pdesc['enum']
    if pdesc.get('repeated'):
        entry['repeated'] = True
    if pdesc.get('pattern'):
        entry['pattern'] = pdesc['pattern']
    return entry


# ── Walk Discovery resource tree ──────────────────────────────────────────────
def walk_resource(resource_desc: dict, resource_chain: list,
                  schemas: dict, service_name: str, results: dict):
    for method_name, method_desc in resource_desc.get('methods', {}).items():
        http  = method_desc.get('httpMethod', 'GET')
        path  = method_desc.get('path', '')
        desc  = method_desc.get('description', '')
        scopes = method_desc.get('scopes', [])

        params = method_desc.get('parameters', {})
        required_params = {}
        optional_params = {}
        for pname, pdesc in sorted(params.items()):
            entry = build_param_entry(pdesc)
            if pdesc.get('required'):
                required_params[pname] = entry
            else:
                optional_params[pname] = entry

        resp_ref    = method_desc.get('response', {}).get('$ref', '')
        resp_fields = expand_schema(resp_ref, schemas) if resp_ref else {}

        paginated           = 'nextPageToken' in resp_fields
        supports_pagination = 'pageToken' in optional_params

        chain_call = (
            'svc.' +
            '.'.join(f'{r}()' for r in resource_chain) + '.' +
            method_name + '(**params).execute()'
        ) if resource_chain else f'svc.{method_name}(**params).execute()'

        op_key = 'gcp.' + service_name + '.' + '.'.join(resource_chain) + '.' + method_name

        kind = classify_kind(method_name, http)

        results[op_key] = {
            'kind':              kind,
            'http_method':       http,
            'side_effect':       has_side_effect(kind, http),
            'path':              path,
            'description':       desc,
            'resource_chain':    resource_chain[:],
            'method':            method_name,
            'python_call':       chain_call,
            'required_params':   required_params,
            'optional_params':   optional_params,
            'response_schema':   resp_ref,
            'response_fields':   resp_fields,
            'scopes':            scopes,
            'paginated':         paginated,
            'supports_pagination': supports_pagination,
        }

    for res_name, res_desc in resource_desc.get('resources', {}).items():
        walk_resource(res_desc, resource_chain + [res_name],
                      schemas, service_name, results)


# ── Fetch from GitHub cache ───────────────────────────────────────────────────
def fetch_from_github(service: str, version: str) -> dict | None:
    url = f'{GITHUB_CACHE}{service}.{version}.json'
    try:
        resp = urllib.request.urlopen(url, timeout=15)
        return json.loads(resp.read())
    except Exception:
        return None


def find_github_version(service: str, hint_version: str | None) -> tuple[dict | None, str | None]:
    """Try hint_version, then common fallbacks."""
    candidates = []
    if hint_version:
        candidates.append(hint_version)
    for v in ['v1', 'v2', 'v1beta1', 'v1alpha', 'v2beta', 'v1beta', 'v3', 'v4']:
        if v not in candidates:
            candidates.append(v)

    for v in candidates:
        doc = fetch_from_github(service, v)
        if doc:
            return doc, v
    return None, None


# ── Main builder ──────────────────────────────────────────────────────────────
def build_step1_from_github(svc_dir: Path) -> dict | None:
    old_path = svc_dir / 'step1_operation_registry.json'
    service  = svc_dir.name

    # Get hint version from old file
    hint_version = None
    if old_path.exists():
        try:
            old = json.load(open(old_path))
            hint_version = old.get('version')
        except Exception:
            pass

    doc, version = find_github_version(service, hint_version)
    if not doc:
        return {'status': 'skip', 'reason': 'not in GitHub cache'}

    schemas = doc.get('schemas', {})

    operations = {}
    walk_resource(doc, [], schemas, service, operations)

    if not operations:
        return {'status': 'skip', 'reason': 'no operations found in doc'}

    registry = {
        'service':          service,
        'version':          version,
        'csp':              'gcp',
        'title':            doc.get('title', ''),
        'description':      doc.get('description', '')[:200],
        'documentation':    doc.get('documentationLink', ''),
        'base_url':         doc.get('baseUrl', ''),
        'data_source':      'googleapiclient_discovery_github_cache',
        'total_operations': len(operations),
        'operations':       operations,
    }

    with open(old_path, 'w') as f:
        json.dump(registry, f, indent=2)

    read_ops  = sum(1 for op in operations.values() if op['kind'].startswith('read'))
    write_ops = sum(1 for op in operations.values() if not op['kind'].startswith('read'))
    return {
        'status':  'ok',
        'version': version,
        'total':   len(operations),
        'read':    read_ops,
        'write':   write_ops,
    }


def run():
    print('=' * 70)
    print('Rebuilding step1 from GitHub Discovery cache for skipped services')
    print('=' * 70)
    print()

    # Find services that still have old format (not yet rebuilt)
    all_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and (d / 'step1_operation_registry.json').exists()
    )

    skipped_dirs = []
    for d in all_dirs:
        try:
            data = json.load(open(d / 'step1_operation_registry.json'))
            if data.get('data_source') != 'googleapiclient_discovery':
                skipped_dirs.append(d)
        except Exception:
            pass

    print(f'Services to rebuild: {len(skipped_dirs)}')
    print()

    built = skipped = 0
    total_ops = total_read = total_write = 0

    for sdir in skipped_dirs:
        result = build_step1_from_github(sdir)
        if result is None or result['status'] == 'skip':
            reason = result.get('reason', '?') if result else '?'
            print(f'  ⏭  {sdir.name}: SKIP ({reason})')
            skipped += 1
            continue

        total_ops   += result['total']
        total_read  += result['read']
        total_write += result['write']
        built += 1
        print(f'  ✓ {sdir.name} [{result["version"]}]: '
              f'{result["total"]} ops  ({result["read"]} read / {result["write"]} write)')

        time.sleep(0.05)

    print()
    print('=' * 70)
    print(f'Built:          {built} services')
    print(f'Skipped:        {skipped}')
    print(f'Total ops:      {total_ops}')
    print(f'Total read ops: {total_read}')
    print(f'Total write ops:{total_write}')
    print('=' * 70)


if __name__ == '__main__':
    run()
