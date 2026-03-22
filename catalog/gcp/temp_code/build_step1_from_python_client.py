#!/usr/bin/env python3
"""
Rebuild step1_operation_registry.json for every GCP service
directly from the googleapiclient Discovery doc (python client).

This REPLACES the old step1 which was hand-crafted from partial data.

New step1 structure per operation:
{
  "op_key": {
    "kind":            "read_list" | "read_get" | "write_create" | ... | "other"
    "http_method":     "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
    "path":            "projects/{projectId}/datasets/{datasetId}"
    "description":     "..."
    "resource_chain":  ["datasets"]               ← python client resource chain
    "method":          "list"                     ← final method name
    "python_call":     "svc.datasets().list(**params).execute()"
    "required_params": {
      "projectId": {"type": "string", "location": "path", "description": "..."}
    }
    "optional_params": {
      "filter": {"type": "string", "location": "query", "description": "..."}
    }
    "response_schema": "DatasetList"              ← Discovery schema ref name
    "response_fields": {                          ← expanded from schema
      "datasets":      {"type": "array", "items": "Dataset", "item_fields": [...]}
      "nextPageToken": {"type": "string"}
    }
    "scopes":          ["https://www.googleapis.com/auth/cloud-platform"]
    "paginated":       true | false               ← has pageToken in response
    "supports_pagination": true | false           ← has pageToken in optional params
  }
}
"""

import json
import re
import time
import urllib.request
from pathlib import Path
from collections import defaultdict

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

# ── Kind classification (same logic as before) ────────────────────────────────
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
    # 'other' — classify by HTTP + name
    if http_method == 'GET':            return 'read_get'
    if READ_OTHER_RE.match(m):          return 'other'  # side-effectful read-like
    return 'other'

def has_side_effect(kind: str, http_method: str) -> bool:
    return http_method != 'GET'

# ── Schema expansion ──────────────────────────────────────────────────────────
def expand_schema(ref: str, schemas: dict, depth: int = 0) -> dict:
    """Expand a schema ref into {field: {type, items?, item_fields?}}."""
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
            # expand item schema to get field names
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

        # params
        params = method_desc.get('parameters', {})
        required_params = {}
        optional_params = {}
        for pname, pdesc in sorted(params.items()):
            entry = build_param_entry(pdesc)
            if pdesc.get('required'):
                required_params[pname] = entry
            else:
                optional_params[pname] = entry

        # response
        resp_ref    = method_desc.get('response', {}).get('$ref', '')
        resp_fields = expand_schema(resp_ref, schemas) if resp_ref else {}

        # pagination detection
        paginated           = 'nextPageToken' in resp_fields
        supports_pagination = 'pageToken' in optional_params

        # python call
        chain_call = (
            'svc.' +
            '.'.join(f'{r}()' for r in resource_chain) + '.' +
            method_name + '(**params).execute()'
        ) if resource_chain else f'svc.{method_name}(**params).execute()'

        # op_key
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

    # recurse into nested resources
    for res_name, res_desc in resource_desc.get('resources', {}).items():
        walk_resource(res_desc, resource_chain + [res_name],
                      schemas, service_name, results)


# ── Fetch Discovery doc ───────────────────────────────────────────────────────
def fetch_discovery_doc(service: str, version: str) -> dict | None:
    url = f'https://www.googleapis.com/discovery/v1/apis/{service}/{version}/rest'
    try:
        resp = urllib.request.urlopen(url, timeout=15)
        return json.loads(resp.read())
    except Exception as e:
        return None


def get_preferred_version(service: str) -> str | None:
    """Ask the Discovery list API for the preferred version of a service."""
    url = f'https://www.googleapis.com/discovery/v1/apis?name={service}'
    try:
        resp = urllib.request.urlopen(url, timeout=10)
        data = json.loads(resp.read())
        items = data.get('items', [])
        if not items:
            return None
        # prefer 'preferred' flag
        for item in items:
            if item.get('preferred'):
                return item['version']
        return items[0]['version']
    except Exception:
        return None


# ── Main builder ──────────────────────────────────────────────────────────────
def build_step1(svc_dir: Path, disc_versions: dict) -> dict | None:
    """
    Build step1_operation_registry.json from live Discovery doc.
    Returns summary dict or None if skipped.
    """
    old_path = svc_dir / 'step1_operation_registry.json'
    service  = svc_dir.name

    # Determine version
    version = None
    if old_path.exists():
        old = json.load(open(old_path))
        version = old.get('version')

    # Override with discovery-preferred if None or missing
    if not version:
        version = disc_versions.get(service)
        if not version:
            version = get_preferred_version(service)

    if not version:
        return {'status': 'skip', 'reason': 'no version found'}

    # Fetch Discovery doc
    doc = fetch_discovery_doc(service, version)
    if not doc:
        # try v1 fallback
        if version != 'v1':
            doc = fetch_discovery_doc(service, 'v1')
            if doc:
                version = 'v1'
    if not doc:
        return {'status': 'skip', 'reason': f'could not fetch discovery doc ({version})'}

    schemas = doc.get('schemas', {})

    # Walk all resources
    operations = {}
    walk_resource(doc, [], schemas, service, operations)

    if not operations:
        return {'status': 'skip', 'reason': 'no operations found'}

    # Build registry
    registry = {
        'service':          service,
        'version':          version,
        'csp':              'gcp',
        'title':            doc.get('title', ''),
        'description':      doc.get('description', '')[:200],
        'documentation':    doc.get('documentationLink', ''),
        'base_url':         doc.get('baseUrl', ''),
        'data_source':      'googleapiclient_discovery',
        'total_operations': len(operations),
        'operations':       operations,
    }

    with open(old_path, 'w') as f:
        json.dump(registry, f, indent=2)

    read_ops  = sum(1 for op in operations.values() if op['kind'].startswith('read'))
    write_ops = sum(1 for op in operations.values() if not op['kind'].startswith('read'))
    return {
        'status':     'ok',
        'version':    version,
        'total':      len(operations),
        'read':       read_ops,
        'write':      write_ops,
    }


def run():
    print('=' * 70)
    print('Rebuilding step1_operation_registry.json from GCP python client')
    print('=' * 70)

    # Fetch full Discovery list for version lookup
    print('Fetching GCP Discovery list...')
    disc_versions = {}
    try:
        resp = urllib.request.urlopen(
            'https://www.googleapis.com/discovery/v1/apis', timeout=15)
        data = json.loads(resp.read())
        for item in data.get('items', []):
            name = item['name']
            if item.get('preferred') and name not in disc_versions:
                disc_versions[name] = item['version']
            elif name not in disc_versions:
                disc_versions[name] = item['version']
        print(f'  Got {len(disc_versions)} services from Discovery list')
    except Exception as e:
        print(f'  WARNING: could not fetch Discovery list: {e}')
    print()

    service_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and (d / 'step1_operation_registry.json').exists()
    )

    built = skipped = 0
    total_ops = total_read = total_write = 0

    for sdir in service_dirs:
        result = build_step1(sdir, disc_versions)
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

        # small delay to avoid rate limiting
        time.sleep(0.05)

    print()
    print('=' * 70)
    print(f'Built:          {built} services')
    print(f'Skipped:        {skipped}')
    print(f'Total ops:      {total_ops}')
    print(f'Total read ops: {total_read}')
    print(f'Total write ops:{total_write}')
    print('=' * 70)

    # Show sample
    print()
    print('── Sample: bigquery/datasets.list ──────────────────────────────────')
    sample = json.load(open(BASE_DIR / 'bigquery/step1_operation_registry.json'))
    op = sample['operations'].get('gcp.bigquery.datasets.list', {})
    print(json.dumps(op, indent=2))


if __name__ == '__main__':
    run()
