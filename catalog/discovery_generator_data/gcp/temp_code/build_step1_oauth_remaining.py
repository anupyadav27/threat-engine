#!/usr/bin/env python3
"""
Fetch Discovery docs for the 6 remaining services that need auth.
Uses Application Default Credentials (ADC) via gcloud.
Same output format as build_step1_from_python_client.py
"""

import json, re, time, urllib.request
from pathlib import Path
import google.auth
import google.auth.transport.requests

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

# Services still in old format
REMAINING = [
    'contactcenteraiplatform',
    'doubleclickbidmanager',
    'merchantapi',
    'playgrouping',
    'searchads360',
    'youtubeAnalytics',
]

# ── Kind classification (same as other scripts) ────────────────────────────────
READ_LIST_METHODS  = {'list', 'aggregatedlist', 'aggregated'}
READ_GET_METHODS   = {'get', 'describe', 'fetch'}
WRITE_CREATE_RE = re.compile(r'^(create|insert|provision|enable|register|add|import|upload|batchcreate)$', re.I)
WRITE_UPDATE_RE = re.compile(r'^(update|patch|modify|set|change|reset|replace|move|rename)$', re.I)
WRITE_DELETE_RE = re.compile(r'^(delete|remove|terminate|destroy|disable|undelete|purge|cancel|dismiss|invalidate|reject|abandon)$', re.I)
WRITE_APPLY_RE  = re.compile(r'^(attach|associate|grant|revoke|authorize|tag|bind|assign|link|approve)$', re.I)
READ_OTHER_RE   = re.compile(
    r'^(get|list|describe|fetch|read|search|query|aggregate|find|lookup|count|'
    r'check|validate|preview|diagnose|inspect|analyze|analyse|explain|summary|'
    r'report|discover|suggest|autocomplete|recommend|export|generate|view|show|'
    r'batchget|testiam|getiampolicy|stream|poll|watch|listen|verify|'
    r'troubleshoot|runquery|partitionquery|counttokens|executequery).*$', re.I)

def classify_kind(m, http):
    ml = m.lower().replace('_','').replace('-','')
    if ml in READ_LIST_METHODS:    return 'read_list'
    if ml in READ_GET_METHODS:     return 'read_get'
    if WRITE_CREATE_RE.match(ml):  return 'write_create'
    if WRITE_UPDATE_RE.match(ml):  return 'write_update'
    if WRITE_DELETE_RE.match(ml):  return 'write_delete'
    if WRITE_APPLY_RE.match(ml):   return 'write_apply'
    if http == 'GET':              return 'read_get'
    if READ_OTHER_RE.match(ml):    return 'other'
    return 'other'

# ── Schema expansion ──────────────────────────────────────────────────────────
def expand_schema(ref, schemas, depth=0):
    if depth > 1 or not ref or ref not in schemas:
        return {}
    result = {}
    for pname, pdesc in schemas[ref].get('properties', {}).items():
        ptype = pdesc.get('type', '')
        pref  = pdesc.get('$ref', '')
        items = pdesc.get('items', {})
        desc  = pdesc.get('description', '')[:120]
        enum  = pdesc.get('enum', [])
        if ptype == 'array':
            item_ref  = items.get('$ref', '')
            item_type = items.get('type', 'string')
            item_fields = list(schemas[item_ref].get('properties', {}).keys()) if item_ref and item_ref in schemas and depth == 0 else []
            entry = {'type': 'array', 'items': item_ref or item_type, 'item_fields': item_fields}
        elif pref:
            entry = {'type': 'object', 'ref': pref}
        elif ptype == 'object':
            entry = {'type': 'object'}
        else:
            entry = {'type': ptype or 'string'}
        if desc:  entry['description'] = desc
        if enum:  entry['enum'] = enum
        result[pname] = entry
    return result

def build_param_entry(pdesc):
    entry = {'type': pdesc.get('type', 'string'), 'location': pdesc.get('location', 'query')}
    desc = pdesc.get('description', '')[:120]
    if desc:             entry['description'] = desc
    if pdesc.get('enum'):    entry['enum'] = pdesc['enum']
    if pdesc.get('repeated'): entry['repeated'] = True
    if pdesc.get('pattern'): entry['pattern'] = pdesc['pattern']
    return entry

def walk_resource(resource_desc, resource_chain, schemas, service_name, results):
    for method_name, method_desc in resource_desc.get('methods', {}).items():
        http   = method_desc.get('httpMethod', 'GET')
        path   = method_desc.get('path', '')
        desc   = method_desc.get('description', '')
        scopes = method_desc.get('scopes', [])
        params = method_desc.get('parameters', {})
        required_params, optional_params = {}, {}
        for pname, pdesc in sorted(params.items()):
            entry = build_param_entry(pdesc)
            if pdesc.get('required'):
                required_params[pname] = entry
            else:
                optional_params[pname] = entry
        resp_ref    = method_desc.get('response', {}).get('$ref', '')
        resp_fields = expand_schema(resp_ref, schemas) if resp_ref else {}
        paginated   = 'nextPageToken' in resp_fields
        supports_pg = 'pageToken' in optional_params
        chain_call  = ('svc.' + '.'.join(f'{r}()' for r in resource_chain) + '.' + method_name + '(**params).execute()') if resource_chain else f'svc.{method_name}(**params).execute()'
        op_key      = 'gcp.' + service_name + '.' + '.'.join(resource_chain) + '.' + method_name
        kind        = classify_kind(method_name, http)
        results[op_key] = {
            'kind': kind, 'http_method': http, 'side_effect': http != 'GET',
            'path': path, 'description': desc, 'resource_chain': resource_chain[:],
            'method': method_name, 'python_call': chain_call,
            'required_params': required_params, 'optional_params': optional_params,
            'response_schema': resp_ref, 'response_fields': resp_fields,
            'scopes': scopes, 'paginated': paginated, 'supports_pagination': supports_pg,
        }
    for res_name, res_desc in resource_desc.get('resources', {}).items():
        walk_resource(res_desc, resource_chain + [res_name], schemas, service_name, results)

# ── OAuth fetch ───────────────────────────────────────────────────────────────
def get_token():
    creds, _ = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    req = google.auth.transport.requests.Request()
    creds.refresh(req)
    return creds.token

def fetch_discovery_authed(service, version, token):
    url = f'https://www.googleapis.com/discovery/v1/apis/{service}/{version}/rest'
    req = urllib.request.Request(url, headers={'Authorization': f'Bearer {token}'})
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        return json.loads(resp.read())
    except Exception as e:
        return None

def get_preferred_version_authed(service, token):
    url = f'https://www.googleapis.com/discovery/v1/apis?name={service}'
    req = urllib.request.Request(url, headers={'Authorization': f'Bearer {token}'})
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read())
        items = data.get('items', [])
        if not items: return None
        for item in items:
            if item.get('preferred'): return item['version']
        return items[0]['version']
    except Exception:
        return None

def run():
    print('=' * 70)
    print('Building step1 for remaining services via OAuth (ADC)')
    print('=' * 70)

    token = get_token()
    print('OAuth token acquired ✓\n')

    for service in REMAINING:
        svc_dir  = BASE_DIR / service
        old_path = svc_dir / 'step1_operation_registry.json'

        # Get hint version
        hint = None
        if old_path.exists():
            try:
                old = json.load(open(old_path))
                hint = old.get('version')
            except: pass

        # Try versions
        doc = None
        version = None
        candidates = []
        if hint: candidates.append(hint)
        for v in ['v1', 'v2', 'v1beta1', 'v1alpha', 'v2beta', 'v1beta']:
            if v not in candidates: candidates.append(v)

        for v in candidates:
            doc = fetch_discovery_authed(service, v, token)
            if doc:
                version = v
                break

        if not doc:
            # try preferred
            pref = get_preferred_version_authed(service, token)
            if pref:
                doc = fetch_discovery_authed(service, pref, token)
                if doc: version = pref

        if not doc:
            print(f'  ✗ {service}: Could not fetch Discovery doc even with auth')
            continue

        schemas    = doc.get('schemas', {})
        operations = {}
        walk_resource(doc, [], schemas, service, operations)

        if not operations:
            print(f'  ⚠  {service} [{version}]: Doc found but 0 operations')
            continue

        registry = {
            'service': service, 'version': version, 'csp': 'gcp',
            'title': doc.get('title', ''), 'description': doc.get('description', '')[:200],
            'documentation': doc.get('documentationLink', ''),
            'base_url': doc.get('baseUrl', ''),
            'data_source': 'googleapiclient_discovery',
            'total_operations': len(operations), 'operations': operations,
        }
        with open(old_path, 'w') as f:
            json.dump(registry, f, indent=2)

        r = sum(1 for op in operations.values() if op['kind'].startswith('read'))
        w = len(operations) - r
        print(f'  ✓ {service} [{version}]: {len(operations)} ops ({r} read / {w} write)')
        time.sleep(0.1)

    print('\nDone.')

if __name__ == '__main__':
    run()
