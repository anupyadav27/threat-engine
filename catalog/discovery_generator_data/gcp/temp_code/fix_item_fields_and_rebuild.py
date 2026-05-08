#!/usr/bin/env python3
"""
Fix item_fields for array response fields in step1 — capturing BOTH:
  1. $ref items  (e.g. InstanceList.items → ref: Instance → fields: [name, id, zone, ...])
  2. Inline items (e.g. DatasetList.datasets → inline properties: [id, datasetReference, ...])

Also fixes output_id_field in execution_model to point to the actual field
INSIDE each list item (e.g. "name" for compute instances, "id" for bigquery datasets).

Then re-enriches step1, re-splits step2_read/write, rebuilds step3 chains.

Approach:
 - For each service, fetch the discovery doc (from GitHub cache, same logic as before)
 - Re-run expand_schema with the fixed version
 - Overwrite step1, step2_read, step2_write, step3 for that service
"""

import json
import re
import time
import urllib.request
from pathlib import Path
from collections import defaultdict

BASE_DIR   = Path('/Users/apple/Desktop/data_pythonsdk/gcp')
GITHUB_CACHE = (
    'https://raw.githubusercontent.com/googleapis/google-api-python-client'
    '/main/googleapiclient/discovery_cache/documents/'
)

# ── ID field priority inside a list item ─────────────────────────────────────
# When extracting the resource ID from a list item, prefer these field names
ID_PRIORITY = ['name', 'id', 'uid', 'selfLink', 'resourceId', 'identifier',
               'instanceId', 'clusterId', 'nodeId', 'keyId', 'bucketId']

SKIP_ITEM_FIELDS = {'nextPageToken', 'etag', 'kind', 'selfLink', 'totalItems',
                    'unreachable', 'warning', 'id', 'missing'}

ALWAYS_AVAILABLE = {
    'projectId', 'project', 'parent',
    'location', 'region', 'zone',
    'organizationId', 'folderId', 'billingAccountId',
    'customerId', 'accountId',
}

LIST_ARRAY_FIELDS = {
    'items', 'resources', 'instances', 'datasets', 'tables', 'buckets',
    'clusters', 'nodes', 'snapshots', 'operations', 'results', 'entries',
    'connections', 'policies', 'keys', 'services', 'versions', 'revisions',
    'backups', 'replicas', 'zones', 'regions', 'networks', 'subnetworks',
    'addresses', 'firewalls', 'routes', 'projects', 'folders', 'members',
    'roles', 'bindings', 'subscriptions', 'topics', 'messages', 'jobs',
    'tasks', 'triggers', 'functions', 'logs', 'sinks', 'metrics',
    'exclusions', 'alerts', 'channels', 'uptimeCheckConfigs', 'groups',
    'monitoredResources', 'dashboards', 'serviceAccounts', 'repos',
    'artifacts', 'packages', 'tags', 'builds', 'workers', 'workflows',
    'executions', 'deployments', 'releases', 'targets', 'pipelines',
    'rollouts', 'assets', 'feeds', 'secrets', 'secretVersions',
    'cryptoKeys', 'cryptoKeyVersions', 'keyRings', 'certificates',
    'managedZones', 'changes', 'policies', 'rrsets', 'rrdatas',
    'attestors', 'caPools', 'reusableConfigs', 'importJobs',
}

READ_LIST_METHODS = {'list', 'aggregatedlist', 'aggregated'}
READ_GET_METHODS  = {'get', 'describe', 'fetch'}

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

PATH_PARAM_RE = re.compile(r'\{[+]?(\w+)\}')


# ── Kind classification ───────────────────────────────────────────────────────
def classify_kind(m, http):
    ml = m.lower().replace('_', '').replace('-', '')
    if ml in READ_LIST_METHODS:    return 'read_list'
    if ml in READ_GET_METHODS:     return 'read_get'
    if WRITE_CREATE_RE.match(ml):  return 'write_create'
    if WRITE_UPDATE_RE.match(ml):  return 'write_update'
    if WRITE_DELETE_RE.match(ml):  return 'write_delete'
    if WRITE_APPLY_RE.match(ml):   return 'write_apply'
    if http == 'GET':              return 'read_get'
    if READ_OTHER_RE.match(ml):    return 'other'
    return 'other'


# ── FIXED: Schema expansion capturing inline item schemas ─────────────────────
def pick_id_field_from_item_props(item_props: dict) -> str | None:
    """
    Given the properties of a list item object, pick the best ID field.
    Priority: name > id > uid > selfLink > first non-metadata field
    """
    keys = set(item_props.keys())
    for f in ID_PRIORITY:
        if f in keys:
            return f
    # Try nested refs: datasetReference.datasetId, tableReference.tableId etc.
    for fname, finfo in item_props.items():
        ref = finfo.get('$ref', '')
        if ref and ref.endswith('Reference'):
            return fname  # e.g. "datasetReference" — caller will resolve sub-field
    # fallback: first non-skip field
    for fname in item_props:
        if fname not in SKIP_ITEM_FIELDS:
            return fname
    return None


def expand_schema(ref: str, schemas: dict, depth: int = 0) -> dict:
    """
    Expand a schema $ref into {field: {type, items?, item_fields?, id_field?}}.
    Handles BOTH $ref items and inline item properties.
    """
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
            item_ref    = items.get('$ref', '')
            item_type   = items.get('type', 'string')
            item_props  = items.get('properties', {})  # ← inline item schema

            if item_ref and item_ref in schemas and depth == 0:
                # $ref items: expand from schemas
                item_schema_props = schemas[item_ref].get('properties', {})
                item_fields = list(item_schema_props.keys())
                id_field    = pick_id_field_from_item_props(item_schema_props)
            elif item_props and depth == 0:
                # Inline items: properties embedded directly
                item_fields = list(item_props.keys())
                id_field    = pick_id_field_from_item_props(item_props)
                item_ref    = 'inline'
            else:
                item_fields = []
                id_field    = None

            entry = {
                'type':        'array',
                'items':       item_ref or item_type,
                'item_fields': item_fields,
            }
            if id_field:
                entry['id_field'] = id_field

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
        chain_call  = ('svc.' + '.'.join(f'{r}()' for r in resource_chain) + '.'
                       + method_name + '(**params).execute()') if resource_chain \
                      else f'svc.{method_name}(**params).execute()'
        op_key = 'gcp.' + service_name + '.' + '.'.join(resource_chain) + '.' + method_name
        kind   = classify_kind(method_name, http)
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


# ── Fetch helpers ─────────────────────────────────────────────────────────────
def fetch_live(service, version):
    url = f'https://www.googleapis.com/discovery/v1/apis/{service}/{version}/rest'
    try:
        return json.loads(urllib.request.urlopen(url, timeout=12).read())
    except:
        return None

def fetch_github(service, version):
    url = f'{GITHUB_CACHE}{service}.{version}.json'
    try:
        return json.loads(urllib.request.urlopen(url, timeout=12).read())
    except:
        return None

def get_doc(service, version, data_source):
    """Try live first (for live-source services), then GitHub cache."""
    if data_source == 'googleapiclient_discovery':
        doc = fetch_live(service, version)
        if doc:
            return doc, 'googleapiclient_discovery'
    # Try GitHub cache (handles both github-cached and old-format services)
    for v in [version, 'v1', 'v2', 'v1beta1', 'v1alpha']:
        doc = fetch_github(service, v)
        if doc:
            return doc, 'googleapiclient_discovery_github_cache'
    return None, None


# ── Enrichment helpers (same as enrich_and_split.py) ─────────────────────────
def get_path_params(path):
    return PATH_PARAM_RE.findall(path)

def build_resource_path(service, path):
    clean = path.lstrip('/')
    clean = re.sub(r'\{\+(\w+)\}', r'{\1}', clean)
    return f'//{service}.googleapis.com/{clean}'

def find_output_list_field(response_fields, kind):
    if kind != 'read_list':
        return None
    for f in LIST_ARRAY_FIELDS:
        if f in response_fields and response_fields[f].get('type') == 'array':
            return f
    for fname, finfo in response_fields.items():
        if finfo.get('type') == 'array' and fname not in ('nextPageToken',):
            return fname
    return None

def find_output_id_field(response_fields, list_field):
    """
    Returns the actual field name INSIDE each list item that contains the resource ID.
    Uses the id_field we now store directly in the array field info.
    """
    if not list_field or list_field not in response_fields:
        return None
    # Use the id_field we computed during expand_schema
    id_field = response_fields[list_field].get('id_field')
    if id_field:
        return id_field
    # Fallback: priority search over item_fields
    item_fields = response_fields[list_field].get('item_fields', [])
    for f in ID_PRIORITY:
        if f in item_fields:
            return f
    # Last resort: first non-skip item field
    for f in item_fields:
        if f not in SKIP_ITEM_FIELDS:
            return f
    return None

def list_op_output_param(op_key):
    parts = op_key.split('.')
    if len(parts) >= 2:
        resource = parts[-2]
        singular = resource
        if singular.endswith('ies'):   singular = singular[:-3] + 'y'
        elif singular.endswith('sses'): singular = singular[:-2]
        elif singular.endswith('ses'):  singular = singular[:-2]
        elif singular.endswith('s') and not singular.endswith('ss'):
            singular = singular[:-1]
        return singular + 'Id'
    return None

def build_list_ops_params(ops):
    candidates = defaultdict(list)
    for op_key, op in ops.items():
        if op.get('kind') != 'read_list':
            continue
        rf         = op.get('response_fields', {})
        list_field = find_output_list_field(rf, 'read_list')
        id_field   = find_output_id_field(rf, list_field)
        out_param  = list_op_output_param(op_key)
        if out_param:
            candidates[out_param].append((op_key, list_field, id_field))

    result = {}
    for param, cands in candidates.items():
        if len(cands) == 1:
            result[param] = cands[0]
            continue
        base = re.sub(r'Id$|Name$', '', param).lower()
        def score(c):
            parts = c[0].split('.')
            if len(parts) >= 2:
                res = parts[-2].lower()
                if res.rstrip('s') == base or res.startswith(base):
                    return 0
            return 1
        result[param] = sorted(cands, key=score)[0]
    return result

def compute_independence(ops):
    list_op_outputs = defaultdict(set)
    for op_key, op in ops.items():
        if op.get('kind') != 'read_list':
            continue
        out_param = list_op_output_param(op_key)
        if out_param:
            list_op_outputs[out_param].add(op_key)

    result = {}
    for op_key, op in ops.items():
        required = list(op.get('required_params', {}).keys())
        is_ind = True
        for p in required:
            if p in ALWAYS_AVAILABLE:
                continue
            is_ind = False
            break
        result[op_key] = is_ind
    return result

def build_execution_model(op, service, list_ops_params):
    kind          = op.get('kind', '')
    path          = op.get('path', '')
    required      = op.get('required_params', {})
    response_flds = op.get('response_fields', {})
    path_params   = get_path_params(path)

    input_params = []
    for pname, pinfo in required.items():
        if pname in ALWAYS_AVAILABLE:
            entry = {'param': pname, 'required': True, 'source': 'always_available',
                     'type': pinfo.get('type', 'string'), 'location': pinfo.get('location', 'path')}
        else:
            entry = {'param': pname, 'required': True, 'source': 'from_prior_op',
                     'type': pinfo.get('type', 'string'), 'location': pinfo.get('location', 'path')}
            producer = list_ops_params.get(pname)
            if producer:
                from_op, from_list_field, from_id_field = producer
                entry['from_op']         = from_op
                entry['from_field']      = from_id_field or pname
                entry['from_list_field'] = from_list_field
        input_params.append(entry)

    output_list_field = find_output_list_field(response_flds, kind)
    output_id_field   = find_output_id_field(response_flds, output_list_field)

    downstream_param = None
    if kind == 'read_list' and output_id_field:
        non_always = [p for p in path_params if p not in ALWAYS_AVAILABLE]
        if non_always:
            downstream_param = non_always[-1]

    resource_path = build_resource_path(service, path)
    runtime_template = resource_path
    for pp in path_params:
        if pp in ALWAYS_AVAILABLE:
            runtime_template = runtime_template.replace(f'{{{pp}}}', f'{{{{ input.{pp} }}}}')
        else:
            runtime_template = runtime_template.replace(f'{{{pp}}}', f'{{{{ item.{output_id_field or pp} }}}}')

    model = {
        'input_params':      input_params,
        'output_list_field': output_list_field,
        'output_id_field':   output_id_field,
    }
    if output_id_field:
        model['output_id_field_path'] = f'{{{{ item.{output_id_field} }}}}'
    if downstream_param:
        model['output_id_feeds_param'] = downstream_param
    model['full_resource_name_template'] = resource_path
    model['full_resource_name_runtime']  = runtime_template
    return model

def enrich_ops(ops, service):
    independence    = compute_independence(ops)
    list_ops_params = build_list_ops_params(ops)
    for op_key, op in ops.items():
        path        = op.get('path', '')
        path_params = get_path_params(path)
        op['resource_path']     = build_resource_path(service, path)
        op['resource_id_param'] = path_params[-1] if path_params else None
        op['parent_params']     = path_params[:-1] if len(path_params) > 1 else []
        op['independent']       = independence.get(op_key, False)
        op['execution_model']   = build_execution_model(op, service, list_ops_params)
    return ops

READ_KINDS  = {'read_list', 'read_get', 'other'}
WRITE_KINDS = {'write_create', 'write_update', 'write_delete', 'write_apply'}

def write_step2(svc_dir, data, ops):
    header = {k: data.get(k, '') for k in
              ['service', 'version', 'csp', 'title', 'description', 'documentation', 'base_url', 'data_source']}
    read_ops  = {k: v for k, v in ops.items() if v.get('kind', '') in READ_KINDS}
    write_ops = {k: v for k, v in ops.items() if v.get('kind', '') in WRITE_KINDS}
    with open(svc_dir / 'step2_read_operation_registry.json', 'w') as f:
        json.dump({**header, 'total_operations': len(read_ops),  'operations': read_ops},  f, indent=2)
    with open(svc_dir / 'step2_write_operation_registry.json', 'w') as f:
        json.dump({**header, 'total_operations': len(write_ops), 'operations': write_ops}, f, indent=2)
    return read_ops, write_ops


# ── Step3: dependency chain builder ──────────────────────────────────────────
def build_chains(ops, service):
    param_to_list_op = {}
    from_op_provides = defaultdict(set)
    for op_key, op in ops.items():
        em = op.get('execution_model', {})
        for ip in em.get('input_params', []):
            if ip.get('source') == 'from_prior_op' and ip.get('from_op'):
                from_op_provides[ip['from_op']].add(ip['param'])
                if ip['param'] not in param_to_list_op:
                    param_to_list_op[ip['param']] = ip['from_op']
        feeds = em.get('output_id_feeds_param')
        if feeds and op.get('kind') == 'read_list':
            param_to_list_op.setdefault(feeds, op_key)

    def resolve_chain(target_key, visited=None):
        if visited is None: visited = set()
        if target_key in visited: return []
        visited.add(target_key)
        op = ops.get(target_key)
        if not op: return []
        em, chain_before = op.get('execution_model', {}), []
        for ip in em.get('input_params', []):
            if ip.get('source') != 'from_prior_op': continue
            provider = ip.get('from_op') or param_to_list_op.get(ip['param'])
            if not provider or provider == target_key or provider in visited: continue
            for item in resolve_chain(provider, visited):
                if item not in chain_before:
                    chain_before.append(item)
        chain_before.append(target_key)
        return chain_before

    def make_step(op_key, step_num, is_target):
        op  = ops.get(op_key, {})
        em  = op.get('execution_model', {})
        feeds = em.get('output_id_feeds_param')
        if not feeds:
            provided = from_op_provides.get(op_key, set())
            feeds = list(provided)[0] if len(provided) == 1 else (list(provided) if provided else None)
        return {
            'step':      step_num,
            'op':        op_key,
            'kind':      op.get('kind', ''),
            'independent': op.get('independent', False),
            'python_call': op.get('python_call', ''),
            'purpose':   'Target operation' if is_target else (f'Provides: {feeds}' if feeds else 'Prerequisite'),
            'path':      op.get('path', ''),
            'required_params': op.get('required_params', {}),
            'output_list_field': em.get('output_list_field'),
            'output_id_field':  em.get('output_id_field'),
            'feeds_param': feeds,
            'full_resource_name_template': em.get('full_resource_name_template', ''),
        }

    chains = {}
    for op_key, op in ops.items():
        em = op.get('execution_model', {})
        always_av  = [ip['param'] for ip in em.get('input_params', []) if ip.get('source') == 'always_available']
        unresolved = [ip['param'] for ip in em.get('input_params', [])
                      if ip.get('source') == 'from_prior_op'
                      and not ip.get('from_op') and ip['param'] not in param_to_list_op]
        chain_keys = resolve_chain(op_key)
        execution_order = [make_step(k, i+1, k == op_key) for i, k in enumerate(chain_keys)]
        chains[op_key] = {
            'target_op':    op_key, 'kind': op.get('kind', ''),
            'independent':  op.get('independent', False),
            'chain_length': len(chain_keys),
            'execution_order': execution_order,
            'always_available_params': always_av,
            'unresolved_params':       unresolved,
        }
    return chains


# ── Main ──────────────────────────────────────────────────────────────────────
def process_service(svc_dir: Path) -> dict | None:
    step1_path = svc_dir / 'step1_operation_registry.json'
    if not step1_path.exists():
        return None

    existing = json.load(open(step1_path))
    service  = existing.get('service', svc_dir.name)
    version  = existing.get('version', 'v1')
    src      = existing.get('data_source', 'old')

    # Fetch the discovery doc to re-run schema expansion with the fix
    doc, new_src = get_doc(service, version, src)

    if doc:
        schemas = doc.get('schemas', {})
        operations = {}
        walk_resource(doc, [], schemas, service, operations)
        if not operations:
            # fall back to existing ops, just re-enrich
            operations = existing.get('operations', {})
        new_src = new_src or src
    else:
        # Can't re-fetch; use existing ops, re-enrich only
        operations = existing.get('operations', {})
        new_src = src

    if not operations:
        return {'status': 'skip', 'reason': 'no ops'}

    # Enrich (independence + execution_model + resource_path)
    operations = enrich_ops(operations, service)

    # Write step1
    registry = {
        'service': service, 'version': version, 'csp': 'gcp',
        'title': existing.get('title', doc.get('title', '') if doc else ''),
        'description': existing.get('description', ''),
        'documentation': existing.get('documentation', ''),
        'base_url': existing.get('base_url', ''),
        'data_source': new_src,
        'total_operations': len(operations),
        'operations': operations,
    }
    with open(step1_path, 'w') as f:
        json.dump(registry, f, indent=2)

    # Write step2
    read_ops, write_ops = write_step2(svc_dir, registry, operations)

    # Build and write step3 (chains from read ops only)
    chains = build_chains(read_ops, service)
    step3 = {
        'service': service, 'version': version,
        'total_ops': len(read_ops),
        'total_chains': len(chains),
        'independent_ops': sum(1 for op in read_ops.values() if op.get('independent')),
        'dependent_ops':   sum(1 for op in read_ops.values() if not op.get('independent')),
        'chains': chains,
    }
    with open(svc_dir / 'step3_read_operation_dependency_chain_independent.json', 'w') as f:
        json.dump(step3, f, indent=2)

    return {
        'status': 'ok',
        'total': len(operations), 'read': len(read_ops), 'write': len(write_ops),
        'chains': len(chains),
        'refetched': doc is not None,
    }


def run():
    print('=' * 70)
    print('Fix item_fields + output_id_field → rebuild step1/2/3 all services')
    print('=' * 70)
    print()

    all_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and (d / 'step1_operation_registry.json').exists()
    )

    ok = skip = 0
    total_ops = total_read = total_write = total_chains = 0

    for svc_dir in all_dirs:
        result = process_service(svc_dir)
        if not result or result['status'] == 'skip':
            reason = result.get('reason', '?') if result else '?'
            print(f'  ⏭  {svc_dir.name}: skip ({reason})')
            skip += 1
            continue
        ok += 1
        total_ops    += result['total']
        total_read   += result['read']
        total_write  += result['write']
        total_chains += result['chains']
        refetch = '↺' if result['refetched'] else '⚡'
        print(f'  {refetch} {svc_dir.name}: '
              f'{result["total"]} ops ({result["read"]} read / {result["write"]} write) '
              f'| {result["chains"]} chains')
        time.sleep(0.03)

    print()
    print('=' * 70)
    print(f'Services rebuilt:  {ok}')
    print(f'Skipped:           {skip}')
    print(f'Total ops:         {total_ops}')
    print(f'  Read:            {total_read}')
    print(f'  Write:           {total_write}')
    print(f'Total chains:      {total_chains}')
    print('=' * 70)


if __name__ == '__main__':
    run()
