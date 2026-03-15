#!/usr/bin/env python3
"""
Enrich ALL step1 files with:
  - resource_path         (static GCP full resource name template)
  - resource_id_param     (the final path param = resource ID)
  - parent_params         (preceding path params)
  - independent           (CORRECTED: true only if no required param
                           comes from a read_list op in same service)
  - execution_model       (input_params with source, output fields, feeds)

Then re-write step2_read and step2_write with enriched ops.

FIXED independence rule:
  An op is independent=True if ALL its required params are either:
    (a) always-available GCP context params (project, zone, etc.), OR
    (b) NOT produced as output by any read_list op in the same service
  i.e. independent=True iff no required param has an entity that is
  the output of a list op in the same service.
"""

import json
import re
from pathlib import Path

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

# Truly always-available from GCP account context (NOT 'name' - that's resource-specific)
ALWAYS_AVAILABLE = {
    'projectId', 'project', 'parent',
    'location', 'region', 'zone',
    'organizationId', 'folderId', 'billingAccountId', 'customerId',
    'accountId', 'customerId',
}

# Path param extraction from URL template
PATH_PARAM_RE = re.compile(r'\{[+]?(\w+)\}')

# Fields that indicate a list response array
LIST_ARRAY_FIELDS = {
    'items', 'resources', 'instances', 'datasets', 'tables', 'buckets',
    'clusters', 'nodes', 'snapshots', 'operations', 'results', 'entries',
    'connections', 'policies', 'keys', 'services', 'versions', 'revisions',
    'backups', 'replicas', 'zones', 'regions', 'networks', 'subnetworks',
    'addresses', 'firewalls', 'routes', 'projects', 'folders', 'members',
    'roles', 'bindings', 'subscriptions', 'topics', 'snapshots', 'messages',
    'jobs', 'tasks', 'triggers', 'functions', 'logs', 'sinks', 'metrics',
    'exclusions', 'alerts', 'channels', 'uptimeCheckConfigs', 'groups',
    'monitoredResources', 'timeSeries', 'dashboards', 'serviceAccounts',
    'workloadIdentityPools', 'providers', 'repos', 'refs', 'files',
    'artifacts', 'packages', 'tags', 'builds', 'triggers', 'workers',
    'workflows', 'executions', 'deployments', 'releases', 'targets',
    'pipelines', 'stages', 'rollouts', 'patches', 'patchJobs', 'reports',
    'assets', 'feeds', 'savedQueries', 'secrets', 'secretVersions',
    'cryptoKeys', 'cryptoKeyVersions', 'keyRings', 'importJobs',
    'attestors', 'certificates', 'certificateAuthorities', 'caPools',
    'caPoolIssuancePolicy', 'rootCerts',
}

# Priority ordering for picking output_id_field from list response
ID_FIELD_PRIORITY = ['name', 'id', 'selfLink', 'uid', 'resourceId', 'identifier']


def get_path_params(path: str) -> list[str]:
    """Extract ordered path parameters from URL template."""
    return PATH_PARAM_RE.findall(path)


def infer_id_param_from_list_op(op: dict) -> str | None:
    """
    For a read_list op, infer the ID param name that downstream ops will need.
    Strategy:
      1. Last non-ALWAYS_AVAILABLE path param of THIS op (e.g. routines.list path has datasetId → output datasetId)
      2. Resource segment before .list in op_key (e.g. datasets.list → dataset → datasetId)
    Returns the param name (e.g. 'datasetId') that consumers will pass in.
    """
    return None  # resolved per-call in build_list_ops_params


def build_resource_path(service: str, path: str) -> str:
    """Build GCP full resource name template from service and path."""
    # Clean up path: remove leading slash, collapse doubles
    clean = path.lstrip('/')
    # Remove + from {+param} style
    clean = re.sub(r'\{\+(\w+)\}', r'{\1}', clean)
    svc_host = f'{service}.googleapis.com'
    return f'//{svc_host}/{clean}'


def find_output_list_field(response_fields: dict, kind: str) -> str | None:
    """Find the array field that contains the list items."""
    if kind != 'read_list':
        return None
    # Try known list field names first
    for f in LIST_ARRAY_FIELDS:
        if f in response_fields and response_fields[f].get('type') == 'array':
            return f
    # Fall back: first array field
    for fname, finfo in response_fields.items():
        if finfo.get('type') == 'array' and fname not in ('nextPageToken',):
            return fname
    return None


def find_output_id_field(response_fields: dict, list_field: str | None,
                          schemas_ref: str = '') -> str | None:
    """Find the ID field within list items."""
    if not list_field:
        return None
    # Try priority field names
    for f in ID_FIELD_PRIORITY:
        if f in response_fields:
            return f
    # Use first non-metadata field
    skip = {'nextPageToken', 'etag', 'kind', 'selfLink', 'totalItems',
            'unreachable', 'warning', 'id'}
    for fname in response_fields:
        if fname not in skip:
            return fname
    return None


def param_to_path_segment(param: str) -> str:
    """Convert param name to likely URL path segment name."""
    # e.g. datasetId -> datasets, tableId -> tables, instanceId -> instances
    if param.endswith('Id'):
        base = param[:-2]
        # pluralize simply
        if base.endswith('s'):
            return base + 'es'
        return base + 's'
    if param.endswith('Name'):
        return param[:-4] + 's'
    return param + 's'


def build_execution_model(op: dict, service: str,
                           list_ops_params: dict) -> dict:
    """
    Build execution_model for an op.
    list_ops_params: dict of param_name -> (op_key, output_list_field, output_id_field)
    for all read_list ops in this service.
    """
    kind          = op.get('kind', '')
    path          = op.get('path', '')
    required      = op.get('required_params', {})
    response_flds = op.get('response_fields', {})
    path_params   = get_path_params(path)

    # ── input_params ──────────────────────────────────────────────
    input_params = []
    for pname, pinfo in required.items():
        if pname in ALWAYS_AVAILABLE:
            source = 'always_available'
            entry  = {
                'param':    pname,
                'required': True,
                'source':   source,
                'type':     pinfo.get('type', 'string'),
                'location': pinfo.get('location', 'path'),
            }
        else:
            source = 'from_prior_op'
            # Find which list op produces this param
            producer = list_ops_params.get(pname)
            entry = {
                'param':    pname,
                'required': True,
                'source':   source,
                'type':     pinfo.get('type', 'string'),
                'location': pinfo.get('location', 'path'),
            }
            if producer:
                from_op, from_list_field, from_id_field = producer
                entry['from_op']        = from_op
                entry['from_field']     = from_id_field or pname
                entry['from_list_field'] = from_list_field
        input_params.append(entry)

    # ── output fields ──────────────────────────────────────────────
    output_list_field = find_output_list_field(response_flds, kind)
    output_id_field   = find_output_id_field(response_flds, output_list_field)

    # Which param does the output ID feed into downstream ops?
    # Heuristic: look at path params — the last non-ALWAYS_AVAILABLE one
    downstream_param = None
    if kind == 'read_list' and output_id_field:
        # The param name is often like tableId for tables, datasetId for datasets etc.
        # Try to match from path params
        non_always = [p for p in path_params if p not in ALWAYS_AVAILABLE]
        if non_always:
            downstream_param = non_always[-1]

    # ── full resource name template ───────────────────────────────
    resource_path = build_resource_path(service, path)

    # Runtime template: replace {param} with {{ input.param }} or {{ item.id_field }}
    runtime_template = resource_path
    for pp in path_params:
        if pp in ALWAYS_AVAILABLE:
            runtime_template = runtime_template.replace(f'{{{pp}}}', f'{{{{ input.{pp} }}}}')
        else:
            runtime_template = runtime_template.replace(f'{{{pp}}}', f'{{{{ item.{output_id_field or pp} }}}}')

    model = {
        'input_params':       input_params,
        'output_list_field':  output_list_field,
        'output_id_field':    output_id_field,
    }
    if output_id_field:
        model['output_id_field_path'] = f'{{{{ item.{output_id_field} }}}}'
    if downstream_param:
        model['output_id_feeds_param'] = downstream_param
    model['full_resource_name_template'] = resource_path
    model['full_resource_name_runtime']  = runtime_template

    return model


# ── Independence logic (FIXED) ────────────────────────────────────────────────
def compute_independence(ops: dict) -> dict:
    """
    Returns {op_key: bool} independence map.

    An op is independent=True iff ALL its required params are either:
      - in ALWAYS_AVAILABLE, OR
      - NOT a param that any read_list op in the same service outputs

    i.e. it does NOT need the output of any list call in this service.
    """
    # Step 1: Collect what each read_list op outputs (the ID param it feeds)
    # We map: param_name -> set of list op keys that produce it
    list_op_outputs: dict[str, set] = {}

    for op_key, op in ops.items():
        if op.get('kind') != 'read_list':
            continue
        # Use resource-name-based derivation: datasets.list → datasetId
        output_param = list_op_output_param(op_key, op)
        if output_param:
            list_op_outputs.setdefault(output_param, set()).add(op_key)

    # Step 2: For each op, check if any required param is produced by a list op
    result = {}
    for op_key, op in ops.items():
        required = list(op.get('required_params', {}).keys())
        is_independent = True
        for p in required:
            if p in ALWAYS_AVAILABLE:
                continue
            # If this param is produced by a list op → dependent
            if p in list_op_outputs:
                is_independent = False
                break
            # If NOT in always_available and NOT produced by list op:
            # treat as dependent (unknown external dependency)
            is_independent = False
            break
        result[op_key] = is_independent

    return result


def list_op_output_param(op_key: str, op: dict) -> str | None:
    """
    Determine what ID param a read_list op produces for downstream consumers.

    Two strategies:
    1. Derive from op_key resource segment: gcp.bigquery.datasets.list → 'datasetId'
    2. Last non-ALWAYS_AVAILABLE path param of THIS op (e.g. tables.list has datasetId in path
       as an INPUT, not output — so skip strategy 2 for this)

    Strategy 1 is primary: the resource being listed IS the output.
    datasets.list   → datasetId
    tables.list     → tableId
    instances.list  → instanceId
    """
    # Strategy 1: resource name from op_key (second-to-last part)
    parts = op_key.split('.')
    if len(parts) >= 2:
        resource = parts[-2]  # e.g. 'datasets', 'tables', 'instances'
        # singularize and add Id: datasets → datasetId, tables → tableId
        singular = resource
        if singular.endswith('ies'):
            singular = singular[:-3] + 'y'
        elif singular.endswith('sses'):
            singular = singular[:-2]
        elif singular.endswith('ses'):
            singular = singular[:-2]
        elif singular.endswith('s') and not singular.endswith('ss'):
            singular = singular[:-1]
        param_id = singular + 'Id'
        return param_id
    return None


def build_list_ops_params(ops: dict) -> dict:
    """
    Build map: param_name -> (op_key, list_field, id_field)
    for all read_list ops — used by execution_model builder.

    For each read_list op, the OUTPUT param is derived from the resource it lists
    (e.g. datasets.list → datasetId), NOT from its path params (which are inputs).
    """
    candidates: dict[str, list] = {}
    for op_key, op in ops.items():
        if op.get('kind') != 'read_list':
            continue
        resp_fields  = op.get('response_fields', {})
        list_field   = find_output_list_field(resp_fields, 'read_list')
        id_field     = find_output_id_field(resp_fields, list_field)
        output_param = list_op_output_param(op_key, op)
        if output_param:
            candidates.setdefault(output_param, []).append(
                (op_key, list_field, id_field)
            )

    # Pick best candidate per param: prefer the op where resource matches param
    result = {}
    for param, cands in candidates.items():
        if len(cands) == 1:
            result[param] = cands[0]
            continue
        # derive base from param: datasetId → dataset
        base = re.sub(r'Id$|Name$', '', param).lower()
        def score(c):
            parts = c[0].split('.')
            if len(parts) >= 2:
                res = parts[-2].lower()
                if res.rstrip('s') == base or res.startswith(base):
                    return 0
            return 1
        best = sorted(cands, key=score)[0]
        result[param] = best

    return result


# ── Main enrichment ───────────────────────────────────────────────────────────
def enrich_service(svc_dir: Path) -> dict:
    step1_path = svc_dir / 'step1_operation_registry.json'
    if not step1_path.exists():
        return {'status': 'skip', 'reason': 'no step1'}

    data = json.load(open(step1_path))
    ops  = data.get('operations', {})
    if not ops:
        return {'status': 'skip', 'reason': 'empty ops'}

    service = data.get('service', svc_dir.name)

    # Compute independence for all ops
    independence = compute_independence(ops)

    # Build list-op param map for execution model
    list_ops_params = build_list_ops_params(ops)

    # Enrich each op
    for op_key, op in ops.items():
        path        = op.get('path', '')
        path_params = get_path_params(path)

        # resource_path fields
        resource_path    = build_resource_path(service, path)
        resource_id_param = path_params[-1] if path_params else None
        parent_params    = path_params[:-1] if len(path_params) > 1 else []

        op['resource_path']      = resource_path
        op['resource_id_param']  = resource_id_param
        op['parent_params']      = parent_params
        op['independent']        = independence.get(op_key, False)
        op['execution_model']    = build_execution_model(op, service, list_ops_params)

    # Write enriched step1
    data['operations'] = ops
    with open(step1_path, 'w') as f:
        json.dump(data, f, indent=2)

    # Re-split into step2_read and step2_write
    READ_KINDS  = {'read_list', 'read_get', 'other'}
    WRITE_KINDS = {'write_create', 'write_update', 'write_delete', 'write_apply'}

    read_ops  = {k: v for k, v in ops.items() if v.get('kind', '') in READ_KINDS}
    write_ops = {k: v for k, v in ops.items() if v.get('kind', '') in WRITE_KINDS}

    header = {
        'service':     data.get('service', service),
        'version':     data.get('version', ''),
        'csp':         data.get('csp', 'gcp'),
        'title':       data.get('title', ''),
        'description': data.get('description', ''),
        'documentation': data.get('documentation', ''),
        'base_url':    data.get('base_url', ''),
        'data_source': data.get('data_source', 'unknown'),
    }

    with open(svc_dir / 'step2_read_operation_registry.json', 'w') as f:
        json.dump({**header, 'total_operations': len(read_ops), 'operations': read_ops}, f, indent=2)

    with open(svc_dir / 'step2_write_operation_registry.json', 'w') as f:
        json.dump({**header, 'total_operations': len(write_ops), 'operations': write_ops}, f, indent=2)

    n_ind = sum(1 for v in independence.values() if v)
    n_dep = sum(1 for v in independence.values() if not v)

    return {
        'status': 'ok',
        'total': len(ops),
        'read':  len(read_ops),
        'write': len(write_ops),
        'independent': n_ind,
        'dependent':   n_dep,
    }


def run():
    print('=' * 70)
    print('Enriching step1 + re-splitting step2_read/write for all services')
    print('=' * 70)
    print()

    all_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and (d / 'step1_operation_registry.json').exists()
    )

    total_services = 0
    total_ops = total_read = total_write = 0
    total_ind = total_dep = 0
    skipped = []

    for svc_dir in all_dirs:
        result = enrich_service(svc_dir)
        if result['status'] == 'skip':
            skipped.append((svc_dir.name, result.get('reason', '?')))
            continue
        total_services += 1
        total_ops   += result['total']
        total_read  += result['read']
        total_write += result['write']
        total_ind   += result['independent']
        total_dep   += result['dependent']
        print(f'  ✓ {svc_dir.name}: {result["total"]} ops '
              f'({result["read"]} read / {result["write"]} write) '
              f'[{result["independent"]} ind / {result["dependent"]} dep]')

    print()
    print('=' * 70)
    print(f'Services enriched:    {total_services}')
    print(f'Total operations:     {total_ops}')
    print(f'  Read ops:           {total_read}')
    print(f'  Write ops:          {total_write}')
    print(f'  Independent ops:    {total_ind}')
    print(f'  Dependent ops:      {total_dep}')
    if skipped:
        print(f'Skipped ({len(skipped)}):')
        for s, r in skipped:
            print(f'  {s}: {r}')
    print('=' * 70)


if __name__ == '__main__':
    run()
