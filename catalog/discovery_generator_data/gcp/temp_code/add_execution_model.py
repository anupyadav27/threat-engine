#!/usr/bin/env python3
"""
Add execution_model to each op in step2_read_operation_registry.json.

The execution_model answers:
  1. What params do I pass IN?         → input_params[]
  2. What field do I iterate over?     → output_list_field
  3. What field gives the resource ID? → output_id_field / output_id_field_path
  4. What param does that ID feed?     → output_id_feeds_param
  5. How do I build the full resource name at runtime? → full_resource_name_template

Example for compute.instances.list:
{
  "execution_model": {
    "input_params": [
      {"param": "project",  "required": true,  "source": "always_available"},
      {"param": "zone",     "required": true,  "source": "always_available"}
    ],
    "output_list_field":       "items",
    "output_id_field":         "name",
    "output_id_field_path":    "{{ item.name }}",
    "output_id_feeds_param":   "instance",
    "full_resource_name_template": "//compute.googleapis.com/projects/{project}/zones/{zone}/instances/{instance}",
    "full_resource_name_runtime":  "//compute.googleapis.com/projects/{{ item.project }}/zones/{{ item.zone }}/instances/{{ item.name }}"
  }
}

Example for compute.instances.get  (dependent — needs prior list):
{
  "execution_model": {
    "input_params": [
      {"param": "project",  "required": true, "source": "always_available"},
      {"param": "zone",     "required": true, "source": "always_available"},
      {"param": "instance", "required": true, "source": "from_prior_op",
       "from_entity": "gcp.compute.instances.name",
       "from_op":     "gcp.compute.instances.list",
       "from_field":  "name"}
    ],
    "output_list_field":       null,
    "output_id_field":         "name",
    "output_id_field_path":    "{{ response.name }}",
    "output_id_feeds_param":   "instance",
    "full_resource_name_template": "//compute.googleapis.com/projects/{project}/zones/{zone}/instances/{instance}",
    "full_resource_name_runtime":  "//compute.googleapis.com/projects/{{ input.project }}/zones/{{ input.zone }}/instances/{{ response.name }}"
  }
}
"""

import json
import re
from pathlib import Path
from collections import defaultdict

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

ALWAYS_AVAILABLE = {
    'projectId', 'project', 'parent', 'name',
    'location', 'region', 'zone',
    'organizationId', 'folderId', 'billingAccountId',
    'customerId',
}

# Fields that typically carry the resource's own ID (priority order)
ID_FIELD_PRIORITY = [
    'name', 'selfLink', 'id', 'resourceId',
    'datasetId', 'tableId', 'jobId', 'clusterId', 'instanceId',
    'bucketId', 'objectId', 'topicId', 'subscriptionId',
    'networkId', 'subnetworkId', 'firewallId',
    'projectId', 'projectNumber',
]

# Fields that are NOT resource IDs (skip these)
NON_ID_FIELDS = {
    'kind', 'etag', 'nextPageToken', 'pageToken',
    'warning', 'warnings', 'unreachable', 'unreachables',
    'totalItems', 'pageInfo', 'done',
}

# Param name → likely field on item that provides it
PARAM_TO_ITEM_FIELD = {
    'instance':             'name',
    'disk':                 'name',
    'network':              'name',
    'subnetwork':           'name',
    'firewall':             'name',
    'address':              'name',
    'instanceGroup':        'name',
    'instanceGroupManager': 'name',
    'backendService':       'name',
    'forwardingRule':       'name',
    'route':                'name',
    'router':               'name',
    'snapshot':             'name',
    'image':                'name',
    'zone':                 'name',
    'region':               'name',
    'datasetId':            'datasetReference.datasetId',
    'tableId':              'tableReference.tableId',
    'jobId':                'jobReference.jobId',
    'bucketName':           'name',
    'object':               'name',
    'topic':                'name',
    'subscription':         'name',
    'clusterId':            'name',
    'nodePoolId':           'name',
}


def best_output_list_field(produces: list) -> str | None:
    """Find the primary list/collection field from produces."""
    # Prefer source='output' first
    output_fields = [p['path'] for p in produces if p.get('source') == 'output']
    if output_fields:
        return output_fields[0]
    return None


def best_id_field(produces: list, resource_id_param: str | None) -> tuple[str | None, str | None]:
    """
    Returns (field_name, jinja_path) for the field most likely to be the resource's own ID.
    Prefers fields matching the resource_id_param, then falls back to priority list.
    """
    item_fields = {p['path']: p for p in produces if p.get('source') == 'item'}

    if not item_fields:
        return None, None

    # 1. If resource_id_param maps to a known item field
    if resource_id_param and resource_id_param in PARAM_TO_ITEM_FIELD:
        candidate = PARAM_TO_ITEM_FIELD[resource_id_param]
        # candidate might be a dotted path like datasetReference.datasetId
        base = candidate.split('.')[0]
        if base in item_fields:
            return candidate, f'{{{{ item.{candidate} }}}}'

    # 2. If resource_id_param itself is a field name
    if resource_id_param and resource_id_param in item_fields:
        return resource_id_param, f'{{{{ item.{resource_id_param} }}}}'

    # 3. Check priority list
    for f in ID_FIELD_PRIORITY:
        if f in item_fields:
            return f, f'{{{{ item.{f} }}}}'

    # 4. First item field that isn't a non-ID field
    for path, p in item_fields.items():
        base = path.split('.')[0]
        if base not in NON_ID_FIELDS:
            return path, f'{{{{ item.{path} }}}}'

    return None, None


def build_full_resource_name_runtime(resource_path: str, input_params: list,
                                     output_id_field: str | None,
                                     resource_id_param: str | None,
                                     kind: str) -> str:
    """
    Build a Jinja2 runtime template for the full resource name.
    Params come from: always_available → {{ input.param }}
                      from_prior_op   → {{ item.field }} (list) or {{ response.field }} (get)
    """
    if not resource_path:
        return resource_path or ''

    result = resource_path
    item_or_response = 'item' if kind == 'read_list' else 'response'

    # Replace each {param} with its runtime source
    for ip in input_params:
        param = ip['param']
        if ip['source'] == 'always_available':
            result = re.sub(r'\{' + re.escape(param) + r'\}',
                            f'{{{{ input.{param} }}}}', result)
        else:
            field = ip.get('from_field', param)
            result = re.sub(r'\{' + re.escape(param) + r'\}',
                            f'{{{{ {item_or_response}.{field} }}}}', result)

    # Replace the resource_id_param with the output_id_field
    if resource_id_param and output_id_field:
        result = re.sub(r'\{' + re.escape(resource_id_param) + r'\}',
                        f'{{{{ {item_or_response}.{output_id_field} }}}}', result)

    return result


def build_execution_model(op_key: str, op: dict, all_ops: dict, service: str) -> dict:
    """Build the execution_model block for a single operation."""
    kind              = op.get('kind', '')
    consumes          = op.get('consumes', []) or []
    produces          = op.get('produces', []) or []
    required_params   = op.get('required_params', []) or []
    resource_path     = op.get('resource_path', '')
    resource_id_param = op.get('resource_id_param')
    parent_params     = op.get('parent_params', []) or []

    # ── Build input_params ───────────────────────────────────────────────────
    # Map param → consume entry
    consume_by_param = {c['param']: c for c in consumes if 'param' in c}

    input_params = []
    for param in required_params:
        c = consume_by_param.get(param, {})
        entity = c.get('entity', '')

        if param in ALWAYS_AVAILABLE:
            input_params.append({
                'param':    param,
                'required': True,
                'source':   'always_available',
            })
        else:
            # Find which op produces this entity → from_prior_op
            from_op_key  = None
            from_field   = None

            for other_key, other_op in all_ops.items():
                if other_key == op_key:
                    continue
                for p in (other_op.get('produces') or []):
                    if p.get('entity') == entity:
                        from_op_key = other_key
                        from_field  = PARAM_TO_ITEM_FIELD.get(param, p.get('path', param))
                        break
                if from_op_key:
                    break

            entry = {
                'param':       param,
                'required':    True,
                'source':      'from_prior_op',
                'from_entity': entity,
            }
            if from_op_key:
                entry['from_op']    = from_op_key
                entry['from_field'] = from_field or param
            input_params.append(entry)

    # ── Output list field ────────────────────────────────────────────────────
    output_list_field = best_output_list_field(produces)

    # ── Output ID field ──────────────────────────────────────────────────────
    output_id_field, output_id_field_path = best_id_field(produces, resource_id_param)

    # For get ops: response.field rather than item.field
    if output_id_field and kind == 'read_get':
        output_id_field_path = f'{{{{ response.{output_id_field} }}}}'

    # ── What param does the ID feed into the next call ───────────────────────
    # = resource_id_param of this op (that's what consumers will use)
    output_id_feeds_param = resource_id_param if resource_id_param not in ALWAYS_AVAILABLE else None

    # ── Full resource name runtime template ──────────────────────────────────
    full_resource_name_runtime = build_full_resource_name_runtime(
        resource_path, input_params,
        output_id_field, resource_id_param, kind
    )

    return {
        'input_params':               input_params,
        'output_list_field':          output_list_field,
        'output_id_field':            output_id_field,
        'output_id_field_path':       output_id_field_path,
        'output_id_feeds_param':      output_id_feeds_param,
        'full_resource_name_template': resource_path,
        'full_resource_name_runtime': full_resource_name_runtime,
    }


def enrich_service(svc_dir: Path) -> tuple[int, int] | None:
    read_path = svc_dir / 'step2_read_operation_registry.json'
    if not read_path.exists():
        return None

    reg = json.load(open(read_path))
    ops = reg.get('operations', {})
    if not ops:
        return None

    service = reg.get('service', svc_dir.name)
    enriched = 0

    for op_key, op in ops.items():
        op['execution_model'] = build_execution_model(op_key, op, ops, service)
        enriched += 1

    with open(read_path, 'w') as f:
        json.dump(reg, f, indent=2)

    return enriched, 0


def run():
    print('=' * 70)
    print('Adding execution_model to step2_read_operation_registry.json')
    print('=' * 70)

    service_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
    )

    processed = skipped = 0
    total_ops = 0

    for sdir in service_dirs:
        result = enrich_service(sdir)
        if result is None:
            skipped += 1
            continue
        enc, _ = result
        total_ops += enc
        processed += 1
        print(f'  ✓ {sdir.name}: {enc} ops')

    print()
    print(f'Processed:   {processed} services')
    print(f'Skipped:     {skipped} (no read registry)')
    print(f'Total ops:   {total_ops}')
    print('=' * 70)

    # ── Show examples ────────────────────────────────────────────────────────
    print()
    examples = [
        ('/Users/apple/Desktop/data_pythonsdk/gcp/compute/step2_read_operation_registry.json',
         ['gcp.compute.instances.list', 'gcp.compute.instances.get']),
        ('/Users/apple/Desktop/data_pythonsdk/gcp/bigquery/step2_read_operation_registry.json',
         ['gcp.bigquery.datasets.list', 'gcp.bigquery.datasets.get']),
        ('/Users/apple/Desktop/data_pythonsdk/gcp/adexperiencereport/step2_read_operation_registry.json',
         ['gcp.adexperiencereport.sites.get']),
    ]
    for path, keys in examples:
        d = json.load(open(path))
        for k in keys:
            op = d['operations'].get(k, {})
            em = op.get('execution_model', {})
            print(f'── {k} ──')
            print(json.dumps(em, indent=2))
            print()


if __name__ == '__main__':
    run()
