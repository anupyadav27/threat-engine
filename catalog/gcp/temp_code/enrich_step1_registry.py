#!/usr/bin/env python3
"""
Enrich step1_operation_registry.json (single source of truth) with:

  resource_path      — GCP full resource name pattern (ARN equivalent)
                       e.g. //compute.googleapis.com/projects/{project}/zones/{zone}/disks/{disk}
  resource_id_param  — last path param = the resource's own ID
                       e.g. "disk"
  parent_params      — preceding path params = the hierarchy above it
                       e.g. ["project", "zone"]
  independent        — true if all required_params are ALWAYS_AVAILABLE (no prior call needed)
  execution_model    — runtime call model: what goes in, what comes out, how to build the resource name

After enriching step1, re-split into step2_read and step2_write so they stay
in sync with step1 as the single source of truth.
"""

import json
import re
from pathlib import Path

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

# Params GCP always has from context — no prior API call needed
ALWAYS_AVAILABLE = {
    'projectId', 'project', 'parent', 'name',
    'location', 'region', 'zone',
    'organizationId', 'folderId', 'billingAccountId',
    'customerId',
}

# READ / WRITE classification (same as split_operation_registry.py)
READ_KINDS  = {'read_get', 'read_list'}
WRITE_KINDS = {'write_create', 'write_update', 'write_delete',
               'create', 'update', 'delete', 'action', 'write_apply'}

READ_METHOD_RE = re.compile(
    r'^(get|list|describe|fetch|read|search|query|aggregate|aggregated|'
    r'find|lookup|count|check|validate|preview|diagnose|inspect|analyze|analyse|'
    r'explain|summary|report|discover|suggest|autocomplete|recommend|export|'
    r'generate|view|show|batchget|batch_get|testiam|getiampolicy|'
    r'listorgpolicies|getorgpolicy|listavailableorgpolicyconstraints|'
    r'geteffectiveorgpolicy|stream|poll|watch|listen|searchlite|'
    r'querygrantableroles|querytestablepermissions|queryauditableservices|'
    r'queryaccessibledata|troubleshoot|bulkcheck|verify|listrecentstats|'
    r'fetchreportresults|listenercheck|getworkerstacktraces|linkedtargets|'
    r'listtransferableoffers|listtransferableskus|getancestry|checkaccess|'
    r'checkconsistency|checkcompatibility|checkupgrade|checkconsumerconfig|'
    r'checkmigrationpermission|checkcloudidentityaccountsexist|'
    r'listmanagedinstances|listperinstanceconfigs|listinstances|listnodes|'
    r'listxpnhosts|listgrouppriorityordering|listcollectionids|'
    r'listorgpolicies|listavailableorgpolicyconstraints|listoptimaltrials|'
    r'evaluateuserconsents|decodeintegritytoken|decodepcintegritytoken|'
    r'exporttensorboardtimeseries|exportsbom|exportartifact|exportstate|'
    r'exportmetadata|exportdata|exportdocuments|exportassets|'
    r'queryhistoryrecord|queryrecord|querymetrics|queryperformanceoverview|'
    r'queryassets|querytabularstats|querytimeseriesstats|queryaccounts|'
    r'querymetadata|searchresources|searchentries|searchbyviewurl|searchlinks|'
    r'batchsearchlinkprocesses|searchmodeldeploymentmonitoringstatsanomalies|'
    r'searchnearby|searchtext|searchnearestentities|debugsearch|'
    r'analyze[a-z]*|inspect[a-z]*|generate[a-z]*(url|report|script|token|cert|spec|rubric|challenge|bytes|default|wallet)$|'
    r'fetch[a-z]*(token|acl|access|certs|status|results|options|value)$|'
    r'read[a-z]*|stream[a-z]*|partitionquery|partitionread|runaggregationquery|'
    r'runquery|executegraphqlread|executequery|impersonatequery|'
    r'batchreadfeaturevalues|readfeaturevalues|streamingreadfeaturevalues|'
    r'findneighbors|readindexdatapoints|lookupversion|findbyidentifier|findbyowner|'
    r'validateaddress|validatetrust|validatedirectoryservice|validatemessage|'
    r'validateattestationoccurrence|validateattributeexpression|validatecustomconnectorspec|'
    r'resource-validate|search-type|counttokens|precheckmajorversionupgrade|'
    r'getapkdetails|generatemembershiprbacrolebindingyaml|getendpoint|'
    r'getsimlockstate|getsyncauthorization|gethealth|getverificationcode|'
    r'fetchverificationoptions|getworkerstacktraces|gettoken|'
    r'getconfig|getorgpolicy|geteffectiveorgpolicy|batchverifytargetsites|'
    r'bulkeditadvertiserassignedtargetingoptions|editguaranteedorderreadaccessors|'
    r'editinventorysourcereadwriteaccessors|generateopenapispec|'
    r'generatedeploychangereport|generateundeploychangereport|'
    r'reportassetframes|checkearlystoppingstate|checktrialearlystoppingstate|'
    r'getsimlockstate|getancestry|generatesshscript|generatetcpproxyscript|'
    r'fetchreadtoken|fetchreadwritetoken|fetchpredictoperation|'
    r'readfeaturevalues|batchreadfeaturevalues|streamingreadfeaturevalues|'
    r'analyzeentities|analyzeentitysentiment|analyzesentiment|analyzesyntax|'
    r'analyzepackages|analyzeiampolicylongrunning|'
    r'rundiscovery|createiacvalidationreport|generateconfigreport|'
    r'bulkanalyze|reviewdocument|evaluateprocessorversion)$',
    re.IGNORECASE
)

# Fields that typically carry the resource's own ID (priority order)
ID_FIELD_PRIORITY = [
    'name', 'selfLink', 'id', 'resourceId',
    'datasetId', 'tableId', 'jobId', 'clusterId', 'instanceId',
    'bucketId', 'objectId', 'topicId', 'subscriptionId',
    'networkId', 'subnetworkId', 'firewallId',
    'projectId', 'projectNumber',
]

NON_ID_FIELDS = {
    'kind', 'etag', 'nextPageToken', 'pageToken',
    'warning', 'warnings', 'unreachable', 'unreachables',
    'totalItems', 'pageInfo', 'done',
}

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


# ── Classification ───────────────────────────────────────────────────────────

def classify_op(op_key: str, op: dict) -> str:
    """Return 'read' or 'write'."""
    kind = op.get('kind', 'unknown')
    if kind in READ_KINDS:
        return 'read'
    if kind in WRITE_KINDS:
        return 'write'
    method = op_key.split('.')[-1]
    method_norm = method.replace('_', '').replace('-', '').lower()
    if READ_METHOD_RE.match(method_norm):
        return 'read'
    return 'write'


# ── Resource path helpers ─────────────────────────────────────────────────────

def clean_path(path: str) -> str:
    path = re.sub(r'^v\d+[a-zA-Z0-9]*/', '', path)
    path = re.sub(r':[a-zA-Z]+$', '', path)
    path = re.sub(r'\{\+(\w+)\}', r'{\1}', path)
    return path


def extract_path_params(path: str) -> list[str]:
    return re.findall(r'\{[+]?(\w+)\}', path)


def build_resource_path(service: str, path: str) -> str:
    clean = clean_path(path)
    if clean:
        return f'//{service}.googleapis.com/{clean}'
    return f'//{service}.googleapis.com'


# ── Independence ──────────────────────────────────────────────────────────────

def is_independent(op: dict) -> bool:
    req = op.get('required_params', []) or []
    consumes = op.get('consumes', []) or []
    has_external_consume = any(
        c.get('required', False) and c.get('param', '') not in ALWAYS_AVAILABLE
        for c in consumes
    )
    return all(p in ALWAYS_AVAILABLE for p in req) and not has_external_consume


# ── Execution model ───────────────────────────────────────────────────────────

def best_output_list_field(produces: list) -> str | None:
    output_fields = [p['path'] for p in produces if p.get('source') == 'output']
    return output_fields[0] if output_fields else None


def best_id_field(produces: list, resource_id_param: str | None) -> tuple[str | None, str | None]:
    item_fields = {p['path']: p for p in produces if p.get('source') == 'item'}
    if not item_fields:
        return None, None
    if resource_id_param and resource_id_param in PARAM_TO_ITEM_FIELD:
        candidate = PARAM_TO_ITEM_FIELD[resource_id_param]
        base = candidate.split('.')[0]
        if base in item_fields:
            return candidate, f'{{{{ item.{candidate} }}}}'
    if resource_id_param and resource_id_param in item_fields:
        return resource_id_param, f'{{{{ item.{resource_id_param} }}}}'
    for f in ID_FIELD_PRIORITY:
        if f in item_fields:
            return f, f'{{{{ item.{f} }}}}'
    for path in item_fields:
        if path.split('.')[0] not in NON_ID_FIELDS:
            return path, f'{{{{ item.{path} }}}}'
    return None, None


def build_full_resource_name_runtime(resource_path: str, input_params: list,
                                     output_id_field: str | None,
                                     resource_id_param: str | None,
                                     kind: str) -> str:
    if not resource_path:
        return resource_path or ''
    result = resource_path
    item_or_response = 'item' if kind == 'read_list' else 'response'
    for ip in input_params:
        param = ip['param']
        if ip['source'] == 'always_available':
            result = re.sub(r'\{' + re.escape(param) + r'\}',
                            f'{{{{ input.{param} }}}}', result)
        else:
            field = ip.get('from_field', param)
            result = re.sub(r'\{' + re.escape(param) + r'\}',
                            f'{{{{ {item_or_response}.{field} }}}}', result)
    if resource_id_param and output_id_field:
        result = re.sub(r'\{' + re.escape(resource_id_param) + r'\}',
                        f'{{{{ {item_or_response}.{output_id_field} }}}}', result)
    return result


def build_execution_model(op_key: str, op: dict, all_ops: dict) -> dict:
    kind              = op.get('kind', '')
    consumes          = op.get('consumes', []) or []
    produces          = op.get('produces', []) or []
    required_params   = op.get('required_params', []) or []
    resource_path     = op.get('resource_path', '')
    resource_id_param = op.get('resource_id_param')

    consume_by_param = {c['param']: c for c in consumes if 'param' in c}

    input_params = []
    for param in required_params:
        c = consume_by_param.get(param, {})
        entity = c.get('entity', '')
        if param in ALWAYS_AVAILABLE:
            input_params.append({'param': param, 'required': True, 'source': 'always_available'})
        else:
            from_op_key = from_field = None
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
            entry = {'param': param, 'required': True, 'source': 'from_prior_op', 'from_entity': entity}
            if from_op_key:
                entry['from_op']    = from_op_key
                entry['from_field'] = from_field or param
            input_params.append(entry)

    output_list_field = best_output_list_field(produces)
    output_id_field, output_id_field_path = best_id_field(produces, resource_id_param)

    if output_id_field and kind == 'read_get':
        output_id_field_path = f'{{{{ response.{output_id_field} }}}}'

    output_id_feeds_param = (
        resource_id_param if resource_id_param and resource_id_param not in ALWAYS_AVAILABLE
        else None
    )

    full_resource_name_runtime = build_full_resource_name_runtime(
        resource_path, input_params, output_id_field, resource_id_param, kind
    )

    return {
        'input_params':                input_params,
        'output_list_field':           output_list_field,
        'output_id_field':             output_id_field,
        'output_id_field_path':        output_id_field_path,
        'output_id_feeds_param':       output_id_feeds_param,
        'full_resource_name_template': resource_path,
        'full_resource_name_runtime':  full_resource_name_runtime,
    }


# ── Main enrichment ───────────────────────────────────────────────────────────

def enrich_step1(svc_dir: Path) -> tuple[int, int, int] | None:
    """Returns (total_ops, read_ops, write_ops) or None."""
    reg_path = svc_dir / 'step1_operation_registry.json'
    if not reg_path.exists():
        return None

    reg = json.load(open(reg_path))
    ops = reg.get('operations', {})
    if not ops:
        return None

    service = reg.get('service', svc_dir.name)

    # ── Pass 1: resource_path, resource_id_param, parent_params, independent ─
    for op_key, op in ops.items():
        http_path = op.get('path', '')

        resource_path     = build_resource_path(service, http_path) if http_path else ''
        params            = extract_path_params(http_path)
        resource_id_param = params[-1] if params else None
        parent_params     = params[:-1] if len(params) > 1 else []

        op['resource_path']     = resource_path
        op['resource_id_param'] = resource_id_param
        op['parent_params']     = parent_params
        op['independent']       = is_independent(op)

    # ── Pass 2: execution_model (needs resource_path already set) ────────────
    for op_key, op in ops.items():
        op['execution_model'] = build_execution_model(op_key, op, ops)

    # Write enriched step1
    with open(reg_path, 'w') as f:
        json.dump(reg, f, indent=2)

    # ── Re-split into step2_read and step2_write ──────────────────────────────
    read_ops  = {}
    write_ops = {}
    for op_key, op in ops.items():
        if classify_op(op_key, op) == 'read':
            read_ops[op_key]  = op
        else:
            write_ops[op_key] = op

    base = {k: v for k, v in reg.items() if k not in ('operations', 'registry_type', 'total_operations')}

    read_reg = {**base,
                'registry_type':    'read',
                'total_operations': len(read_ops),
                'operations':       read_ops}

    write_reg = {**base,
                 'registry_type':    'write',
                 'total_operations': len(write_ops),
                 'operations':       write_ops}

    with open(svc_dir / 'step2_read_operation_registry.json', 'w') as f:
        json.dump(read_reg, f, indent=2)
    with open(svc_dir / 'step2_write_operation_registry.json', 'w') as f:
        json.dump(write_reg, f, indent=2)

    return len(ops), len(read_ops), len(write_ops)


def run():
    print('=' * 70)
    print('Enriching step1_operation_registry.json + re-splitting step2')
    print('=' * 70)

    service_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
    )

    processed = skipped = 0
    total_ops = total_read = total_write = 0

    for sdir in service_dirs:
        result = enrich_step1(sdir)
        if result is None:
            skipped += 1
            continue
        total, r, w = result
        total_ops   += total
        total_read  += r
        total_write += w
        processed   += 1
        print(f'  ✓ {sdir.name}: {total} ops  ({r} read / {w} write)')

    print()
    print(f'Processed:        {processed} services')
    print(f'Skipped:          {skipped} (no step1 registry)')
    print(f'Total ops:        {total_ops}')
    print(f'Total read ops:   {total_read}')
    print(f'Total write ops:  {total_write}')
    print('=' * 70)

    # ── Verify example ────────────────────────────────────────────────────────
    print()
    print('── Verify: bigquery/step1 datasets.list ─────────────────────────────')
    s1 = json.load(open('/Users/apple/Desktop/data_pythonsdk/gcp/bigquery/step1_operation_registry.json'))
    op = s1['operations'].get('gcp.bigquery.datasets.list', {})
    for field in ['path', 'resource_path', 'resource_id_param', 'parent_params', 'independent']:
        print(f'  {field}: {op.get(field)}')
    em = op.get('execution_model', {})
    print(f'  execution_model.input_params: {em.get("input_params")}')
    print(f'  execution_model.output_list_field: {em.get("output_list_field")}')
    print(f'  execution_model.full_resource_name_template: {em.get("full_resource_name_template")}')
    print(f'  execution_model.full_resource_name_runtime: {em.get("full_resource_name_runtime")}')

    print()
    print('── Verify: step2_read has same enrichment ───────────────────────────')
    s2r = json.load(open('/Users/apple/Desktop/data_pythonsdk/gcp/bigquery/step2_read_operation_registry.json'))
    op2 = s2r['operations'].get('gcp.bigquery.datasets.list', {})
    print(f'  has resource_path: {"resource_path" in op2}')
    print(f'  has independent:   {"independent" in op2}')
    print(f'  has execution_model: {"execution_model" in op2}')

    print()
    print('── Verify: step2_write has same enrichment ──────────────────────────')
    s2w = json.load(open('/Users/apple/Desktop/data_pythonsdk/gcp/bigquery/step2_write_operation_registry.json'))
    write_key = next(iter(s2w['operations']), None)
    op3 = s2w['operations'].get(write_key, {})
    print(f'  sample write op: {write_key}')
    print(f'  has resource_path: {"resource_path" in op3}')
    print(f'  has independent:   {"independent" in op3}')
    print(f'  has execution_model: {"execution_model" in op3}')


if __name__ == '__main__':
    run()
