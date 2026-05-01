#!/usr/bin/env python3
"""
Split step1_operation_registry.json into:
  step2_read_operation_registry.json   — read-only operations (safe to enumerate)
  step2_write_operation_registry.json  — write/mutate/action operations

Classification rules (in priority order):
  READ  → kind in {read_get, read_list}
  WRITE → kind in {write_create, write_update, write_delete, create, update, delete, action, write_apply}
  OTHER (kind='other', side_effect=True) → classify by method name:
        READ-like  if name matches READ_METHOD_PATTERNS
        WRITE-like otherwise
"""

import json
import re
from pathlib import Path

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

# ── Classification constants ─────────────────────────────────────────────────

READ_KINDS  = {'read_get', 'read_list'}
WRITE_KINDS = {'write_create', 'write_update', 'write_delete',
               'create', 'update', 'delete', 'action', 'write_apply'}

# Method-name patterns that indicate a READ even when kind='other'
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

def classify(op_key: str, op: dict) -> str:
    """Return 'read' or 'write'."""
    kind = op.get('kind', 'unknown')

    if kind in READ_KINDS:
        return 'read'
    if kind in WRITE_KINDS:
        return 'write'

    # kind == 'other' (all have side_effect=True)
    method = op_key.split('.')[-1]
    method_norm = method.replace('_', '').replace('-', '').lower()
    if READ_METHOD_RE.match(method_norm):
        return 'read'
    return 'write'


def split_registry(svc_dir: Path) -> tuple[int, int]:
    reg_path = svc_dir / 'step1_operation_registry.json'
    if not reg_path.exists():
        return 0, 0

    reg = json.load(open(reg_path))
    ops = reg.get('operations', {})

    read_ops  = {}
    write_ops = {}

    for key, op in ops.items():
        bucket = classify(key, op)
        if bucket == 'read':
            read_ops[key] = op
        else:
            write_ops[key] = op

    # ── Build read registry ──────────────────────────────────────────────────
    read_reg = {
        'service':      reg.get('service'),
        'version':      reg.get('version'),
        'csp':          reg.get('csp'),
        'data_quality': reg.get('data_quality'),
        'registry_type': 'read',
        'total_operations': len(read_ops),
        'kind_rules':   reg.get('kind_rules'),
        'entity_aliases': reg.get('entity_aliases'),
        'overrides':    reg.get('overrides'),
        'operations':   read_ops,
        '_metadata':    reg.get('_metadata'),
    }

    # ── Build write registry ─────────────────────────────────────────────────
    write_reg = {
        'service':      reg.get('service'),
        'version':      reg.get('version'),
        'csp':          reg.get('csp'),
        'data_quality': reg.get('data_quality'),
        'registry_type': 'write',
        'total_operations': len(write_ops),
        'kind_rules':   reg.get('kind_rules'),
        'entity_aliases': reg.get('entity_aliases'),
        'overrides':    reg.get('overrides'),
        'operations':   write_ops,
        '_metadata':    reg.get('_metadata'),
    }

    read_path  = svc_dir / 'step2_read_operation_registry.json'
    write_path = svc_dir / 'step2_write_operation_registry.json'

    with open(read_path, 'w') as f:
        json.dump(read_reg, f, indent=2)
    with open(write_path, 'w') as f:
        json.dump(write_reg, f, indent=2)

    return len(read_ops), len(write_ops)


def run():
    print('=' * 70)
    print('Splitting step1 operation registry → step2_read + step2_write')
    print('=' * 70)

    service_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and not d.name.endswith('.py') and not d.name.endswith('.md')
    )

    total_read = total_write = services = 0
    for sdir in service_dirs:
        r, w = split_registry(sdir)
        if r + w == 0:
            continue
        services += 1
        total_read  += r
        total_write += w
        print(f'  {sdir.name}: {r} read  +  {w} write')

    print()
    print(f'Services processed : {services}')
    print(f'Total READ  ops    : {total_read}')
    print(f'Total WRITE ops    : {total_write}')
    print(f'Grand total        : {total_read + total_write}')
    print('=' * 70)


if __name__ == '__main__':
    run()
