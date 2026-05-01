#!/usr/bin/env python3
"""
add_missing_ops.py
==================
Adds the 14 missing GCP discovery ops that are referenced in check rules but
not present in any final_discovery_v1.yaml, reducing SKIP from 131 to 0.

Actions taken:
  1. Add missing ops to existing final_discovery yamls (11 ops)
  2. Create new final_discovery yamls for 6 new services
     (cloudbilling, cloudtrace, looker, cloudaudit, config_connector, vertex_ai)

Usage:
    python add_missing_ops.py           # dry-run
    python add_missing_ops.py --apply   # write files
"""

import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional

import yaml

# ──────────────────────────────────────────────────────────────────────────────
ROOT    = Path('/Users/apple/Desktop/threat-engine')
GEN_DIR = ROOT / 'catalog/discovery_generator/gcp'
# ──────────────────────────────────────────────────────────────────────────────

DRY_RUN = '--apply' not in sys.argv

NOW = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _load_yaml(p: Path) -> dict:
    try:
        return yaml.safe_load(p.read_text()) or {}
    except Exception:
        return {}


# ─── New ops to add to EXISTING final_discovery yamls ────────────────────────
# Format: op_id → {service_dir (gen_svc), action, fields_needed}
EXISTING_YAML_OPS: List[Dict] = [
    # apigee: environments.list (independent, returns list of env names)
    {
        'discovery_id': 'gcp.apigee.organizations.environments.list',
        'service_dir':  'apigee',
        'action':       'organizations.environments.list',
        'independent':  True,
        'fields':       ['deployments', 'displayName', 'name', 'state'],
    },
    # bigquery: datasets.list (independent)
    {
        'discovery_id': 'gcp.bigquery.datasets.list',
        'service_dir':  'bigquery',
        'action':       'datasets.list',
        'independent':  True,
        'fields':       ['access', 'defaultEncryptionConfiguration', 'defaultTableExpirationMs',
                         'id', 'labels', 'location'],
    },
    # cloudkms: keyRings.list (independent — parent of cryptoKeys.list)
    {
        'discovery_id': 'gcp.cloudkms.projects.locations.keyRings.list',
        'service_dir':  'cloudkms',
        'action':       'projects.locations.keyRings.list',
        'independent':  True,
        'fields':       ['createTime', 'labels', 'name', 'versionTemplate'],
    },
    # datacatalog: tagTemplates.list (independent)
    {
        'discovery_id': 'gcp.datacatalog.projects.locations.tagTemplates.list',
        'service_dir':  'datacatalog',
        'action':       'projects.locations.tagTemplates.list',
        'independent':  True,
        'fields':       ['accessControl', 'auditConfig', 'displayName', 'encryptionConfig',
                         'fields', 'iamPolicy', 'isPubliclyReadable', 'labels', 'monitoringConfig',
                         'name', 'networkConfig', 'retentionPolicy', 'schemaValidation',
                         'versioningConfig'],
    },
    # dataflow: pipelines.list (independent)
    {
        'discovery_id': 'gcp.dataflow.projects.locations.pipelines.list',
        'service_dir':  'dataflow',
        'action':       'projects.locations.pipelines.list',
        'independent':  True,
        'fields':       ['createTime', 'displayName', 'name', 'pipelineDefinition',
                         'schedules', 'state', 'type', 'updateTime'],
    },
    # logging: savedQueries.list (independent)
    {
        'discovery_id': 'gcp.logging.savedQueries.list',
        'service_dir':  'logging',
        'action':       'savedQueries.list',
        'independent':  True,
        'fields':       ['createTime', 'description', 'displayName', 'loggingQuery',
                         'name', 'opsAnalyticsQuery', 'updateTime', 'visibility'],
    },
    # monitoring: dashboards.list (independent)
    {
        'discovery_id': 'gcp.monitoring.projects.dashboards.list',
        'service_dir':  'monitoring',
        'action':       'projects.dashboards.list',
        'independent':  True,
        'fields':       ['columnLayout', 'dashboardFilters', 'displayName', 'etag',
                         'labels', 'mosaicLayout', 'name', 'rowLayout', 'userLabels'],
    },
    # osconfig: guestPolicies.list (independent)
    {
        'discovery_id': 'gcp.osconfig.projects.guestPolicies.list',
        'service_dir':  'osconfig',
        'action':       'projects.guestPolicies.list',
        'independent':  True,
        'fields':       ['assignment', 'createTime', 'description', 'etag', 'name',
                         'packageRepositories', 'packages', 'recipes', 'updateTime'],
    },
    # cloudresourcemanager: folders.list (independent)
    {
        'discovery_id': 'gcp.cloudresourcemanager.folders.list',
        'service_dir':  'cloudresourcemanager',
        'action':       'folders.list',
        'independent':  True,
        'fields':       ['createTime', 'deleteTime', 'displayName', 'etag',
                         'iamPolicy', 'labels', 'lifecycleState', 'name',
                         'orgPolicies', 'parent', 'updateTime'],
    },
    # cloudresourcemanager: organizations.list (independent)
    {
        'discovery_id': 'gcp.cloudresourcemanager.organizations.list',
        'service_dir':  'cloudresourcemanager',
        'action':       'organizations.search',
        'independent':  True,
        'fields':       ['createTime', 'deleteTime', 'directoryCustomerId', 'displayName',
                         'etag', 'iamPolicy', 'labels', 'lifecycleState', 'name',
                         'orgPolicies', 'updateTime'],
    },
    # aiplatform: models.versions.list (dependent on models.list)
    {
        'discovery_id': 'gcp.aiplatform.projects.locations.models.versions.list',
        'service_dir':  'aiplatform',
        'action':       'projects.locations.models.listVersions',
        'independent':  False,
        'for_each':     'gcp.aiplatform.projects.locations.models.list',
        'params':       {'name': '{{ item.name }}'},
        'fields':       ['containerSpec', 'createTime', 'displayName', 'etag',
                         'labels', 'metadata', 'modelSourceInfo', 'name',
                         'updateTime', 'versionAliases', 'versionDescription',
                         'versionId', 'versionUpdateTime'],
    },
    # billingbudgets yaml: add cloudbilling.billingAccounts.list
    {
        'discovery_id': 'gcp.cloudbilling.billingAccounts.list',
        'service_dir':  'billingbudgets',
        'action':       'billingAccounts.list',
        'independent':  True,
        'fields':       ['bigqueryExport', 'bindings', 'costManagement', 'displayName',
                         'masterBillingAccount', 'name', 'open', 'parent'],
    },
]

# ─── New service final_discovery yamls to CREATE ──────────────────────────────
# These are services not previously covered or needing their own yaml

NEW_SERVICE_YAMLS: List[Dict] = [
    # cloudbilling: service dir for billing→cloudbilling lookup
    {
        'service_dir': 'cloudbilling',
        'service':     'cloudbilling',
        'provider':    'gcp',
        'version':     'v1',
        'ops': [
            {
                'discovery_id': 'gcp.cloudbilling.billingAccounts.list',
                'action':       'billingAccounts.list',
                'independent':  True,
                'fields':       ['bigqueryExport', 'bindings', 'costManagement', 'displayName',
                                 'masterBillingAccount', 'name', 'open', 'parent'],
            },
        ],
        'identifiers': [
            {
                'resource_type':       'billingAccounts',
                'identifier_op':       'gcp.cloudbilling.billingAccounts.list',
                'identifier_field':    'name',
                'item_var_path':       'item.name',
                'identifier_template': '{name}',
            },
        ],
    },
    # cloudtrace: for trace check service
    {
        'service_dir': 'cloudtrace',
        'service':     'cloudtrace',
        'provider':    'gcp',
        'version':     'v1',
        'ops': [
            {
                'discovery_id': 'gcp.cloudtrace.projects.traces.list',
                'action':       'projects.traces.list',
                'independent':  True,
                'fields':       ['displayName', 'hasRemoteParent', 'name', 'projectId',
                                 'spanCount', 'spans', 'traceId'],
            },
        ],
        'identifiers': [
            {
                'resource_type':       'traces',
                'identifier_op':       'gcp.cloudtrace.projects.traces.list',
                'identifier_field':    'traceId',
                'item_var_path':       'item.traceId',
                'identifier_template': '{traceId}',
            },
        ],
    },
    # looker: for datastudio check service
    {
        'service_dir': 'looker',
        'service':     'looker',
        'provider':    'gcp',
        'version':     'v1',
        'ops': [
            {
                'discovery_id': 'gcp.looker.projects.locations.instances.list',
                'action':       'projects.locations.instances.list',
                'independent':  True,
                'fields':       ['adminSettings', 'createTime', 'customDomain', 'deleteTime',
                                 'encryptionConfig', 'fipsEnabled', 'maintenanceSchedule',
                                 'maintenanceWindow', 'name', 'oauthConfig', 'pscConfig',
                                 'pscEnabled', 'publicIpEnabled', 'reservedRange', 'state',
                                 'updateTime'],
            },
        ],
        'identifiers': [
            {
                'resource_type':       'instances',
                'identifier_op':       'gcp.looker.projects.locations.instances.list',
                'identifier_field':    'name',
                'item_var_path':       'item.name',
                'identifier_template': '{name}',
            },
        ],
    },
    # cloudaudit: wraps logging.entries.list for cloudaudit check service
    {
        'service_dir': 'cloudaudit',
        'service':     'cloudaudit',
        'provider':    'gcp',
        'version':     'v2',
        'ops': [
            {
                'discovery_id': 'gcp.logging.entries.list',
                'action':       'entries.list',
                'independent':  True,
                'fields':       ['httpRequest', 'insertId', 'jsonPayload', 'labels',
                                 'logName', 'metadata', 'operation', 'protoPayload',
                                 'receiveTimestamp', 'resource', 'severity', 'sourceLocation',
                                 'spanId', 'split', 'textPayload', 'timestamp', 'trace',
                                 'traceSampled'],
            },
        ],
        'identifiers': [],
    },
    # config_connector: wraps cloudasset.assets.list for config_connector check service
    {
        'service_dir': 'config_connector',
        'service':     'config_connector',
        'provider':    'gcp',
        'version':     'v1',
        'ops': [
            {
                'discovery_id': 'gcp.cloudasset.assets.list',
                'action':       'assets.list',
                'independent':  True,
                'fields':       ['accessLevel', 'accessPolicy', 'ancestors', 'assetType',
                                 'iamPolicy', 'name', 'orgPolicy', 'relatedAssets',
                                 'relatedResources', 'resource', 'servicePerimeter',
                                 'updateTime'],
            },
        ],
        'identifiers': [],
    },
]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _build_disc_entry(op: Dict) -> str:
    """Render a single discovery entry as YAML text block."""
    lines = []
    did = op['discovery_id']
    ind = op.get('independent', True)
    for_each = op.get('for_each', '')
    params = op.get('params', {})
    fields = sorted(op.get('fields', []))

    if not ind:
        lines.append('  # ════ DEPENDENT (enrich) operations ════')
        lines.append(f'  # ── {did} [dependent] ──')
    else:
        lines.append('  # ════ INDEPENDENT (root) operations ════')
        lines.append(f'  # ── {did} ──')

    lines.append(f'  - discovery_id: {did}')
    if for_each:
        lines.append(f'    for_each: {for_each}')
    lines.append('    calls:')
    lines.append(f"      - action: {op['action']}")
    if params:
        lines.append('        params:')
        for pk, pv in params.items():
            lines.append(f"          {pk}: '{pv}'")
    lines.append("        save_as: response")
    lines.append("        on_error: continue")
    lines.append('    emit:')
    lines.append('      as: item')
    lines.append("      items_for: '{{ response.items }}'")
    if fields:
        lines.append('      item:')
        for f in fields:
            lines.append(f"        {f}: '{{{{ item.{f} }}}}'")
    return '\n'.join(lines)


def add_op_to_existing(service_dir: str, op: Dict) -> bool:
    """
    Append a new discovery op to an existing final_discovery_v1.yaml.
    Returns True if modified.
    """
    yaml_path = GEN_DIR / service_dir / 'final_discovery_v1.yaml'
    if not yaml_path.exists():
        print(f'  WARN: {yaml_path} does not exist — skipping')
        return False

    data = _load_yaml(yaml_path)
    existing_ids = {d.get('discovery_id') for d in data.get('discovery', [])}
    did = op['discovery_id']

    if did in existing_ids:
        print(f'  SKIP {did} — already in {service_dir}')
        return False

    entry_text = _build_disc_entry(op)
    if DRY_RUN:
        print(f'  [DRY] Would add {did} → {service_dir}/final_discovery_v1.yaml')
        return True

    # Append the new entry text to the yaml file
    original = yaml_path.read_text()
    if original.endswith('\n\n'):
        new_text = original + entry_text + '\n\n'
    elif original.endswith('\n'):
        new_text = original + '\n' + entry_text + '\n\n'
    else:
        new_text = original + '\n\n' + entry_text + '\n\n'

    yaml_path.write_text(new_text)
    print(f'  [+] Added {did} → {service_dir}/final_discovery_v1.yaml')
    return True


def create_new_yaml(spec: Dict) -> bool:
    """Create a brand-new final_discovery_v1.yaml for a service."""
    service_dir = spec['service_dir']
    svc_path = GEN_DIR / service_dir
    svc_path.mkdir(parents=True, exist_ok=True)
    yaml_path = svc_path / 'final_discovery_v1.yaml'

    if yaml_path.exists():
        print(f'  EXISTS: {service_dir}/final_discovery_v1.yaml — checking ops')
        # Just add missing ops
        for op in spec['ops']:
            add_op_to_existing(service_dir, op)
        return True

    if DRY_RUN:
        n = len(spec['ops'])
        print(f'  [DRY] Would create {service_dir}/final_discovery_v1.yaml ({n} ops)')
        return True

    service  = spec['service']
    provider = spec['provider']
    version  = spec['version']
    ops_text = '\n'.join(_build_disc_entry(o) for o in spec['ops'])

    rii_lines = []
    for r in spec.get('identifiers', []):
        rii_lines.append(f"  - resource_type: {r['resource_type']}")
        rii_lines.append(f"    identifier_op: {r['identifier_op']}")
        rii_lines.append(f"    identifier_field: {r['identifier_field']}")
        rii_lines.append(f"    item_var_path: {r['item_var_path']}")
        rii_lines.append(f"    identifier_template: '{r['identifier_template']}'")
    rii_block = '\n'.join(rii_lines) if rii_lines else '  []'

    content = f"""\
# ============================================================
# Discovery YAML — {service_dir} (final_discovery v1)
# Generated: {NOW}
# Check rules: auto | ops in scope: {len(spec['ops'])}
# ============================================================
version: '{version}'
provider: {provider}
service: {service_dir}

services:
  client: {service}
  module: "googleapiclient.discovery.build('{service}', '{version}')"

# Resource identifiers — used by inventory engine for asset dedup/linking
inventory_resource_identifiers:
{rii_block}

checks: []

discovery:

{ops_text}
"""
    yaml_path.write_text(content)
    print(f'  [+] Created {service_dir}/final_discovery_v1.yaml ({len(spec["ops"])} ops)')
    return True


# ─── Also build vertex_ai yaml from aiplatform yaml ──────────────────────────

def create_vertex_ai_yaml() -> bool:
    """
    Create vertex_ai/final_discovery_v1.yaml as a copy of aiplatform yaml
    plus the models.versions.list op.
    """
    service_dir = 'vertex_ai'
    svc_path = GEN_DIR / service_dir
    src_path  = GEN_DIR / 'aiplatform' / 'final_discovery_v1.yaml'

    if not src_path.exists():
        print('  WARN: aiplatform/final_discovery_v1.yaml not found')
        return False

    dst_path = svc_path / 'final_discovery_v1.yaml'

    if dst_path.exists():
        print('  EXISTS: vertex_ai/final_discovery_v1.yaml — checking models.versions.list')
        vertex_data = _load_yaml(dst_path)
        existing = {d.get('discovery_id') for d in vertex_data.get('discovery', [])}
        if 'gcp.aiplatform.projects.locations.models.versions.list' in existing:
            print('  SKIP models.versions.list — already present')
            return False
        # Add it
        mv_op = next(o for o in EXISTING_YAML_OPS
                     if o['discovery_id'] == 'gcp.aiplatform.projects.locations.models.versions.list')
        return add_op_to_existing(service_dir, mv_op)

    if DRY_RUN:
        print(f'  [DRY] Would create vertex_ai/final_discovery_v1.yaml from aiplatform yaml')
        return True

    svc_path.mkdir(parents=True, exist_ok=True)

    # Copy aiplatform yaml and patch the header/service name
    content = src_path.read_text()
    content = content.replace(
        '# Discovery YAML — aiplatform (final_discovery v1)',
        '# Discovery YAML — vertex_ai (final_discovery v1)',
    ).replace(
        'service: aiplatform',
        'service: vertex_ai',
    )
    dst_path.write_text(content)
    print(f'  [+] Created vertex_ai/final_discovery_v1.yaml from aiplatform yaml')

    # Now add models.versions.list op
    mv_op = next(o for o in EXISTING_YAML_OPS
                 if o['discovery_id'] == 'gcp.aiplatform.projects.locations.models.versions.list')
    add_op_to_existing(service_dir, mv_op)
    return True


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

if DRY_RUN:
    print('*** DRY RUN — pass --apply to write files ***\n')

print('═' * 60)
print('Step 1 — Add ops to existing final_discovery yamls')
print('═' * 60)

for op in EXISTING_YAML_OPS:
    add_op_to_existing(op['service_dir'], op)

print()
print('═' * 60)
print('Step 2 — Create new service final_discovery yamls')
print('═' * 60)

for spec in NEW_SERVICE_YAMLS:
    create_new_yaml(spec)

print()
print('═' * 60)
print('Step 3 — Create vertex_ai/final_discovery_v1.yaml')
print('═' * 60)
create_vertex_ai_yaml()

print()
if DRY_RUN:
    print('*** DRY RUN complete — run with --apply to write ***')
else:
    print('Done.')
    print()
    print('Next steps:')
    print('  1. python enrich_final_discovery_from_checks.py --apply')
    print('  2. python validate_check_vars_vs_discovery.py')
    print('  3. python sync_gcp_to_db.py --dry-run')
