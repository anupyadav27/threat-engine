#!/usr/bin/env python3
"""
Generate final_discovery_v1.yaml for every k8s service that has check rules.

Sources:
  - k8s_master_field_catalog.csv  → fields per op, is_id identifiers
  - k8s_*_finalized_discovery_v1.yaml per service → action, api_class, client, items_for
  - catalog/rule/k8s_rule_check/<svc>/<svc>.checks.yaml → which for_each ops to scope

Output: catalog/discovery_generator/k8s/<svc>/final_discovery_v1.yaml
"""

import argparse
import csv
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml

# ──────────────────────────────────────────────────────────────────────────────
ROOT     = Path('/Users/apple/Desktop/threat-engine')
K8S_DIR  = ROOT / 'catalog/discovery_generator/k8s'
CHECK_DIR = ROOT / 'catalog/rule/k8s_rule_check'
CSV_PATH  = K8S_DIR / 'k8s_master_field_catalog.csv'
# ──────────────────────────────────────────────────────────────────────────────


def _load_yaml(path: Path) -> dict:
    try:
        return yaml.safe_load(path.read_text()) or {}
    except Exception:
        return {}


# ══════════════════════════════════════════════════════════════════════════════
# 1.  Load k8s CSV
# ══════════════════════════════════════════════════════════════════════════════

def load_csv(path: Path) -> Dict:
    """
    Returns:
      op_meta   : {op_id → {chain_ops, is_independent, python_call, ...}}
      op_fields : {op_id → [row, ...]}  (all CSV rows for that op)
    """
    op_meta:   Dict[str, dict]       = {}
    op_fields: Dict[str, List[dict]] = {}

    with open(path, newline='', encoding='utf-8') as fh:
        for row in csv.DictReader(fh):
            op = row.get('producing_op', '').strip()
            if not op:
                continue

            op_fields.setdefault(op, []).append(row)

            if op not in op_meta:
                op_meta[op] = {
                    'chain_ops':      row.get('chain_ops', '').strip(),
                    'is_independent': row.get('is_independent', '').strip().lower() == 'yes',
                    'python_call':    row.get('python_call', '').strip(),
                    'http_path':      row.get('http_path', '').strip(),
                }

    return {'op_meta': op_meta, 'op_fields': op_fields}


# ══════════════════════════════════════════════════════════════════════════════
# 2.  Load existing k8s_*_finalized_discovery_v1.yaml per service
#     → extract action, api_class, client, items_for per discovery_id
# ══════════════════════════════════════════════════════════════════════════════

def load_finalized_yaml(svc: str) -> Dict[str, dict]:
    """
    Returns {discovery_id → {action, api_class, client, items_for, params, for_each}}
    """
    p = K8S_DIR / svc / f'k8s_{svc}_finalized_discovery_v1.yaml'
    if not p.exists():
        return {}

    data = _load_yaml(p)
    out: Dict[str, dict] = {}

    svc_block = data.get('services', {})
    api_class = svc_block.get('api_class', '')
    client    = svc_block.get('client', '')

    for entry in data.get('discovery', []):
        did = entry.get('discovery_id', '')
        if not did:
            continue

        calls     = entry.get('calls', [{}])
        call      = calls[0] if calls else {}
        action    = call.get('action', '')
        params    = call.get('params', {})
        emit      = entry.get('emit', {})
        items_for = emit.get('items_for', '{{ response.items }}')
        for_each  = entry.get('for_each', '')

        out[did] = {
            'action':    action,
            'api_class': api_class,
            'client':    client,
            'items_for': items_for,
            'params':    params,
            'for_each':  for_each,
        }

    return out


# ══════════════════════════════════════════════════════════════════════════════
# 3.  Check-rule for_each ops per service
# ══════════════════════════════════════════════════════════════════════════════

def get_check_for_each_ops(svc: str) -> Tuple[Set[str], int]:
    f = CHECK_DIR / svc / f'{svc}.checks.yaml'
    if not f.exists():
        return set(), 0
    data   = _load_yaml(f)
    checks = data.get('checks', [])
    ops    = {r['for_each'] for r in checks if r.get('for_each')}
    return ops, len(checks)


# ══════════════════════════════════════════════════════════════════════════════
# 4.  Build action from python_call (fallback when finalized yaml missing entry)
# ══════════════════════════════════════════════════════════════════════════════

# Map python_call API prefix → (client, api_class)
API_CLASS_MAP = {
    'core_v1_api':                    ('core_v1_api',                 'CoreV1Api'),
    'apps_v1_api':                    ('apps_v1_api',                 'AppsV1Api'),
    'rbac_authorization_v1_api':      ('rbac_authorization_v1_api',   'RbacAuthorizationV1Api'),
    'batch_v1_api':                   ('batch_v1_api',                'BatchV1Api'),
    'networking_v1_api':              ('networking_v1_api',           'NetworkingV1Api'),
    'storage_v1_api':                 ('storage_v1_api',              'StorageV1Api'),
    'autoscaling_v2_api':             ('autoscaling_v2_api',          'AutoscalingV2Api'),
    'certificates_v1_api':            ('certificates_v1_api',         'CertificatesV1Api'),
    'policy_v1_api':                  ('policy_v1_api',               'PolicyV1Api'),
    'admissionregistration_v1_api':   ('admissionregistration_v1_api','AdmissionregistrationV1Api'),
    'apiregistration_v1_api':         ('apiregistration_v1_api',      'ApiregistrationV1Api'),
    'events_v1_api':                  ('events_v1_api',               'EventsV1Api'),
}


def parse_python_call(python_call: str) -> Tuple[str, str, str]:
    """
    'core_v1_api.list_pod_for_all_namespaces_pod_security(**params)'
    → (client='core_v1_api', api_class='CoreV1Api', method='list_pod_for_all_namespaces_pod_security')
    """
    m = re.match(r'^(\w+)\.(\w+)\(', python_call)
    if not m:
        return '', '', ''
    prefix = m.group(1)
    method = m.group(2)
    client, api_class = API_CLASS_MAP.get(prefix, (prefix, ''))
    return client, api_class, method


def derive_action(op: str, python_call: str) -> str:
    """
    Derive the clean API action from python_call by stripping the service suffix.
    e.g. list_pod_for_all_namespaces_pod_security → list_pod_for_all_namespaces
    """
    _, _, method = parse_python_call(python_call)
    if not method:
        # fallback: last segment of op
        return op.rsplit('.', 1)[-1]
    # strip trailing _<service_segment> suffix that csv sometimes adds
    svc_part = op.split('.')[1] if op.count('.') >= 2 else ''
    if svc_part and method.endswith(f'_{svc_part}'):
        method = method[: -len(f'_{svc_part}')]
    return method


# ══════════════════════════════════════════════════════════════════════════════
# 5.  Build emit.item dict from CSV rows for an op
# ══════════════════════════════════════════════════════════════════════════════

def build_emit_item(op_rows: List[dict]) -> Dict[str, str]:
    """
    Build {field → '{{ item.FIELD }}'} for all top-level fields of an op.
    """
    item: Dict[str, str] = {}
    for row in op_rows:
        fp       = row.get('field_path', '').strip()
        item_var = row.get('item_var_path', '').strip()
        if not fp or not item_var:
            continue
        # Only top-level fields (no dots in field_path, unless it's metadata.X)
        # Actually include all fields up to depth 2
        parts = fp.split('.')
        if len(parts) <= 2:
            item[fp] = f'{{{{ {item_var} }}}}'
    return item


# ══════════════════════════════════════════════════════════════════════════════
# 6.  Build inventory_resource_identifiers
# ══════════════════════════════════════════════════════════════════════════════

def is_namespaced_op(op: str, op_rows: List[dict]) -> bool:
    """
    Determine if a k8s op returns namespaced resources.
    Uses http_path: if it contains '{namespace}', resource is namespace-scoped.
    Falls back to checking if op action name contains 'for_all_namespaces' or 'namespaced'.
    """
    http_path = ''
    for row in op_rows:
        hp = row.get('http_path', '').strip()
        if hp:
            http_path = hp
            break

    # Real REST paths (apis/rbac.../v1/namespaces/{namespace}/...) are reliable
    if '{namespace}' in http_path:
        return True
    # Paths without {namespace} and with a real API prefix → cluster-scoped
    if http_path.startswith('/apis/') or (http_path.startswith('/api/') and '{namespace}' not in http_path):
        # Check if the path pattern is a real API path (not a generic placeholder like /api/v1/rbacs)
        # Generic placeholder paths end in plural service name, not standard resource path
        path_parts = http_path.rstrip('/').split('/')
        last_part = path_parts[-1]
        # Real paths end in resource type like 'clusterroles', not generic like 'rbacs'
        if not last_part.endswith(('roles', 'bindings')) or 'namespace' in http_path:
            pass

    # Fallback: use action name heuristics
    action_part = op.rsplit('.', 1)[-1]
    if 'for_all_namespaces' in action_part or 'namespaced' in action_part:
        return True

    # Known cluster-scoped resources by op pattern
    CLUSTER_SCOPED_PATTERNS = [
        'clusterrole', 'clusterrolebinding', 'storageclass', 'persistentvolume',
        'node', 'namespace', 'apiservice', 'api_service',
    ]
    op_lower = op.lower()
    for pattern in CLUSTER_SCOPED_PATTERNS:
        if pattern in op_lower:
            return False

    return False   # default to cluster-scoped if unknown


def build_identifier_rows(scoped_ops: Set[str], op_fields: Dict[str, List[dict]]) -> List[dict]:
    """
    For each scoped op, find is_id=Yes rows from CSV.
    Fallback: use metadata.name > name > metadata.uid.
    Returns list of identifier dicts.
    """
    rows: List[dict] = []
    FALLBACKS = ['metadata.name', 'metadata.uid', 'name', 'uid']

    for op in sorted(scoped_ops):
        op_rows = op_fields.get(op, [])

        # Primary: is_id=Yes rows for this op
        id_rows = [r for r in op_rows if r.get('is_id', '').strip() == 'Yes']

        # Use http_path to determine namespace-scoped vs cluster-scoped
        namespaced = is_namespaced_op(op, op_rows)

        if id_rows:
            name_row = next((r for r in id_rows if r['field_path'] == 'metadata.name'), None)
            uid_row  = next((r for r in id_rows if r['field_path'] == 'metadata.uid'), None)

            if name_row:
                tmpl = '{namespace}/{name}' if namespaced else '{name}'
                rows.append({
                    'resource_type':        '',
                    'identifier_op':        op,
                    'identifier_field':     'metadata.name',
                    'item_var_path':        name_row['item_var_path'],
                    'identifier_template':  tmpl,
                })
            elif uid_row:
                rows.append({
                    'resource_type':        '',
                    'identifier_op':        op,
                    'identifier_field':     'metadata.uid',
                    'item_var_path':        uid_row['item_var_path'],
                    'identifier_template':  '',
                })
            else:
                r0 = id_rows[0]
                rows.append({
                    'resource_type':        '',
                    'identifier_op':        op,
                    'identifier_field':     r0['field_path'],
                    'item_var_path':        r0['item_var_path'],
                    'identifier_template':  '',
                })
        else:
            # Fallback: search produced fields
            produced = {r['field_path'] for r in op_rows}
            added = False
            for fb in FALLBACKS:
                if fb in produced:
                    item_var = next(
                        (r['item_var_path'] for r in op_rows if r['field_path'] == fb), f'item.{fb}'
                    )
                    tmpl = '{namespace}/{name}' if (namespaced and 'name' in fb) else ('{name}' if 'name' in fb else '')
                    rows.append({
                        'resource_type':        '',
                        'identifier_op':        op,
                        'identifier_field':     fb,
                        'item_var_path':        item_var,
                        'identifier_template':  tmpl,
                    })
                    added = True
                    break

            if not added:
                rows.append({
                    'resource_type':        '',
                    'identifier_op':        op,
                    'identifier_field':     'metadata.name',
                    'item_var_path':        'item.metadata.name',
                    'identifier_template':  '{name}',
                })

    return rows


# ══════════════════════════════════════════════════════════════════════════════
# 7.  Render YAML text
# ══════════════════════════════════════════════════════════════════════════════

def render_yaml(
    svc:         str,
    api_class:   str,
    client:      str,
    n_rules:     int,
    scoped_ops:  Set[str],
    ident_rows:  List[dict],
    ops_info:    List[dict],   # [{discovery_id, action, items_for, params, for_each, op_rows}]
) -> str:
    now  = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    n_id = len(ident_rows)
    n_op = len(ops_info)

    lines: List[str] = [
        '# ============================================================',
        f'# Discovery YAML — {svc} (final_discovery v1)',
        f'# Generated: {now}',
        f'# Check rules: {n_rules} | ops in scope: {n_op}',
        '# ============================================================',
        "version: '1.0'",
        'provider: k8s',
        f'service: {svc}',
        '',
        'services:',
        f'  client: {client}',
        '  module: kubernetes.client',
        f'  api_class: {api_class}',
        '',
        '# Resource identifiers — used by inventory engine for asset dedup/linking',
        'inventory_resource_identifiers:',
    ]

    for r in ident_rows:
        lines.append(f"  - resource_type: {r['resource_type']}")
        lines.append(f"    identifier_op: {r['identifier_op']}")
        lines.append(f"    identifier_field: {r['identifier_field']}")
        lines.append(f"    item_var_path: {r['item_var_path']}")
        if r.get('identifier_template'):
            lines.append(f"    identifier_template: '{r['identifier_template']}'")

    lines += ['', 'checks: []', '', 'discovery:', '']

    for info in ops_info:
        did       = info['discovery_id']
        action    = info['action']
        items_for = info['items_for']
        params    = info.get('params', {})
        for_each  = info.get('for_each', '')
        op_rows   = info.get('op_rows', [])
        is_dep    = bool(for_each)
        prefix    = '  # ════ DEPENDENT (enrich) operations ════' if is_dep else '  # ════ INDEPENDENT (root) operations ════'

        lines.append(prefix)
        if is_dep:
            lines.append(f'  # ── {did} [dependent] ──')
        else:
            lines.append(f'  # ── {did} ──')

        lines.append(f'  - discovery_id: {did}')
        if for_each:
            lines.append(f'    for_each: {for_each}')
        lines.append('    calls:')
        lines.append(f'      - action: {action}')
        if params:
            lines.append('        params:')
            for pk, pv in params.items():
                lines.append(f"          {pk}: '{pv}'")
        lines.append("        save_as: response")
        lines.append("        on_error: continue")

        lines.append('    emit:')
        lines.append('      as: item')

        if items_for and 'response.items' in items_for:
            lines.append(f"      items_for: '{{{{ response.items }}}}'")
            item_dict = build_emit_item(op_rows)
            if item_dict:
                lines.append('      item:')
                for field, tpl in sorted(item_dict.items()):
                    lines.append(f"        {field}: '{tpl}'")
        else:
            lines.append(f"      item:")
            item_dict = build_emit_item(op_rows)
            if item_dict:
                for field, tpl in sorted(item_dict.items()):
                    lines.append(f"        {field}: '{tpl}'")
            else:
                lines.append(f"        response: '{{{{ response }}}}'")

        lines.append('')

    return '\n'.join(lines) + '\n'


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

parser = argparse.ArgumentParser()
parser.add_argument('--apply',   action='store_true', help='Write YAML files')
parser.add_argument('--service', default=None,         help='Process only this service')
args, _ = parser.parse_known_args()

print('Loading CSV …', end=' ', flush=True)
catalog = load_csv(CSV_PATH)
print(f'done ({len(catalog["op_meta"])} ops loaded)')

check_services = sorted(d.name for d in CHECK_DIR.iterdir() if d.is_dir())
generated = 0
skipped   = 0

for svc in check_services:
    if args.service and svc != args.service:
        continue

    for_each_ops, n_rules = get_check_for_each_ops(svc)
    if not for_each_ops:
        skipped += 1
        continue

    # Load existing finalized yaml for action/api_class
    finalized = load_finalized_yaml(svc)

    # Build op info list — only scoped check-rule ops (all independent in k8s)
    ops_info:  List[dict] = []
    api_class = ''
    client    = ''
    missing_ops: List[str] = []

    for op in sorted(for_each_ops):
        fin = finalized.get(op)
        if fin:
            action    = fin['action']
            items_for = fin['items_for']
            params    = fin.get('params', {})
            for_each  = fin.get('for_each', '')
            if not api_class:
                api_class = fin['api_class']
                client    = fin['client']
        else:
            # Fallback: derive from CSV python_call
            meta = catalog['op_meta'].get(op)
            if meta and meta.get('python_call'):
                c, ac, method = parse_python_call(meta['python_call'])
                action = derive_action(op, meta['python_call'])
                if not api_class:
                    api_class = ac
                    client    = c
            else:
                action = op.rsplit('.', 1)[-1]
                missing_ops.append(op)
            items_for = '{{ response.items }}'
            params    = {}
            for_each  = ''

        op_rows = catalog['op_fields'].get(op, [])

        ops_info.append({
            'discovery_id': op,
            'action':       action,
            'items_for':    items_for,
            'params':       params,
            'for_each':     for_each,
            'op_rows':      op_rows,
        })

    if not ops_info:
        skipped += 1
        continue

    # Identifier rows from CSV is_id=Yes
    scoped_op_fields = {op: catalog['op_fields'].get(op, []) for op in for_each_ops}
    ident_rows = build_identifier_rows(for_each_ops, scoped_op_fields)

    # Print status
    miss_str = f' [WARN: no finalized yaml for {missing_ops}]' if missing_ops else ''
    print(
        f'  [{svc:<30s}] {n_rules:4d} rules | {len(for_each_ops):2d} ops | '
        f'{len(ident_rows):2d} identifiers | api_class={api_class}{miss_str}'
    )

    if args.apply:
        out_dir = K8S_DIR / svc
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / 'final_discovery_v1.yaml'
        yaml_text = render_yaml(
            svc=svc,
            api_class=api_class,
            client=client,
            n_rules=n_rules,
            scoped_ops=for_each_ops,
            ident_rows=ident_rows,
            ops_info=ops_info,
        )
        out_path.write_text(yaml_text)
        print(f'    WROTE {out_path}')
        generated += 1

print()
print('═' * 70)
print(f'Services with check rules: {generated + (len(check_services) - skipped - generated if not args.apply else 0)}  |  Skipped (no ops): {skipped}')
if args.apply:
    print(f'Files written: {generated}')
else:
    print('(dry-run — pass --apply to write files)')
