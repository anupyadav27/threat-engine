#!/usr/bin/env python3
"""
generate_gcp_final_discovery.py
================================
For every GCP service that has check rules, generates
  catalog/discovery_generator/gcp/<svc>/final_discovery_v1.yaml

Approach
--------
  1. Master CSV (gcp_master_field_catalog.csv) is the ONLY field source.
  2. Check rule for_each ops define the SCOPE — only ops referenced by
     check rules (and their full dependency chains) are included.
  3. Step-2 provides param metadata (source: always_available vs from_list_op).
  4. Step-3 provides chain resolution (which parent field fills which param).
  5. Step-5 provides resource identifier templates → written to
     inventory_resource_identifiers block in the YAML.
  6. Identifier fields (is_id=Yes in CSV) are emitted alongside all other fields.

DRY-RUN by default — pass --apply to write files.
"""

import argparse
import csv
import json
import re
import textwrap
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

ROOT      = Path('/Users/apple/Desktop/threat-engine')
CHECK_DIR = ROOT / 'catalog/rule/gcp_rule_check'
GEN_DIR   = ROOT / 'catalog/discovery_generator/gcp'
CSV_PATH  = GEN_DIR / 'gcp_master_field_catalog.csv'

# Check-rule service name → discovery-generator directory name
SERVICE_ALIASES: Dict[str, str] = {
    'audit':                   'logging',
    'bigtable':                'bigtableadmin',
    'billing':                 'billingbudgets',
    'cloudrun':                'run',
    'data':                    'datacatalog',
    'endpoints':               'servicemanagement',
    'filestore':               'file',
    'function':                'cloudfunctions',
    'functions':               'cloudfunctions',
    'gke':                     'container',
    'kms':                     'cloudkms',
    'lb':                      'compute',
    'resourcemanager':         'cloudresourcemanager',
    'scc':                     'securitycenter',
    'security_command_center': 'securitycenter',
    'sql':                     'sqladmin',
    'vpc':                     'compute',
    'vpc_flow':                'compute',
}

# always_available param name → anchor template value
ANCHOR_PARAMS: Dict[str, str] = {
    'project':     '{{ project_id }}',
    'projectId':   '{{ project_id }}',
    'project_id':  '{{ project_id }}',
    'zone':        '{{ zone }}',
    'region':      '{{ region }}',
    'location':    '{{ location }}',
    'org_id':      '{{ org_id }}',
    'folder_id':   '{{ folder_id }}',
    'parent':      '{{ project_id }}',   # common fallback
}


# ══════════════════════════════════════════════════════════════════════════════
# 1.  Load CSV
# ══════════════════════════════════════════════════════════════════════════════

def load_csv(path: Path) -> Dict:
    """Return several indexes built from the master field CSV."""
    # op_fields[svc][op] = list of field-row dicts
    op_fields: Dict[str, Dict[str, List[dict]]] = defaultdict(lambda: defaultdict(list))
    # op_meta[svc][op]   = {is_independent, root_op, chain_ops, python_call, ...}
    op_meta:   Dict[str, Dict[str, dict]]       = defaultdict(dict)

    with open(path, newline='', encoding='utf-8') as fh:
        for row in csv.DictReader(fh):
            svc = row['service']
            op  = row['producing_op']
            op_fields[svc][op].append(row)
            if op not in op_meta[svc]:
                op_meta[svc][op] = {
                    'is_independent': row['is_independent'] == 'Yes',
                    'root_op':        row['root_op'],
                    'chain_ops':      row['chain_ops'],
                    'chain_length':   int(row['chain_length'] or 1),
                    'python_call':    row['python_call'],
                    'http_path':      row['http_path'],
                }
    return {'op_fields': op_fields, 'op_meta': op_meta}


# ══════════════════════════════════════════════════════════════════════════════
# 2.  Parse check rules
# ══════════════════════════════════════════════════════════════════════════════

def _load_yaml_simple(path: Path) -> dict:
    """Load YAML without full PyYAML (avoid dependency on ruamel)."""
    import yaml
    return yaml.safe_load(path.read_text(encoding='utf-8')) or {}


def get_check_for_each_ops(svc: str) -> Tuple[Set[str], int]:
    """Return (set_of_for_each_op_ids, total_rule_count) for a service."""
    checks_file = CHECK_DIR / svc / f'{svc}.checks.yaml'
    if not checks_file.exists():
        return set(), 0

    data   = _load_yaml_simple(checks_file)
    checks = data.get('checks', [])
    ops    = set()
    for rule in checks:
        fe = rule.get('for_each', '')
        if fe:
            ops.add(fe)
    return ops, len(checks)


# ══════════════════════════════════════════════════════════════════════════════
# 3.  Expand dependency chains
# ══════════════════════════════════════════════════════════════════════════════

def expand_chains(for_each_ops: Set[str],
                  op_meta: Dict[str, dict]) -> Tuple[List[str], Dict[str, str]]:
    """
    Given a set of for_each op IDs, return:
      - all_ops: ALL ops in their dependency chains, topological order (roots first)
      - parent_of: {op → immediate parent op in chain} (root ops have no entry)

    parent_of is built from the chains encountered during expansion and is more
    reliable than each op's own chain_ops entry (which can be self-referential
    for dead-end dependents).
    """
    all_ops: List[str] = []
    seen:     Set[str]  = set()
    parent_of: Dict[str, str] = {}   # op → its parent op in chain

    for op in sorted(for_each_ops):
        meta = op_meta.get(op)
        if not meta:
            continue
        chain_str = meta['chain_ops']   # "root -> dep1 -> dep2"
        parts = [p.strip() for p in chain_str.split(' -> ')]
        for i, p in enumerate(parts):
            if p not in seen:
                seen.add(p)
                all_ops.append(p)
            # Record parent (first occurrence wins)
            if i > 0 and p not in parent_of:
                parent_of[p] = parts[i - 1]

    # Sort so independent ops (no parent, or explicitly is_independent) come first
    def sort_key(o: str):
        is_root = (o not in parent_of) or (op_meta.get(o, {}).get('is_independent', False))
        return (0 if is_root else 1, o)

    return sorted(all_ops, key=sort_key), parent_of


# ══════════════════════════════════════════════════════════════════════════════
# 4.  Load step-2 params for an op
# ══════════════════════════════════════════════════════════════════════════════

def load_step2(svc_dir: Path) -> Dict[str, dict]:
    """Return {op_id: {required: [...], output: {...}}} from step2."""
    p = svc_dir / 'step2_read_operation_registry.json'
    if not p.exists():
        return {}
    d = json.loads(p.read_text())
    return d.get('operations', {})


def load_step3(svc_dir: Path) -> Dict[str, dict]:
    """Return {op_id: chain_entry} from step3."""
    p = svc_dir / 'step3_read_operation_dependency_chain_independent.json'
    if not p.exists():
        return {}
    d = json.loads(p.read_text())
    return d.get('chains', {})


def load_step5(svc_dir: Path, svc_name: str) -> Dict[str, dict]:
    """Return resource-level identifier info from step5."""
    p = svc_dir / 'step5_resource_catalog_inventory_enrich.json'
    if not p.exists():
        return {}
    d = json.loads(p.read_text())
    svcs = d.get('services', {})
    svc_data = svcs.get(svc_name, {})
    return svc_data.get('resources', {})


def build_params_for_op(op: str,
                        step2_ops: Dict[str, dict],
                        step3_chains: Dict[str, dict],
                        op_meta: Dict[str, dict]) -> Dict[str, str]:
    """
    Build the params dict for a YAML `calls` block.

    Strategy
    ---------
    1. If op is independent (root) → all params are always_available anchors.
    2. If op is dependent → use step3 execution_steps param_sources for the
       last step (the target op itself) to find 'from parent item' params.
    """
    meta = op_meta.get(op, {})
    is_independent = meta.get('is_independent', True)

    # Try step3 for param_sources first (most authoritative for dependents)
    chain_entry = step3_chains.get(op, {})
    exec_steps  = chain_entry.get('execution_steps', [])

    # Find this op's step entry (last step = the op itself)
    this_step = None
    for step in exec_steps:
        if step.get('op') == op:
            this_step = step
            break

    params: Dict[str, str] = {}

    if this_step and not is_independent:
        param_sources = this_step.get('param_sources', {})
        for param, source in param_sources.items():
            if source == 'always_available':
                params[param] = ANCHOR_PARAMS.get(param, f'{{{{ {param} }}}}')
            elif isinstance(source, dict):
                field = source.get('field', 'name')
                params[param] = f'{{{{ item.{field} }}}}'
            else:
                # 'unresolved' or other → use after_segment from step2 as hint
                params[param] = f'{{{{ item.{param} }}}}'
    else:
        # Fall back to step2 slots
        step2_entry = step2_ops.get(op, {})
        required = step2_entry.get('inputs', {}).get('required', []) or \
                   step2_entry.get('required_params', {})

        if isinstance(required, list):
            for req in required:
                param = req.get('param', '')
                slots = req.get('slots', [])
                if not slots:
                    params[param] = ANCHOR_PARAMS.get(param, f'{{{{ {param} }}}}')
                    continue
                slot = slots[0]
                if slot.get('source') == 'always_available':
                    params[param] = ANCHOR_PARAMS.get(param, f'{{{{ {param} }}}}')
                else:
                    after_seg = slot.get('after_segment', param)
                    if after_seg:
                        params[param] = f'{{{{ item.{after_seg} }}}}'
                    else:
                        params[param] = f'{{{{ item.{param} }}}}'
        elif isinstance(required, dict):
            for param in required:
                params[param] = ANCHOR_PARAMS.get(param, f'{{{{ {param} }}}}')

    return params


# ══════════════════════════════════════════════════════════════════════════════
# 5.  Build emit block from CSV fields
# ══════════════════════════════════════════════════════════════════════════════

def get_items_for(op: str,
                  op_rows: List[dict],
                  step3_chains: Dict[str, dict]) -> Optional[str]:
    """
    Derive items_for path for a list/read_list op.

    Priority
    --------
    1. aggregatedList ops → always None (zone-keyed nested dict, not a flat list)
    2. step3 execution_steps[0].output_list_field (most authoritative)
    3. Most-common non-trivial array prefix from CSV field_paths
    4. op_kind is list/read_list and no better guess → default 'items'
    """
    # 1. aggregatedList → no items_for (response.items is zone-keyed dict, not a list)
    if op.lower().endswith('aggregatedlist'):
        return None

    # Trivial / noise prefixes that are NOT the items list
    SKIP_PREFIXES = {
        'warnings', 'warning', 'unreachables', 'id', 'kind',
        'etag', 'selfLink', 'nextPageToken',
    }

    # 2. Try step3 output_list_field
    chain_entry = step3_chains.get(op, {})
    for step in chain_entry.get('execution_steps', []):
        if step.get('op') == op:
            olf = step.get('output_list_field')
            if olf and olf not in SKIP_PREFIXES:
                return f'{{{{ response.{olf} }}}}'
            break

    # 3. CSV array-prefix voting (skip trivial prefixes)
    prefixes: Dict[str, int] = defaultdict(int)
    for row in op_rows:
        fp = row.get('field_path', '')
        m  = re.match(r'^([a-zA-Z][a-zA-Z0-9_]*)\[\]\.', fp)
        if m and m.group(1) not in SKIP_PREFIXES:
            prefixes[m.group(1)] += 1

    if prefixes:
        top = max(prefixes, key=lambda k: prefixes[k])
        return f'{{{{ response.{top} }}}}'

    # 4. op_kind list → default to items
    if op_rows:
        op_kind = op_rows[0].get('op_kind', '')
        if op_kind in ('read_list', 'list'):
            return '{{ response.items }}'

    return None


def build_emit_item(op: str,
                    op_rows: List[dict],
                    has_items_for: bool,
                    is_dependent: bool) -> Dict[str, str]:
    """
    Build emit.item dict from CSV field rows for one op.

    Independent with items_for → template '{{ item.FIELD }}'
    Dependent (get op)          → template '{{ response.FIELD }}'
    Independent without items_for → template '{{ response.FIELD }}'

    For aggregatedList ops the item block is intentionally empty — the response
    items_for is not set and the emitted block is left blank (the whole response
    is the data structure).
    """
    # aggregatedList ops: no item block (zone-keyed dict, handled by scanner)
    if op.lower().endswith('aggregatedlist'):
        return {}

    # Items-for prefix to strip from field_path
    items_for_prefix_re = re.compile(r'^[a-zA-Z][a-zA-Z0-9_]*\[\]\.')

    emit: Dict[str, str] = {}
    for row in op_rows:
        fp   = row.get('field_path', '')
        # Strip items_for array-prefix if list op (items[].name → name)
        if has_items_for:
            fp = items_for_prefix_re.sub('', fp)
        # Top-level key only (disks[].type → disks)
        top_key = re.split(r'[\.\[]', fp)[0] if fp else ''
        if not top_key or top_key in emit:
            continue
        if not is_dependent and has_items_for:
            emit[top_key] = f'{{{{ item.{top_key} }}}}'
        else:
            emit[top_key] = f'{{{{ response.{top_key} }}}}'

    return emit


# ══════════════════════════════════════════════════════════════════════════════
# 6.  Build identifier rows for inventory_resource_identifiers block
# ══════════════════════════════════════════════════════════════════════════════

def build_identifier_rows(
        svc_dir: Path,
        gen_svc: str,
        op_fields: Dict[str, List[dict]],
) -> List[dict]:
    """
    Return identifier rows **scoped to the ops present in check rules**.

    Sources (both filtered to scoped_ops):
      1. step5 identifier.part_sources  — resource_type + identifier_template
      2. CSV is_id=Yes fields            — fallback when step5 has no entry

    Only ops in op_fields (the check-rule scope) produce identifier rows.
    Step5 entries for resource types whose producer op is NOT in scope are
    excluded — those resources are not evaluated by any check rule.
    """
    scoped_ops: Set[str] = set(op_fields.keys())
    rows: List[dict] = []

    # ── 1. step5 identifier templates (filtered to scoped ops) ────────────────
    step5_resources = load_step5(svc_dir, gen_svc)
    for res_type, res_data in step5_resources.items():
        ident      = res_data.get('identifier', {})
        full_ident = ident.get('full_identifier', {})
        template   = full_ident.get('template', '')
        part_sources = ident.get('part_sources', {})
        for part, src in part_sources.items():
            if not isinstance(src, dict) or not src.get('op'):
                continue
            producer_op = src['op']
            # Only include if this op is in check-rule scope
            if producer_op not in scoped_ops:
                continue
            fp       = src.get('field_path', part)
            item_var = 'item.' + re.sub(r'^items\[\]\.', '', fp)
            rows.append({
                'resource_type':       res_type,
                'identifier_op':       producer_op,
                'identifier_field':    fp,
                'item_var_path':       item_var,
                'identifier_template': template,
            })

    # ── 2. CSV is_id=Yes fields (already scoped to op_fields) ─────────────────
    for op, op_rows in op_fields.items():
        for row in op_rows:
            if row.get('is_id', 'No') != 'Yes':
                continue
            fp       = row['field_path']
            item_var = row['item_var_path']
            rows.append({
                'resource_type':       '',   # not derivable from CSV alone
                'identifier_op':       op,
                'identifier_field':    fp,
                'item_var_path':       item_var,
                'identifier_template': '',
            })

    # ── 3. Fallback: any scoped op not yet covered ────────────────────────────
    # For ops with no identifier from step5 or CSV is_id, derive one from common
    # identity fields (selfLink > name > id) present in the op's CSV fields.
    FALLBACK_FIELDS = ['selfLink', 'name', 'id']
    covered_ops = {r['identifier_op'] for r in rows}
    for op, op_rows in op_fields.items():
        if op in covered_ops:
            continue
        # Collect field names produced by this op
        # Strip items[]. prefix and take top-level key
        produced_tops: Set[str] = set()
        for row in op_rows:
            fp = re.sub(r'^[a-zA-Z][a-zA-Z0-9_]*\[\]\.', '', row.get('field_path', ''))
            top = re.split(r'[\.\[]', fp)[0]
            if top:
                produced_tops.add(top)
        # Pick best fallback field
        chosen: Optional[str] = None
        for candidate in FALLBACK_FIELDS:
            if candidate in produced_tops:
                chosen = candidate
                break
        if chosen:
            # item_var_path: strip items[] prefix if present
            item_var = f'item.{chosen}'
            rows.append({
                'resource_type':       '',
                'identifier_op':       op,
                'identifier_field':    chosen,
                'item_var_path':       item_var,
                'identifier_template': '',
            })

    # ── Deduplicate by (op, field_path) ───────────────────────────────────────
    seen:  Set[Tuple[str, str]] = set()
    dedup: List[dict]           = []
    for r in rows:
        key = (r['identifier_op'], r['identifier_field'])
        if key not in seen:
            seen.add(key)
            dedup.append(r)

    return dedup


# ══════════════════════════════════════════════════════════════════════════════
# 7.  YAML rendering helpers
# ══════════════════════════════════════════════════════════════════════════════

def _quote(val: Any) -> str:
    """Render a scalar YAML value with appropriate quoting."""
    s = str(val)
    if s.startswith('{') or ':' in s or "'" in s:
        return f"'{s}'"
    return s


def render_discovery_yaml(
        svc: str,
        gen_svc: str,
        n_rules: int,
        ops_ordered: List[str],
        parent_of: Dict[str, str],
        op_fields: Dict[str, List[dict]],
        op_meta: Dict[str, dict],
        step2_ops: Dict[str, dict],
        step3_chains: Dict[str, dict],
        identifier_rows: List[dict],
) -> str:
    """Build the complete final_discovery_v1.yaml string."""
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    n_ops = len(ops_ordered)
    n_ind = sum(1 for o in ops_ordered if op_meta.get(o, {}).get('is_independent'))

    lines = [
        f'# ============================================================',
        f'# Discovery YAML — {svc} (final_discovery v1)',
        f'# Generated: {now}',
        f'# Source: gcp_master_field_catalog.csv',
        f'# Check rules: {n_rules} | ops in scope: {n_ops} ({n_ind} independent, {n_ops-n_ind} dependent)',
        f'# ============================================================',
        f"version: '1.0'",
        f'provider: gcp',
        f'service: {svc}',
        '',
        f'services:',
        f'  client: {gen_svc}',
        f"  module: \"googleapiclient.discovery.build('{gen_svc}', 'v1')\"",
        '',
        '# Anchors: service-level parameters provided by caller',
        'anchors:',
        '  project_id: null',
        '  org_id: null',
        '  folder_id: null',
        '  location: null',
        '  zone: null',
        '  region: null',
        '',
    ]

    # ── inventory_resource_identifiers block ─────────────────────────────────
    if identifier_rows:
        lines.append('# Resource identifiers — used by inventory engine for asset dedup/linking')
        lines.append('inventory_resource_identifiers:')
        for r in identifier_rows:
            lines.append(f"  - resource_type: {r['resource_type'] or 'unknown'}")
            lines.append(f"    identifier_op: {r['identifier_op']}")
            lines.append(f"    identifier_field: {r['identifier_field']}")
            lines.append(f"    item_var_path: {r['item_var_path']}")
            if r['identifier_template']:
                lines.append(f"    identifier_template: '{r['identifier_template']}'")
        lines.append('')

    lines.append('checks: []')
    lines.append('')
    lines.append('discovery:')
    lines.append('')

    # ── Independent ops first ─────────────────────────────────────────────────
    # An op is a root if it has no parent in our expansion chains.
    ind_ops = [o for o in ops_ordered if o not in parent_of]
    dep_ops = [o for o in ops_ordered if o in parent_of]

    if ind_ops:
        lines.append('  # ════ INDEPENDENT (root) operations ════')

    for op in ind_ops:
        op_rows = op_fields.get(op, [])
        meta    = op_meta.get(op, {})
        py_call = meta.get('python_call', '')

        params     = build_params_for_op(op, step2_ops, step3_chains, op_meta)
        items_for  = get_items_for(op, op_rows, step3_chains)
        emit_item  = build_emit_item(op, op_rows, items_for is not None, is_dependent=False)

        # Derive action from op id: gcp.{svc}.resource.method → resource.method
        parts  = op.split('.')
        action = '.'.join(parts[2:]) if len(parts) > 2 else op

        lines.append(f'  # ── {op} ──')
        if py_call:
            lines.append(f'  # python: {py_call}')
        lines.append(f'  - discovery_id: {op}')

        lines.append('    calls:')
        lines.append(f'      - action: {action}')
        if params:
            lines.append('        params:')
            for pk, pv in sorted(params.items()):
                lines.append(f"          {pk}: '{pv}'")
        else:
            lines.append('        params: {}')
        lines.append('        save_as: response')
        lines.append('        on_error: continue')

        lines.append('    emit:')
        lines.append('      as: item')
        if items_for:
            lines.append(f"      items_for: '{items_for}'")
        if emit_item:
            lines.append('      item:')
            for fk, fv in sorted(emit_item.items()):
                lines.append(f"        {fk}: '{fv}'")
        lines.append('')

    # ── Dependent ops ─────────────────────────────────────────────────────────
    if dep_ops:
        lines.append('  # ════ DEPENDENT (enrich) operations ════')

    for op in dep_ops:
        op_rows   = op_fields.get(op, [])
        meta      = op_meta.get(op, {})
        py_call   = meta.get('python_call', '')

        params    = build_params_for_op(op, step2_ops, step3_chains, op_meta)
        emit_item = build_emit_item(op, op_rows, has_items_for=False, is_dependent=True)

        parts  = op.split('.')
        action = '.'.join(parts[2:]) if len(parts) > 2 else op
        # Use parent_of from chain expansion (more reliable than op's own chain_ops)
        parent_op = parent_of.get(op, meta.get('root_op', op))

        lines.append(f'  # ── {op} [dependent] ──')
        if py_call:
            lines.append(f'  # python: {py_call}')
        lines.append(f'  - discovery_id: {op}')
        lines.append(f'    for_each: {parent_op}')

        lines.append('    calls:')
        lines.append(f'      - action: {action}')
        if params:
            lines.append('        params:')
            for pk, pv in sorted(params.items()):
                lines.append(f"          {pk}: '{pv}'")
        else:
            lines.append('        params: {}')
        lines.append('        save_as: response')
        lines.append('        on_error: continue')

        lines.append('    emit:')
        lines.append('      as: item')
        if emit_item:
            lines.append('      item:')
            for fk, fv in sorted(emit_item.items()):
                lines.append(f"        {fk}: '{fv}'")
        lines.append('')

    return '\n'.join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

parser = argparse.ArgumentParser()
parser.add_argument('--apply',   action='store_true', help='Write YAML files')
parser.add_argument('--service', default=None,         help='Process only this service')
args, _ = parser.parse_known_args()

print(f'Loading CSV …', end=' ', flush=True)
catalog = load_csv(CSV_PATH)
print(f'done ({sum(len(v) for v in catalog["op_meta"].values())} services loaded)')

check_services = sorted(d.name for d in CHECK_DIR.iterdir() if d.is_dir())
generated = 0
skipped   = 0

for svc in check_services:
    if args.service and svc != args.service:
        continue

    gen_svc = SERVICE_ALIASES.get(svc, svc)
    svc_dir = GEN_DIR / gen_svc

    for_each_ops, n_rules = get_check_for_each_ops(svc)
    if not for_each_ops:
        skipped += 1
        continue

    # Get op catalog for this service (from CSV)
    svc_op_meta   = catalog['op_meta'].get(svc) or catalog['op_meta'].get(gen_svc) or {}
    svc_op_fields = catalog['op_fields'].get(svc) or catalog['op_fields'].get(gen_svc) or {}

    if not svc_op_meta:
        print(f'  [{svc}] SKIP — no ops in CSV (gen_svc={gen_svc})')
        skipped += 1
        continue

    # Expand chains
    ops_ordered, parent_of = expand_chains(for_each_ops, svc_op_meta)
    if not ops_ordered:
        # for_each ops not found in CSV — include only the for_each ops themselves
        ops_ordered = sorted(for_each_ops)
        parent_of   = {}

    # Filter op_fields to ops in scope
    scoped_op_fields = {op: svc_op_fields.get(op, []) for op in ops_ordered}

    # Load step2 / step3
    step2_ops    = load_step2(svc_dir) if svc_dir.exists() else {}
    step3_chains = load_step3(svc_dir) if svc_dir.exists() else {}

    # Identifier rows
    ident_rows = build_identifier_rows(svc_dir, gen_svc, scoped_op_fields) if svc_dir.exists() else []

    yaml_str = render_discovery_yaml(
        svc             = svc,
        gen_svc         = gen_svc,
        n_rules         = n_rules,
        ops_ordered     = ops_ordered,
        parent_of       = parent_of,
        op_fields       = scoped_op_fields,
        op_meta         = svc_op_meta,
        step2_ops       = step2_ops,
        step3_chains    = step3_chains,
        identifier_rows = ident_rows,
    )

    out_path = GEN_DIR / gen_svc / 'final_discovery_v1.yaml'
    n_ind = sum(1 for o in ops_ordered if svc_op_meta.get(o, {}).get('is_independent'))
    n_dep = len(ops_ordered) - n_ind

    print(
        f'  [{svc:30s}] → {gen_svc:30s} | '
        f'{n_rules:4d} rules | {len(for_each_ops):3d} for_each ops | '
        f'{n_ind:3d} ind + {n_dep:2d} dep = {len(ops_ordered):3d} ops | '
        f'{len(ident_rows):3d} identifiers'
    )

    if args.apply:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(yaml_str, encoding='utf-8')
        print(f'    WROTE {out_path}')

    generated += 1

print(f'\n{"═"*70}')
print(f'Services with check rules: {generated}  |  Skipped (no ops): {skipped}')
if not args.apply:
    print('(dry-run — pass --apply to write files)')
else:
    print('All files written.')
