#!/usr/bin/env python3
"""
generate_master_write_ops.py
============================
Build aws_master_write_ops.csv (AWS only — scoped to services that have
active check rules in catalog/rule/aws_rule_check/).

One row per write operation.  Slim, action-UI focused columns only.

Column set (17):
  csp, service, op_name, op_kind,
  python_call, yaml_action,
  required_params, optional_params,
  resource_type, target_resource_id_param, iam_action,
  param_sources,            ← ParamName:read_op|...
  dependency_chain,         ← full ordered read-op chain for all params
  dependency_chain_length,  ← max hops across all sourcing read ops
  is_active, updated_at

Usage:
    python generate_master_write_ops.py          # dry-run
    python generate_master_write_ops.py --apply  # write file
"""

import csv
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ──────────────────────────────────────────────────────────────────────────────
ROOT      = Path('/Users/apple/Desktop/threat-engine')
GEN_DIR   = ROOT / 'catalog/discovery_generator'
RULE_DIR  = ROOT / 'catalog/rule'

AWS_GEN_DIR   = GEN_DIR / 'aws'
OUTPUT_CSV    = AWS_GEN_DIR / 'aws_master_write_ops.csv'
FIELD_CATALOG = AWS_GEN_DIR / 'aws_master_field_catalog.csv'
CHECK_RULE_DIR = RULE_DIR / 'aws_rule_check'

# ID-type suffix tokens used for suffix-matching params → fields.
# SPECIFIC ones (Arn, Identifier, Alias) are safe cross-service.
# GENERIC ones (Id, Name, Key) are same-service only — too noisy cross-service.
_ID_SUFFIXES_SPECIFIC = ('Arn', 'Identifier', 'Alias', 'arn', 'identifier', 'alias')
_ID_SUFFIXES_GENERIC  = ('Id', 'Name', 'Key', 'id', 'name', 'key')
_ID_SUFFIXES = _ID_SUFFIXES_SPECIFIC + _ID_SUFFIXES_GENERIC

COLUMNS = [
    'csp', 'service', 'op_name', 'op_kind',
    'python_call', 'yaml_action',
    'required_params', 'optional_params',
    'resource_type', 'target_resource_id_param', 'iam_action',
    'param_sources',
    'dependency_chain',
    'dependency_chain_length',
    'is_active', 'updated_at',
]


# ──────────────────────────────────────────────────────────────────────────────
# Step 1 — collect check-enabled services
# ──────────────────────────────────────────────────────────────────────────────

def load_check_services() -> set:
    return {d.name for d in CHECK_RULE_DIR.iterdir() if d.is_dir()}


# ──────────────────────────────────────────────────────────────────────────────
# Step 2 — build field index from aws_master_field_catalog.csv
#
# Two indexes:
#   same_svc_index : (service, field_lower) → best FieldRecord
#   global_index   : field_lower            → [FieldRecord, ...] (all services)
# ──────────────────────────────────────────────────────────────────────────────

FieldRecord = dict  # keys: service, field_path, producing_op, root_op,
                    #        chain_ops, chain_length, hop

def build_field_indexes(
) -> Tuple[Dict[Tuple[str, str], FieldRecord], Dict[str, List[FieldRecord]]]:
    same_svc: Dict[Tuple[str, str], FieldRecord] = {}
    global_idx: Dict[str, List[FieldRecord]] = defaultdict(list)

    for row in csv.DictReader(FIELD_CATALOG.open()):
        svc   = row.get('service', '').strip()
        field = row.get('field_path', '').strip()
        op    = row.get('producing_op', '').strip()
        if not (svc and field and op):
            continue

        hop = int(row.get('hop_distance', '0') or 0)
        rec: FieldRecord = {
            'service':       svc,
            'field_path':    field,
            'producing_op':  op,
            'root_op':       row.get('root_op', op).strip() or op,
            'chain_ops':     row.get('chain_ops', op).strip() or op,
            'chain_length':  int(row.get('chain_length', '1') or 1),
            'hop':           hop,
        }

        key = (svc, field.lower())
        # Keep the record with the lowest hop (prefer root-level producers)
        if key not in same_svc or hop < same_svc[key]['hop']:
            same_svc[key] = rec

        global_idx[field.lower()].append(rec)

    return same_svc, global_idx


# ──────────────────────────────────────────────────────────────────────────────
# Step 3 — param → read-op matching
# ──────────────────────────────────────────────────────────────────────────────

def _best_from_list(recs: List[FieldRecord]) -> FieldRecord:
    """Prefer lowest hop; ties broken by alphabetical producing_op."""
    return min(recs, key=lambda r: (r['hop'], r['producing_op']))


def resolve_param(
    param: str,
    service: str,
    same_svc: Dict[Tuple[str, str], FieldRecord],
    global_idx: Dict[str, List[FieldRecord]],
) -> Optional[FieldRecord]:
    """
    Find the read op that produces a value usable as `param`.

    Match order (first hit wins):
      1. Same-service, exact case-insensitive
      2. Same-service, plural→singular (strip trailing 's' / 'Ids'→'Id')
      3. Same-service, suffix match on known ID tokens
         e.g. analyzerArn → match field 'arn' in same service
      4. Cross-service, exact
      5. Cross-service, plural→singular
      6. Cross-service, suffix match on known ID tokens
    """
    p_low = param.lower()

    # ── helpers ──────────────────────────────────────────────────────────────
    def same(field_low: str) -> Optional[FieldRecord]:
        return same_svc.get((service, field_low))

    def cross(field_low: str) -> Optional[FieldRecord]:
        recs = global_idx.get(field_low, [])
        return _best_from_list(recs) if recs else None

    def singulars(p: str) -> List[str]:
        """Generate singular candidates from a plural param."""
        lp = p.lower()
        out = []
        if lp.endswith('ids'):
            out.append(lp[:-1])   # 'ids' → 'id'
            out.append(lp[:-3] + 'id')
        if lp.endswith('names'):
            out.append(lp[:-1])
            out.append(lp[:-5] + 'name')
        if lp.endswith('arns'):
            out.append(lp[:-1])
        if lp.endswith('s'):
            out.append(lp[:-1])
        return out

    def suffix_candidates(p: str, specific_only: bool = False) -> List[str]:
        """
        If param ends with a known ID token, that token itself is a candidate.
        e.g. 'analyzerArn' → 'arn', 'analyzerName' → 'name', 'instanceId' → 'id'
        specific_only=True → only Arn/Identifier/Alias (safe for cross-service)
        """
        lp = p.lower()
        pool = _ID_SUFFIXES_SPECIFIC if specific_only else _ID_SUFFIXES
        hits = []
        for suf in pool:
            sl = suf.lower()
            if lp.endswith(sl) and lp != sl:
                hits.append(sl)
        return hits

    # ── 1. same-service exact ────────────────────────────────────────────────
    rec = same(p_low)
    if rec:
        return rec

    # ── 2. same-service plural→singular ─────────────────────────────────────
    for s in singulars(param):
        rec = same(s)
        if rec:
            return rec

    # ── 3. same-service suffix (all suffixes including generic Id/Name) ───────
    for suf in suffix_candidates(param, specific_only=False):
        rec = same(suf)
        if rec:
            return rec

    # ── 4. cross-service exact ───────────────────────────────────────────────
    rec = cross(p_low)
    if rec:
        return rec

    # ── 5. cross-service plural→singular ────────────────────────────────────
    for s in singulars(param):
        rec = cross(s)
        if rec:
            return rec

    # ── 6. cross-service suffix — specific suffixes only (Arn/Identifier/Alias)
    for suf in suffix_candidates(param, specific_only=True):
        recs = global_idx.get(suf, [])
        # Still prefer same-service hits
        same_hits = [r for r in recs if r['service'] == service]
        if same_hits:
            return _best_from_list(same_hits)
        if recs:
            return _best_from_list(recs)

    return None


# ──────────────────────────────────────────────────────────────────────────────
# Step 4 — build dependency chain columns from resolved param sources
# ──────────────────────────────────────────────────────────────────────────────

def build_dependency_cols(
    required: List[str],
    service: str,
    same_svc: Dict[Tuple[str, str], FieldRecord],
    global_idx: Dict[str, List[FieldRecord]],
) -> Tuple[str, str, int]:
    """
    Returns (param_sources, dependency_chain, dependency_chain_length).

    param_sources      : 'ParamName:producing_op|...'
    dependency_chain   : ordered unique chain ops (read-op DAG), pipe-sep
                         each entry is the full chain_ops string from the
                         field catalog, which uses ' -> ' as separator.
    dependency_chain_length : max chain_length across all sourcing read ops
    """
    param_sources_parts: List[str] = []
    chain_op_sets: List[str] = []        # full chain strings, in order
    max_chain_len = 0

    seen_chains: set = set()

    for param in required:
        rec = resolve_param(param, service, same_svc, global_idx)
        if rec:
            param_sources_parts.append(f'{param}:{rec["producing_op"]}')
            chain = rec['chain_ops']
            if chain not in seen_chains:
                seen_chains.add(chain)
                chain_op_sets.append(chain)
            if rec['chain_length'] > max_chain_len:
                max_chain_len = rec['chain_length']

    # Flatten chain strings into a pipe-sep list of unique ops in order
    # chain_ops format in catalog: 'op1 -> op2 -> op3'
    flat_ops: List[str] = []
    seen_ops: set = set()
    for chain_str in chain_op_sets:
        for op in chain_str.split(' -> '):
            op = op.strip()
            if op and op not in seen_ops:
                seen_ops.add(op)
                flat_ops.append(op)

    return (
        '|'.join(param_sources_parts),
        '|'.join(flat_ops),
        max_chain_len,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Step 5 — RII map for resource_type enrichment
# ──────────────────────────────────────────────────────────────────────────────

def build_rii_map() -> Dict[str, str]:
    """service → dominant resource_type, inferred from final_discovery_v1.yaml."""
    import yaml

    svc_types: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for svc_dir in sorted(AWS_GEN_DIR.iterdir()):
        if not svc_dir.is_dir():
            continue
        yp = svc_dir / 'final_discovery_v1.yaml'
        if not yp.exists():
            continue
        try:
            data = yaml.safe_load(yp.read_text()) or {}
        except Exception:
            continue
        for rii in data.get('inventory_resource_identifiers') or []:
            res_type = (rii.get('resource_type') or '').strip()
            id_op    = (rii.get('identifier_op') or '').strip()
            if res_type and id_op:
                svc = id_op.split('.')[1] if id_op.count('.') >= 2 else ''
                if svc:
                    svc_types[svc][res_type] += 1

    # Pick the most-seen resource_type per service
    return {
        svc: max(types, key=lambda t: types[t])
        for svc, types in svc_types.items()
    }


# ──────────────────────────────────────────────────────────────────────────────
# Step 6 — infer target_resource_id_param
# ──────────────────────────────────────────────────────────────────────────────

def infer_target_param(required: List[str], optional: List[str]) -> str:
    for param_list in (required, optional):
        for p in param_list:
            if any(p.endswith(s) for s in ('Id', 'Arn', 'Name', 'Key', 'Identifier', 'Alias')):
                return p
            if any(p.lower().endswith(s) for s in ('id', 'arn', 'name', 'key')):
                return p
    return (required or optional or [''])[0]


# ──────────────────────────────────────────────────────────────────────────────
# MAIN ASSEMBLY
# ──────────────────────────────────────────────────────────────────────────────

def generate(apply: bool) -> None:
    print(f'\n{"═" * 60}')
    print('Building aws_master_write_ops.csv')
    print('═' * 60)

    # Load
    check_services = load_check_services()
    print(f'  Check-enabled services : {len(check_services)}')

    print(f'  Building field indexes from {FIELD_CATALOG.name} ...')
    same_svc_idx, global_idx = build_field_indexes()
    print(f'  Field index entries    : {len(same_svc_idx)}')

    print(f'  Building RII map ...')
    rii_map = build_rii_map()
    print(f'  RII service→type entries: {len(rii_map)}')

    now_ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    output_rows: List[dict] = []

    # Walk write registries — only check-enabled services
    total_skipped = 0
    for svc_dir in sorted(AWS_GEN_DIR.iterdir()):
        if not svc_dir.is_dir():
            continue
        registry_path = svc_dir / 'step2_write_operation_registry.json'
        if not registry_path.exists():
            continue

        try:
            registry = json.loads(registry_path.read_text())
        except Exception as exc:
            print(f'  WARN  {registry_path.name}: {exc}')
            continue

        svc_name = registry.get('service', svc_dir.name)
        if svc_name not in check_services:
            total_skipped += 1
            continue

        ops = registry.get('operations', {})
        resource_type = rii_map.get(svc_name, '')

        for op_pascal, meta in ops.items():
            if not isinstance(meta, dict):
                continue

            python_method = (meta.get('python_method') or '').strip()
            yaml_action   = (meta.get('yaml_action') or python_method).strip()
            kind          = (meta.get('kind') or 'write_other').strip()

            op_name     = f'aws.{svc_name}.{python_method}' if python_method else f'aws.{svc_name}.{op_pascal.lower()}'
            python_call = f'client.{python_method}()' if python_method else ''

            required = [str(p) for p in (meta.get('required_params') or [])]
            optional = [str(p) for p in (meta.get('optional_params') or [])]

            param_sources, dep_chain, dep_chain_len = build_dependency_cols(
                required, svc_name, same_svc_idx, global_idx
            )

            output_rows.append({
                'csp':                       'aws',
                'service':                   svc_name,
                'op_name':                   op_name,
                'op_kind':                   kind,
                'python_call':               python_call,
                'yaml_action':               yaml_action,
                'required_params':           '|'.join(required),
                'optional_params':           '|'.join(optional),
                'resource_type':             resource_type,
                'target_resource_id_param':  infer_target_param(required, optional),
                'iam_action':                f'{svc_name}:{op_pascal}',
                'param_sources':             param_sources,
                'dependency_chain':          dep_chain,
                'dependency_chain_length':   dep_chain_len,
                'is_active':                 'true',
                'updated_at':                now_ts,
            })

    # ── Stats ─────────────────────────────────────────────────────────────────
    total   = len(output_rows)
    by_kind: Dict[str, int] = {}
    for r in output_rows:
        by_kind[r['op_kind']] = by_kind.get(r['op_kind'], 0) + 1

    with_deps   = sum(1 for r in output_rows if r['dependency_chain'])
    with_no_req = sum(1 for r in output_rows if not r['required_params'])
    total_req   = sum(len(r['required_params'].split('|')) for r in output_rows if r['required_params'])
    resolved    = sum(len(r['param_sources'].split('|')) for r in output_rows if r['param_sources'])

    print(f'\n  Services included      : {len(check_services)}')
    print(f'  Services skipped       : {total_skipped}')
    print(f'  Total write ops        : {total:>6}')
    print(f'  No required params     : {with_no_req:>6}  (independent — run directly)')
    print(f'  Have dependency chain  : {with_deps:>6}')
    print(f'  Total required params  : {total_req:>6}')
    print(f'  Params resolved→read-op: {resolved:>6}  ({100*resolved//total_req if total_req else 0}%)')
    print(f'\n  by op_kind:')
    for k, v in sorted(by_kind.items()):
        print(f'    {k:<22} {v:>5}')

    if apply:
        with OUTPUT_CSV.open('w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=COLUMNS)
            writer.writeheader()
            writer.writerows(output_rows)
        print(f'\n  Wrote {total:,} rows → {OUTPUT_CSV}')
    else:
        # Print 2 sample rows (one with deps, one without)
        sample_with  = next((r for r in output_rows if r['dependency_chain']), None)
        sample_plain = next((r for r in output_rows if not r['required_params']), None)
        for label, r in [('with deps', sample_with), ('no req params', sample_plain)]:
            if r:
                print(f'\n  Sample ({label}):')
                for k, v in r.items():
                    if v and v not in ('0', 'aws', 'true'):
                        print(f'    {k:<28}: {str(v)[:80]}')
        print(f'\n  Would write {total:,} rows → {OUTPUT_CSV}')


# ──────────────────────────────────────────────────────────────────────────────

APPLY = '--apply' in sys.argv

if not APPLY:
    print('*** DRY RUN — pass --apply to write ***')

generate(APPLY)
print('\nDone.')
