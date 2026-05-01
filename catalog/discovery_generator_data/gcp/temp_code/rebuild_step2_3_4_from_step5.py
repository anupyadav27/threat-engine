#!/usr/bin/env python3
"""
Rebuild step2_read, step3_chains, step4_fields_dependency_chain
using corrected independence from step1_api_driven_registry.

Independence rule (from step1):
  - param in ALWAYS_AVAILABLE            → always_available
  - param with composite path pattern    → all slots must be always_available
  - otherwise                            → from_list_op (dependent)

step3 now uses the SAME 5-tier slot resolver as build_api_driven_registry.py
so that BFS hop distances resolve correctly even for cases like:
  sites.get (needs 'name' = 'sites/{siteId}')
  → slot siteId, after_segment='sites'
  → Tier 2 match: violatingSites.list (resource 'violatingSites' ends with 'sites')
  → hop_distance: 1  (not 999)
"""

import json
import re
from pathlib import Path
from collections import defaultdict, deque

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

ALWAYS_AVAILABLE = {
    'projectId','project','parent','location','region','zone',
    'organizationId','folderId','billingAccountId','customerId','accountId',
}

SEGMENT_TO_ALWAYS = {
    'projects':       'project',
    'locations':      'location',
    'regions':        'region',
    'zones':          'zone',
    'organizations':  'organizationId',
    'folders':        'folderId',
    'billingAccounts':'billingAccountId',
    'customers':      'customerId',
    'accounts':       'accountId',
}


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS (shared with build_api_driven_registry.py logic)
# ─────────────────────────────────────────────────────────────────────────────

def singularize(resource: str) -> str:
    if resource.endswith('ies'):  return resource[:-3]+'y'
    if resource.endswith('sses'): return resource[:-2]
    if resource.endswith('ses'):  return resource[:-2]
    if resource.endswith('s') and not resource.endswith('ss'): return resource[:-1]
    return resource


def _is_var_segment(seg: str) -> bool:
    return seg in ('[^/]+', '[^/]*', '.*', '.+', '__VAR__')


def parse_pattern(pattern: str) -> tuple[str, list[dict]]:
    if not pattern:
        return '', []
    clean = pattern.lstrip('^').rstrip('$')
    clean = re.sub(r'\[\^/\]\+', '__VAR__', clean)
    clean = re.sub(r'\[\^/\]\*', '__VAR__', clean)
    clean = re.sub(r'\.\*',      '__VAR__', clean)
    clean = re.sub(r'\.\+',      '__VAR__', clean)
    raw_parts = clean.split('/')

    template_parts = []
    slots = []
    prev_literal = None

    for part in raw_parts:
        if _is_var_segment(part):
            if prev_literal and prev_literal in SEGMENT_TO_ALWAYS:
                slot_name = SEGMENT_TO_ALWAYS[prev_literal]
                source = 'always_available'
            elif prev_literal:
                slot_name = singularize(prev_literal) + 'Id'
                source = 'from_list_op'
            else:
                slot_name = 'resourceId'
                source = 'unknown'
            template_parts.append('{' + slot_name + '}')
            slots.append({'slot': slot_name, 'source': source, 'after_segment': prev_literal or ''})
        else:
            template_parts.append(part)
            prev_literal = part

    return '/'.join(template_parts), slots


def get_list_output(op_key, op):
    """
    Return (list_field, id_field) for a read_list op.
    Supports both old format (response_fields dict) and
    new format (outputs.list_field / outputs.id_field).
    """
    # New format: outputs section
    outputs = op.get('outputs', {})
    if outputs.get('list_field') is not None:
        return outputs.get('list_field'), outputs.get('id_field')

    # Old format: response_fields dict
    rf = op.get('response_fields', {})
    for fname, finfo in rf.items():
        if finfo.get('type') == 'array' and finfo.get('id_field'):
            return fname, finfo['id_field']
    for fname, finfo in rf.items():
        if finfo.get('type') == 'array' and fname not in ('unreachable',):
            return fname, finfo.get('id_field','name')
    return None, None


def get_item_fields(op):
    """
    Return item_fields list for a read_list op.
    Supports both old format (response_fields dict) and
    new format (outputs.produces_fields paths).
    """
    # New format: extract from produces_fields paths like 'violatingSites[].reviewedSite'
    outputs = op.get('outputs', {})
    if outputs:
        list_field = outputs.get('list_field')
        pf = outputs.get('produces_fields', [])
        if list_field and pf:
            prefix = f'{list_field}[].'
            return [p['path'][len(prefix):] for p in pf
                    if p['path'].startswith(prefix)]
        return []

    # Old format: response_fields dict
    rf = op.get('response_fields', {})
    for fname, finfo in rf.items():
        if finfo.get('type') == 'array' and finfo.get('id_field'):
            return finfo.get('item_fields', [])
    for fname, finfo in rf.items():
        if finfo.get('type') == 'array' and fname not in ('unreachable',):
            return finfo.get('item_fields', [])
    return []


# ─────────────────────────────────────────────────────────────────────────────
# TIERED SLOT RESOLVER (same logic as build_api_driven_registry.py)
# ─────────────────────────────────────────────────────────────────────────────

def build_list_ops_info(ops: dict) -> dict:
    """Pre-compute { op_key: {resource, list_field, id_field, item_fields} }."""
    result = {}
    for lk, lop in ops.items():
        if lop.get('kind') != 'read_list':
            continue
        parts = lk.split('.')
        resource = parts[-2] if len(parts) >= 2 else ''
        list_field, id_field = get_list_output(lk, lop)
        item_fields = get_item_fields(lop)
        result[lk] = {
            'resource':   resource,
            'list_field': list_field,
            'id_field':   id_field,
            'item_fields': item_fields,
        }
    return result


def resolve_list_op_for_slot(after_segment, slot_name, list_ops_info):
    """
    5-tier resolver → (op_key, op_info, tier).
    Tier 5 = external_input (no match).
    """
    if not after_segment and not slot_name:
        return None, None, 5

    after_lower   = after_segment.lower() if after_segment else ''
    slot_base     = slot_name.replace('Id', '').lower() if slot_name else ''
    after_singular = singularize(after_lower)

    # Tier 1: exact resource match
    for lk, li in list_ops_info.items():
        if li['resource'] == after_segment:
            return lk, li, 1

    # Tier 2: suffix / plural / camelCase suffix match
    for lk, li in list_ops_info.items():
        res_lower    = li['resource'].lower()
        res_singular = singularize(res_lower)
        if (res_lower.endswith(after_lower) and after_lower
                or after_lower.endswith(res_lower) and res_lower
                or res_singular == after_singular and after_singular):
            return lk, li, 2

    # Tier 3: slot_name base appears in item_fields
    for lk, li in list_ops_info.items():
        for f in li.get('item_fields', []):
            if slot_base and slot_base in f.lower():
                return lk, li, 3

    # Tier 4: id_field base matches slot base
    for lk, li in list_ops_info.items():
        id_base = (li.get('id_field') or '').lower()
        if slot_base and (id_base.endswith(slot_base) or slot_base.endswith(id_base)):
            return lk, li, 4
        if slot_base and singularize(id_base) == singularize(slot_base):
            return lk, li, 4

    return None, None, 5


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — re-split read/write using corrected independence from step1
# ─────────────────────────────────────────────────────────────────────────────

READ_KINDS  = {'read_list','read_get','other'}
WRITE_KINDS = {'write_create','write_update','write_delete','write_apply'}

def rebuild_step2(svc_dir: Path) -> bool:
    s1 = svc_dir / 'step1_api_driven_registry.json'
    if not s1.exists():
        return False

    s1d  = json.load(open(s1))
    ops  = s1d.get('operations', {})

    read_ops  = {k:v for k,v in ops.items() if v.get('kind','') in READ_KINDS}
    write_ops = {k:v for k,v in ops.items() if v.get('kind','') in WRITE_KINDS}

    base = {k:v for k,v in s1d.items() if k not in ('operations','total_operations','stats')}

    r2 = {**base, 'total_operations': len(read_ops),  'operations': read_ops}
    w2 = {**base, 'total_operations': len(write_ops), 'operations': write_ops}

    json.dump(r2, open(svc_dir/'step2_read_operation_registry.json','w'),  indent=2)
    json.dump(w2, open(svc_dir/'step2_write_operation_registry.json','w'), indent=2)
    return True


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — rebuild dependency chains with TIERED resolver
# ─────────────────────────────────────────────────────────────────────────────

def get_required_params_dict(op: dict) -> dict:
    """
    Get required params as a dict {pname: pinfo} from either:
      - New format: op['inputs']['required'] (list of objects with 'param' key)
      - Old format: op['required_params'] (dict)
    """
    # New format
    inputs = op.get('inputs', {})
    req_list = inputs.get('required', [])
    if req_list:
        return {r['param']: {
            'type':        r.get('type', 'string'),
            'location':    r.get('location', 'path'),
            'pattern':     r.get('pattern', ''),
            'description': r.get('description', ''),
        } for r in req_list}

    # Old format
    return op.get('required_params', {})


def get_required_slots(op: dict) -> list[dict]:
    """
    Return list of {pname, slot_name, after_segment} for params that
    are NOT always_available (i.e. must come from a prior op).
    Supports both new format (inputs.required[]) and old format (required_params).
    """
    slots = []

    # New format: use pre-parsed slots from inputs.required[].slots[]
    inputs = op.get('inputs', {})
    req_list = inputs.get('required', [])
    if req_list:
        for r in req_list:
            pname = r['param']
            if pname in ALWAYS_AVAILABLE:
                continue
            for slot in r.get('slots', []):
                if slot.get('source') == 'from_list_op':
                    slots.append({
                        'pname':        pname,
                        'slot_name':    slot['slot'],
                        'after_segment': slot.get('after_segment', pname.replace('Id','')),
                    })
            # If no from_list_op slots but param itself is not always_available
            if not r.get('slots') or all(s.get('source') != 'from_list_op' for s in r.get('slots', [])):
                # Check if simple non-composite param
                pattern = r.get('pattern', '')
                is_composite = bool(re.search(r'(?<!\[)[^[]*/', pattern))
                if not is_composite and pname not in ALWAYS_AVAILABLE:
                    slots.append({
                        'pname':        pname,
                        'slot_name':    pname,
                        'after_segment': pname.replace('Id', ''),
                    })
        return slots

    # Old format
    req = op.get('required_params', {})
    for pname, pinfo in req.items():
        if pname in ALWAYS_AVAILABLE:
            continue
        pattern = pinfo.get('pattern', '')
        is_composite = bool(re.search(r'(?<!\[)[^[]*/', pattern))

        if is_composite:
            _, parsed_slots = parse_pattern(pattern)
            for s in parsed_slots:
                if s['source'] == 'from_list_op':
                    slots.append({
                        'pname':        pname,
                        'slot_name':    s['slot'],
                        'after_segment': s['after_segment'],
                    })
        else:
            slots.append({
                'pname':        pname,
                'slot_name':    pname,
                'after_segment': pname.replace('Id', ''),
            })
    return slots


def rebuild_step3(svc_dir: Path) -> dict | None:
    s2 = svc_dir / 'step2_read_operation_registry.json'
    if not s2.exists(): return None
    s2d  = json.load(open(s2))
    ops  = s2d.get('operations', {})
    if not ops: return None

    # Pre-compute list_ops_info for tiered resolver
    list_ops_info = build_list_ops_info(ops)

    # Build param_producers using TIERED resolver:
    # For each dependent op, find which list op can provide each of its slots.
    # param_producers maps: slot_name → [list_op_key, ...]
    # But we also need a per-op mapping: op_key → [(slot_name, list_op_key), ...]
    slot_producers = {}  # (op_key, slot_name) → list_op_key

    for op_key, op in ops.items():
        if op.get('kind') == 'read_list' or op.get('independent', False):
            continue
        for slot_info in get_required_slots(op):
            after_seg  = slot_info['after_segment']
            slot_name  = slot_info['slot_name']
            key = (op_key, slot_name)
            lk, li, tier = resolve_list_op_for_slot(after_seg, slot_name, list_ops_info)
            if tier < 5 and lk:
                slot_producers[key] = lk

    # Build adjacency: list_op → dependent_ops (that it feeds)
    # Also build param_producers for BFS: slot_name → [list_op_keys]
    param_producers_map = defaultdict(list)  # slot_name → [list_op_key]
    for (dep_op, slot_name), list_op in slot_producers.items():
        if list_op not in param_producers_map[slot_name]:
            param_producers_map[slot_name].append(list_op)

    # Build adjacency for BFS
    adjacency = defaultdict(set)
    for op_key, op in ops.items():
        for slot_info in get_required_slots(op):
            slot_name = slot_info['slot_name']
            key = (op_key, slot_name)
            if key in slot_producers:
                prod = slot_producers[key]
                adjacency[prod].add(op_key)

    # BFS hop distances from independent roots
    distances = {}
    queue = deque()
    for op_key, op in ops.items():
        if op.get('independent', False):
            distances[op_key] = 0
            queue.append(op_key)
    while queue:
        cur = queue.popleft()
        d   = distances[cur]
        for nxt in adjacency.get(cur, set()):
            if nxt not in distances:
                distances[nxt] = d + 1
                queue.append(nxt)
    for op_key in ops:
        if op_key not in distances:
            distances[op_key] = 999

    # ── Build execution chain for each op ────────────────────────────────────

    def best_list_op_for_slot(op_key, slot_name, exclude):
        key = (op_key, slot_name)
        cand = slot_producers.get(key)
        if cand and cand not in exclude:
            return cand
        # fallback: search by slot_name in all slot_producers
        for (ok2, sn), lop in slot_producers.items():
            if sn == slot_name and lop not in exclude:
                return lop
        return None

    def collect_chain(target_op_key, visited):
        """DFS: collect prerequisite list ops in execution order."""
        if target_op_key in visited:
            return []
        visited = visited | {target_op_key}
        op = ops.get(target_op_key, {})
        before = []
        for slot_info in get_required_slots(op):
            slot_name = slot_info['slot_name']
            prod = best_list_op_for_slot(target_op_key, slot_name, visited)
            if not prod:
                continue
            # Recursively get what prod needs
            for item in collect_chain(prod, visited):
                if item not in before:
                    before.append(item)
            if prod not in before:
                before.append(prod)
        return before

    chains = {}
    for op_key, op in ops.items():
        pre         = collect_chain(op_key, set())
        steps_keys  = pre + [op_key]
        steps       = []
        # Track what each earlier step produces
        step_provides = {}  # slot_name → (step_n, from_op_key, id_field)

        for i, sk in enumerate(steps_keys, 1):
            sop  = ops.get(sk, {})
            kind = sop.get('kind', '')
            list_field, id_field = get_list_output(sk, sop) if kind == 'read_list' else (None, None)

            parts    = sk.split('.')
            resource = parts[-2] if len(parts) >= 2 else ''

            # What param does this list op feed?
            # Use singularize(resource)+'Id' as the canonical slot name
            feeds_slot = (singularize(resource) + 'Id') if kind == 'read_list' else None

            # param_sources for this step
            param_sources = {}
            req = get_required_params_dict(sop)
            for pname, pinfo in req.items():
                if pname in ALWAYS_AVAILABLE:
                    param_sources[pname] = 'always_available'
                else:
                    pattern = pinfo.get('pattern', '')
                    is_composite = bool(re.search(r'(?<!\[)[^[]*/', pattern))
                    if is_composite:
                        _, parsed_slots = parse_pattern(pattern)
                        from_list_slots = [s for s in parsed_slots if s['source'] == 'from_list_op']
                        if from_list_slots:
                            resolved = {}
                            for s in from_list_slots:
                                sn = s['slot']
                                if sn in step_provides:
                                    step_n, from_op, field = step_provides[sn]
                                    resolved[sn] = {'from_step': step_n, 'from_op': from_op, 'field': field}
                            if resolved:
                                param_sources[pname] = resolved
                            else:
                                param_sources[pname] = 'unresolved'
                        else:
                            param_sources[pname] = 'always_available'
                    else:
                        # Simple param or slot lookup
                        # Check both the param name and the slot name from inputs.required
                        found = False
                        # Try slot names from inputs.required
                        for slot_info in get_required_slots(sop):
                            if slot_info['pname'] == pname:
                                sn = slot_info['slot_name']
                                if sn in step_provides:
                                    step_n, from_op, field = step_provides[sn]
                                    param_sources[pname] = {'from_step': step_n, 'from_op': from_op, 'field': field}
                                    found = True
                                    break
                        if not found:
                            if pname in step_provides:
                                step_n, from_op, field = step_provides[pname]
                                param_sources[pname] = {'from_step': step_n, 'from_op': from_op, 'field': field}
                            else:
                                param_sources[pname] = 'unresolved'

            # Record what this step provides for future steps
            if feeds_slot and list_field and id_field:
                step_provides[feeds_slot] = (i, sk, id_field)
                # Also record under the resource name and singular variants
                step_provides[resource]              = (i, sk, id_field)
                step_provides[singularize(resource)] = (i, sk, id_field)
                # Also record under the actual id_field name and its base
                step_provides[id_field]              = (i, sk, id_field)
                id_base = singularize(id_field.lower())
                step_provides[id_base]               = (i, sk, id_field)
                # Record slot names from dependent ops' resolver results
                for dep_op_key2, dep_slot in slot_producers.items():
                    if dep_slot == sk:
                        op_key2, slot_nm = dep_op_key2
                        step_provides[slot_nm] = (i, sk, id_field)

            purpose = 'Target operation' if sk == op_key else f'Provides: {feeds_slot or sk}'

            # Build path from op http section (new format) or direct path (old format)
            op_path = sop.get('http', {}).get('path', '') or sop.get('path', '')

            steps.append({
                'step':              i,
                'op':                sk,
                'kind':              kind,
                'independent':       sop.get('independent', False),
                'python_call':       sop.get('python_call', ''),
                'path':              op_path,
                'required_params':   req,
                'output_list_field': list_field,
                'output_id_field':   id_field,
                'produces': {feeds_slot: {
                    'via_list_field': list_field,
                    'from_id_field':  id_field,
                    'note': (
                        f'Iterate response["{list_field}"][], '
                        f'extract item["{id_field}"] → pass as "{feeds_slot}"'
                    ),
                }} if feeds_slot and list_field else {},
                'param_sources':  param_sources,
                'purpose':        purpose,
                'full_resource_name_template': sop.get('resource_path', '') or sop.get('path', ''),
            })

        # Summarise unresolved params at target step
        target_step = steps[-1] if steps else {}
        unresolved = [
            p for p, v in target_step.get('param_sources', {}).items()
            if v == 'unresolved'
        ]
        req_dict = get_required_params_dict(op)
        always_params = [p for p in req_dict if p in ALWAYS_AVAILABLE]

        chains[op_key] = {
            'target_op':            op_key,
            'kind':                 op.get('kind', ''),
            'independent':          op.get('independent', False),
            'hop_distance':         distances.get(op_key, 999),
            'chain_length':         len(steps),
            'execution_steps':      steps,
            'always_available_params': always_params,
            'unresolved_params':    unresolved,
        }

    n_ind = sum(1 for c in chains.values() if c['independent'])
    return {
        'service':        s2d.get('service', svc_dir.name),
        'version':        s2d.get('version', ''),
        'total_ops':      len(chains),
        'total_chains':   len(chains),
        'independent_ops': n_ind,
        'dependent_ops':  len(chains) - n_ind,
        'chains':         chains,
    }


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — rebuild fields dependency chain from step3
# ─────────────────────────────────────────────────────────────────────────────

def rebuild_step4(svc_dir: Path) -> dict | None:
    s3_path = svc_dir / 'step3_read_operation_dependency_chain_independent.json'
    s2_path = svc_dir / 'step2_read_operation_registry.json'
    if not s3_path.exists() or not s2_path.exists(): return None

    s3  = json.load(open(s3_path))
    s2  = json.load(open(s2_path))
    ops = s2.get('operations', {})

    # Roots = independent ops
    roots = []
    for op_key, op in ops.items():
        if op.get('independent', False):
            list_field, id_field = get_list_output(op_key, op) if op.get('kind') == 'read_list' else (None, None)
            parts    = op_key.split('.')
            resource = parts[-2] if len(parts) >= 2 else ''
            feeds    = (singularize(resource) + 'Id') if op.get('kind') == 'read_list' else None
            roots.append({
                'op':           op_key,
                'kind':         op.get('kind', ''),
                'python_call':  op.get('python_call', ''),
                'path':         op.get('path', ''),
                'required_params': op.get('required_params', {}),
                'output_list_field': list_field,
                'output_id_field':   id_field,
                'produces': {feeds: {
                    'via_list_field': list_field,
                    'from_id_field':  id_field,
                    'note': f'Iterate response["{list_field}"][], extract item["{id_field}"] → pass as "{feeds}"',
                }} if feeds and list_field else {},
                'hop_distance': 0,
            })

    # Build step4 chains using step3 execution_steps as base
    result_chains = {}
    for op_key, chain in s3.get('chains', {}).items():
        steps = chain.get('execution_steps', [])
        result_chains[op_key] = {
            'target_op':    op_key,
            'kind':         chain.get('kind', ''),
            'independent':  chain.get('independent', False),
            'hop_distance': chain.get('hop_distance', 999),
            'chain_length': chain.get('chain_length', 1),
            'execution_steps': steps,
            'always_available_params': chain.get('always_available_params', []),
            'unresolved_params': chain.get('unresolved_params', []),
        }

    n_ind = sum(1 for c in result_chains.values() if c['independent'])
    return {
        'service':       s2.get('service', svc_dir.name),
        'version':       s2.get('version', ''),
        'total_ops':     len(result_chains),
        'independent_ops': n_ind,
        'dependent_ops': len(result_chains) - n_ind,
        'roots':         roots,
        'chains':        result_chains,
    }


# ─────────────────────────────────────────────────────────────────────────────
# RUN ALL
# ─────────────────────────────────────────────────────────────────────────────

def run():
    print('='*70)
    print('Rebuilding step2 / step3 / step4 from step1 (tiered resolver)')
    print('='*70)

    all_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and (d / 'step1_api_driven_registry.json').exists()
    )

    s2_ok = s3_ok = s4_ok = 0
    total_resolved = 0
    total_unresolved = 0
    total_chains = 0

    for svc_dir in all_dirs:
        svc = svc_dir.name

        # step2
        ok2 = rebuild_step2(svc_dir)
        if ok2: s2_ok += 1

        # step3
        s3 = rebuild_step3(svc_dir)
        if s3:
            json.dump(s3, open(svc_dir/'step3_read_operation_dependency_chain_independent.json','w'), indent=2)
            s3_ok += 1
            # Count resolved vs unresolved
            for chain in s3.get('chains', {}).values():
                total_chains += 1
                ur = chain.get('unresolved_params', [])
                total_unresolved += len(ur)
                total_resolved   += chain.get('chain_length', 1) - len(ur)

        # step4
        s4 = rebuild_step4(svc_dir)
        if s4:
            json.dump(s4, open(svc_dir/'step4_fields_dependency_chain.json','w'), indent=2)
            s4_ok += 1

        status = f's2={"✓" if ok2 else "✗"}  s3={"✓" if s3 else "✗"}  s4={"✓" if s4 else "✗"}'
        print(f'  {svc:45s}  {status}')

    print()
    print('='*70)
    print(f'step2 rebuilt    : {s2_ok}')
    print(f'step3 rebuilt    : {s3_ok}')
    print(f'step4 rebuilt    : {s4_ok}')
    print(f'Total chains     : {total_chains}')
    print(f'Unresolved params: {total_unresolved}')
    print('='*70)

if __name__ == '__main__':
    run()
