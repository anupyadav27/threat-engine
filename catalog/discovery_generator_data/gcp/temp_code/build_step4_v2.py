#!/usr/bin/env python3
"""
Step4 v2 — Full produced-fields index + min-hop dependency chain resolution.

For every service:

PHASE 1 — Build produced_fields index
  Each op declares what params/fields it can produce for downstream ops.

  read_list op:
    - iterates over output_list_field items
    - each item has fields (item_fields from response schema)
    - the id_field of the item becomes available as a param (e.g. "name", "id")
    - the param name consumed downstream is derived from the resource (e.g. tableId, datasetId)
    - produces: { param_name: { from_field: "name", via_list_field: "items", op: "..." } }

  read_get op:
    - returns a single object with all response_fields
    - each scalar field becomes producible
    - produces: { field_name: { from_field: "field_name", op: "..." } }

PHASE 2 — For each required param of every op, find ALL ops that can produce it
  - Map: param_name → list of (op_key, hops_from_root)
  - hops_from_root = BFS distance from an independent root op
  - Pick the producer with MINIMUM hops

PHASE 3 — Build the resolved execution chain
  - For each op, walk its required params, find min-hop producers
  - Recursively resolve producers' own dependencies
  - Deduplicate, sort topologically
  - Result: ordered list of steps with no unresolved params

Output per op:
{
  "target_op": "gcp.bigquery.tables.get",
  "kind": "read_get",
  "independent": false,
  "chain_length": 3,
  "execution_steps": [
    {
      "step": 1,
      "op": "gcp.bigquery.datasets.list",
      "kind": "read_list",
      "python_call": "svc.datasets().list(**params).execute()",
      "required_params": {"projectId": {...}},
      "produces": {
        "datasetId": {
          "via_list_field": "datasets",
          "from_id_field": "id",
          "note": "iterate datasets[], extract item.id → use as datasetId"
        }
      },
      "param_sources": { "projectId": "always_available" }
    },
    {
      "step": 2,
      "op": "gcp.bigquery.tables.list",
      "kind": "read_list",
      "python_call": "svc.tables().list(**params).execute()",
      "required_params": {"projectId": {...}, "datasetId": {...}},
      "produces": {
        "tableId": {
          "via_list_field": "tables",
          "from_id_field": "id",
          "note": "iterate tables[], extract item.id → use as tableId"
        }
      },
      "param_sources": {
        "projectId": "always_available",
        "datasetId": {"from_step": 1, "from_op": "gcp.bigquery.datasets.list", "field": "id"}
      }
    },
    {
      "step": 3,
      "op": "gcp.bigquery.tables.get",
      "kind": "read_get",
      "python_call": "svc.tables().get(**params).execute()",
      "required_params": {"projectId": {...}, "datasetId": {...}, "tableId": {...}},
      "produces": { ... all response fields ... },
      "param_sources": {
        "projectId": "always_available",
        "datasetId": {"from_step": 1, "from_op": "gcp.bigquery.datasets.list", "field": "id"},
        "tableId":   {"from_step": 2, "from_op": "gcp.bigquery.tables.list",   "field": "id"}
      }
    }
  ]
}
"""

import json
import re
from pathlib import Path
from collections import defaultdict, deque

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

ALWAYS_AVAILABLE = {
    'projectId', 'project', 'parent',
    'location', 'region', 'zone',
    'organizationId', 'folderId', 'billingAccountId',
    'customerId', 'accountId',
}

PATH_PARAM_RE = re.compile(r'\{[+]?(\w+)\}')


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1: Build produced_fields index for every op
# ─────────────────────────────────────────────────────────────────────────────

def singularize(resource: str) -> str:
    """datasets → dataset, instances → instance, policies → policy"""
    if resource.endswith('ies'):
        return resource[:-3] + 'y'
    if resource.endswith('sses'):
        return resource[:-2]
    if resource.endswith('ses'):
        return resource[:-2]
    if resource.endswith('s') and not resource.endswith('ss'):
        return resource[:-1]
    return resource


def param_name_for_resource(resource: str) -> str:
    """datasets → datasetId, instances → instanceId, keyRings → keyRingId"""
    return singularize(resource) + 'Id'


def build_produced_fields(ops: dict) -> dict:
    """
    Returns: { op_key: { param_or_field: { description } } }

    For read_list:  produces { paramId: {via_list_field, from_id_field, note} }
    For read_get:   produces { field_name: {type, note} } for each response field
    For others:     produces {} (empty — we only care about read ops for dependency)
    """
    produced = {}

    for op_key, op in ops.items():
        kind          = op.get('kind', '')
        response_flds = op.get('response_fields', {})
        parts         = op_key.split('.')
        resource      = parts[-2] if len(parts) >= 2 else ''

        op_produces = {}

        if kind == 'read_list':
            # Find the list field and its id_field
            list_field = None
            id_field   = None
            for fname, finfo in response_flds.items():
                if finfo.get('type') == 'array' and finfo.get('id_field'):
                    list_field = fname
                    id_field   = finfo['id_field']
                    break
            # Fallback: find any array field
            if not list_field:
                for fname, finfo in response_flds.items():
                    if finfo.get('type') == 'array' and fname not in ('nextPageToken', 'unreachable'):
                        list_field = fname
                        id_field   = finfo.get('id_field') or 'name'
                        break

            if list_field and id_field:
                # The param this op feeds downstream
                param_id = param_name_for_resource(resource)
                op_produces[param_id] = {
                    'via_list_field': list_field,
                    'from_id_field':  id_field,
                    'note': (f'Iterate response["{list_field}"][], '
                             f'extract item["{id_field}"] → pass as "{param_id}"'),
                }
                # Also expose item_fields as producible (for richer consumers)
                item_fields = response_flds.get(list_field, {}).get('item_fields', [])
                op_produces['_item_fields'] = item_fields
                op_produces['_list_field']  = list_field
                op_produces['_id_field']    = id_field

        elif kind == 'read_get':
            # Produces all scalar/object response fields
            for fname, finfo in response_flds.items():
                ftype = finfo.get('type', 'string')
                op_produces[fname] = {
                    'type': ftype,
                    'note': f'response field "{fname}" from {op_key}',
                }

        produced[op_key] = op_produces

    return produced


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2: BFS from roots → compute hop distance for every op
# ─────────────────────────────────────────────────────────────────────────────

def compute_hop_distances(ops: dict, produced: dict) -> dict:
    """
    BFS from all independent (root) ops.
    Returns: { op_key: int }  where int = min hops from any root (root=0)
    """
    # Build graph: op_key → set of op_keys it can unlock (has params for)
    # An op B is unlocked by op A if A produces a param that B requires.

    # param → list of ops that produce it
    param_producers: dict[str, list] = defaultdict(list)
    for op_key, prods in produced.items():
        for pname, pinfo in prods.items():
            if pname.startswith('_'):
                continue  # skip metadata keys
            param_producers[pname].append(op_key)

    # Build adjacency: op_A → ops_it_unlocks
    adjacency: dict[str, set] = defaultdict(set)
    for op_key, op in ops.items():
        required = op.get('required_params', {})
        for pname in required:
            if pname in ALWAYS_AVAILABLE:
                continue
            for producer in param_producers.get(pname, []):
                if producer != op_key:
                    adjacency[producer].add(op_key)

    # BFS from all independent ops simultaneously
    distances: dict[str, int] = {}
    queue = deque()

    for op_key, op in ops.items():
        if op.get('independent', False):
            distances[op_key] = 0
            queue.append(op_key)

    while queue:
        current = queue.popleft()
        current_dist = distances[current]
        for neighbor in adjacency.get(current, set()):
            if neighbor not in distances:
                distances[neighbor] = current_dist + 1
                queue.append(neighbor)

    # Ops not reachable from any root get distance = 999 (unresolvable)
    for op_key in ops:
        if op_key not in distances:
            distances[op_key] = 999

    return distances, param_producers


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3: Resolve execution chain for each op
# ─────────────────────────────────────────────────────────────────────────────

def resolve_chain_for_op(
    target_key: str,
    ops: dict,
    produced: dict,
    param_producers: dict,
    distances: dict,
) -> list[str]:
    """
    Returns ordered list of op_keys to execute for this target op.
    Picks min-hop producer for each unresolved param.
    Uses DFS with visited set to avoid cycles.
    """
    def best_producer(param: str, exclude: set) -> str | None:
        candidates = [
            op for op in param_producers.get(param, [])
            if op not in exclude
        ]
        if not candidates:
            return None
        # Pick minimum hop distance, break ties by op_key alphabetically
        return min(candidates, key=lambda x: (distances.get(x, 999), x))

    def collect(op_key: str, visited: set) -> list[str]:
        if op_key in visited:
            return []
        visited = visited | {op_key}

        op       = ops.get(op_key, {})
        required = op.get('required_params', {})
        before   = []

        for pname in required:
            if pname in ALWAYS_AVAILABLE:
                continue
            producer = best_producer(pname, visited)
            if not producer:
                continue
            sub = collect(producer, visited)
            for item in sub:
                if item not in before:
                    before.append(item)
            if producer not in before:
                before.append(producer)

        return before

    visited    = set()
    chain_before = collect(target_key, visited)

    # Deduplicate preserving order
    seen = set()
    ordered = []
    for key in chain_before:
        if key not in seen:
            seen.add(key)
            ordered.append(key)

    ordered.append(target_key)
    return ordered


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4: Build step entries with param_sources
# ─────────────────────────────────────────────────────────────────────────────

def build_step_entry(
    op_key: str,
    step_num: int,
    is_target: bool,
    ops: dict,
    produced: dict,
    chain_keys: list,
    param_producers: dict,
    distances: dict,
) -> dict:
    op       = ops.get(op_key, {})
    required = op.get('required_params', {})
    em       = op.get('execution_model', {})

    # Build param_sources: for each required param, find which step provides it
    # and which field
    param_sources = {}

    # Build lookup: param → (step_num, op_key, field) from earlier steps
    earlier_provides: dict[str, tuple] = {}
    for prev_key in chain_keys:
        if prev_key == op_key:
            break
        prev_step_num = chain_keys.index(prev_key) + 1
        prev_prods = produced.get(prev_key, {})
        for pname, pinfo in prev_prods.items():
            if pname.startswith('_'):
                continue
            if pname not in earlier_provides:
                earlier_provides[pname] = (prev_step_num, prev_key, pinfo)

    for pname in required:
        if pname in ALWAYS_AVAILABLE:
            param_sources[pname] = 'always_available'
        elif pname in earlier_provides:
            step_n, from_op, pinfo = earlier_provides[pname]
            param_sources[pname] = {
                'from_step': step_n,
                'from_op':   from_op,
                'field':     pinfo.get('from_id_field', pinfo.get('note', pname)),
            }
        else:
            param_sources[pname] = 'unresolved'

    # What this step produces
    op_produces = {k: v for k, v in produced.get(op_key, {}).items()
                   if not k.startswith('_')}

    # Metadata from execution_model
    list_field = em.get('output_list_field') or produced.get(op_key, {}).get('_list_field')
    id_field   = em.get('output_id_field') or produced.get(op_key, {}).get('_id_field')

    return {
        'step':             step_num,
        'op':               op_key,
        'kind':             op.get('kind', ''),
        'independent':      op.get('independent', False),
        'python_call':      op.get('python_call', ''),
        'path':             op.get('path', ''),
        'required_params':  required,
        'output_list_field': list_field,
        'output_id_field':  id_field,
        'produces':         op_produces,
        'param_sources':    param_sources,
        'purpose':          'Target operation' if is_target else (
            f'Provides: {list(op_produces.keys())[0]}' if op_produces else 'Prerequisite'
        ),
        'full_resource_name_template': op.get('resource_path', ''),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main per-service builder
# ─────────────────────────────────────────────────────────────────────────────

def build_step4_for_service(svc_dir: Path) -> dict | None:
    s2_path = svc_dir / 'step2_read_operation_registry.json'
    if not s2_path.exists():
        return None

    data    = json.load(open(s2_path))
    ops     = data.get('operations', {})
    service = data.get('service', svc_dir.name)
    version = data.get('version', '')

    if not ops:
        return None

    # Phase 1: what each op produces
    produced = build_produced_fields(ops)

    # Phase 2: hop distances from roots
    distances, param_producers = compute_hop_distances(ops, produced)

    # Phase 3 + 4: build full chain entries
    roots        = []
    chain_entries = {}

    # Identify independent ops (roots)
    for op_key, op in ops.items():
        if op.get('independent', False):
            prods  = {k: v for k, v in produced.get(op_key, {}).items()
                      if not k.startswith('_')}
            em     = op.get('execution_model', {})
            roots.append({
                'op':               op_key,
                'kind':             op.get('kind', ''),
                'python_call':      op.get('python_call', ''),
                'path':             op.get('path', ''),
                'required_params':  op.get('required_params', {}),
                'output_list_field': em.get('output_list_field') or produced[op_key].get('_list_field'),
                'output_id_field':  em.get('output_id_field') or produced[op_key].get('_id_field'),
                'produces':         prods,
                'hop_distance':     0,
            })

    # Build chains for ALL ops
    for op_key, op in ops.items():
        chain_keys = resolve_chain_for_op(
            op_key, ops, produced, param_producers, distances
        )

        always_av  = [p for p in op.get('required_params', {}) if p in ALWAYS_AVAILABLE]
        unresolved = [
            p for p in op.get('required_params', {})
            if p not in ALWAYS_AVAILABLE
            and p not in {
                pname for prev_key in chain_keys[:-1]
                for pname in produced.get(prev_key, {})
                if not pname.startswith('_')
            }
        ]

        execution_steps = [
            build_step_entry(
                key, i + 1, key == op_key,
                ops, produced, chain_keys, param_producers, distances
            )
            for i, key in enumerate(chain_keys)
        ]

        chain_entries[op_key] = {
            'target_op':    op_key,
            'kind':         op.get('kind', ''),
            'independent':  op.get('independent', False),
            'hop_distance': distances.get(op_key, 999),
            'chain_length': len(chain_keys),
            'execution_steps': execution_steps,
            'always_available_params': always_av,
            'unresolved_params':       unresolved,
        }

    n_ind = sum(1 for op in ops.values() if op.get('independent'))
    n_dep = len(ops) - n_ind

    return {
        'service':         service,
        'version':         version,
        'total_ops':       len(ops),
        'independent_ops': n_ind,
        'dependent_ops':   n_dep,
        'roots':           roots,
        'chains':          chain_entries,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────────────────────────────────────

def run():
    print('=' * 70)
    print('Step4 v2 — produced_fields index + min-hop chain resolution')
    print('=' * 70)
    print()

    all_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and (d / 'step2_read_operation_registry.json').exists()
    )

    built = skipped = 0
    total_roots = total_resolved = total_unresolved = 0

    for svc_dir in all_dirs:
        result = build_step4_for_service(svc_dir)
        if not result:
            print(f'  ⏭  {svc_dir.name}: skip')
            skipped += 1
            continue

        out_path = svc_dir / 'step4_fields_dependency_chain.json'
        with open(out_path, 'w') as f:
            json.dump(result, f, indent=2)

        built += 1

        # Count resolved vs unresolved params across all chains
        n_resolved   = sum(
            1 for c in result['chains'].values()
            for step in c['execution_steps']
            for src in step['param_sources'].values()
            if src != 'unresolved'
        )
        n_unresolved = sum(
            len(c['unresolved_params']) for c in result['chains'].values()
        )
        total_roots      += len(result['roots'])
        total_resolved   += n_resolved
        total_unresolved += n_unresolved

        print(f'  ✓ {svc_dir.name}: '
              f'{len(result["roots"])} roots | '
              f'{result["dependent_ops"]} dep | '
              f'{n_unresolved} unresolved params')

    print()
    print('=' * 70)
    print(f'Services built:       {built}')
    print(f'Skipped:              {skipped}')
    print(f'Total roots:          {total_roots}')
    print(f'Total resolved params:{total_resolved}')
    print(f'Total unresolved:     {total_unresolved}')
    print('=' * 70)


if __name__ == '__main__':
    run()
