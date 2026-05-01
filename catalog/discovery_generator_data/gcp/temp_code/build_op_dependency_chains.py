#!/usr/bin/env python3
"""
For every dependent op in step2_read_operation_registry.json, trace its
full execution chain back to independent roots.

Output per service: step3_op_dependency_chains.json

Structure:
{
  "service": "bigquery",
  "total_chains": 23,
  "chains": {
    "gcp.bigquery.tables.get": {
      "target_op": "gcp.bigquery.tables.get",
      "independent": false,
      "chain_length": 3,
      "execution_order": [
        {
          "step": 1,
          "op": "gcp.bigquery.datasets.list",
          "kind": "read_list",
          "independent": true,
          "purpose": "Provides: datasetId",
          "required_params": {"projectId": ...},
          "output_list_field": "datasets",
          "output_id_field": "datasets",
          "output_id_feeds_param": null,
          "feeds_param": "datasetId"
        },
        {
          "step": 2,
          "op": "gcp.bigquery.tables.list",
          "kind": "read_list",
          "independent": false,
          "purpose": "Provides: tableId",
          "required_params": {...},
          "output_list_field": "tables",
          "output_id_field": "tables",
          "feeds_param": "tableId"
        },
        {
          "step": 3,
          "op": "gcp.bigquery.tables.get",
          "kind": "read_get",
          "independent": false,
          "purpose": "Target operation",
          "required_params": {...},
          "output_list_field": null,
          "output_id_field": null,
          "feeds_param": null
        }
      ],
      "always_available_params": ["projectId"],
      "unresolved_params": ["resource"]   ← params with no known provider
    }
  }
}
"""

import json
from pathlib import Path
from collections import defaultdict

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')


def build_chains_for_service(svc_dir: Path) -> dict | None:
    step2_path = svc_dir / 'step2_read_operation_registry.json'
    if not step2_path.exists():
        return None

    data = json.load(open(step2_path))
    ops  = data.get('operations', {})
    if not ops:
        return None

    service = data.get('service', svc_dir.name)

    # ── Index all ops ─────────────────────────────────────────────────────────
    # param → list op that produces it
    param_to_list_op: dict[str, str] = {}
    for op_key, op in ops.items():
        if op.get('kind') != 'read_list':
            continue
        em = op.get('execution_model', {})
        feeds = em.get('output_id_feeds_param')
        if feeds:
            # prefer this mapping
            param_to_list_op[feeds] = op_key

        # Also infer from input_params of other ops that reference this op
        # (build reverse index from from_op links)

    # Build reverse index: from_op → params it provides
    # Walk all ops and collect from_op links
    from_op_provides: dict[str, set] = defaultdict(set)
    for op_key, op in ops.items():
        em = op.get('execution_model', {})
        for ip in em.get('input_params', []):
            if ip.get('source') == 'from_prior_op' and ip.get('from_op'):
                from_op_provides[ip['from_op']].add(ip['param'])
                # also record it as producing that param
                if ip['param'] not in param_to_list_op:
                    param_to_list_op[ip['param']] = ip['from_op']

    # ── Resolve full chain for one op ─────────────────────────────────────────
    def resolve_chain(target_key: str, visited: set = None) -> list[dict]:
        """
        Returns ordered list of ops to execute, from roots to target.
        Uses BFS/DFS to collect all prerequisite ops.
        """
        if visited is None:
            visited = set()
        if target_key in visited:
            return []
        visited.add(target_key)

        op = ops.get(target_key)
        if not op:
            return []

        em            = op.get('execution_model', {})
        input_params  = em.get('input_params', [])
        chain_before  = []

        # For each required param that comes from a prior op, recurse
        for ip in input_params:
            if ip.get('source') != 'from_prior_op':
                continue
            provider_op = ip.get('from_op')
            if not provider_op:
                # try param_to_list_op index
                provider_op = param_to_list_op.get(ip['param'])
            if not provider_op or provider_op == target_key:
                continue
            if provider_op in visited:
                continue
            # Recurse: get the chain needed to produce this provider
            sub_chain = resolve_chain(provider_op, visited)
            for item in sub_chain:
                if item not in chain_before:
                    chain_before.append(item)

        # Add self
        chain_before.append(target_key)
        return chain_before

    # ── Build step info for one op ─────────────────────────────────────────────
    def make_step(op_key: str, step_num: int, is_target: bool) -> dict:
        op = ops.get(op_key, {})
        em = op.get('execution_model', {})

        # Which param does this op feed into the next step?
        feeds_param = em.get('output_id_feeds_param')
        # If not set, infer from what the next steps need from this op
        if not feeds_param:
            provided = from_op_provides.get(op_key, set())
            feeds_param = list(provided)[0] if len(provided) == 1 else (list(provided) if provided else None)

        return {
            'step':             step_num,
            'op':               op_key,
            'kind':             op.get('kind', ''),
            'independent':      op.get('independent', False),
            'python_call':      op.get('python_call', ''),
            'purpose':          'Target operation' if is_target else (
                                f'Provides: {feeds_param}' if feeds_param else 'Prerequisite'),
            'path':             op.get('path', ''),
            'required_params':  op.get('required_params', {}),
            'output_list_field': em.get('output_list_field'),
            'output_id_field':  em.get('output_id_field'),
            'feeds_param':      feeds_param,
            'full_resource_name_template': em.get('full_resource_name_template', ''),
        }

    # ── Process all ops ────────────────────────────────────────────────────────
    chains = {}

    for op_key, op in ops.items():
        # Build chain for ALL ops (both independent and dependent)
        # Independent ops have chain_length=1 (just themselves)

        em           = op.get('execution_model', {})
        input_params = em.get('input_params', [])

        # Collect unresolved params (no from_op and not always_available)
        always_av = [ip['param'] for ip in input_params if ip.get('source') == 'always_available']
        unresolved = [
            ip['param'] for ip in input_params
            if ip.get('source') == 'from_prior_op'
            and not ip.get('from_op')
            and ip['param'] not in param_to_list_op
        ]

        # Resolve full ordered chain
        visited  = set()
        chain_keys = resolve_chain(op_key, visited)

        # Build execution_order steps
        execution_order = []
        for i, key in enumerate(chain_keys):
            is_target = (key == op_key)
            execution_order.append(make_step(key, i + 1, is_target))

        chains[op_key] = {
            'target_op':             op_key,
            'kind':                  op.get('kind', ''),
            'independent':           op.get('independent', False),
            'chain_length':          len(chain_keys),
            'execution_order':       execution_order,
            'always_available_params': always_av,
            'unresolved_params':     unresolved,
        }

    return {
        'service':      service,
        'version':      data.get('version', ''),
        'total_ops':    len(ops),
        'total_chains': len(chains),
        'independent_ops': sum(1 for op in ops.values() if op.get('independent')),
        'dependent_ops':   sum(1 for op in ops.values() if not op.get('independent')),
        'chains':       chains,
    }


def run():
    print('=' * 70)
    print('Building op dependency chains for all GCP services')
    print('=' * 70)
    print()

    all_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and (d / 'step2_read_operation_registry.json').exists()
    )

    total_svcs = 0
    total_chains = 0
    max_depth = 0
    max_depth_svc = ''

    for svc_dir in all_dirs:
        result = build_chains_for_service(svc_dir)
        if not result:
            continue

        # Write output
        out_path = svc_dir / 'step3_read_operation_dependency_chain_independent.json'
        with open(out_path, 'w') as f:
            json.dump(result, f, indent=2)

        total_svcs   += 1
        total_chains += result['total_chains']

        # Track deepest chain
        if result['chains']:
            deepest = max(c['chain_length'] for c in result['chains'].values())
            if deepest > max_depth:
                max_depth     = deepest
                max_depth_svc = result['service']

        print(f'  ✓ {svc_dir.name}: '
              f'{result["independent_ops"]} ind / {result["dependent_ops"]} dep ops, '
              f'{result["total_chains"]} chains')

    print()
    print('=' * 70)
    print(f'Services processed: {total_svcs}')
    print(f'Total chains built: {total_chains}')
    print(f'Deepest chain:      {max_depth} steps ({max_depth_svc})')
    print('=' * 70)


if __name__ == '__main__':
    run()
