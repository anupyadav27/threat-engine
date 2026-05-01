#!/usr/bin/env python3
"""
Regenerate step4_read_operation_dependency_chain.json for ALL services
from the new step3_read_operation_dependency_chain_independent.json data.

step4 is the EXECUTION PLAN format — answers:
"Given a target op, what is the complete ordered list of API calls to make,
with exact params to pass at each step (where they come from)?"

Structure:
{
  "service": "bigquery",
  "version": "v2",
  "total_ops": 27,
  "independent_ops": 5,
  "dependent_ops": 22,
  "roots": [                            ← independent ops (starting points)
    {
      "op": "gcp.bigquery.datasets.list",
      "kind": "read_list",
      "python_call": "svc.datasets().list(**params).execute()",
      "required_params": {...},
      "output_list_field": "datasets",
      "output_id_field": "id",
      "feeds_param": "datasetId"
    }
  ],
  "chains": {                           ← one entry per op (ind + dep)
    "gcp.bigquery.tables.get": {
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
          "output_list_field": "datasets",
          "output_id_field": "id",
          "feeds_param": "datasetId",
          "param_sources": {
            "projectId": "always_available"
          }
        },
        {
          "step": 2,
          "op": "gcp.bigquery.tables.list",
          "kind": "read_list",
          "python_call": "svc.tables().list(**params).execute()",
          "required_params": {"projectId": {...}, "datasetId": {...}},
          "output_list_field": "tables",
          "output_id_field": "id",
          "feeds_param": "tableId",
          "param_sources": {
            "projectId": "always_available",
            "datasetId": "step_1.output_id"
          }
        },
        {
          "step": 3,
          "op": "gcp.bigquery.tables.get",
          "kind": "read_get",
          "python_call": "svc.tables().get(**params).execute()",
          "required_params": {"projectId": {...}, "datasetId": {...}, "tableId": {...}},
          "output_list_field": null,
          "output_id_field": null,
          "feeds_param": null,
          "param_sources": {
            "projectId": "always_available",
            "datasetId": "step_1.output_id",
            "tableId": "step_2.output_id"
          }
        }
      ],
      "always_available_params": ["projectId"],
      "unresolved_params": []
    }
  }
}
"""

import json
from pathlib import Path

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

ALWAYS_AVAILABLE = {
    'projectId', 'project', 'parent',
    'location', 'region', 'zone',
    'organizationId', 'folderId', 'billingAccountId',
    'customerId', 'accountId',
}


def build_param_sources(execution_order: list) -> list:
    """
    For each step, compute param_sources dict:
    param_name → "always_available" | "step_N.output_id" | "unresolved"

    Walk steps in order, tracking what each step's output_id_field feeds.
    """
    # Track: after each step, which param becomes available and from which step
    available_params: dict[str, str] = {}  # param_name → source string

    result_steps = []

    for i, step in enumerate(execution_order):
        step_num     = step['step']
        required     = step.get('required_params', {})
        feeds_param  = step.get('feeds_param')
        out_id_field = step.get('output_id_field')

        # Build param_sources for this step
        param_sources = {}
        for pname in required:
            if pname in ALWAYS_AVAILABLE:
                param_sources[pname] = 'always_available'
            elif pname in available_params:
                param_sources[pname] = available_params[pname]
            else:
                param_sources[pname] = 'unresolved'

        # After this step runs, its output becomes available for subsequent steps
        # feeds_param tells us what downstream param this step's output populates
        if feeds_param and out_id_field:
            available_params[feeds_param] = f'step_{step_num}.output_id'

        enriched_step = {
            'step':             step_num,
            'op':               step['op'],
            'kind':             step['kind'],
            'python_call':      step.get('python_call', ''),
            'path':             step.get('path', ''),
            'required_params':  required,
            'output_list_field': step.get('output_list_field'),
            'output_id_field':  out_id_field,
            'feeds_param':      feeds_param,
            'param_sources':    param_sources,
            'full_resource_name_template': step.get('full_resource_name_template', ''),
        }
        result_steps.append(enriched_step)

    return result_steps


def build_step4_for_service(svc_dir: Path) -> dict | None:
    s3_path = svc_dir / 'step3_read_operation_dependency_chain_independent.json'
    if not s3_path.exists():
        return None

    s3 = json.load(open(s3_path))
    chains = s3.get('chains', {})
    if not chains:
        return None

    service = s3.get('service', svc_dir.name)
    version = s3.get('version', '')

    # Build roots list (independent ops)
    roots = []
    for op_key, chain in chains.items():
        if chain.get('independent') and chain.get('chain_length', 0) == 1:
            step = chain['execution_order'][0] if chain.get('execution_order') else {}
            roots.append({
                'op':               op_key,
                'kind':             chain.get('kind', ''),
                'python_call':      step.get('python_call', ''),
                'path':             step.get('path', ''),
                'required_params':  step.get('required_params', {}),
                'output_list_field': step.get('output_list_field'),
                'output_id_field':  step.get('output_id_field'),
                'feeds_param':      step.get('feeds_param'),
                'full_resource_name_template': step.get('full_resource_name_template', ''),
            })

    # Build full chain entries with param_sources
    chain_entries = {}
    for op_key, chain in chains.items():
        execution_order = chain.get('execution_order', [])
        enriched_steps  = build_param_sources(execution_order)

        chain_entries[op_key] = {
            'target_op':    op_key,
            'kind':         chain.get('kind', ''),
            'independent':  chain.get('independent', False),
            'chain_length': chain.get('chain_length', 1),
            'execution_steps': enriched_steps,
            'always_available_params': chain.get('always_available_params', []),
            'unresolved_params': chain.get('unresolved_params', []),
        }

    return {
        'service':         service,
        'version':         version,
        'total_ops':       s3.get('total_ops', len(chains)),
        'independent_ops': s3.get('independent_ops', 0),
        'dependent_ops':   s3.get('dependent_ops', 0),
        'roots':           roots,
        'chains':          chain_entries,
    }


def run():
    print('=' * 70)
    print('Building step4 from step3 for all GCP services')
    print('=' * 70)
    print()

    all_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and (d / 'step1_operation_registry.json').exists()
    )

    built = skipped = 0
    total_roots = total_chains = 0

    for svc_dir in all_dirs:
        result = build_step4_for_service(svc_dir)
        if not result:
            print(f'  ⏭  {svc_dir.name}: no step3 — skipping')
            skipped += 1
            continue

        out_path = svc_dir / 'step4_fields_dependency_chain.json'
        with open(out_path, 'w') as f:
            json.dump(result, f, indent=2)

        built       += 1
        total_roots += len(result['roots'])
        total_chains += len(result['chains'])

        print(f'  ✓ {svc_dir.name}: '
              f'{len(result["roots"])} roots / '
              f'{result["independent_ops"]} ind / '
              f'{result["dependent_ops"]} dep / '
              f'{len(result["chains"])} chains')

    print()
    print('=' * 70)
    print(f'Services built:   {built}')
    print(f'Skipped:          {skipped}')
    print(f'Total roots:      {total_roots}')
    print(f'Total chains:     {total_chains}')
    print('=' * 70)


if __name__ == '__main__':
    run()
